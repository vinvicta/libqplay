#!/usr/bin/env python3
"""Export the original 1.8 server-file to cache flow from IDA.

This is a read-only Hex-Rays export for the packet-102 handler, cached-stream
assembly, resource filename resolution, and the request-side file path. The
manual notes are intentionally conservative. They distinguish a server or
man-in-the-middle controlled file response from a proven exploit and preserve
the exact ARM64 binary identity used by the analysis.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import ida_funcs
import ida_hexrays
import ida_kernwin
import idaapi
import idautils
import idc


TARGETS = [
    ("0x1f0de4", "TClient_parseEncodedFileChunk", "packet-102 parser"),
    ("0x1ec764", "TClient_processFileChunk", "cache chunk assembly"),
    ("0x1eb12c", "TClient_beginBigFileDownload", "big-file start"),
    ("0x1ef48c", "TClient_setBigFileSize", "big-file declared size"),
    ("0x1eb208", "TClient_finishDownloadFile", "ordinary-file finish"),
    ("0x1eb294", "TClient_finishFileDownload", "big-file finish"),
    ("0x1ec4a0", "TClient_finishCachedFile", "cached-file finish"),
    ("0x1fa6e8", "TCachedStream_save_bool", "cache save"),
    (
        "0x1fb744",
        "TCachedStream_saveAndUpdate_TCachedStream_TString_const",
        "cache save and resource update",
    ),
    ("0x1fb5b8", "TCachedStream_resolveFilename_void", "cache path resolution"),
    (
        "0x1fa920",
        "TCachedStream_getDownloadFilename_TString_const",
        "download filename mapping",
    ),
    (
        "0xedbcc",
        "TResourceFunctions_getLevelFileResource_TString_const",
        "resource lookup",
    ),
    (
        "0xeec84",
        "TResourceFunctions_getGameFile_TString_const_bool",
        "resource lookup and download gate",
    ),
    ("0x1e8964", "TClient_requestDownload_TString_const", "download queue"),
    ("0x1f0470", "TClient_requestGameFile", "game-file request parser"),
    (
        "0x2013d4",
        "THTTPRequest_requestURLAsGameFile_TString_const_TString_const_uint_bool",
        "game-file HTTP request",
    ),
]


MANUAL_REVIEWS = [
    {
        "address": "0x1f0de4",
        "function": "TClient_parseEncodedFileChunk",
        "classification": "server-file-response-entry",
        "confidence": "confirmed-static",
        "severity": "context-dependent-availability",
        "evidence": [
            "The inbound handler table maps wire packet 102 to handler index 24 and index 24 to this function.",
            "The parser requires more than six bytes, decodes a five-byte offset, and separates the encoded filename field from the remaining file data before calling TClient_processFileChunk.",
            "The offset uses 32-bit arithmetic and has the protocol's 28-bit effective range, but the parser does not impose a total file-size limit here.",
            "Short or malformed bodies are silently ignored rather than reported as a protocol error.",
        ],
        "interpretation": "A trusted game connection can supply the input that reaches cached-file assembly. The parser's local bounds are not a fixed-buffer overwrite finding, but repeated or oversized responses can exercise downstream string growth and filesystem work.",
    },
    {
        "address": "0x1ec764",
        "function": "TClient_processFileChunk",
        "classification": "append-without-declared-size-or-offset-validation",
        "confidence": "confirmed-static",
        "severity": "availability-risk",
        "evidence": [
            "The function resolves or creates a TCachedStream for the supplied filename, appends the data TString to the cached stream, and stores the encoded offset as metadata.",
            "The reviewed body does not compare the offset with the current stream length and does not compare accumulated bytes with the big-file declared size.",
            "For an ordinary response with no active big filename, it immediately emits completion events, saves the cached stream, validates the file key, and advances the download action.",
            "The append operation ultimately uses dynamic TString allocation without a total response budget or allocation-failure handling.",
        ],
        "interpretation": "The server can cause the client to retain and process more data than the declared size suggests. The practical impact is resource exhaustion or inconsistent cache state; no direct write outside the dynamic string was established in this function.",
    },
    {
        "address": "0x1ef48c",
        "function": "TClient_setBigFileSize",
        "classification": "unchecked-big-file-size-metadata",
        "confidence": "confirmed-static",
        "severity": "availability-risk",
        "evidence": [
            "The handler decodes five 7-bit fields into a signed int and stores the result in data_TClient_bigfilesize.",
            "A short body becomes zero, and the function does not reject an oversized or inconsistent value before later progress callbacks use it.",
            "The value is used for progress reporting and is not visibly used to reserve or cap the cached stream in the reviewed path.",
        ],
        "interpretation": "The declared size is metadata rather than an enforced allocation or end-of-file contract. A complete protocol hardening pass should reject inconsistent size and offset sequences before appending data.",
    },
    {
        "address": "0x1fa6e8",
        "function": "TCachedStream_save_bool",
        "classification": "persistent-cache-write-and-executable-guard",
        "confidence": "confirmed-static",
        "severity": "high-impact-capability",
        "evidence": [
            "The function creates parent directories, checks whether the path is below the base user folder, and compares the lowercased path with the configured base executable.",
            "If the path is outside the expected user folder or identifies the base executable, it redirects the save to the configured full executable path, deletes the existing file when present, and sets the replacement flag.",
            "Ordinary files are saved directly or after the resource encryption helper, and the optional timestamp is applied afterward.",
            "The function itself does not verify a package signature or use an atomic replacement protocol.",
        ],
        "interpretation": "This is the concrete file-write side of the previously documented executable replacement capability. The package and resource path checks determine whether an untrusted response can reach it, so this is not a claim that any arbitrary server response can replace the executable.",
    },
    {
        "address": "0x1fb744",
        "function": "TCachedStream_saveAndUpdate_TCachedStream_TString_const",
        "classification": "cache-policy-and-resource-update",
        "confidence": "confirmed-static",
        "severity": "context-dependent",
        "evidence": [
            "The function resolves the final filename before saving and treats .gupd, .gmap, and .wav as persistent-cache classes.",
            "Files outside the configured base folders can be discarded after an in-memory save, while files under approved folders are passed to updateResourceObject.",
            "The stream length is compared with configured RAM and disk cache thresholds, but no general protocol maximum is established here.",
            "The resource update callback can refresh objects that refer to the saved file and can emit follow-up level-file events.",
        ],
        "interpretation": "The cache policy limits some persistence but does not turn a server response into a bounded parser input. The path and file-classification logic needs to be evaluated together with symlink and canonicalization behavior.",
    },
    {
        "address": "0x1fb5b8",
        "function": "TCachedStream_resolveFilename_void",
        "classification": "fallback-path-selection",
        "confidence": "confirmed-static",
        "severity": "path-trust-boundary",
        "evidence": [
            "The resolver lowercases .gupd names and extracts the filepath, then accepts an existing path below the base user folder or chooses a download filename when the path is absent.",
            "The existing-path test uses TFiles_fileExists, which is based on stat, and the reviewed path contains no realpath or no-follow open operation.",
            "The fallback is chosen for a missing file, a non-approved path, or a failed path extraction, so later save behavior depends on the download filename mapper.",
        ],
        "interpretation": "The visible issue is a symlink and canonicalization question, not a proven traversal. A disposable directory test should create links under each accepted folder and observe the final file target before assigning exploitability.",
    },
    {
        "address": "0x1fa920",
        "function": "TCachedStream_getDownloadFilename_TString_const",
        "classification": "extension-and-prefix-directory-mapping",
        "confidence": "confirmed-static",
        "severity": "path-trust-boundary",
        "evidence": [
            "The mapper routes update packages below updatepackages, sound below sounds, maps and level assets below levels or levels3d, and other recognized media into fixed application directories.",
            "Nonprivileged update packages add an escaped server-name component, while the supplied filename is lowercased before extension selection.",
            "The mapper uses the native escaped-filename helper for the final component, but the report does not treat escaping as canonical path validation.",
        ],
        "interpretation": "The mapping is materially narrower than raw concatenation, but it should be paired with an explicit canonical-root check and no-follow file creation in a modern repair.",
    },
    {
        "address": "0xedbcc",
        "function": "TResourceFunctions_getLevelFileResource_TString_const",
        "classification": "registered-resource-lookup",
        "confidence": "confirmed-static",
        "severity": "reviewed-boundary",
        "evidence": [
            "The resolver normalizes the lookup name, searches the global resource-object table case-insensitively, and checks whether the requested path is absolute before accepting an existing resource path.",
            "For relative names it compares extracted directory paths with the primary and alternative resource directories.",
            "When a resource is missing and the extension is .code, it creates a resource object through the cached download filename path.",
        ],
        "interpretation": "This provides the level-file bridge from a requested .nw or .code resource to the cache, but it is not a substitute for canonical filesystem enforcement.",
    },
    {
        "address": "0x1e8964",
        "function": "TClient_requestDownload_TString_const",
        "classification": "deduplicated-download-queue",
        "confidence": "confirmed-static",
        "severity": "resource-amplification",
        "evidence": [
            "The request is dropped when the name is already present in any of four requested-file hash tables.",
            "New names are added to a list, and non-package requests are sent only while the active queue remains at or below ten entries.",
            "Package names are inserted at position ten when the list is already beyond that threshold, preserving update priority without imposing a general total list bound in this function.",
        ],
        "interpretation": "The deduplication reduces repeated requests but is not a complete server-file budget. Resource names supplied by a game script or map still need a total request and cache policy.",
    },
    {
        "address": "0x1f0470",
        "function": "TClient_requestGameFile",
        "classification": "encoded-game-file-request-parser",
        "confidence": "confirmed-static",
        "severity": "reviewed-boundary",
        "evidence": [
            "The handler requires a minimum body length, decodes a five-byte value, validates the embedded filename length against the TString length, strips the filename prefix, and passes the result to THTTPRequest_requestURLAsGameFile.",
            "It uses the bounded TString substring helper for the extracted prefix and filename.",
            "Malformed lengths are ignored without an explicit protocol error event.",
        ],
        "interpretation": "The visible parsing checks prevent the normal substring calls from reading beyond the TString object. The downstream URL and resource policies remain the relevant trust boundaries.",
    },
]


DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_download_cache_flow_review_20260830.json"
)


def sha256_file(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def effective_callers(address: int) -> list[dict]:
    queue = [address]
    visited = set()
    callers = []
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        for reference in idautils.XrefsTo(current, 0):
            caller = ida_funcs.get_func(reference.frm)
            if caller is None or caller.start_ea == current:
                continue
            name = idc.get_func_name(caller.start_ea) or ""
            segment = idc.get_segm_name(caller.start_ea) or ""
            if name.startswith(".") or segment.startswith(".plt"):
                queue.append(caller.start_ea)
                continue
            callers.append(
                {
                    "callsite": "0x%x" % reference.frm,
                    "caller": "0x%x" % caller.start_ea,
                    "caller_name": name,
                }
            )
    unique = {(row["caller"], row["callsite"]): row for row in callers}
    return sorted(
        unique.values(),
        key=lambda row: (int(row["caller"], 16), int(row["callsite"], 16)),
    )


def export_function(address: int, expected_name: str, role: str) -> dict:
    current_name = idc.get_func_name(address) or ""
    if current_name != expected_name:
        raise RuntimeError(
            "unexpected function name at %s: %s (expected %s)"
            % (hex(address), current_name, expected_name)
        )
    function = ida_hexrays.decompile(address)
    if function is None:
        raise RuntimeError("Hex-Rays could not decompile %s" % hex(address))
    code = str(function)
    function_info = ida_funcs.get_func(address)
    literals = sorted(set(re.findall(r'"(?:\\.|[^"\\])*"', code)))
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": (
            "0x%x" % function_info.start_ea if function_info is not None else None
        ),
        "function_end": (
            "0x%x" % function_info.end_ea if function_info is not None else None
        ),
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "string_literals": literals[:300],
        "callers": effective_callers(address)[:300],
        "code": code,
    }


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")
    functions = [
        export_function(int(address, 16), name, role)
        for address, name, role in TARGETS
    ]
    result = {
        "schema": "libqplay.original-download-cache-flow.v1",
        "artifact": "original_download_cache_flow_review_20260830",
        "scope": (
            "read-only Hex-Rays export of original 1.8 packet-102 file response, "
            "resource resolution, and cache save flow"
        ),
        "network_contacted": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": sha256_file(idaapi.get_input_file_path()),
        },
        "validated_constants": {
            "packet_102_handler_index": 24,
            "packet_102_minimum_body_bytes": 7,
            "encoded_file_offset_bits": 28,
            "ordinary_download_queue_active_limit": 10,
            "maximum_http_request_objects": 10000,
        },
        "manual_reviews": MANUAL_REVIEWS,
        "functions": functions,
        "interpretation": [
            "Wire packet 102 reaches TClient_parseEncodedFileChunk through handler index 24, then passes a filename and data string to TClient_processFileChunk.",
            "The chunk assembler appends dynamic data and records the offset, but the reviewed path does not enforce offset order or the declared big-file size before saving.",
            "Ordinary downloads finish immediately and save through TCachedStream_saveAndUpdate, while big downloads use the 68, 84, 102, 69 handler sequence before the same save path.",
            "The resource resolver maps recognized extensions to application-owned directories and uses escaped filenames, but the reviewed filesystem operations do not show canonical-root enforcement or no-follow creation.",
            "This report establishes a server-response to cache path in static code and local protocol work, but it does not claim that a production untrusted peer can reach it when TLS and package verification are working.",
        ],
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    output = os.environ.get("IDA_DOWNLOAD_CACHE_FLOW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(encoded, encoding="utf-8")
    ida_kernwin.msg("wrote %s\n" % output)
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
