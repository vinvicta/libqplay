#!/usr/bin/env python3
"""Export the original 1.8 update and file-integrity boundary from IDA.

The exporter is read-only. It records the request-side checksum construction,
the update-package download state machine, and the response-side file save
path. The report distinguishes a CRC used in a request from verification of an
untrusted response. It does not execute the library, modify the IDB, fuzz a
parser, or contact a service.
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
    ("0x1fbe78", "TFileDownload_download_TString_const", "ordinary download request gate"),
    ("0x1fbf98", "TFileDownload_update_TString_const", "update request gate"),
    ("0x1fbcc0", "TFileDownload_canDownload_void", "download availability"),
    ("0x1fbcd8", "TFileDownload_isDownloadingFiles_void", "download status"),
    ("0x1fbd98", "TFileDownload_onFileEvent_TString_const_TFileDownload_fileeventtype", "scripted download events"),
    ("0x1fc0cc", "TFileDownload_ignore_TString_const", "ignored download request"),
    ("0x1e8780", "TClient_startFileDownloading_void", "download scheduler"),
    ("0x1e987c", "TClient_beginUpdatePackageDownload", "package download state"),
    ("0x1f8e60", "TClient_sendRequestUpdatePackage_TUpdatePackage_bool", "package request encoding"),
    ("0x1f4cf8", "TClient_sendWantImageUpdateCRC_TString_const", "conditional file request checksum"),
    ("0xf02f8", "TResourceObject_getChecksum_void", "resource CRC32"),
    ("0xe59c8", "gs_checksum_TString_const", "script CRC32"),
    ("0x1ec764", "TClient_processFileChunk", "file response accumulation"),
    ("0x1eb208", "TClient_finishDownloadFile", "ordinary response completion"),
    ("0x1eb294", "TClient_finishFileDownload", "large response completion"),
    ("0x2097c8", "TUpdatePackage_update_bool", "update request scheduling"),
    ("0x1ec044", "TClient_handleUpdatePackageDownloaded", "package completion"),
    ("0x1fa6e8", "TCachedStream_save_bool", "cache persistence"),
    ("0xf0aa8", "TStream_SaveToFile_TString_const_uint", "stream write"),
]


MANUAL_REVIEWS = [
    {
        "address": "0x1f4cf8",
        "function": "TClient_sendWantImageUpdateCRC_TString_const",
        "classification": "request-side-conditional-crc",
        "confidence": "confirmed-static",
        "severity": "integrity-boundary",
        "evidence": [
            "Existing resources are resolved before a five-character checksum is constructed for the request.",
            "A local .gupd package is loaded and CRC32 is calculated over the package bytes; other resources use TResourceObject_getChecksum.",
            "The computed value is encoded with five 7-bit characters and sent with the lowercased basename, or is delivered to the scripted onSendImageUpdateCRC event in scripted mode.",
        ],
        "interpretation": "This is a conditional request mechanism. The function does not verify the bytes of the later packet-102 response, and a CRC32 request value is not an authenticity check.",
    },
    {
        "address": "0xf02f8",
        "function": "TResourceObject_getChecksum_void",
        "classification": "resource-crc32",
        "confidence": "confirmed-static",
        "severity": "integrity-boundary",
        "evidence": [
            "The function obtains the resource stream and feeds its entire TString buffer to crc32.",
            "The result is consumed by TClient_sendRequestUpdatePackage_TUpdatePackage_bool and TClient_sendWantImageUpdateCRC_TString_const.",
            "No signature or keyed MAC is calculated in this helper.",
        ],
        "interpretation": "CRC32 detects accidental changes for cache negotiation, but it does not authenticate server-supplied content against an attacker.",
    },
    {
        "address": "0x1f8e60",
        "function": "TClient_sendRequestUpdatePackage_TUpdatePackage_bool",
        "classification": "package-request-encoding",
        "confidence": "confirmed-static",
        "severity": "integrity-boundary",
        "evidence": [
            "The function sets downloadsblocked while it constructs the request and clears the flag before invoking the script or network callback.",
            "Each nonempty package FILE entry is reduced to a basename for resource lookup, and a five-character CRC field is appended when the package state requests checksum use.",
            "When no local resource is available, the checksum field is five spaces. The function sends the package metadata through the client's callback slot; it does not verify a response here.",
        ],
        "interpretation": "The update request tells the peer what the client already has. The reviewed code does not turn that request checksum into a signed package-manifest or response-authentication step.",
    },
    {
        "address": "0x1e8780",
        "function": "TClient_startFileDownloading_void",
        "classification": "download-scheduler-order",
        "confidence": "confirmed-static",
        "severity": "availability-and-state",
        "evidence": [
            "The function calls requestUpdatePackage_void before ordinary file queues are sent.",
            "It sends at most the first ten entries of the ordinary and modification queues in this pass, while later entries remain queued.",
            "The scripted download mode skips the native queue dispatch.",
        ],
        "interpretation": "The ten-entry behavior is a concurrency or scheduling limit, not a byte-size limit. It does not bound the size of an individual response or the total cached data.",
    },
    {
        "address": "0x1fbe78",
        "function": "TFileDownload_download_TString_const",
        "classification": "ordinary-download-input-filter",
        "confidence": "confirmed-static",
        "severity": "input-policy",
        "evidence": [
            "The function refuses downloads while downloadsblocked is set.",
            "It ignores empty values, a literal hyphen, numeric-only values, and values containing the encoded URL marker.",
            "It strips the input to a filename before native requests and suppresses .gft requests. Scripted mode records an event instead of making the native request.",
        ],
        "interpretation": "The helper applies a narrow request policy, but it is not a trust or authenticity check for content returned after a valid request.",
    },
    {
        "address": "0x1fbf98",
        "function": "TFileDownload_update_TString_const",
        "classification": "update-download-input-filter",
        "confidence": "confirmed-static",
        "severity": "path-trust-boundary",
        "evidence": [
            "The helper rejects numeric-only values and accepts a path only when it has no path or begins with the native base user folder.",
            "It removes filename escapes or strips the filename before calling TClient_requestUpdate.",
            "The helper has no signature verification and does not perform canonical path resolution.",
        ],
        "interpretation": "The base-user prefix check is a string check. It reduces the direct update-request surface but does not replace final canonical containment or response validation.",
    },
    {
        "address": "0x1ec764",
        "function": "TClient_processFileChunk",
        "classification": "response-accumulation-without-integrity-check",
        "confidence": "confirmed-static",
        "severity": "integrity-and-availability",
        "evidence": [
            "The decoded packet offset is stored on the cached stream, then the response data is appended to the current stream buffer.",
            "The body updates progress counters and routes ordinary files to cache save and resource validation.",
            "The reviewed body contains no CRC32, RSA verification, signature comparison, offset-order check, or declared-total-size check before the ordinary save path.",
        ],
        "interpretation": "A peer that has already passed the connection and protocol boundary can influence cached bytes and resource state. The strongest static result is missing response-integrity and size enforcement, not a claim that an unauthenticated remote peer can reach it in stock operation.",
    },
    {
        "address": "0x1eb294",
        "function": "TClient_finishFileDownload",
        "classification": "large-response-finalization",
        "confidence": "confirmed-static",
        "severity": "integrity-and-availability",
        "evidence": [
            "The function obtains the cached stream for the big filename, emits the download event, removes the request, and calls TCachedStream_saveAndUpdate.",
            "It validates the resource key after saving and invokes the package completion hook for .gupd files.",
            "No response CRC, signature, or accumulated-size comparison is visible in this finalizer.",
        ],
        "interpretation": "The large-file path shares the cache writer without a visible final content-authentication check. Declared size and packet ordering should be enforced before a modern implementation makes the file persistent.",
    },
    {
        "address": "0x2097c8",
        "function": "TUpdatePackage_update_bool",
        "classification": "forced-update-preparation",
        "confidence": "confirmed-static",
        "severity": "high-impact-capability",
        "evidence": [
            "When the package is marked as the main executable and the boolean argument is true, the function deletes the base executable below the base user folder before sending the package request.",
            "It clears package progress state and calls TClient_sendRequestUpdatePackage_TUpdatePackage_bool.",
            "No package signature verification is performed in this function.",
        ],
        "interpretation": "Forced replacement has a destructive precondition. Whether an untrusted package can set the main-executable state remains a caller and trust-chain question, but the operation deserves a hard stop in any repair build.",
    },
    {
        "address": "0x1ec044",
        "function": "TClient_handleUpdatePackageDownloaded",
        "classification": "package-completion-and-exec-handoff",
        "confidence": "confirmed-static",
        "severity": "high-impact-capability",
        "evidence": [
            "The handler marks the package downloaded, sets its local version, and invokes onUpdatePackageDownloaded.",
            "After all package downloads complete, it invokes onPackagesDownloadComplete and checks the replacement flag.",
            "If the flag is set, it calls TSetup_startExeReplacer with the configured full executable path.",
        ],
        "interpretation": "A successful package response reaches a high-impact executable handoff through state flags and script events. This code does not establish remote reachability or package authenticity by itself.",
    },
    {
        "address": "0x1fa6e8",
        "function": "TCachedStream_save_bool",
        "classification": "persistent-cache-write",
        "confidence": "confirmed-static",
        "severity": "integrity-and-availability",
        "evidence": [
            "The function creates parent directories, redirects a path outside the base user prefix or matching the base executable to the full executable path, and calls TStream_SaveToFile.",
            "The write path has no package signature check, atomic rename, or no-follow open operation.",
            "The executable redirect deletes an existing target and sets the replacement flag.",
        ],
        "interpretation": "The cache writer is the point where previously accepted bytes become persistent state. It should be treated as a trust boundary even though this function alone does not prove an attacker-controlled input path.",
    },
    {
        "address": "0xf0aa8",
        "function": "TStream_SaveToFile_TString_const_uint",
        "classification": "unchecked-file-write",
        "confidence": "confirmed-static",
        "severity": "integrity-and-availability",
        "evidence": [
            "The writer uses wb or ab, writes the stream in one fwrite call, and does not compare the return value with the requested length.",
            "An open failure is logged, but no structured write failure is returned to the cache state machine.",
        ],
        "interpretation": "Interrupted or partial writes can leave a truncated cached package or resource while surrounding code continues. A repaired writer should use checked temporary writes and an atomic replacement policy.",
    },
    {
        "address": "0x1fbd98",
        "function": "TFileDownload_onFileEvent_TString_const_TFileDownload_fileeventtype",
        "classification": "scripted-event-queue",
        "confidence": "confirmed-static",
        "severity": "availability-and-state",
        "evidence": [
            "In scripted mode the function appends a filename and an integer event code to a global TStringList.",
            "The list is lazily allocated and the reviewed function has no visible total event-count or string-length cap.",
            "A small ignore hash can suppress selected event types, but it does not cap the queue.",
        ],
        "interpretation": "A script-facing caller can accumulate unbounded event state if it remains in scripted mode. This is a local availability concern until the caller and lifecycle are shown to be remotely controlled.",
    },
]


DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_update_integrity_review_20260830.json"
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
    info = ida_funcs.get_func(address)
    literals = sorted(set(re.findall(r'"(?:\\.|[^"\\])*"', code)))
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": "0x%x" % info.start_ea if info else None,
        "function_end": "0x%x" % info.end_ea if info else None,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "string_literals": literals[:400],
        "callers": effective_callers(address)[:400],
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
        "schema": "libqplay.original-update-integrity-review.v1",
        "artifact": "original_update_integrity_review_20260830",
        "scope": (
            "read-only Hex-Rays export of original 1.8 update requests, "
            "checksum construction, response accumulation, and cache writes"
        ),
        "network_contacted": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": sha256_file(idaapi.get_input_file_path()),
        },
        "manual_reviews": MANUAL_REVIEWS,
        "interpretation": [
            "The original client uses CRC32 values in conditional file and update-package requests.",
            "The reviewed packet-102 accumulation and completion bodies do not show a matching CRC, RSA signature, or keyed MAC verification before ordinary cache persistence.",
            "The update scheduler limits queue dispatch but does not impose a general response-size or total-cache budget.",
            "The executable replacement path remains a high-impact state transition, but this export does not establish that a remote peer can set the required flags in stock operation.",
            "This artifact records static behavior and does not claim an unauthenticated remote exploit. Reachability still requires a controlled local protocol and filesystem test.",
        ],
        "functions": functions,
    }
    output = os.environ.get("IDA_UPDATE_INTEGRITY_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ida_kernwin.msg("wrote %s\n" % output)
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
