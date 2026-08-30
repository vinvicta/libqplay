#!/usr/bin/env python3
"""Export the original 1.8 signed script-package boundary from IDA.

The exporter is read-only. It records the outer package parser, RSA gate,
encrypted ZIP handling, script dispatch, and download completion path. Long
embedded crypto literals are redacted from the public artifact and represented
by length and SHA-256 metadata. The script does not execute the library,
modify the IDB, fuzz an archive, or contact a service.
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
    ("0x22cf78", "TScriptUniverse_compileZippedScripts_TString_const", "signed encrypted ZIP parser"),
    ("0x22cf98", "TScriptUniverse_addZippedScripts_TString_const_TSocketConnection", "connector script activation"),
    ("0x200010", "THTTPRequest_saveDownloadedData_void", "download completion dispatcher"),
    ("0xf758c", "TEncryption_rsa_verify_TString_const_TString_const_TString_const", "RSA signature verification"),
    ("0xf7d94", "TEncryption_sha256_TString_const", "SHA-256 digest helper"),
    ("0x22bcf8", "TScriptUniverse_runScripts_bool", "script runtime start"),
    ("0x22cc88", "TScriptUniverse_addClassScript_TString_const_TString_const", "class script registration"),
]


SENSITIVE_SHORT_LITERALS = {
    "PjosLg8D",
    "Pw0Y0G3BAcHcyOSI",
    "JZfkUMydBH0=",
}
LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"')


MANUAL_REVIEWS = [
    {
        "address": "0x22cf78",
        "function": "TScriptUniverse_compileZippedScripts_TString_const",
        "classification": "signed-encrypted-script-package",
        "confidence": "confirmed-static",
        "severity": "trust-boundary-and-availability",
        "evidence": [
            "The parser requires more than three input bytes, decodes a signed outer length and payload length, and rejects the payload when the calculated end exceeds the input string.",
            "It computes SHA-256 over the recovered package material and calls TEncryption_rsa_verify before RC4 decryption and ZIP parsing.",
            "ZIP global entry count is capped at 10000 and an individual uncompressed entry is processed only when its reported size is at most 0x40000000 bytes.",
            "Each accepted entry is read into a dynamically sized stream, but there is no visible aggregate decompressed-size budget and the return value is not compared with the requested entry size.",
        ],
        "interpretation": "The connector script package has a real embedded RSA verification gate, which is separate from the TLS certificate check. The archive limits reduce but do not eliminate resource-exhaustion risk. The public artifact redacts the embedded crypto literals.",
    },
    {
        "address": "0x22cf98",
        "function": "TScriptUniverse_addZippedScripts_TString_const_TSocketConnection",
        "classification": "verified-script-activation",
        "confidence": "confirmed-static",
        "severity": "high-impact-trust-boundary",
        "evidence": [
            "The function calls compileZippedScripts and looks up StartScript_Connector in the resulting script universe.",
            "If the connector script exists and has an onCreated catcher, the socket IP, SSL cipher, SSL subject, and SSL issuer are exposed as script variables.",
            "It then calls TScriptUniverse_runScripts_bool. When setup fails it looks for StartScript_Fail and logs a networking error.",
        ],
        "interpretation": "A package that passes the RSA gate can install and run connector script logic. This explains why stale or mismatched con.png material fails before normal login handoff and why connector package verification must remain enabled in a repair build.",
    },
    {
        "address": "0x200010",
        "function": "THTTPRequest_saveDownloadedData_void",
        "classification": "download-to-script-or-cache-dispatch",
        "confidence": "confirmed-static",
        "severity": "trust-boundary-and-availability",
        "evidence": [
            "The function handles HTTP completion and error states, then routes script-marked responses to TScriptUniverse_addZippedScripts_TString_const_TSocketConnection.",
            "Ordinary responses are routed through TCachedStream_saveAndUpdate and TResourceFunctions_validateFileKey before download events are emitted.",
            "The function retries or continues queued requests for selected failures and records partial retrieval states, but the cache save path does not perform the script package RSA check.",
        ],
        "interpretation": "The response type determines whether bytes become executable script state or ordinary cached data. The script branch relies on the package verifier, while ordinary resources rely on the separate cache and resource policy.",
    },
    {
        "address": "0xf758c",
        "function": "TEncryption_rsa_verify_TString_const_TString_const_TString_const",
        "classification": "RSA-public-key-verifier",
        "confidence": "confirmed-static",
        "severity": "trust-boundary",
        "evidence": [
            "The helper decodes an RSA public key, verifies a supplied signature over the provided digest, and returns the recovered verification result through a TString assignment.",
            "The connector ZIP parser is the reviewed caller in this ARM64 database.",
            "The key material is embedded in the native library rather than obtained from the Java trust store.",
        ],
        "interpretation": "This is a package-signing trust anchor, not a TLS certificate check. Replacing it or bypassing its result would make the connector script boundary accept unauthenticated code.",
    },
    {
        "address": "0x22cf78",
        "function": "TScriptUniverse_compileZippedScripts_TString_const",
        "classification": "archive-entry-dispatch",
        "confidence": "confirmed-static",
        "severity": "path-and-resource-policy",
        "evidence": [
            "The parser reads ZIP entry names into a fixed 256-byte name buffer and separates the entry path from its final component.",
            "The reviewed dispatch recognizes .rk, .t, NPCS/ entries, and CLASSES/ entries. It creates script objects or assigns class streams rather than directly writing the ZIP name to disk in this function.",
            "The archive entry count is bounded, but there is no visible name-count, total decompressed-size, or per-entry script execution budget beyond the reported 1 GiB entry check.",
        ],
        "interpretation": "ZIP path traversal is not established from this dispatch because entry names are used as script-object identifiers in the reviewed path. Large or numerous accepted entries remain a context-dependent availability risk.",
    },
    {
        "address": "0x22cc88",
        "function": "TScriptUniverse_addClassScript_TString_const_TString_const",
        "classification": "class-script-installation",
        "confidence": "confirmed-static",
        "severity": "script-trust-boundary",
        "evidence": [
            "The function creates or obtains a class object, checks its privilege level against the server privilege value, and installs the supplied script stream when allowed.",
            "It marks the class loaded and invokes onClassLoaded on the universe and class object.",
            "The caller in the ZIP parser supplies the archive entry stream after the outer RSA check.",
        ],
        "interpretation": "Class code is an executable content boundary. The privilege check is a semantic script policy, not a substitute for authenticating the package that supplied the stream.",
    },
    {
        "address": "0x22bcf8",
        "function": "TScriptUniverse_runScripts_bool",
        "classification": "script-runtime-start",
        "confidence": "confirmed-static",
        "severity": "high-impact-capability",
        "evidence": [
            "The connector package activation path calls this function after locating a verified StartScript_Connector object and its onCreated catcher.",
            "The function is the transition from script registration to script-machine execution in the reviewed call chain.",
        ],
        "interpretation": "This is the final high-impact edge in the connector package path. A diagnostic RSA bypass is appropriate only for a private, bounded fixture, never as a general compatibility repair.",
    },
]


DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_script_package_review_20260830.json"
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


def redact_literal(match: re.Match[str], redactions: list[dict]) -> str:
    quoted = match.group(0)
    content = quoted[1:-1]
    decoded = content.replace(r'\\', "\\").replace(r'\"', '"')
    should_redact = decoded in SENSITIVE_SHORT_LITERALS or (
        len(decoded) >= 80
        and re.fullmatch(r"[A-Za-z0-9+/=_-]+", decoded) is not None
    )
    if not should_redact:
        return quoted
    row = {
        "length": len(decoded),
        "sha256": sha256_text(decoded),
    }
    redactions.append(row)
    marker = "<redacted-static-literal length=%d sha256=%s>" % (
        row["length"],
        row["sha256"],
    )
    return '"%s"' % marker


def redact_code(code: str) -> tuple[str, list[dict]]:
    redactions: list[dict] = []
    redacted = LITERAL_RE.sub(
        lambda match: redact_literal(match, redactions),
        code,
    )
    return redacted, redactions


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


def export_function(address: int, expected_name: str, role: str) -> tuple[dict, list[dict]]:
    current_name = idc.get_func_name(address) or ""
    if current_name != expected_name:
        raise RuntimeError(
            "unexpected function name at %s: %s (expected %s)"
            % (hex(address), current_name, expected_name)
        )
    function = ida_hexrays.decompile(address)
    if function is None:
        raise RuntimeError("Hex-Rays could not decompile %s" % hex(address))
    raw_code = str(function)
    code, redactions = redact_code(raw_code)
    info = ida_funcs.get_func(address)
    literals = sorted(set(re.findall(r'"(?:\\.|[^"\\])*"', code)))
    return (
        {
            "address": "0x%x" % address,
            "name": current_name,
            "role": role,
            "function_start": "0x%x" % info.start_ea if info else None,
            "function_end": "0x%x" % info.end_ea if info else None,
            "code_sha256": sha256_text(code),
            "code_bytes": len(code.encode("utf-8")),
            "code_literals_redacted": True,
            "string_literals": literals[:400],
            "callers": effective_callers(address)[:400],
            "code": code,
        },
        redactions,
    )


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")
    functions = []
    redactions = []
    for address, name, role in TARGETS:
        function, rows = export_function(int(address, 16), name, role)
        functions.append(function)
        redactions.extend(rows)
    unique_redactions = {
        (row["length"], row["sha256"]): row for row in redactions
    }
    result = {
        "schema": "libqplay.original-script-package-review.v1",
        "artifact": "original_script_package_review_20260830",
        "scope": (
            "read-only Hex-Rays export of original 1.8 signed connector script "
            "package parsing and download activation"
        ),
        "network_contacted": False,
        "public_artifact_redactions": {
            "embedded_crypto_literals": sorted(
                unique_redactions.values(),
                key=lambda row: (row["length"], row["sha256"]),
            ),
            "reason": "Avoid publishing embedded private or key-like literals while retaining structural evidence.",
        },
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": sha256_file(idaapi.get_input_file_path()),
        },
        "manual_reviews": MANUAL_REVIEWS,
        "interpretation": [
            "The connector script package is protected by an embedded RSA verification step before encrypted ZIP entries are dispatched.",
            "TLS trust and package signing are separate gates. A valid certificate does not make a mismatched package valid, and a diagnostic package-signature bypass must remain private.",
            "The archive parser limits entry count and individual reported size but has no visible aggregate decompressed-size budget.",
            "The reviewed ZIP dispatch uses recognized entry names as script-object identifiers and does not directly write arbitrary ZIP paths to disk.",
            "This artifact does not claim a remote exploit. It records static trust and resource boundaries without contacting a service or publishing embedded key material.",
        ],
        "functions": functions,
    }
    output = os.environ.get("IDA_SCRIPT_PACKAGE_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ida_kernwin.msg("wrote %s\n" % output)
    print(
        json.dumps(
            {
                "function_count": len(functions),
                "redacted_literals": len(unique_redactions),
                "output": output,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
