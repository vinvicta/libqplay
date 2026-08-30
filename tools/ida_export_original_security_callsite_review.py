#!/usr/bin/env python3
"""Export a compact security call-site review for the original ARM64 IDB.

The fixed addresses belong to the original 1.8 ARM64 library. The exporter is
read-only and records the decompiler text, relevant imported API tokens, string
literals, function bounds, and effective callers. It does not execute the
library or contact a service.

Set ``IDA_SECURITY_REVIEW_OUT`` to write the JSON artifact. If it is omitted,
the result is printed to IDA's console.
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
    ("0x196fe0", "TSetup_startExeReplacer_TString_const", "process execution"),
    ("0xe6dfc", "TFiles_deleteFile_TString_const", "file deletion"),
    ("0xec158", "TIdentification_getMacAddressBuffer_void", "device identifier"),
    ("0xec1cc", "TIdentification_retrieveMACAddress_bool", "device identifier"),
    ("0xec21c", "TIdentification_getNetworkID_void", "device identifier"),
    ("0xec6f8", "TIdentification_getSystemID_int", "device identifier"),
    ("0xec290", "TIdentification_getCookieFilename_void", "cookie storage"),
    ("0xec3e8", "TIdentification_getCookie_void", "cookie storage"),
    ("0xfbf0c", "TFileScripting_AllowedFoldername_TString_const_bool", "file policy"),
    ("0xfc110", "TFileScripting_getScriptAccessFilename_TString_const_bool", "file policy"),
    ("0xfc4b0", "TFileScripting_script_deleteFile", "file policy caller"),
    ("0xfc8a0", "TFileScripting_getScriptWriteAccessFolder_TString_const", "file policy"),
    ("0xfd054", "TFileScripting_initStaticVars_void", "file policy"),
    ("0xe7a50", "TFiles_escapedFilename_TString_const", "file policy"),
    ("0x206bd8", "TSocketConnection_connectSocket_TString_const_int", "socket transport"),
    ("0x206450", "TSocketConnection_enableSSLOnSocket_void", "TLS state machine"),
    ("0x2074d4", "TSocketConnection_read_void", "TLS state machine"),
    ("0x1ec044", "TClient_handleUpdatePackageDownloaded", "update caller"),
    ("0x2097c8", "TUpdatePackage_update_bool", "update caller"),
    ("0x20a9cc", "TUpdatePackage_uninstall_void", "update caller"),
]


CALL_WORDS = {
    "abort",
    "bind",
    "chmod",
    "close",
    "connect",
    "CyaSSL_connect",
    "CyaSSL_CTX_load_verify_buffer",
    "execvp",
    "fork",
    "gethostbyname",
    "ioctl",
    "listen",
    "open",
    "recv",
    "recvfrom",
    "send",
    "sendto",
    "socket",
    "unlink",
    "write",
}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def effective_callers(address: int) -> list[dict]:
    """Follow PLT thunks so the report names real callers when possible."""

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
            caller_name = idc.get_func_name(caller.start_ea) or ""
            segment_name = idc.get_segm_name(caller.start_ea) or ""
            if caller_name.startswith(".") or segment_name.startswith(".plt"):
                queue.append(caller.start_ea)
                continue
            callers.append(
                {
                    "callsite": "0x%x" % reference.frm,
                    "caller": "0x%x" % caller.start_ea,
                    "caller_name": caller_name,
                }
            )
    unique = {(item["caller"], item["callsite"]): item for item in callers}
    return sorted(
        unique.values(),
        key=lambda item: (int(item["caller"], 16), int(item["callsite"], 16)),
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
    tokens = sorted(
        word
        for word in CALL_WORDS
        if re.search(
            r"(?<![A-Za-z0-9_])" + re.escape(word) + r"(?![A-Za-z0-9_])",
            code,
        )
    )
    literals = sorted(set(re.findall(r'"(?:\\.|[^"\\])*"', code)))
    callers = effective_callers(address)
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
        "call_tokens": tokens,
        "string_literals": literals[:160],
        "callers": callers[:250],
        "caller_count": len(callers),
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
        "schema": "libqplay.original-security-callsite-review.v1",
        "artifact": "original_security_callsite_review_20260830",
        "scope": "read-only Hex-Rays export of sensitive imported-API call sites in the original 1.8 ARM64 IDB",
        "network_contacted": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": os.environ.get("ORIGINAL_BINARY_SHA256"),
        },
        "functions": functions,
        "interpretation": [
            "A call token or imported API is evidence of capability, not proof of a vulnerability.",
            "startExeReplacer chmods the stored executable path, forks, and calls execvp with argv[0] only; the reviewed code does not verify an update signature itself.",
            "deleteFile ultimately passes a TFiles path to unlink, so the safety boundary is established by its callers and path helpers.",
            "The script-file helpers reject executable and library extensions, constrain filename and folder forms, and escape server-derived names before constructing paths.",
            "The identifier path reads the eth0 hardware address, stores it, and offers an MD5-derived network ID alongside other system-ID modes.",
            "The socket path preserves nonblocking TCP, delayed TLS setup, trust-buffer loading, peer verification, hostname checks, and CyaSSL reads.",
            "The update path can delete a local executable and start a stored replacement after package completion; this is a confirmed capability, not proof of remote reachability.",
        ],
    }
    output = os.environ.get("IDA_SECURITY_REVIEW_OUT")
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(encoded, encoding="utf-8")
    else:
        ida_kernwin.msg(encoded)
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
