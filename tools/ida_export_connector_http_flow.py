#!/usr/bin/env python3
"""Export the original connector HTTP lifecycle from an ARM64 IDA database.

This is a read-only Hex-Rays export for the original Graal Online Classic 1.8
library. It preserves the decompiler text for the small set of request,
response, and event-loop functions that explain connector failures without
publishing another full IDA database or function dump.

Set ``IDA_CONNECTOR_FLOW_OUT`` to write the JSON artifact. If it is omitted,
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
    ("0x1ffd40", "THTTPRequest_canOpenConnection_void", "connection limit"),
    ("0x1ffd6c", "THTTPRequest_sendOutgoing_void", "request write"),
    ("0x1ff3a8", "THTTPRequest_checkKeepConnection_void", "keep-alive reuse"),
    ("0x1ffde8", "THTTPRequest_sendRequest_void", "request construction"),
    ("0x200010", "THTTPRequest_saveDownloadedData_void", "download completion"),
    ("0x200a70", "THTTPRequest_read_void", "response read"),
    ("0x201d68", "THTTPRequest_preParseData_void", "HTTP header parsing"),
    ("0x2023fc", "THTTPRequest_parseData_void", "response body parsing"),
    ("0x2025a0", "THTTPRequest_runScript_void", "request state machine"),
]

DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "connector_http_flow_review_20260830.json")


CALL_WORDS = {
    "CyaSSL_connect",
    "CyaSSL_read",
    "CyaSSL_write",
    "close",
    "connect",
    "gethostbyname",
    "recv",
    "send",
    "socket",
}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def effective_callers(address: int) -> list[dict]:
    """Follow PLT thunks and retain real callers where IDA exposes them."""

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
        "string_literals": literals[:200],
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
        "schema": "libqplay.original-connector-http-flow.v1",
        "artifact": "connector_http_flow_review_20260830",
        "scope": "read-only Hex-Rays export of original 1.8 connector HTTP lifecycle functions",
        "network_contacted": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "functions": functions,
        "interpretation": [
            "sendRequest constructs HTTP/1.0 GET requests, includes the Graal version string, requests Keep-Alive, and creates a native socket connection when no reusable connection exists.",
            "The parser lowercases complete header lines before matching header names, records status and Content-Length, and removes the parsed header block from the body stream.",
            "The state machine reads incrementally, retries selected redirect or error responses, follows connector redirects through the HTTP location field, and dispatches body completion to script or file handlers.",
            "saveDownloadedData is a completion path for connector scripts and game files. Its path and package behavior must be read together with the resource and file-policy helpers.",
            "The decompilation is evidence of native behavior in this APK revision, not proof that a current remote service still accepts the same request or response envelope.",
        ],
    }
    output = os.environ.get("IDA_CONNECTOR_FLOW_OUT", DEFAULT_OUTPUT)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(encoded, encoding="utf-8")
    else:
        ida_kernwin.msg(encoded)
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
