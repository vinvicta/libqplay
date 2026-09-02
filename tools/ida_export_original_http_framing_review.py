#!/usr/bin/env python3
"""Export the original HTTP response framing and parser-boundary review.

The exporter is read-only. It records socket accumulation, line parsing,
header interpretation, body dispatch, and the response state machine. It does
not open a socket, fuzz a parser, or contact a live endpoint.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import ida_funcs
import ida_hexrays
import idaapi
import idautils
import idc


TARGETS = [
    ("0x2077a0", "TSocketConnection_read_void", "socket and TLS read accumulation"),
    ("0x200a70", "THTTPRequest_read_void", "HTTP stream accumulation"),
    ("0xf0ce0", "TStream_readLine_void", "line extraction"),
    ("0x201d68", "THTTPRequest_preParseData_void", "HTTP status and header parser"),
    ("0x2023fc", "THTTPRequest_parseData_void", "HTTP body dispatch"),
    ("0x2025a0", "THTTPRequest_runScript_void", "response completion state machine"),
]

DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_http_framing_review_20260830.json")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def effective_callers(address: int) -> list[dict]:
    callers = []
    for reference in idautils.XrefsTo(address, 0):
        caller = ida_funcs.get_func(reference.frm)
        if caller is None:
            continue
        callers.append(
            {
                "callsite": "0x%x" % reference.frm,
                "caller": "0x%x" % caller.start_ea,
                "caller_name": idc.get_func_name(caller.start_ea) or "",
            }
        )
    unique = {(item["caller"], item["callsite"]): item for item in callers}
    return sorted(
        unique.values(),
        key=lambda item: (int(item["caller"], 16), int(item["callsite"], 16)),
    )[:250]


def export_function(address: int, expected_name: str, role: str) -> dict:
    current_name = idc.get_func_name(address) or ""
    if current_name != expected_name:
        raise RuntimeError(
            "unexpected function name at %s: %s (expected %s)"
            % (hex(address), current_name, expected_name)
        )
    decompiled = ida_hexrays.decompile(address)
    if decompiled is None:
        raise RuntimeError("Hex-Rays could not decompile %s" % hex(address))
    code = str(decompiled)
    function = ida_funcs.get_func(address)
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": "0x%x" % function.start_ea if function else None,
        "function_end": "0x%x" % function.end_ea if function else None,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "callers": effective_callers(address),
        "code": code,
    }


OBSERVATIONS = [
    {
        "address": "0x2077a0",
        "classification": "bounded-read-unbounded-accumulation",
        "confidence": "confirmed-static",
        "evidence": [
            "TSocketConnection_read reads at most 8192 bytes per native recv, recvfrom, or CyaSSL_read call.",
            "It repeats while the TLS read continues to return data, and THTTPRequest_read appends each returned string to its response stream.",
            "The reviewed read and append path has no general total response-buffer cap.",
        ],
        "interpretation": "The 8192-byte socket chunk is an I/O buffer size, not a maximum response size.",
    },
    {
        "address": "0xf0ce0",
        "classification": "line-parser-boundary",
        "confidence": "confirmed-static",
        "evidence": [
            "TStream_readLine scans from the current offset until LF or the current stream end.",
            "It removes a preceding CR from the copied line but does not impose a per-line length limit.",
            "TStringList_LoadFromStream repeatedly calls the same helper without a line-count or aggregate-size budget.",
        ],
        "interpretation": "A large or unterminated header line can consume the accumulated response buffer before normal header processing finishes.",
    },
    {
        "address": "0x201d68",
        "classification": "HTTP-header-interpretation",
        "confidence": "confirmed-static",
        "evidence": [
            "The pre-parser accepts a status line when its first token starts with HTTP and converts the second token with strtoint.",
            "It recognizes server, last-modified, location, content-language, content-type, content-length, connection: keep-alive, and modtime.",
            "It lowercases each complete header line before matching names, but it does not inspect Transfer-Encoding or reject duplicate framing headers.",
            "Each recognized content-length line overwrites the stored integer, so a later value wins without a duplicate consistency check.",
        ],
        "interpretation": "The parser follows a narrow legacy HTTP subset and is lenient about status and framing metadata.",
    },
    {
        "address": "0x2023fc",
        "classification": "body-dispatch",
        "confidence": "confirmed-static",
        "evidence": [
            "For ordinary non-download responses, parseData loads the remaining stream into a TStringList and exposes each line through the data variable.",
            "The body path does not contain a Transfer-Encoding chunk decoder.",
            "The request state machine applies a declared web-download size check, but that check does not provide a general header or unknown-length response cap.",
        ],
        "interpretation": "A chunked response would be treated as ordinary bytes and can reach the consumer with its chunk framing still present.",
    },
    {
        "address": "0x2025a0",
        "classification": "completion-and-size-state",
        "confidence": "confirmed-static",
        "evidence": [
            "For a positive Content-Length, the response state machine uses the declared boundary once the accumulated stream reaches that length; when the length is absent or nonpositive, it waits for the socket error or close path before completing.",
            "A declared body above the native web-download limit is cleared and reported as too huge rather than saved.",
            "Redirect-like statuses are handled before the normal body path and have a separate ten-attempt loop bound.",
        ],
        "interpretation": "The declared-size guard is useful for selected downloads, but it is not a complete framing or memory-safety policy.",
    },
]


FINDINGS = [
    {
        "id": "HTTP-FRAME-001",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "HTTP response accumulation has no general header or total-buffer cap",
        "evidence": [
            "TSocketConnection_read uses repeated 8192-byte reads, and THTTPRequest_read appends each result to the response stream.",
            "TStream_readLine has no per-line limit, and the header parser has no header-count or aggregate-header budget.",
            "The web-download size check is applied after header parsing and does not cover every unknown-length or ordinary response path.",
        ],
        "impact": "A peer that reaches the HTTP parser may consume client memory with a long header, many headers, or a response whose framing does not reach a bounded completion path. A modern client should cap header bytes, line length, body bytes, and aggregate decompressed data before appending.",
        "limits": "The stock connector and game paths still have separate package, protocol, and declared-download gates. No malformed response was fuzzed and no live endpoint was contacted, so this is an availability finding rather than a demonstrated crash.",
    },
    {
        "id": "HTTP-FRAME-002",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "The legacy parser does not implement chunked transfer coding",
        "evidence": [
            "THTTPRequest_preParseData recognizes Content-Length and a keep-alive hint but has no Transfer-Encoding branch.",
            "THTTPRequest_parseData consumes the remaining stream directly instead of decoding HTTP chunks.",
        ],
        "impact": "A current endpoint that sends a chunked response can fail compatibility or deliver chunk-size markers to the connector, script, or file consumer. Framing assumptions can also become ambiguous if a proxy or server mixes chunked and length-based behavior.",
        "limits": "The original client deliberately sends HTTP/1.0, and the local compatibility responder used Content-Length or EOF. No current service response was observed.",
    },
    {
        "id": "HTTP-FRAME-003",
        "severity": "low",
        "confidence": "confirmed-static",
        "title": "Response framing metadata is accepted without strict consistency checks",
        "evidence": [
            "The status parser checks only that the first token starts with HTTP and accepts the integer conversion of the next token.",
            "Repeated Content-Length headers overwrite the stored value instead of being rejected or compared.",
            "The parser does not visibly validate the HTTP version, duplicate header policy, or a bounded numeric range before using the parsed length.",
        ],
        "impact": "Malformed or conflicting responses can be interpreted differently by the client and an intermediary, creating compatibility and framing ambiguity. A strict parser should reject invalid status lines, conflicting lengths, unsupported transfer codings, and overflow.",
        "limits": "No request-smuggling or cross-component exploit was demonstrated. The client uses a simple HTTP/1.0 request path, and no live proxy chain was tested.",
    },
]


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")
    functions = [
        export_function(int(address, 16), name, role)
        for address, name, role in TARGETS
    ]
    result = {
        "schema": "libqplay.original-http-framing-review.v1",
        "artifact": "original_http_framing_review_20260830",
        "scope": "read-only review of original 1.8 HTTP response accumulation and framing",
        "network_contacted": False,
        "fuzzing_performed": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "read_chunk_size": 8192,
        "recognized_headers": [
            "server",
            "last-modified",
            "location",
            "content-language",
            "content-type",
            "content-length",
            "connection: keep-alive",
            "modtime",
        ],
        "transfer_encoding_supported": False,
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "The native 8192-byte read size should not be mistaken for a total response limit.",
            "The connector's legacy Content-Length and EOF behavior is compatible with the local replay, but chunked responses and malformed framing remain unverified.",
            "A repair should enforce bounded response framing before parsing or saving data and should reject unsupported transfer codings rather than passing them to consumers.",
        ],
    }
    output = os.environ.get("IDA_HTTP_FRAMING_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
