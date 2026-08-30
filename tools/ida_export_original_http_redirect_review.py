#!/usr/bin/env python3
"""Export the original HTTP redirect and destination-change path.

The exporter is read-only. It records how response status codes and Location
headers can replace an HTTP request's host, port, path, and TLS flag. It does
not open a socket or contact a live endpoint.
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
    ("0x2025a0", "THTTPRequest_runScript_void", "HTTP response state machine"),
    ("0x200d44", "THTTPRequest_extractHTTPHostPortFile_TString_const_TString_int_TString_bool", "absolute URL parser"),
    ("0x1ffde8", "THTTPRequest_sendRequest_void", "request construction and transport selection"),
    ("0x2013d4", "THTTPRequest_requestURLAsGameFile_TString_const_TString_const_uint_bool", "game-file request creation"),
    ("0x200f98", "THTTPRequest_findOrCreateFromUrl", "script URL request factory"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_http_redirect_review_20260830.json"
)


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
        "address": "0x2025a0",
        "classification": "redirect-status-dispatch",
        "confidence": "confirmed-static",
        "evidence": [
            "The HTTP state machine treats statuses 300 through 303, 305, and 307 as redirect-like responses.",
            "It tokenizes the stored Location value, extracts an absolute HTTP or HTTPS host, port, and path, and replaces the request fields before sending again.",
            "The redirect counter is incremented and limited to ten attempts.",
        ],
        "interpretation": "A response can change the destination of an existing request, while the retry limit provides a bounded loop control rather than a destination policy.",
    },
    {
        "address": "0x200d44",
        "classification": "absolute-url-parser",
        "confidence": "confirmed-static",
        "evidence": [
            "The parser accepts both http:// and https:// prefixes.",
            "It defaults to port 80 or 443, accepts an explicit numeric port, and returns the path beginning at the first slash.",
            "The reviewed function contains no host allowlist, certificate pin selection, or canonical destination comparison.",
        ],
        "interpretation": "The redirect target can change both the endpoint and whether the next request uses the native TLS path.",
    },
    {
        "address": "0x1ffde8",
        "classification": "transport-selection",
        "confidence": "confirmed-static",
        "evidence": [
            "The request builder uses the parsed host and port in the Host header and socket connection.",
            "It selects SSL from the request scheme flag and calls the connector trust helper when the request retains its connector marker.",
            "The request line remains legacy HTTP/1.0 and the connection header is Keep-Alive.",
        ],
        "interpretation": "A redirect that changes the scheme changes the transport used for the next request. No redirect-specific HTTPS-to-HTTP prohibition is visible here.",
    },
    {
        "address": "0x2013d4",
        "classification": "game-file-request-boundary",
        "confidence": "confirmed-static",
        "evidence": [
            "The game-file request helper creates an HTTP request from a supplied filename and marks the request as a game-file transfer.",
            "It marks the connector pseudo-file separately, so the redirect state machine can remain relevant to connector and ordinary requests.",
        ],
        "interpretation": "The redirect behavior is shared infrastructure around more than one request category. The narrower filename checks do not establish a redirect destination allowlist.",
    },
    {
        "address": "0x200f98",
        "classification": "script-url-request-factory",
        "confidence": "confirmed-static",
        "evidence": [
            "The script-facing URL factory parses the supplied URL and creates or reuses a native HTTP request.",
            "The same request object later uses the generic response state machine and absolute Location parser.",
        ],
        "interpretation": "Redirects reinforce the previously documented broad destination capability of the ordinary script HTTP API.",
    },
]


FINDINGS = [
    {
        "id": "HTTP-REDIR-001",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "HTTP redirects can replace the destination without an allowlist",
        "evidence": [
            "THTTPRequest_runScript accepts redirect-like status codes and feeds Location into THTTPRequest_extractHTTPHostPortFile.",
            "The parser accepts arbitrary absolute HTTP and HTTPS hosts and ports visible in the response.",
            "The next send uses the parsed host and port, with only a ten-attempt retry cap.",
        ],
        "impact": "A trusted response or a cleartext response modified in transit can move a request to an attacker-selected endpoint. A modern client should restrict redirect hosts and ports per request class, or disable redirects for connector and update traffic.",
        "limits": "Ordinary script URL creation is already a broad capability, while connector package activation still has separate TLS and RSA gates. No live redirect was sent and no remote exploit path was demonstrated.",
    },
    {
        "id": "HTTP-REDIR-002",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Redirect parsing permits an HTTPS-to-HTTP transport downgrade",
        "evidence": [
            "The absolute URL parser accepts both schemes and returns a boolean scheme flag.",
            "The response state machine copies that flag into the request before calling sendRequest.",
            "sendRequest enables native SSL from the copied flag, so an http:// Location causes a cleartext follow-up.",
        ],
        "impact": "A request that began with native HTTPS can be redirected to cleartext, exposing subsequent request metadata and response contents to the network. Redirect handling should preserve HTTPS or apply an explicit per-host downgrade policy.",
        "limits": "A network attacker would first need to influence a response that the client accepts, or exploit the existing HTTP fallback. The report does not claim that a current HTTPS service issues such a redirect.",
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
        "schema": "libqplay.original-http-redirect-review.v1",
        "artifact": "original_http_redirect_review_20260830",
        "scope": "read-only review of original 1.8 HTTP redirect handling and destination changes",
        "network_contacted": False,
        "fuzzing_performed": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8",
        },
        "redirect_statuses": [300, 301, 302, 303, 305, 307],
        "redirect_limit": 10,
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "The retry counter is a loop bound, not a trust boundary.",
            "The redirect path is separate from the signed connector-package verifier and from the game-socket NewGraal handshake.",
            "The highest-value repair is a request-class redirect policy that preserves HTTPS and restricts destination hosts and ports.",
        ],
    }
    output = os.environ.get("IDA_HTTP_REDIRECT_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
