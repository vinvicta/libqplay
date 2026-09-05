#!/usr/bin/env python3
"""Export the original 1.8 native socket-policy and HTTP-limit review.

The exporter is read-only. It records the script socket gates, their matching
logic, selected HTTP defaults, and the relevant decompiler output. It does not
open a socket, invoke a script, or contact a live endpoint.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import idaapi
import idautils


TARGETS = [
    ("TSocket_checkAllowConnect_TString_const_int", "outbound policy gate"),
    ("IsHostAndPortInList_TString_const_TString_const_int", "host and port matcher"),
    ("TSocket_connect_TString_const_int", "script outbound connection"),
    ("TSocket_checkAllowBind_int", "listener policy gate"),
    ("TSocket_bind_int_bool", "script listener setup"),
    ("TSocketConnection_bindSocket_int_bool", "native bind and listen"),
    ("TSocket_clearStaticStrings", "policy-string cleanup"),
    ("TSocket_setAllowedPortsBind", "script bind-policy setter"),
    ("TSocket_setAllowedSocketsConnect", "script outbound-policy setter"),
]

GLOBAL_TARGETS = [
    ("data_THTTPRequest_webdownloadsizelimit", "selected web-download byte limit", "dword", "bytes"),
    ("data_THTTPRequest_maxconnections", "HTTP request-pool limit", "dword", "requests"),
    ("data_TSocket_allowedportsbind", "bind policy string", "tstring", None),
    ("data_TSocket_allowedsocketsconnect", "outbound policy string", "tstring", None),
    ("data_TSocket_allowedbindzero", "whether port zero is allowed", "byte", None),
]

DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "artifacts"
    / "original_socket_policy_review_20260902.json"
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def address_for_name(name: str) -> int:
    address = ida_name.get_name_ea(idaapi.BADADDR, name)
    if address == idaapi.BADADDR:
        raise RuntimeError("could not resolve %s" % name)
    return address


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
                "caller_name": ida_funcs.get_func_name(caller.start_ea) or "",
            }
        )
    unique = {(item["caller"], item["callsite"]): item for item in callers}
    return sorted(
        unique.values(),
        key=lambda item: (int(item["caller"], 16), int(item["callsite"], 16)),
    )[:250]


def export_function(name: str, role: str) -> dict:
    address = address_for_name(name)
    decompiled = ida_hexrays.decompile(address)
    if decompiled is None:
        raise RuntimeError("Hex-Rays could not decompile %s" % name)
    code = str(decompiled)
    function = ida_funcs.get_func(address)
    return {
        "address": "0x%x" % address,
        "name": ida_funcs.get_func_name(address) or name,
        "role": role,
        "function_start": "0x%x" % function.start_ea if function else None,
        "function_end": "0x%x" % function.end_ea if function else None,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "callers": effective_callers(address),
        "code": code,
    }


def export_global(name: str, description: str, kind: str, unit: str | None) -> dict:
    address = address_for_name(name)
    item = {
        "address": "0x%x" % address,
        "name": name,
        "description": description,
        "kind": kind,
    }
    if unit is not None:
        item["unit"] = unit
    if kind == "dword":
        item["value"] = ida_bytes.get_dword(address)
    elif kind == "byte":
        item["value"] = ida_bytes.get_byte(address)
        item["value_note"] = "Static storage may contain an initialization sentinel in an IDB; treat this as an address and code-path record unless runtime state is captured."
    return item


OBSERVATIONS = [
    {
        "address": "0x204ec8",
        "classification": "outbound-socket-gate",
        "confidence": "confirmed-static",
        "evidence": [
            "TSocket_connect calls TSocket_checkAllowConnect before allocating a TSocketConnection.",
            "A denied request is logged as Script connection to <host>:<port> is not allowed, blocking.",
            "An accepted request copies the script access filenames, SSL settings, host, and port into the new native connection.",
        ],
        "interpretation": "The script connect surface is gated before native socket creation, but the policy is configurable from the script property table.",
    },
    {
        "address": "0x2079ac",
        "classification": "host-port-policy-parser",
        "confidence": "confirmed-static",
        "evidence": [
            "A policy string equal to * returns allow immediately.",
            "Otherwise the string is split on commas. Each entry is either a port specification or a host:port specification.",
            "Host names use exact comparison or the native pattern matcher. A port can be an exact decimal value or a slash-separated range.",
            "The requested port is converted to a decimal TString before exact comparison at 0x207a48.",
        ],
        "interpretation": "The intended policy format is expressive enough to restrict both host and port, but its range branch has a separate implementation defect recorded below.",
    },
    {
        "address": "0x207ad4",
        "classification": "outbound-range-index-confusion",
        "confidence": "confirmed-static",
        "evidence": [
            "The allowlist loop initializes W21 to zero at 0x207a2c and increments it once per comma-separated entry.",
            "The slash-range branch compares W21 at 0x207ad4 and 0x207ae0 with the parsed end and start values.",
            "The requested port is W26, and W26 is used for exact comparison, but it is not used by the range comparisons.",
        ],
        "interpretation": "A range entry is evaluated against its position in the allowlist, not the requested port. Exact port entries and host matching remain separate paths.",
    },
    {
        "address": "0x2057a0",
        "classification": "bind-port-policy",
        "confidence": "confirmed-static",
        "evidence": [
            "TSocket_checkAllowBind accepts * immediately, conditionally permits port zero through allowedbindzero, and otherwise scans allowedportsbind.",
            "Exact decimal bind-port entries compare against the requested port at 0x205898.",
            "The slash-range branch compares the entry index W20 at 0x20591c and 0x205924, while the requested port is W26.",
        ],
        "interpretation": "Bind ranges have the same index-versus-port defect as outbound ranges. The defect can deny intended ranges or allow unintended ports when an entry index falls inside the configured interval.",
    },
    {
        "address": "0x2068b4",
        "classification": "wildcard-listener",
        "confidence": "confirmed-static",
        "evidence": [
            "The native bind path creates an IPv4 TCP or UDP socket, zeros the sockaddr address, and writes only the requested port and AF_INET family.",
            "TCP bind calls listen with a backlog of 10 when the datagram flag is false.",
            "The zero address is the wildcard IPv4 address, so an allowed TCP listener is not statically limited to loopback.",
        ],
        "interpretation": "If an activated script reaches bind with a permissive policy, it can request a listener exposed on the local host interfaces. Stock runtime reachability still requires a signed script package and was not demonstrated for this branch.",
    },
    {
        "address": "0xe0680",
        "classification": "policy-lifecycle",
        "confidence": "confirmed-static",
        "evidence": [
            "TSocket_clearStaticStrings clears allowedportsbind and allowedsocketsconnect.",
            "The script property table exposes setters at 0x204678 and 0x204688 that replace those strings.",
        ],
        "interpretation": "The policy state is process-global static script state rather than a hard-coded per-socket policy.",
    },
    {
        "address": "0x2025a0",
        "classification": "selected-download-limit",
        "confidence": "confirmed-static",
        "evidence": [
            "data_THTTPRequest_webdownloadsizelimit is initialized to 0x6400000, or 104857600 bytes.",
            "THTTPRequest_runScript applies that limit when deciding whether to dispatch or save a selected web download.",
            "data_THTTPRequest_maxconnections is initialized to 0xa, or 10 concurrent HTTP requests.",
            "The limit is checked after header parsing and does not cap every ordinary response, unknown-length response, header line, or accumulated stream.",
        ],
        "interpretation": "The client has useful selected-transfer and pool defaults, but they do not replace general HTTP framing and memory limits.",
    },
]


FINDINGS = [
    {
        "id": "SOCKET-POLICY-003",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Configured socket port ranges compare the allowlist index instead of the requested port",
        "evidence": [
            "IsHostAndPortInList initializes the outbound entry index in W21, but its range checks at 0x207ad4 and 0x207ae0 use W21 rather than the requested port W26.",
            "TSocket_checkAllowBind initializes the bind entry index in W20, but its range checks at 0x20591c and 0x205924 use W20 rather than the requested bind port W26.",
            "Exact decimal entries still use the requested port, so this finding is specific to slash-separated ranges.",
        ],
        "impact": "A policy author who writes a port range can receive an unexpected denial, or can accidentally allow a port because the range happens to contain the comma-separated entry index. This undermines the intended destination and listener boundary. A repair should compare the requested port and validate the range before use.",
        "limits": "This is confirmed from ARM64 instructions and decompiler output. No untrusted production script was run, and no live network or listener was opened.",
    },
    {
        "id": "SOCKET-POLICY-004",
        "severity": "medium",
        "confidence": "confirmed-static-conditional",
        "title": "A permissive activated script can request a wildcard-address listener",
        "evidence": [
            "The script surface registers bind, connect, send, and sendudp.",
            "TSocket_bind calls TSocketConnection_bindSocket after the configurable bind policy passes.",
            "The native sockaddr is zeroed before the requested port is written, producing an IPv4 wildcard bind address, and TCP listeners use backlog 10.",
        ],
        "impact": "If a signed or otherwise activated script sets a permissive policy and reaches bind, the client may expose a local TCP or UDP service beyond loopback. A repair should keep listener creation disabled for untrusted content, require an explicit loopback or approved-address policy, and validate ports with a correct range implementation.",
        "limits": "Static capability is confirmed, but stock startup did not invoke bind in the reviewed local replay. This is not a claim that the public service currently delivers such a script.",
    },
    {
        "id": "HTTP-LIMIT-002",
        "severity": "informational",
        "confidence": "confirmed-static",
        "title": "Selected web downloads are limited to 100 MiB and the HTTP pool defaults to ten requests",
        "evidence": [
            "data_THTTPRequest_webdownloadsizelimit at 0x385ad4 is 0x6400000, or 104857600 bytes.",
            "data_THTTPRequest_maxconnections at 0x385ad8 is 0xa, or 10.",
            "The selected-download guard occurs after response parsing and does not impose a general total response, header, or unknown-length cap.",
        ],
        "impact": "These defaults bound one selected transfer and limit normal request-pool concurrency, but they should not be treated as a complete memory-safety policy. A repair should add independent header, line, body, and aggregate-buffer limits.",
        "limits": "No malformed response was fuzzed and no live endpoint was contacted.",
    },
]


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")
    functions = [export_function(name, role) for name, role in TARGETS]
    globals_ = [export_global(name, description, kind, unit) for name, description, kind, unit in GLOBAL_TARGETS]
    result = {
        "schema": "libqplay.original-socket-policy-review.v1",
        "artifact": "original_socket_policy_review_20260902",
        "scope": "read-only review of original 1.8 ARM64 script socket policy and HTTP defaults",
        "network_contacted": False,
        "native_execution": False,
        "database": {
            "input_file": Path(idaapi.get_input_file_path()).name,
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "policy_format": {
            "wildcard": "*",
            "entry_separator": ",",
            "host_separator": ":",
            "range_separator": "/",
            "host_match": "exact or native patternMatches",
            "range_endpoint_inclusive": True,
            "range_implementation_note": "The ARM64 range branches compare the comma-separated entry index, not the requested port.",
        },
        "global_values": globals_,
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "Exact host and port entries are a real pre-socket gate for script outbound connections.",
            "Slash-separated port ranges are not reliable because both range branches use the entry index register.",
            "The script listener surface is conditional and remains behind package activation in the stock workflow.",
            "The 100 MiB selected-download guard and ten-request pool default are useful operating limits, not substitutes for a general HTTP framing budget.",
        ],
    }
    output = os.environ.get("IDA_SOCKET_POLICY_REVIEW_OUT", str(DEFAULT_OUTPUT))
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "global_count": len(globals_), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
