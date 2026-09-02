#!/usr/bin/env python3
"""Export the original game's native connection lifecycle from IDA.

This is a read-only Hex-Rays export for the original Graal Online Classic 1.8
ARM64 library. It preserves the decompiler text for the small set of login,
server-warp, socket, TLS, and network-thread functions that explain the
transition from connector login to a game server.

Set ``IDA_GAME_CONNECTION_FLOW_OUT`` to write the JSON artifact. If it is
omitted, the result is printed to IDA's console.
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
    ("0x204420", "TServerList_login_void", "connector login selection"),
    ("0x204488", "TServerList_handleServerWarp_void", "server-warp handoff"),
    ("0x1eb964", "TClient_setSSLParameters_scriptCallback", "script TLS parameter callback"),
    ("0x1e7058", "TClient_connectToGameServer_void", "game-server connect setup"),
    ("0x1feb98", "TGraalConnection_connectToServer_TString_const_TString_const", "game connection field transfer"),
    ("0x1feb38", "TGraalConnection_setSSLVerifyCert_TString_const", "game-server verify-buffer setter"),
    ("0x1feae8", "TGraalConnection_setSSLProtocol_TString_const", "game-server TLS protocol setter"),
    ("0x1fea98", "TGraalConnection_setSSLCipherList_TString_const", "game-server TLS cipher setter"),
    ("0x1fea70", "TGraalConnection_setEnableSSL_bool", "game-server SSL enable setter"),
    ("0x206bd8", "TSocketConnection_connectSocket_TString_const_int", "nonblocking socket connect"),
    ("0x206a48", "TSocketConnection_checkConnecting_void", "delayed connect completion"),
    ("0x2067b4", "TSocketConnection_setStatus_int", "socket status transition"),
    ("0x206450", "TSocketConnection_enableSSLOnSocket_void", "delayed TLS setup"),
    ("0x208920", "TClient_networkThreadMain", "game network thread"),
    ("0x203360", "TServerList_handleClient_void", "game client event loop"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "game_connection_flow_review_20260830.json"
)


CALL_WORDS = {
    "CyaSSL_connect",
    "CyaSSL_read",
    "CyaSSL_write",
    "close",
    "connect",
    "gethostbyname",
    "getsockopt",
    "nanosleep",
    "recv",
    "select",
    "send",
    "socket",
    "TSocketConnection_checkConnecting",
    "TSocketConnection_connectSocket",
    "TSocketConnection_enableSSLOnSocket",
    "TSocketConnection_setStatus",
    "TClient_connectToGameServer",
    "TClient_processIncomingPackages",
    "TClient_processOutgoingPackages",
    "TClient_readIncomingData",
    "TClient_sendOutgoingPackages",
    "TServerList_handleServerWarp",
    "TGraalConnection_setEnableSSL",
    "TGraalConnection_setSSLVerifyCert",
    "TGraalConnection_setSSLProtocol",
    "TGraalConnection_setSSLCipherList",
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
        "schema": "libqplay.original-game-connection-flow.v1",
        "artifact": "game_connection_flow_review_20260830",
        "scope": "read-only Hex-Rays export of original 1.8 game connection lifecycle functions",
        "network_contacted": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "functions": functions,
        "interpretation": [
            "TServerList_login selects connector mode and prepares the login request. A later server-warp event supplies the host, server name, and port for the game connection.",
            "TClient_connectToGameServer validates the supplied address and port, records an address-and-port digest, creates the client thread, and reports a generic failure when the inputs are empty or the socket is already in error.",
            "The script callback at 0x1eb964 accepts an SSL enable flag, protocol, cipher list, and encrypted certificate. It decrypts the certificate with the recovered NakFpz15 key and copies all four values into TGraalConnection fields.",
            "TGraalConnection_connectToServer transfers the stored SSL fields to the new socket before connecting. The companion game_server_tls artifact records that the recovered Classic source sets usessl false and guards setSSLParameters, so this stale game TLS material is dormant in the stock Classic branch.",
            "The socket path is nonblocking. Status 4 represents an in-progress connect, checkConnecting uses select and SO_ERROR, and status 5 represents a completed TCP connection.",
            "setStatus starts TLS when status 5 is reached and the SSL flag is set. The TLS setup selects a CyaSSL method, loads the configured verification buffer, applies optional hostname verification, and calls CyaSSL_connect.",
            "The network thread drains incoming data, processes outgoing packages, sends queued bytes, and sleeps briefly between iterations. The server-list handler drives reconnect, timeout, package, player, and server-warp events.",
            "The export records native behavior in this APK revision. It does not contact a live service or prove that a current host, certificate, or server response is still compatible.",
        ],
    }
    output = os.environ.get("IDA_GAME_CONNECTION_FLOW_OUT", DEFAULT_OUTPUT)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(encoded, encoding="utf-8")
    else:
        ida_kernwin.msg(encoded)
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
