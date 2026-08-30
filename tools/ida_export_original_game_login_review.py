#!/usr/bin/env python3
"""Export the original NewGraal login and framing path from IDA.

The exporter is read-only. It records the protocol parser, RSA key unwrap,
directional cipher setup, sequence check, socket read path, and the packet-54
login event. Long or key-like literals are redacted before the decompiler text
is written to the public artifact.
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
    ("0x1fca6c", "TGraalConnection_setProtocol_NewGraal_TString_const", "NewGraal header setup"),
    ("0x1fe0b4", "TGraalConnection_parseSetEncryptionIn_TString_const", "server cipher setup parser"),
    ("0xf7340", "TEncryption_rsa_decrypt_TString_const_TString_const", "RSA private-key unwrap helper"),
    ("0x1fdfd0", "TGraalConnection_setEncryptionIn_TString_const_TString_const_TString_const", "incoming cipher selection"),
    ("0x1fd6b4", "TGraalConnection_setEncryptionOut_TString_const_TString_const_TString_const", "outgoing cipher selection"),
    ("0x1fdeec", "TGraalConnection_decryptIncoming_void", "incoming stream decryption"),
    ("0x1fcd58", "TGraalConnection_checkPacketID_uint", "incoming sequence check"),
    ("0x1fe31c", "TGraalConnection_parseProtocol_NewGraal_void", "NewGraal frame parser"),
    ("0x1fe940", "TGraalConnection_read_void", "connection read and parse dispatch"),
    ("0x2074d4", "TSocketConnection_read_void", "plain or TLS socket read"),
    ("0x1e7cd0", "TClient_parse_uchar_TString_const", "packet handler dispatch"),
    ("0x1e7c90", "TClient_processIncomingPackage_int_TString_const", "queued packet dispatch"),
    ("0x1edf04", "TClient_handleServerLoginPacket", "packet-54 server login event"),
    ("0x1e97dc", "TClient_handleServerLoginSignature", "script server-login event setter"),
    ("0x1eba28", "TClient_setEncryptionIn", "script-facing incoming cipher bridge"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_game_login_review_20260830.json"
)

REDACTED_LITERALS = {
    "DOQLHRbY": "<redacted fixed key literal>",
    "NakFpz15": "<redacted fixed key literal>",
}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact_code(code: str) -> str:
    for literal, replacement in REDACTED_LITERALS.items():
        code = code.replace(literal, replacement)
    return code


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
    code = redact_code(str(decompiled))
    function = ida_funcs.get_func(address)
    literals = sorted(set(re.findall(r'"(?:\\.|[^"\\])*"', code)))
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": "0x%x" % function.start_ea if function else None,
        "function_end": "0x%x" % function.end_ea if function else None,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "string_literals": literals[:200],
        "callers": effective_callers(address),
        "code": code,
    }


MANUAL_REVIEWS = [
    {
        "address": "0x1fca6c",
        "classification": "framed-protocol-header",
        "confidence": "confirmed-static",
        "evidence": [
            "The setup function identifies the six-character EILLLT header layout.",
            "It records the positions and widths of I, L, and T, caps each discovered width at four bytes, and initializes the packet sequence state.",
            "The L field is a three-byte length in the stock NewGraal string, while T is the packet type at the end of the six-byte header.",
        ],
        "interpretation": "The parser is length-framed and its header metadata is selected from the protocol string rather than hard-coded in the read loop.",
    },
    {
        "address": "0x1fe0b4",
        "classification": "server-cipher-setup",
        "confidence": "confirmed-static",
        "evidence": [
            "The function copies the setup payload, optionally DES-decrypts it with the configured parse key, and passes the result to the RSA decrypt helper.",
            "It removes the leading mode byte and parses two length-prefixed text fields before selecting RC4 for mode one, AES for mode two, or no cipher for other values.",
            "The path calls setEncryptionIn and does not call the package RSA signature verifier.",
        ],
        "interpretation": "The packet-252 or 0xfc setup is a key-unwrapping and cipher-selection path. Its RSA operation is distinct from signed connector-package verification.",
    },
    {
        "address": "0xf7340",
        "classification": "client-held-rsa-private-material",
        "confidence": "confirmed-static",
        "evidence": [
            "The helper decodes a supplied RSA private key and calls CyaInt_RsaPrivateDecrypt on the incoming ciphertext.",
            "It allocates a temporary input copy, bounds the decoded result against a local output buffer, clears the temporary input, and frees it.",
            "The parse-key input is supplied by the preceding game cipher setup path, which is fed from connector script material.",
        ],
        "interpretation": "The RSA unwrap is not a public-key trust anchor. A private key used by the client is recoverable from the client-side trust material, so the design should not be treated as peer authentication without an independent authenticated transport or signature check.",
    },
    {
        "address": "0x1fdfd0",
        "classification": "incoming-cipher-state",
        "confidence": "confirmed-static",
        "evidence": [
            "The function clears the previous incoming key, creates an RC4 or AES context, resets the processed-byte counter, and immediately decrypts buffered input.",
            "RC4 uses the first key string. AES uses the key and IV strings and retains the cipher type in the connection object.",
        ],
        "interpretation": "Cipher state is directional and persistent across the receive buffer. Reinitializing RC4 for each frame will not reproduce the client.",
    },
    {
        "address": "0x1fd6b4",
        "classification": "outgoing-cipher-state",
        "confidence": "confirmed-static",
        "evidence": [
            "Pending outgoing data is sent before the old key is cleared.",
            "The function then selects RC4 or AES and creates a new outgoing context.",
        ],
        "interpretation": "Changing the outgoing key is a state transition with a flush boundary, not a per-packet option.",
    },
    {
        "address": "0x1fdeec",
        "classification": "stream-decryption",
        "confidence": "confirmed-static",
        "evidence": [
            "RC4 decrypts every currently buffered byte and advances the processed-byte count.",
            "AES truncates the available input to complete 16-byte blocks before decrypting.",
            "When no cipher is active, the connection still updates its processed-byte position from the buffer state.",
        ],
        "interpretation": "The receive parser can retain a partial AES block until more bytes arrive. A malformed peer can therefore hold parser state without producing a complete frame.",
    },
    {
        "address": "0x1fcd58",
        "classification": "sequence-order-check",
        "confidence": "confirmed-static",
        "evidence": [
            "The check accepts the first packet without a prior sequence value.",
            "Later values must equal the previous value plus one masked to the configured sequence width.",
            "A mismatch logs invalid data, sets the connection error flag, and rejects the packet.",
        ],
        "interpretation": "Sequence checking provides ordering and replay resistance within the connection state, but it is not a cryptographic authenticity check.",
    },
    {
        "address": "0x1fe31c",
        "classification": "framed-input-parser",
        "confidence": "confirmed-static",
        "evidence": [
            "The parser waits until the declared frame length is present before consuming a frame.",
            "It handles uncompressed input, two decompression modes, packet sequence validation, and a special 0xff prefix used by the compressed stream path.",
            "Invalid extraction or sequence state sets the connection error flag and logs an invalid-data message.",
            "The reviewed code has no explicit application cap below the three-byte protocol length field.",
        ],
        "interpretation": "A peer can advertise a frame up to the protocol's 24-bit length range and make the client retain input while it waits for the remaining bytes. This is a plausible availability risk that still needs a bounded local fuzz test.",
    },
    {
        "address": "0x1fe940",
        "classification": "read-to-parser-bridge",
        "confidence": "confirmed-static",
        "evidence": [
            "The function reads from TSocketConnection, appends the returned bytes to the connection buffer, and enters decryption and protocol parsing when data is available.",
            "The byte counter is adjusted against the previous buffer length, and both NewGraal and the older protocol parser are selected from the connection state.",
        ],
        "interpretation": "The stream buffer is fed directly into the framing parser. There is no visible independent byte-budget check at this bridge.",
    },
    {
        "address": "0x2074d4",
        "classification": "socket-read-boundary",
        "confidence": "confirmed-static",
        "evidence": [
            "Plain sockets use recv with an 8192-byte temporary buffer; TLS sockets use repeated CyaSSL_read calls with the same limit.",
            "EAGAIN, EINTR, and the platform-specific nonblocking error are treated as no new data, while other failures close the socket.",
            "The bytes are appended to a TString returned to the caller, with no visible total receive-buffer cap here.",
        ],
        "interpretation": "The transport read size is bounded per call, but the accumulated protocol buffer is governed by higher-level framing and can grow until a frame completes or the socket fails.",
    },
    {
        "address": "0x1e7cd0",
        "classification": "packet-dispatch-boundary",
        "confidence": "confirmed-static",
        "evidence": [
            "The handler table is indexed by the wire packet type.",
            "The encryption-setup, raw-length, and ping handlers execute immediately, while ordinary packets enter the client queue when the network thread is running.",
        ],
        "interpretation": "The key-setup packet is deliberately outside the ordinary queued path, which explains why a correct 0xfc response must arrive before normal encrypted packets.",
    },
    {
        "address": "0x1edf04",
        "classification": "server-login-event",
        "confidence": "confirmed-static",
        "evidence": [
            "The handler for packet type 54 decodes the first body byte by subtracting the text offset and stores it in TClient::serversignature.",
            "It invokes the onServerLogin event after storing the value.",
            "The ARM64 handler table maps packet type 54 to handler index 10 and this function.",
        ],
        "interpretation": "Packet 54 is a state transition into script-side login completion. It is not itself a TLS certificate or RSA signature verification step.",
    },
    {
        "address": "0x1e97dc",
        "classification": "script-login-signature-setter",
        "confidence": "confirmed-static",
        "evidence": [
            "The function stores its incoming value in TClient::serversignature and invokes onServerLogin.",
            "The script-table inventory identifies the function as the tclient_setserversignature callback.",
        ],
        "interpretation": "The script-facing setter and the packet-54 handler converge on the same event, but the integer server signature is a protocol identity value rather than proof of peer authenticity.",
    },
]


SECURITY_FINDINGS = [
    {
        "id": "GAME-LOGIN-001",
        "severity": "high",
        "confidence": "confirmed-static",
        "title": "Stock Classic leaves the game socket outside TLS",
        "evidence": [
            "The recovered Classic connector script sets usessl=false and guards the setSSLParameters call.",
            "The native connection path can configure CyaSSL, but it only starts that path when the per-socket SSL flag is enabled.",
            "The normal game sequence therefore proceeds over the NewGraal socket without the connector's HTTPS trust buffer.",
        ],
        "impact": "A repair should not assume that fixing the expired connector certificate also authenticates the game socket. A hostile network could observe or alter the legacy game transport unless an independently verified current server path provides authentication.",
        "limits": "This is a static result for the recovered Classic branch. It does not claim that every modified script or later client revision has the same setting, and no live endpoint was contacted.",
    },
    {
        "id": "GAME-LOGIN-002",
        "severity": "high",
        "confidence": "confirmed-static",
        "title": "The client performs RSA private-key unwrap with client-held material",
        "evidence": [
            "The game setup parser optionally DES-decrypts its input with a fixed parse key and calls TEncryption_rsa_decrypt.",
            "TEncryption_rsa_decrypt decodes a supplied RSA private key and calls CyaInt_RsaPrivateDecrypt.",
            "The reviewed setup path does not call TEncryption_rsa_verify, and sequence numbers only enforce order after setup.",
        ],
        "impact": "The embedded private-key material is not a server identity anchor. If the legacy transport is intercepted, an attacker who can reproduce the client-side key material may be able to substitute session setup values. A modern repair should use authenticated server key exchange or TLS with current trust material.",
        "limits": "The full server-side protocol and any checks in code outside this path were not exercised. This finding is a design weakness and a review target, not a claim of a demonstrated remote exploit.",
    },
    {
        "id": "GAME-LOGIN-003",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Framed input has no visible sub-24-bit receive cap",
        "evidence": [
            "The NewGraal length field is three bytes and the parser waits for the declared length.",
            "Socket reads append into the connection TString, and the selected bridge has no independent total-buffer limit.",
        ],
        "impact": "A peer can consume memory or stall the protocol parser by declaring a large incomplete frame. The reachable impact depends on whether an untrusted peer can reach the game socket and should be tested only with a local bounded harness.",
        "limits": "The static pass did not execute a malformed-frame probe and does not establish a practical network reachability path in stock operation.",
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
        "schema": "libqplay.original-game-login-review.v1",
        "artifact": "original_game_login_review_20260830",
        "scope": "read-only Hex-Rays export of original 1.8 NewGraal login and framing functions",
        "network_contacted": False,
        "redactions": {
            "count": len(REDACTED_LITERALS),
            "policy": "Fixed key-like literals are replaced before public export. No raw private key or credential is included.",
        },
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8",
        },
        "packet_mapping": {
            "encryption_setup_type": "0xfc",
            "server_login_type": 54,
            "server_login_handler_index": 10,
            "server_login_handler": "0x1edf04",
            "header_layout": "EILLLT",
            "sequence_first_server_value": 0,
        },
        "manual_reviews": MANUAL_REVIEWS,
        "security_findings": SECURITY_FINDINGS,
        "functions": functions,
        "interpretation": [
            "Connector HTTPS trust and game-socket trust are separate boundaries in this APK.",
            "The local handshake responder is useful for protocol study, but it does not prove live account authentication or current server compatibility.",
        ],
    }
    output = os.environ.get("IDA_GAME_LOGIN_REVIEW_OUT", DEFAULT_OUTPUT)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(encoded, encoding="utf-8")
    else:
        ida_kernwin.msg(encoded)
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
