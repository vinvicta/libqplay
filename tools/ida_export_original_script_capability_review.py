#!/usr/bin/env python3
"""Export script-to-native capability boundaries from the original client.

The exporter is read-only. It records selected script callbacks, their native
implementations, and the nearby file, upload, HTTP, and class-loading paths.
It does not execute a script, contact a server, or change the IDA database.
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
    ("0x0f0790", "TStream_LoadFromFile_TString_const", "generic file reader"),
    ("0x0f0aa8", "TStream_SaveToFile_TString_const_uint", "generic file writer"),
    ("0x0fc110", "TFileScripting_getScriptAccessFilename_TString_const_bool", "script path policy"),
    ("0x0fc880", "TFileScripting_script_getScriptAccessFile", "script path policy callback"),
    ("0x0fc7ec", "TFileScripting_script_fileExists", "policy-aware file existence callback"),
    ("0x0fc740", "TFileScripting_script_fileSize", "policy-aware file-size callback"),
    ("0x0fbda4", "TFileScripting_script_getFileContent", "script file-content reader"),
    ("0x0fbbc8", "TFileScripting_script_setFileContent", "script file-content writer"),
    ("0x0fc4b0", "TFileScripting_script_deleteFile", "policy-aware script deletion callback"),
    ("0x0fca80", "TFileScripting_script_decompressFile", "script archive extraction callback"),
    ("0x157d20", "GSFunctionsClient_script_adventure_uploadfile", "unfiltered upload callback"),
    ("0x157d3c", "GSFunctionsClient_script_uploadfile", "policy-aware upload callback"),
    ("0x1e9068", "TClient_uploadFile_TString_const", "upload queue admission"),
    ("0x1e9198", "TClient_uploadFilesToServer_void", "upload queue sender"),
    ("0x200d44", "THTTPRequest_extractHTTPHostPortFile_TString_const_TString_int_TString_bool", "HTTP URL parser"),
    ("0x1ffa90", "THTTPRequest_findOrCreateStatic", "host-port HTTP request factory"),
    ("0x200f98", "THTTPRequest_findOrCreateFromUrl", "URL HTTP request factory"),
    ("0x2015e8", "THTTPRequest_requestGameFileIfAllowed", "game-file URL policy callback"),
    ("0x156cb4", "GSFunctionsClient_script_openurl", "external URL callback"),
    ("0x158b80", "GSFunctionsClient_script_opengraalurl", "server-mediated URL callback"),
    ("0x158e50", "GSFunctionsClient_script_loadclass", "dynamic class request callback"),
    ("0x22c260", "TScriptUniverse_getClassAndCreate_TString_const_bool", "class lookup and request"),
    ("0x22cc88", "TScriptUniverse_addClassScript_TString_const_TString_const", "class script installation"),
    ("0x216de8", "TScript_loadScriptEncrypted_int_TString_const_uint", "encrypted class script loader"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_script_capability_review_20260830.json"
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


SCRIPT_CAPABILITY_GROUPS = [
    {
        "name": "file-content-access",
        "table_owner": "TFileScripting_initStaticScriptVars_void",
        "table_va": "0x376bd0",
        "entries": [
            {
                "script_name": "adventure_getfilecontent",
                "callback": "0xfbda4",
                "policy_observation": "The callback loads the supplied filename directly through TStream_LoadFromFile.",
            },
            {
                "script_name": "adventure_setfilecontent",
                "callback": "0xfbbc8",
                "policy_observation": "The callback writes the supplied filename directly through TStream_SaveToFile.",
            },
            {
                "script_name": "fileexists",
                "callback": "0xfc7ec",
                "policy_observation": "The callback first resolves the name through TFileScripting_getScriptAccessFilename.",
            },
            {
                "script_name": "filesize",
                "callback": "0xfc740",
                "policy_observation": "Path-like names are resolved through TFileScripting_getScriptAccessFilename; resource names use the game-resource resolver.",
            },
            {
                "script_name": "deletefile",
                "callback": "0xfc4b0",
                "policy_observation": "The callback resolves a policy-controlled path, checks existence, then calls the generic delete helper.",
            },
            {
                "script_name": "decompressfile",
                "callback": "0xfca80",
                "policy_observation": "The callback uses the script access and write-folder helpers before extracting recognized archive resources.",
            },
        ],
    },
    {
        "name": "file-upload",
        "table_owner": "gsfunctions_client_initStaticScriptVars_void",
        "table_va": "0x378c28",
        "entries": [
            {
                "script_name": "adventure_uploadfile",
                "callback": "0x157d20",
                "policy_observation": "The wrapper calls TClient_uploadFile directly without the normal access-filename helper.",
            },
            {
                "script_name": "uploadfile",
                "callback": "0x157d3c",
                "policy_observation": "The normal wrapper checks the one-shot allowed-upload list or resolves the name through the script access helper.",
            },
        ],
        "limits": [
            "TClient_uploadFile rejects a reported file size above 20,000,000 bytes before queueing.",
            "TClient_uploadFilesToServer reads queued files in chunks of at most 32,000 bytes and sends them to the current game connection.",
            "The size limit is not a path allowlist and the direct adventure wrapper does not establish a local filename root.",
        ],
    },
    {
        "name": "HTTP-request-access",
        "table_owner": "THTTPRequest_initStaticScriptVars_void",
        "table_va": "0x385e10",
        "entries": [
            {
                "script_name": "requesthttp",
                "callback": "0x1ffa90",
                "policy_observation": "The factory accepts a supplied host, port, and path and creates or reuses a request object.",
            },
            {
                "script_name": "requesturl",
                "callback": "0x200f98",
                "policy_observation": "The URL parser accepts http:// and https:// forms and the factory has no visible host allowlist.",
            },
            {
                "script_name": "requesturlasgamefile",
                "callback": "0x2015e8",
                "policy_observation": "This narrower path rejects the connector pseudo-file and blocked extensions before requesting the stripped filename as a game file.",
            },
        ],
        "limits": [
            "The reviewed URL parser defaults ports to 80 or 443 and accepts a positive parsed port.",
            "The request object count is capped at 10,000, but no destination allowlist is visible in these wrappers.",
        ],
    },
    {
        "name": "protocol-and-class-bridge",
        "table_owner": "TClientProperties_TClientProperties_void",
        "table_va": "0x3842c0",
        "entries": [
            {"script_name": "sendraw", "callback": "0x1e9518"},
            {"script_name": "senddata", "callback": "0x1e9540"},
            {"script_name": "setsslparameters", "callback": "0x1eb964"},
            {"script_name": "setencryptionparsekey", "callback": "0x1eb960"},
            {"script_name": "setencryptionout", "callback": "0x1eb95c"},
            {"script_name": "getpassword", "callback": "0x1eb93c"},
            {"script_name": "connecttogameserver", "callback": "0x1eba0c"},
        ],
        "observation": "The connector script object has a native protocol bridge with raw-send, encryption, TLS-parameter, connection, and password callbacks. Its trust boundary is the signed script-package verifier, not a small capability sandbox.",
    },
    {
        "name": "dynamic-class-loading",
        "table_owner": "gsfunctions_client_initStaticScriptVars_void",
        "table_va": "0x378c28",
        "entries": [
            {
                "script_name": "loadclass",
                "callback": "0x158e50",
                "policy_observation": "The callback permits class creation while the universe class count is at most 9,999.",
            },
        ],
        "positive_controls": [
            "TScriptUniverse_getClassAndCreate uses requestedclassscripts to avoid duplicate requests.",
            "TScriptUniverse_addClassScript compares a class privilege value against the current server privilege before installing its stream.",
            "TScript_loadScriptEncrypted requests a coded class script and uses the encrypted-script checksum path when the local class is absent.",
        ],
    },
]


SECURITY_FINDINGS = [
    {
        "id": "SCRIPT-001",
        "severity": "high",
        "confidence": "confirmed-static",
        "title": "Adventure file-content callbacks bypass the visible script path policy",
        "evidence": [
            "The adventure_getfilecontent callback passes its filename directly to TStream_LoadFromFile.",
            "The adventure_setfilecontent callback passes its filename directly to TStream_SaveToFile.",
            "Neither wrapper calls TFileScripting_getScriptAccessFilename or TFileScripting_AllowedFoldername, unlike the reviewed fileexists, filesize, deletefile, and decompressfile paths.",
            "TStream_SaveToFile uses a normal writable fopen mode and treats an empty stream as a delete request when overwrite mode is selected.",
        ],
        "impact": "An activated script can request reads or writes for paths accessible to the native process, subject to the Android application sandbox and filesystem permissions. This can expose local application data or alter existing files without the narrower path policy used by neighboring callbacks.",
        "limits": "The finding is about a native capability boundary. The static pass did not prove that an attacker can supply an accepted script package, did not test path variants, and did not contact a server.",
    },
    {
        "id": "SCRIPT-002",
        "severity": "high",
        "confidence": "confirmed-static",
        "title": "The adventure upload callback bypasses the normal filename gate",
        "evidence": [
            "GSFunctionsClient_script_adventure_uploadfile calls TClient_uploadFile directly.",
            "The separate uploadfile callback checks the allowed-upload list or resolves the filename through TFileScripting_getScriptAccessFilename before queueing.",
            "TClient_uploadFile applies only a reported 20,000,000-byte size check, and TClient_uploadFilesToServer later opens the queued path and sends its contents in chunks.",
        ],
        "impact": "A script with access to the direct callback can queue an accessible local file for upload to the current game server. The size ceiling limits one queued file but does not substitute for a local path policy.",
        "limits": "The server-side acceptance and destination were not tested. The Android sandbox still constrains which files are readable, and no live endpoint was contacted.",
    },
    {
        "id": "SCRIPT-003",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Script HTTP request factories have no visible destination allowlist",
        "evidence": [
            "THTTPRequest_extractHTTPHostPortFile accepts both http:// and https:// URLs and parses a supplied host, path, and positive port.",
            "The requesthttp and requesturl factories create or reuse requests from those values without a visible host or private-network filter.",
            "The requesturlasgamefile callback adds filename and extension checks, but the general HTTP callbacks are separate.",
        ],
        "impact": "An activated script may be able to make the client contact arbitrary HTTP(S) destinations and expose request or response data through the script object. This is a device-side egress and data-access capability, not proof of a server-side request forgery.",
        "limits": "The static pass did not execute a script or inspect every later request policy branch. Android network permission and the device network still govern reachability, and no external destination was contacted.",
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
        "schema": "libqplay.original-script-capability-review.v1",
        "artifact": "original_script_capability_review_20260830",
        "scope": "read-only Hex-Rays export of original 1.8 script-to-native file, upload, HTTP, protocol, and class-loading boundaries",
        "network_contacted": False,
        "scripts_executed": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "script_capability_groups": SCRIPT_CAPABILITY_GROUPS,
        "security_findings": SECURITY_FINDINGS,
        "functions": functions,
        "interpretation": [
            "The embedded script runtime is a privileged native bridge. Its security depends on package signing and script provenance as well as on individual callback policies.",
            "The strongest new issue is an inconsistent local-file policy: several ordinary callbacks sanitize names, while adventure file-content and upload callbacks do not show the same gate.",
            "The report records capability reachability and static limits. It does not claim that a production server can deliver an untrusted script or that any external endpoint was contacted.",
        ],
    }
    output = os.environ.get("IDA_SCRIPT_CAPABILITY_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
