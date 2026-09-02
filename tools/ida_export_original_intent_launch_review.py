#!/usr/bin/env python3
"""Export the original Android deep-link to native server-start bridge.

The exporter is read-only. It records the native URI parser and the script
visible server-start fields. Android manifest and smali observations are
included as manually checked evidence so this report can distinguish a real
scheme mismatch from an unproven server-side exploit path.
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
    ("0x202c64", "TServerList_setProtocolString_TString_const", "incoming URI parser"),
    ("0x202a78", "TServerList_setServerStartParams", "script-visible start parameters setter"),
    ("0x202a8c", "TServerList_setServerStartConnect", "script-visible start destination setter"),
    ("0x202aa0", "TServerList_getServerStartParams", "script-visible start parameters getter"),
    ("0x202ad8", "TServerList_getServerStartConnect", "script-visible start destination getter"),
]

DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_intent_launch_review_20260830.json")


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
        "component": "AndroidManifest.xml",
        "method": "QPlayActivity intent filters",
        "source_line": None,
        "classification": "exported-custom-scheme-entrypoint",
        "confidence": "confirmed-static",
        "evidence": [
            "The launcher activity has VIEW and BROWSABLE filters for the graalclassic and graalclassicplus schemes.",
            "The activity omits an explicit exported attribute, so the old component rules infer it as externally launchable because it has intent filters.",
        ],
        "interpretation": "Another application can supply a custom-scheme launch URI to the old activity. The manifest does not constrain the host or path because neither filter declares one.",
    },
    {
        "component": "com.quattroplay.GraalClassic.QPlayRenderer",
        "method": "loadLibrary()",
        "source_line": 173,
        "classification": "intent-forwarding",
        "confidence": "confirmed-static",
        "evidence": [
            "The renderer reads the current Activity intent, checks for a scheme and data URI, converts the data to a string, and passes it as the final QPlayMain argument.",
            "The renderer does not normalize the Android graalclassic or graalclassicplus scheme before passing the string to native code.",
        ],
        "interpretation": "The native startup wrapper receives the complete incoming URI rather than a validated host, path, or parameter structure.",
    },
    {
        "component": "Java_com_quattroplay_GraalClassic_Natives_QPlayMain",
        "method": "QPlayMain",
        "source_line": None,
        "classification": "native-start-event",
        "confidence": "confirmed-static",
        "evidence": [
            "The JNI wrapper converts the final Java string to a native TString.",
            "For a nonempty value it calls TServerList_setProtocolString and then invokes the universe event onStartedWithURL with the original string payload.",
        ],
        "interpretation": "A deep link reaches both native start-state fields and a script event before ordinary connector login is selected.",
    },
    {
        "component": "TServerList_setProtocolString_TString_const",
        "method": "setProtocolString",
        "source_line": None,
        "classification": "scheme-and-path-parser",
        "confidence": "confirmed-static",
        "evidence": [
            "The parser strips graal:// or graal3:// when those prefixes are present.",
            "It searches for :// and otherwise uses / to split a start connection value from start parameters.",
            "It writes the resulting values to the script-visible serverstartconnect and serverstartparams globals.",
        ],
        "interpretation": "The Android-registered graalclassic:// prefix is not one of the prefixes removed by this native parser. It reaches the parser and the event, but does not follow the same split as the native graal:// form.",
    },
    {
        "component": "TServerList script table",
        "method": "serverstartconnect and serverstartparams",
        "source_line": None,
        "classification": "script-visible-start-state",
        "confidence": "confirmed-static",
        "evidence": [
            "The script inventory maps getters and setters for both serverstartconnect and serverstartparams.",
            "The native URI parser writes those same globals before the onStartedWithURL event is invoked.",
        ],
        "interpretation": "Any activated script that reads these properties can observe the incoming launch data, and a script with the setters can change the values later.",
    },
]


FINDINGS = [
    {
        "id": "URI-001",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Android deep-link schemes do not match the native prefix normalizer",
        "evidence": [
            "The Android manifest accepts graalclassic:// and graalclassicplus://.",
            "The renderer passes the complete incoming URI to QPlayMain.",
            "TServerList_setProtocolString strips only graal:// and graal3:// before splitting the value.",
        ],
        "impact": "A launch URI that Android accepts may not populate serverstartconnect and serverstartparams in the form expected by the native graal:// path. This can prevent a deep-link start or make it appear to be a connector failure even though the normal launcher path is unrelated.",
        "limits": "The core startup script that consumes onStartedWithURL was not fully recovered in this pass. The mismatch is confirmed, but the exact user-visible behavior for every URI shape remains a script and runtime question.",
    },
    {
        "id": "URI-002",
        "severity": "medium",
        "confidence": "conditional-capability",
        "title": "An exported activity forwards unvalidated deep-link data into script-visible start state",
        "evidence": [
            "The activity is externally launchable through browsable custom schemes and does not constrain a host or path.",
            "QPlayMain forwards the URI to onStartedWithURL and the native parser writes script-visible start fields.",
            "The reviewed native path shows no destination allowlist or canonical host validation at this boundary.",
        ],
        "impact": "If the installed startup scripts use the event or start fields to open a server connection or HTTP request, another application may be able to make this client contact an attacker-selected destination. A modern repair should validate the scheme, host, port, and parameter grammar before any network action.",
        "limits": "The core script consumer and a real external-app launch were not tested. This is not a proven SSRF, credential leak, or remote code execution path.",
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
        "schema": "libqplay.original-intent-launch-review.v1",
        "artifact": "original_intent_launch_review_20260830",
        "scope": "read-only review of original 1.8 Android custom-scheme launch handling and ARM64 server-start URI parsing",
        "network_contacted": False,
        "external_intent_sent": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "android_entrypoint": {
            "activity": "com.quattroplay.GraalClassic.QPlayActivity",
            "accepted_schemes": ["graalclassic", "graalclassicplus"],
            "native_parser_prefixes": ["graal://", "graal3://"],
            "native_event": "onStartedWithURL",
            "script_fields": ["serverstartconnect", "serverstartparams"],
        },
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "The ordinary launcher has no data URI and follows TServerList_login; the custom-scheme path is a separate input path.",
            "The confirmed scheme mismatch is a compatibility lead. The destination-control concern remains conditional until the core startup script is recovered or a bounded external-intent test is authorized.",
        ],
    }
    output = os.environ.get("IDA_INTENT_LAUNCH_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
