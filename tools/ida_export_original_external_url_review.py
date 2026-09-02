#!/usr/bin/env python3
"""Export the original script-to-Android external URL boundary.

The exporter is read-only. It records the native callbacks that reach the
Android URL bridge, plus the Java-side intent construction checked in the
original DEX. It does not launch an intent, execute a script, open a socket,
or contact a live endpoint.
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
    ("0x106904", "TWindow_openURL_TString_const_bool", "window external URL bridge"),
    ("0x156cb4", "GSFunctionsClient_script_openurl", "script external URL callback"),
    ("0x156cf0", "GSFunctionsClient_script_openurl2", "second script external URL callback"),
    ("0x158b80", "GSFunctionsClient_script_opengraalurl", "server-mediated URL callback"),
    ("0x15aeac", "TAdventure_checkOpenSecureURL_void", "server-mediated URL checker"),
    ("0x15c228", "TAdventure_openSecureURL_TString_const", "server-mediated URL sender"),
    ("0x241288", "JNI_canOpenURL", "Android handler query bridge"),
    ("0x243158", "openAndroidURL_TString_const", "Android external intent bridge"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_external_url_review_20260830.json"
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


JAVA_OBSERVATIONS = [
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "getIntentForURL(java.lang.String)",
        "source": "original DEX smali",
        "behavior": [
            "The exact strings graalclassic:// and graalclassicplus:// create ACTION_RUN intents targeting com.quattroplay.GraalClassic.QPlayActivity.",
            "The exact graalera, graaleraplus, graalzone, graalzoneplus, graalworld, graalworldplus, graalolwest, and graalolwestplus strings target their corresponding legacy package and activity with ACTION_RUN.",
            "Every other string is passed to Uri.parse and placed in an ACTION_VIEW intent without a scheme or host allowlist.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "openURL(java.lang.String)",
        "source": "original DEX smali",
        "behavior": [
            "The method queries PackageManager.queryIntentActivities for the constructed intent.",
            "When at least one handler exists it calls startActivity; otherwise it prints Can't open URL and returns.",
            "The reviewed method has no user confirmation, scheme allowlist, or host allowlist before startActivity.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "canOpenURL(java.lang.String)",
        "source": "original DEX smali",
        "behavior": [
            "The method uses the same getIntentForURL mapping and returns whether queryIntentActivities finds at least one handler.",
            "This exposes installed-handler presence to the caller of the native script bridge.",
        ],
    },
]


OBSERVATIONS = [
    {
        "address": "0x156cb4",
        "classification": "script-to-window-dispatch",
        "confidence": "confirmed-static",
        "evidence": [
            "GSFunctionsClient_script_openurl forwards its argument through the main window virtual method at slot 472.",
            "GSFunctionsClient_script_openurl2 uses the same main-window virtual method.",
            "TWindow_openURL delegates to openAndroidURL_TString_const.",
        ],
        "interpretation": "The openurl and openurl2 script callbacks reach the Android URL bridge rather than a native HTTP request object.",
    },
    {
        "address": "0x243158",
        "classification": "Android-intent-construction",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "openAndroidURL_TString_const calls the Java static openURL([B)V method after copying the native TString into a byte array.",
            "The original QPlayActivity openURL method constructs the intent from the supplied string and starts it when an activity handler exists.",
            "The Java helper maps only exact legacy game strings specially; all other values use ACTION_VIEW and Uri.parse.",
        ],
        "interpretation": "An activated script can request external Android URI handling, subject to installed handlers and the Android sandbox.",
    },
    {
        "address": "0x241288",
        "classification": "Android-handler-query",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "JNI_canOpenURL calls the Java static canOpenURL([B)Z method.",
            "The Java method returns whether PackageManager.queryIntentActivities finds a handler for the constructed intent.",
        ],
        "interpretation": "The script-visible canopenurl callback can probe whether an installed application handles a URI, but it does not launch the handler itself.",
    },
    {
        "address": "0x158b80",
        "classification": "server-mediated-URL-path",
        "confidence": "confirmed-static",
        "evidence": [
            "GSFunctionsClient_script_opengraalurl calls TAdventure_openSecureURL when the Adventure object exists.",
            "With an active player and client, TAdventure_openSecureURL sends a setcookie message to the game server instead of immediately opening the argument.",
            "Without that state, the native function falls back to the main window external URL bridge.",
        ],
        "interpretation": "opengraalurl is a distinct server-mediated path, but its disconnected fallback still reaches the general Android URL bridge.",
    },
]


FINDINGS = [
    {
        "id": "ANDROID-URL-001",
        "severity": "medium",
        "confidence": "confirmed-static-plus-dex",
        "title": "The script external URL bridge launches arbitrary ACTION_VIEW URIs",
        "evidence": [
            "The openurl and openurl2 script callbacks reach TWindow_openURL and openAndroidURL_TString_const.",
            "QPlayActivity.getIntentForURL uses ACTION_VIEW with Uri.parse for every input that is not one of the exact legacy game strings.",
            "QPlayActivity.openURL starts the resolved activity without a visible scheme or host allowlist and without user confirmation.",
        ],
        "impact": "A script that reaches this callback can cause the device to resolve and launch handlers for web, custom, or other supported URI schemes. This can open attacker-controlled content or cross-application flows and may expose the user to phishing or handler-specific side effects.",
        "limits": "The callback still depends on script activation, an installed handler, and Android intent behavior. No script was executed and no intent was launched during this review. This is not evidence of arbitrary native code execution.",
    },
    {
        "id": "ANDROID-URL-002",
        "severity": "low",
        "confidence": "confirmed-static-plus-dex",
        "title": "canopenurl exposes installed-handler presence to scripts",
        "evidence": [
            "JNI_canOpenURL forwards arbitrary input to QPlayActivity.canOpenURL.",
            "The Java method queries PackageManager.queryIntentActivities and returns only whether the result is nonempty.",
        ],
        "impact": "An activated script can use URI-handler queries as a coarse installed-application or capability probe. The result is a privacy signal rather than a direct file or credential read.",
        "limits": "The result is Boolean and depends on Android package visibility and installed applications. No probing was performed against a device during this pass.",
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
        "schema": "libqplay.original-external-url-review.v1",
        "artifact": "original_external_url_review_20260830",
        "scope": "read-only review of original 1.8 script callbacks that reach Android URL intents",
        "network_contacted": False,
        "scripts_executed": False,
        "intents_launched": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "java_observations": JAVA_OBSERVATIONS,
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "openurl and openurl2 are external Android intent capabilities, not the native HTTP request API.",
            "opengraalurl normally sends a server-mediated setcookie message when an active player and client exist, but its disconnected fallback calls the general external URL bridge.",
            "A repair should allow only approved schemes and hosts, keep legacy game routing explicit, and avoid exposing package-handler queries to untrusted scripts.",
        ],
    }
    output = os.environ.get("IDA_EXTERNAL_URL_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
