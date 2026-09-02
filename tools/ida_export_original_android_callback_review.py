#!/usr/bin/env python3
"""Export the remaining Android JNI callback behavior from the 1.8 IDB.

The exporter is read-only. It records the native callback names, decompiler
text, effective callers, and a small set of manually reviewed observations.
The companion Java class inventory is documented in the repository's focused
DEX reviews. This pass is about the native half of the boundary and does not
execute callbacks, launch purchases, open media, or contact a service.
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
    ("0x243c9c", "Java_com_quattroplay_GraalClassic_Natives_onSizeChanged", "surface size bridge"),
    ("0x243d00", "Java_com_quattroplay_GraalClassic_Natives_onMouseEvent", "touch and mouse bridge"),
    ("0x2443b8", "Java_com_quattroplay_GraalClassic_Natives_onKeyEvent", "key event bridge"),
    ("0x2444e8", "Java_com_quattroplay_GraalClassic_Natives_onRegisterEvent", "script event registration bridge"),
    ("0x244624", "Java_com_quattroplay_GraalClassic_Natives_onAddScriptFunction", "script callback registration bridge"),
    ("0x244734", "Java_com_quattroplay_GraalClassic_Natives_onAccelerator", "accelerator bridge"),
    ("0x244758", "Java_com_quattroplay_GraalClassic_Natives_onReloadTextures", "texture reload bridge"),
    ("0x244768", "Java_com_quattroplay_GraalClassic_Natives_onTextEntered", "text input bridge"),
    ("0x24485c", "Java_com_quattroplay_GraalClassic_Natives_onVideoLoaded", "video loaded bridge"),
    ("0x2448dc", "Java_com_quattroplay_GraalClassic_Natives_onVideoFinished", "video finished bridge"),
    ("0x244990", "Java_com_quattroplay_GraalClassic_Natives_onAppEnterBackground", "background transition"),
    ("0x244a68", "Java_com_quattroplay_GraalClassic_Natives_onAppLeaveBackground", "foreground transition"),
    ("0x244ac0", "Java_com_quattroplay_GraalClassic_Natives_onAppPause", "pause bridge"),
    ("0x244af8", "Java_com_quattroplay_GraalClassic_Natives_onAmazonUser", "legacy Amazon user bridge"),
    ("0x244c44", "Java_com_quattroplay_GraalClassic_Natives_onAmazonPurchase", "legacy Amazon purchase bridge"),
    ("0x244f08", "Java_com_quattroplay_GraalClassic_Natives_onAmazonHistory", "legacy Amazon history bridge"),
    ("0x245158", "Java_com_quattroplay_GraalClassic_Natives_onMobirooUser", "legacy Mobiroo user bridge"),
    ("0x2452a4", "Java_com_quattroplay_GraalClassic_Natives_onMobirooInAppItems", "legacy Mobiroo item bridge"),
    ("0x2453f0", "Java_com_quattroplay_GraalClassic_Natives_onMobirooPurchase", "legacy Mobiroo purchase bridge"),
    ("0x24553c", "Java_com_quattroplay_GraalClassic_Natives_onMobirooPurchaseUpdate", "legacy Mobiroo update bridge"),
    ("0x245688", "Java_com_quattroplay_GraalClassic_Natives_onAmazonHistoryDone", "legacy Amazon history completion"),
    ("0x245768", "Java_com_quattroplay_GraalClassic_Natives_onGooglePlayInitialized", "Google Play initialization callback"),
    ("0x2457d4", "Java_com_quattroplay_GraalClassic_Natives_onGooglePlayPurchase", "Google Play purchase callback"),
    ("0x245f54", "Java_com_quattroplay_GraalClassic_Natives_onInvokeEvent", "Java-to-script event bridge"),
]

DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_android_callback_review_20260830.json")


OBSERVATIONS = [
    {
        "address": "0x2440f4",
        "classification": "per-frame-state-machine",
        "confidence": "confirmed-static",
        "evidence": [
            "QPlayLoop throttles work using the native frame timer and returns early until the next frame interval.",
            "It injects queued Android mouse events, resets the graphics state, optionally rebuilds graphics after the reload flag, runs timers, and chooses the loading or game draw path.",
            "It exits the process when closeapplication is set, including the pause and update-replacement paths.",
        ],
        "interpretation": "The Java render callback is the native process heartbeat. A pause or graphics-context transition can stop network and drawing work without being a TLS failure.",
    },
    {
        "address": "0x244ac0",
        "classification": "pause-exit-policy",
        "confidence": "confirmed-static",
        "evidence": [
            "onAppPause sets closeapplication when no client exists or when loadingstate is at most two.",
            "Only a connected client beyond that loading-state threshold avoids the immediate close flag.",
            "QPlayLoop checks closeapplication and calls exit(0).",
        ],
        "interpretation": "The old application treats many early Android pauses as a request to terminate. A compatibility dialog, activity transition, or focus change during startup can therefore look like a silent offline launch.",
    },
    {
        "address": "0x244990",
        "classification": "background-script-dispatch",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback emits onAppEnterBackground to the active script universe.",
            "It then looks up the -Games object and calls prepareEnterBackground when present.",
        ],
        "interpretation": "Background entry is script-visible and can change game state through the -Games object. No direct socket or credential operation is performed by this native wrapper.",
    },
    {
        "address": "0x244a68",
        "classification": "foreground-script-dispatch",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback emits onAppLeaveBackground to the active script universe and returns without additional native state changes.",
        ],
        "interpretation": "Foreground entry depends on the script runtime receiving the event. It is not a native reconnect operation by itself.",
    },
    {
        "address": "0x243d00",
        "classification": "touch-event-marshalling",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback stores Java environment handles, converts the incoming action and pointer data, and forwards the event into the native input queue.",
            "The callback is separate from the later QPlayLoop call that consumes queued Android mouse events.",
        ],
        "interpretation": "Touch input is asynchronous. A visible but not-yet-running render loop can accept Java input callbacks without processing them immediately.",
    },
    {
        "address": "0x2443b8",
        "classification": "key-event-marshalling",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback records the Java environment and forwards key action, key code, and modifier information to native input handling.",
            "The returned native Boolean is used as the Java callback result.",
        ],
        "interpretation": "Key dispatch is a native input path rather than a network path. Its result can affect Android event propagation.",
    },
    {
        "address": "0x244768",
        "classification": "text-event-marshalling",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback reads a Java string, converts it to a native TString, and invokes the native text-entered path.",
            "The native call is made only after the Java-to-native string conversion succeeds in the reviewed wrapper.",
        ],
        "interpretation": "The text bridge is a data boundary from the Android UI into scripts and the game input system. It is separate from the keyboard-close scheduling documented in the media and input review.",
    },
    {
        "address": "0x2444e8",
        "classification": "script-event-registration",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback converts the Java event name and dispatch metadata into native strings and invokes the environment registration path.",
            "The resulting registration is stored in the native script environment rather than sent directly to the network.",
        ],
        "interpretation": "Java can register native script events through this bridge. The security impact depends on the caller and the event table, so this pass does not treat registration alone as code execution.",
    },
    {
        "address": "0x244624",
        "classification": "script-function-registration",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback converts Java names and callback metadata and adds a script function to the native environment.",
            "The operation is a bridge setup action and does not itself perform a file, socket, or process operation.",
        ],
        "interpretation": "This callback expands the script-visible method table. Its caller and registration policy should be kept aligned with the signed-script activation boundary.",
    },
    {
        "address": "0x245f54",
        "classification": "native-script-event-invocation",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback accepts a Java event name and argument string, converts them to native strings, and invokes the corresponding native script event.",
            "The wrapper stores Java environment handles before dispatching the event.",
        ],
        "interpretation": "This is a general Java-to-script dispatch boundary. It should not be exposed to untrusted Java callers without an event allowlist, although no such alternate caller was tested here.",
    },
    {
        "address": "0x245768",
        "classification": "billing-status-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback forwards the Java-side Google Play initialization result into the native script event path.",
            "The focused billing review documents the asynchronous setup behavior and the later purchase callback separately.",
        ],
        "interpretation": "This callback reports billing state; it does not authorize a purchase by itself.",
    },
    {
        "address": "0x2457d4",
        "classification": "purchase-result-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback marshals the Java purchase status and strings into the native event system.",
            "The focused billing review found that the Java activity can pass raw purchase JSON and signature fields even when local verification fails.",
        ],
        "interpretation": "The native wrapper is a transport into scripts, not a second verifier. The purchase trust decision must therefore happen before a script consumes the event.",
    },
    {
        "address": "0x244af8",
        "classification": "legacy-partner-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback marshals Amazon user fields into the native event system.",
            "The partner review found that the stock Java methods for this legacy path are no-ops or inactive compatibility stubs.",
        ],
        "interpretation": "The native entry point remains translated for completeness, but the stock APK does not show a working Amazon service path.",
    },
    {
        "address": "0x244c44",
        "classification": "legacy-partner-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback marshals Amazon purchase fields and invokes the native event path.",
            "The Java-side legacy partner methods are inactive in the reviewed APK.",
        ],
        "interpretation": "This is a compatibility callback with no demonstrated active purchase backend in the stock client.",
    },
    {
        "address": "0x244f08",
        "classification": "legacy-partner-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback marshals Amazon history data into the native event path.",
            "The adjacent history-complete callback reports the end of that legacy sequence.",
        ],
        "interpretation": "The native history surface is present for compatibility. No active Amazon history request was launched during this review.",
    },
    {
        "address": "0x245158",
        "classification": "legacy-partner-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback marshals Mobiroo user fields into the native event system.",
            "The partner review found no active Mobiroo operation in the stock Java helper path.",
        ],
        "interpretation": "This is an inactive legacy compatibility surface in the reviewed APK.",
    },
    {
        "address": "0x2452a4",
        "classification": "legacy-partner-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback marshals Mobiroo in-app item data into native script events.",
            "No working Mobiroo Java service operation was found in the focused partner pass.",
        ],
        "interpretation": "The entry point is retained for ABI completeness but is not evidence of an active store integration.",
    },
    {
        "address": "0x2453f0",
        "classification": "legacy-partner-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback marshals Mobiroo purchase fields into native script events.",
            "The corresponding Java operation is an inactive compatibility path in the reviewed APK.",
        ],
        "interpretation": "No active Mobiroo purchase flow was established.",
    },
    {
        "address": "0x24553c",
        "classification": "legacy-partner-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback marshals a Mobiroo purchase update into native script events.",
            "The Java-side partner methods are inactive in the reviewed APK.",
        ],
        "interpretation": "This is an inactive legacy callback rather than a current purchase or network boundary.",
    },
    {
        "address": "0x245688",
        "classification": "legacy-partner-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The callback reports Amazon history completion to the native event system.",
            "The partner review found no active Amazon history backend in the stock Java bridge.",
        ],
        "interpretation": "The callback is preserved for compatibility and does not prove that an Amazon request can be started.",
    },
]


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


def main() -> dict:
    database_path = str(idaapi.get_path(idaapi.PATH_TYPE_IDB))
    input_path = str(idaapi.get_input_file_path())
    functions = []
    for address_text, expected_name, role in TARGETS:
        functions.append(export_function(int(address_text, 16), expected_name, role))
    output = {
        "artifact": "original_android_callback_review_20260830",
        "database": {
            "path": input_path,
            "idb_path": database_path,
            "imagebase": "0x%x" % idaapi.get_imagebase(),
        },
        "functions": functions,
        "observations": OBSERVATIONS,
        "interpretation": [
            "This pass covers the remaining exported Android JNI callbacks that were not included in the lifecycle, device/media, billing, and partner focused exports.",
            "Callback presence establishes an ABI and dispatch capability, not an active Java service or live network transaction.",
            "The artifact contains no account data, purchase receipt, token, or live response.",
        ],
        "network_contacted": False,
        "schema": "libqplay.original-android-callback-review.v1",
        "scope": "read-only Hex-Rays export of remaining Android JNI callbacks in the original 1.8 ARM64 IDB",
    }
    output_path = Path(os.environ.get("IDA_ANDROID_CALLBACK_REVIEW_OUT", DEFAULT_OUTPUT))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"callbacks": len(functions), "observations": len(OBSERVATIONS), "output": str(output_path)}))
    return output


main()
