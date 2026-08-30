#!/usr/bin/env python3
"""Export the original Android renderer and native lifecycle bridge.

The exporter is read-only. It records the JNI entry points used by the Java
GL renderer, plus the static Java-side facts that control whether those entry
points are reached. It does not install an APK, contact a service, or change
the IDA database.
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
    ("0x243858", "Java_com_quattroplay_GraalClassic_Natives_QPlayMain", "native initialization"),
    ("0x2440f4", "Java_com_quattroplay_GraalClassic_Natives_QPlayLoop", "per-frame native loop"),
    ("0x243c9c", "Java_com_quattroplay_GraalClassic_Natives_onSizeChanged", "surface size bridge"),
    ("0x244990", "Java_com_quattroplay_GraalClassic_Natives_onAppEnterBackground", "background transition"),
    ("0x244a68", "Java_com_quattroplay_GraalClassic_Natives_onAppLeaveBackground", "foreground transition"),
    ("0x244ac0", "Java_com_quattroplay_GraalClassic_Natives_onAppPause", "pause bridge"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_android_lifecycle_review_20260830.json"
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
        "method": "onCreate(Bundle)",
        "source_line": 222,
        "classification": "native-listener-registration",
        "confidence": "confirmed-static",
        "evidence": [
            "The activity stores its ApplicationInfo sourceDir and dataDir, registers itself as the native event listener, and stores itself through SetGLThreadActivity.",
            "The activity sets the content view and requests runtime permissions before the renderer is created by onStart.",
        ],
        "interpretation": "The activity is only the listener and lifecycle owner at creation time. Native initialization is deferred to the GL renderer thread.",
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "onStart()",
        "source_line": 428,
        "classification": "renderer-thread-start",
        "confidence": "confirmed-static",
        "evidence": [
            "onStart calls createGLView, which constructs QPlayRenderer and starts GLThread.",
            "The same method queues the initial onAppLeaveBackground callback, but the callback waits behind the GLThread state gate.",
        ],
        "interpretation": "A successful Activity onCreate is not proof that libqplay has loaded. The first native call occurs only after the GL surface and focus are usable.",
    },
    {
        "class": "com.quattroplay.GraalClassic.GLThread",
        "method": "needToWait()",
        "source_line": 211,
        "classification": "renderer-startup-gate",
        "confidence": "confirmed-static",
        "evidence": [
            "The render loop waits while paused, unfocused, without a surface, after context loss, or after the thread is marked done.",
            "While waiting, guardedRun sleeps for 100 milliseconds and does not call Renderer.drawFrame.",
            "onWindowFocusChanged(true) and surfaceCreated clear the relevant blockers, while onResume clears the pause flag.",
        ],
        "interpretation": "A system compatibility dialog, permission dialog, or another focus holder can make the visible symptom look like a network failure because QPlayRenderer has not reached QPlayMain yet.",
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "PermissionsAllGranted()",
        "source_line": 268,
        "classification": "native-load-permission-gate",
        "confidence": "confirmed-static",
        "evidence": [
            "PermissionsAllGranted sets Natives.downloaded to true.",
            "QPlayRenderer.loadLibrary returns immediately while Natives.downloaded is false.",
            "On Android API 23 and later, AskPermissions examines the permissions declared by the installed package and calls PermissionsAllGranted only when its checks pass.",
        ],
        "interpretation": "The field named downloaded is also the Java-side gate for loading the native library. A permission state that never reaches PermissionsAllGranted suppresses all connector traffic.",
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayRenderer",
        "method": "loadLibrary()",
        "source_line": 121,
        "classification": "native-load-and-argument-marshalling",
        "confidence": "confirmed-static",
        "evidence": [
            "The renderer calls System.loadLibrary(\"qplay\") only after the downloaded gate passes and only when Natives.loaded is false.",
            "It obtains the first external-files directory when available and passes it as the fourth string argument to QPlayMain.",
            "It passes the application sourceDir, application dataDir, display dimensions, display metrics, locale language, and the complete intent URI to QPlayMain.",
            "The Java method sets Natives.loaded to true after QPlayMain returns and does not inspect the native return value.",
        ],
        "interpretation": "Native initialization runs on the GL thread with an Android GL context. The native loaded flag is a Java bookkeeping value, not a checked QPlayMain result.",
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayRenderer",
        "method": "runLibrary(GL10)",
        "source_line": 114,
        "classification": "per-frame-bridge",
        "confidence": "confirmed-static",
        "evidence": [
            "Each renderer frame calls loadLibrary first, then QPlayLoop when Natives.loaded is true.",
            "The boolean returned by QPlayLoop controls whether GLThread swaps the EGL surface for that frame.",
        ],
        "interpretation": "The connector is driven by the render loop. If QPlayLoop is not reached, no native timers or network scheduler work can advance.",
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "onPause() and onStop()",
        "source_line": 368,
        "classification": "early-pause-shutdown",
        "confidence": "confirmed-static",
        "evidence": [
            "onPause queues Natives.onAppPause on the GL thread after setting mPaused.",
            "onStop queues Natives.onAppEnterBackground and then marks the GL thread for exit through requestExitAndWait.",
            "The native onAppPause bridge sets closeapplication when no client exists or loadingstate is at most 2.",
        ],
        "interpretation": "A pause during early startup is not treated as a harmless suspend. The next native frame can call exit(0), which can make a dialog or background transition appear to close the client.",
    },
]


FINDINGS = [
    {
        "id": "ANDROID-001",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Focus and permission gates can suppress native startup before TLS is attempted",
        "evidence": [
            "GLThread requires an active surface, window focus, and a non-paused Activity before it calls QPlayRenderer.drawFrame.",
            "QPlayRenderer does not call System.loadLibrary or QPlayMain until Natives.downloaded is true.",
            "Natives.downloaded is set only by PermissionsAllGranted in the reviewed Java code.",
        ],
        "impact": "A client that displays a title or static layout while a compatibility or permission dialog is present may not have executed any connector code. The first diagnostic should verify focus, surface creation, permission completion, and Natives.loaded before changing certificate or HTTP code.",
        "limits": "The exact grant behavior of WRITE_EXTERNAL_STORAGE with its old max SDK declaration varies by Android release and was not asserted from this static pass. The local replay did load the native library after the compatibility dialog was dismissed.",
    },
    {
        "id": "ANDROID-002",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Early Activity pause can schedule process exit",
        "evidence": [
            "Java queues onAppPause on the GL thread during Activity.onPause.",
            "The native bridge sets closeapplication when the client is absent or loadingstate is at most 2.",
            "QPlayLoop calls exit(0) when closeapplication is set.",
        ],
        "impact": "A startup interruption can terminate the client rather than preserving a resumable loading state. This complicates testing with system dialogs and can be mistaken for a failed network connection.",
        "limits": "The static path does not show which Android dialogs generate onPause on every supported release. No production device behavior was changed.",
    },
    {
        "id": "ANDROID-003",
        "severity": "low",
        "confidence": "confirmed-static",
        "title": "The Java bridge marks native initialization successful without checking its return code",
        "evidence": [
            "QPlayRenderer ignores the integer returned by QPlayMain.",
            "It sets Natives.loaded to true immediately after the call.",
            "QPlayMain calls the engine loader without using its return value in the reviewed wrapper and then returns 1 on its normal path.",
        ],
        "impact": "A partial engine initialization can be reported to Java as loaded, leaving QPlayLoop and later callbacks to operate on incomplete state. A repair build should propagate an initialization result and log the failed stage.",
        "limits": "The normal QPlayMain path returns 1 in the reviewed native function. This is a robustness and observability issue, not proof of a stock initialization failure.",
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
        "schema": "libqplay.original-android-lifecycle-review.v1",
        "artifact": "original_android_lifecycle_review_20260830",
        "scope": "read-only review of the original 1.8 Android Java renderer bridge and ARM64 JNI lifecycle functions",
        "network_contacted": False,
        "apk_executed_by_exporter": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8",
        },
        "java_bridge": {
            "renderer": "com.quattroplay.GraalClassic.QPlayRenderer",
            "thread": "com.quattroplay.GraalClassic.GLThread",
            "native_class": "com.quattroplay.GraalClassic.Natives",
            "entrypoint_order": [
                "Activity.onCreate",
                "Activity.onStart",
                "GLView.setRenderer",
                "GLThread.needToWait gate",
                "QPlayRenderer.loadLibrary",
                "Natives.QPlayMain",
                "Natives.QPlayLoop on later frames",
            ],
        },
        "java_observations": JAVA_OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "The native connector is downstream of Android permission completion, surface creation, window focus, and the GL render loop.",
            "A useful device trace should log those gates and Natives.loaded before diagnosing the native TLS trust bundle.",
            "The local replay showed that the native path becomes active after the compatibility warning is dismissed, so this report narrows the startup diagnosis without replacing the independent stale-certificate finding.",
        ],
    }
    output = os.environ.get("IDA_ANDROID_LIFECYCLE_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
