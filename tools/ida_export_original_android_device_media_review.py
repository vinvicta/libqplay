#!/usr/bin/env python3
"""Export the original 1.8 Android device, display, input, and media review.

The exporter is read-only. It records the native callbacks that expose Android
build information, display metrics, virtual-keyboard state, and the legacy
video path. Java behavior is summarized from the private DEX review. It does
not execute scripts, open media, or contact a service.
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
    ("0x2404a4", "JNI_getAndroidDeviceModel", "Android manufacturer and model bridge"),
    ("0x2405c8", "JNI_getAndroidOSVersion", "Android release-version bridge"),
    ("0x241444", "JNI_closeVirtualKeyboard", "virtual-keyboard close bridge"),
    ("0x242df0", "JNI_setVideoPlayerRectangle", "video rectangle bridge"),
    ("0x242f0c", "openVirtualKeyboard_TString_const_TString_const", "virtual-keyboard open bridge"),
    ("0x2430d4", "closeVirtualKeyboard_void", "native virtual-keyboard close helper"),
    ("0x243274", "openVideoPlayer_TString_const_TString_const", "video open bridge"),
    ("0x24342c", "stopVideoPlayer_void", "video stop bridge"),
    ("0x2440f4", "Java_com_quattroplay_GraalClassic_Natives_QPlayLoop", "Android render loop"),
    ("0x245a18", "Java_com_quattroplay_GraalClassic_Natives_onUpdateVideoPlayerRectangle", "video rectangle native callback"),
    ("0x246628", "MainAndroid_script_androidgetdisplayattributes", "display attributes script callback"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_android_device_media_review_20260830.json"
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


SCRIPT_SURFACE = {
    "owner": "main_android_initStaticScriptVars_void",
    "table_va": "0x38b2d0",
    "registered_function_count": 44,
    "entries": [
        {
            "index": 1,
            "script_name": "getandroidosversion",
            "callback_va": "0x2405c8",
            "native_signature": "getAndroidOSVersion()[B",
        },
        {
            "index": 2,
            "script_name": "getandroiddevicemodel",
            "callback_va": "0x2404a4",
            "native_signature": "getAndroidDeviceModel()[B",
        },
        {
            "index": 4,
            "script_name": "setvideoplayerrectangle",
            "callback_va": "0x242df0",
            "native_signature": "setVideoPlayerRectangle(IIII)V",
        },
        {
            "index": 43,
            "script_name": "forceclosevirtualkeyboard",
            "callback_va": "0x241444",
            "native_signature": "closeVirtualKeyboard(I)V",
        },
    ],
}


JAVA_OBSERVATIONS = [
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "getAndroidOSVersion()",
        "source": "original DEX smali",
        "behavior": [
            "Reads android.os.Build.VERSION.RELEASE.",
            "Returns String.getBytes() using the platform default charset.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "getAndroidDeviceModel()",
        "source": "original DEX smali",
        "behavior": [
            "Concatenates android.os.Build.MANUFACTURER, one space, and android.os.Build.MODEL.",
            "Returns String.getBytes() using the platform default charset.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "openVideoPlayer(String)",
        "source": "original DEX smali",
        "behavior": [
            "Returns immediately without creating or starting a player.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "stopVideoPlayer()",
        "source": "original DEX smali",
        "behavior": [
            "Returns immediately without changing Java-side media state.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "setVideoPlayerRectangle(IIII)",
        "source": "original DEX class method inventory",
        "behavior": [
            "No matching static method declaration was found in Natives.smali.",
            "The native lookup can therefore return no method ID in the reviewed APK.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "closeVirtualKeyboard(boolean)",
        "source": "original DEX smali",
        "behavior": [
            "Returns if the EditText is not visible.",
            "When visible, snapshots the text, schedules a GL-thread onTextEntered(true, text) callback only when the argument is true and Natives.loaded is true, then posts an UI-thread task that hides the input method and makes the EditText gone.",
        ],
    },
]


OBSERVATIONS = [
    {
        "address": "0x2404a4",
        "classification": "device-model-disclosure",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "JNI_getAndroidDeviceModel resolves getAndroidDeviceModel()[B and copies a returned byte array into a native TString.",
            "The Java method joins Build.MANUFACTURER and Build.MODEL.",
            "The native copy accepts lengths from 1 through 1024 bytes and releases the Java array afterward.",
        ],
        "interpretation": "An activated script can learn the device manufacturer and model without a special permission in this path. The callback itself does not transmit the value.",
    },
    {
        "address": "0x2405c8",
        "classification": "os-version-disclosure",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "JNI_getAndroidOSVersion resolves getAndroidOSVersion()[B and uses the same bounded byte-array copy.",
            "The Java method returns Build.VERSION.RELEASE.",
        ],
        "interpretation": "An activated script can learn the user-visible Android release string. This is ordinary environment information, but it can contribute to device fingerprinting when combined with other callbacks.",
    },
    {
        "address": "0x246628",
        "classification": "display-metric serialization",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "QPlayMain stores densityDpi, xdpi, ydpi, and scaledDensity in native globals.",
            "MainAndroid_script_androidgetdisplayattributes formats those four values as a comma-separated TStringList result.",
            "The native names android_density_dpi, android_xdpi, android_ydpi, and android_scaled_density now describe the active IDA data items.",
        ],
        "interpretation": "The callback supplies rendering and layout metrics to scripts. It is a compatibility surface rather than a network or credential path.",
    },
    {
        "address": "0x242df0",
        "classification": "video-rectangle-state",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "JNI_setVideoPlayerRectangle stores four caller-supplied integers in video_rectangle_x, video_rectangle_y, video_rectangle_width, and video_rectangle_height.",
            "It attempts to resolve setVideoPlayerRectangle(IIII)V on the Java class saved by QPlayMain.",
            "The reviewed Natives class has no matching static declaration, so the lookup has no visible Java implementation to reach.",
        ],
        "interpretation": "The native library retains video placement state, but the stock Java bridge does not provide the corresponding setter.",
    },
    {
        "address": "0x2440f4",
        "classification": "video-render-gate",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "QPlayLoop draws a quad only when isVideoPlayerOpen() is true and the cached width and height are positive.",
            "The quad uses the four cached rectangle values after normal game drawing and graphics-state setup.",
            "QPlayActivity.openVideoPlayer and stopVideoPlayer are Java no-ops in the reviewed DEX, so the normal Android listener path does not establish a player.",
        ],
        "interpretation": "The old video path is present in native code but is disabled or incomplete at the Android boundary in this APK. It is not a plausible explanation for connector failure.",
    },
    {
        "address": "0x241444",
        "classification": "keyboard-close-dispatch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "JNI_closeVirtualKeyboard calls the Java closeVirtualKeyboard(I)V method only when a native virtual keyboard control has been registered.",
            "Natives.closeVirtualKeyboard forwards the integer as a boolean to the EventListener.",
            "QPlayActivity.closeVirtualKeyboard snapshots visible text, conditionally sends onTextEntered, then hides the IME and the EditText on the UI thread.",
        ],
        "interpretation": "Keyboard closure is an asynchronous UI and input callback. A startup test that interrupts this sequence can miss text delivery without indicating a network failure.",
    },
]


FINDINGS = [
    {
        "id": "ANDROID-DEVICE-001",
        "severity": "low",
        "confidence": "confirmed-static-plus-dex",
        "title": "Scripts can read Android build identity and release information",
        "evidence": [
            "The Android script table exposes getandroiddevicemodel and getandroidosversion.",
            "The Java implementations read Build.MANUFACTURER, Build.MODEL, and Build.VERSION.RELEASE.",
            "The existing script HTTP and Facebook bridges can provide separate egress or authenticated data paths, although this review did not join them at runtime.",
        ],
        "impact": "A trusted or compromised script can fingerprint the broad device environment. The individual values are not unique identifiers and the callbacks do not themselves contact a server.",
        "limits": "No script was executed and no device model or release was sent to a live service during this pass.",
    },
    {
        "id": "ANDROID-MEDIA-001",
        "severity": "informational",
        "confidence": "confirmed-static-plus-dex",
        "title": "The native video path is not backed by a working stock Java implementation",
        "evidence": [
            "The native path caches rectangle state and conditionally draws it in QPlayLoop.",
            "QPlayActivity.openVideoPlayer and stopVideoPlayer return immediately.",
            "Natives.smali has no static setVideoPlayerRectangle declaration, and the exported native update callback is not declared in the reviewed Natives class.",
        ],
        "impact": "Video features that depend on this bridge can silently do nothing or retain stale rectangle state. This is a compatibility defect, not evidence of a connector or TLS problem.",
        "limits": "The review did not load a media file or exercise a third-party video backend.",
    },
    {
        "id": "ANDROID-INPUT-001",
        "severity": "low",
        "confidence": "confirmed-static-plus-dex",
        "title": "Final virtual-keyboard text delivery depends on asynchronous lifecycle gates",
        "evidence": [
            "The Java closeVirtualKeyboard method returns when the EditText is hidden.",
            "The final text callback requires both the native boolean argument and Natives.loaded to be true.",
            "Text delivery is posted to the GL thread while keyboard hiding is posted to the UI thread.",
        ],
        "impact": "A script or login flow can observe missing final text if the renderer is not loaded or the widget is already hidden. This can look like an input or startup failure rather than a transport failure.",
        "limits": "No live UI interaction was performed during this static pass.",
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
        "schema": "libqplay.original-android-device-media-review.v1",
        "artifact": "original_android_device_media_review_20260830",
        "scope": "read-only review of original 1.8 Android build-info, display, input, and legacy video callbacks",
        "network_contacted": False,
        "scripts_executed": False,
        "media_opened": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "script_surface": SCRIPT_SURFACE,
        "java_observations": JAVA_OBSERVATIONS,
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "The device and display callbacks explain environment data supplied to scripts, not the connector transport failure.",
            "The native video state machine survives in the library, but the reviewed Android activity leaves its open and stop methods empty and does not declare the rectangle setter.",
            "A repair should disclose only the environment fields required by the protocol, keep final text delivery lifecycle-safe, and either remove the dead video bridge or implement it as an explicit feature.",
        ],
    }
    output = os.environ.get("IDA_ANDROID_DEVICE_MEDIA_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
