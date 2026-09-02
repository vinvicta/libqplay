#!/usr/bin/env python3
"""Export the original 1.8 legacy partner bridge review.

The exporter is read-only. It records the Android script-table callbacks for
TapJoy, Distimo, Fabzat, and TrialPay, together with the private DEX evidence
that disables most of those paths. It does not open a partner UI, bind to a
third-party service, or contact a network endpoint.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import ida_funcs
import ida_hexrays
import idaapi
import idautils
import idc


TARGETS = [
    ("0x245f40", "main_android_initStaticScriptVars_void", "Android script table owner"),
    ("0x2401e0", "nullsub_8", "Fabzat logo callback stub"),
    ("0x2401e4", "nullsub_9", "Fabzat share URL callback stub"),
    ("0x2401e8", "nullsub_10", "Fabzat title-font callback stub"),
    ("0x2401ec", "nullsub_11", "Fabzat button-font callback stub"),
    ("0x2401f0", "nullsub_12", "Fabzat texture callback stub"),
    ("0x2401f4", "MainAndroid_script_settapjoysecret", "TapJoy secret setter"),
    ("0x240204", "MainAndroid_script_settapjoyapplicationid", "TapJoy application-ID setter"),
    ("0x2406ec", "JNI_isTrialpaySupported", "TrialPay support probe"),
    ("0x240774", "JNI_isFabzatSupported", "Fabzat support probe"),
    ("0x240994", "JNI_isTapJoyEnabled", "TapJoy support probe"),
    ("0x2410ac", "JNI_connectToTapJoyService", "TapJoy connection bridge"),
    ("0x2414cc", "JNI_showFabzatStore", "Fabzat store bridge"),
    ("0x241540", "JNI_setDistimoRegisteredUser", "Distimo registration bridge"),
    ("0x2417f0", "JNI_showTrialpayOfferwall", "TrialPay offerwall bridge"),
    ("0x24190c", "JNI_setTrialpayAgeAndGender", "TrialPay demographic bridge"),
    ("0x241a38", "JNI_setTrialpayCampaign", "TrialPay campaign bridge"),
    ("0x241c00", "JNI_initTrialpay", "TrialPay initialization bridge"),
    ("0x241d1c", "JNI_fabzatSetResourcePath", "Fabzat resource-path bridge"),
    ("0x241e38", "JNI_initFabzatStore", "Fabzat initialization bridge"),
    ("0x242000", "JNI_registerPurchaseToDistimo", "Distimo purchase bridge"),
    ("0x2421c8", "JNI_connectToDistimoService", "Distimo connection bridge"),
    ("0x242ce0", "JNI_showTapJoyOffers", "TapJoy offers bridge"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_partner_bridge_review_20260830.json"
)


# The Distimo fallback contains a fixed mixed-case alphanumeric literal. Keep
# that value out of the public artifact while preserving the surrounding JNI
# evidence. Ordinary Java method names do not match because this pattern
# requires a digit as well as mixed case.
SENSITIVE_LITERAL_RE = re.compile(
    r'"(?=[A-Za-z0-9]{16,}")'
    r'(?=[A-Za-z0-9]*[0-9])'
    r'(?=[A-Za-z0-9]*[A-Z])'
    r'(?=[A-Za-z0-9]*[a-z])'
    r'[A-Za-z0-9]{16,}"'
)


def redact_pseudocode(code: str) -> str:
    return SENSITIVE_LITERAL_RE.sub('"<redacted fixed literal>"', code)


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
    raw_code = str(decompiled)
    code = redact_pseudocode(raw_code)
    function = ida_funcs.get_func(address)
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": "0x%x" % function.start_ea if function else None,
        "function_end": "0x%x" % function.end_ea if function else None,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "code_redacted_literals": raw_code != code,
        "callers": effective_callers(address),
        "code": code,
    }


SCRIPT_SURFACE = {
    "owner": "main_android_initStaticScriptVars_void",
    "table_va": "0x38b2d0",
    "registered_function_count": 44,
    "source": "IDA script_table_inventory.json plus active IDA database",
    "entries": [
        {
            "script_name": "istapjoyenabled",
            "callback_va": "0x240994",
            "native_signature": "isTapJoyEnabled()Z",
        },
        {
            "script_name": "settapjoyapplicationid",
            "callback_va": "0x240204",
            "native_signature": "TString -> native global",
        },
        {
            "script_name": "settapjoysecret",
            "callback_va": "0x2401f4",
            "native_signature": "TString -> native global",
        },
        {
            "script_name": "connecttotapjoyservice",
            "callback_va": "0x2410ac",
            "native_signature": "connectToTapJoyService([B[B)Z",
        },
        {
            "script_name": "showtapjoyoffers",
            "callback_va": "0x242ce0",
            "native_signature": "showTapJoyOffers([B)V",
        },
        {
            "script_name": "connecttodistimoservice",
            "callback_va": "0x2421c8",
            "native_signature": "connectToDistimoService([B)V",
        },
        {
            "script_name": "setdistimoregistereduser",
            "callback_va": "0x241540",
            "native_signature": "setDistimoRegisteredUser()V",
        },
        {
            "script_name": "registerpurchasetodistimo",
            "callback_va": "0x242000",
            "native_signature": "registerPurchaseToDistimo([B[B)V",
        },
        {
            "script_name": "isfabzatsupported",
            "callback_va": "0x240774",
            "native_signature": "isFabzatSupported()Z",
        },
        {
            "script_name": "initfabzatstore",
            "callback_va": "0x241e38",
            "native_signature": "initFabzatStore([B[B)V",
        },
        {
            "script_name": "fabzatsetresourcepath",
            "callback_va": "0x241d1c",
            "native_signature": "fabzatSetResourcePath([B)V",
        },
        {
            "script_name": "showfabzatstore",
            "callback_va": "0x2414cc",
            "native_signature": "showFabzatStore()V",
        },
        {
            "script_name": "fabzatsetlogo",
            "callback_va": "0x2401e0",
            "native_signature": "native nullsub",
        },
        {
            "script_name": "fabzatsetshareurl",
            "callback_va": "0x2401e4",
            "native_signature": "native nullsub",
        },
        {
            "script_name": "fabzatsettitlefont",
            "callback_va": "0x2401e8",
            "native_signature": "native nullsub",
        },
        {
            "script_name": "fabzatsetbuttonsfont",
            "callback_va": "0x2401ec",
            "native_signature": "native nullsub",
        },
        {
            "script_name": "fabzatreplacetexture",
            "callback_va": "0x2401f0",
            "native_signature": "native nullsub",
        },
        {
            "script_name": "istrialpaysupported",
            "callback_va": "0x2406ec",
            "native_signature": "isTrialpaySupported()Z",
        },
        {
            "script_name": "inittrialpay",
            "callback_va": "0x241c00",
            "native_signature": "initTrialpay([B)V",
        },
        {
            "script_name": "settrialpaycampaign",
            "callback_va": "0x241a38",
            "native_signature": "setTrialpayCampaign([B[B)V",
        },
        {
            "script_name": "settrialpayageandgender",
            "callback_va": "0x24190c",
            "native_signature": "setTrialpayAgeAndGender(I[B)V",
        },
        {
            "script_name": "showtrialpayofferwall",
            "callback_va": "0x2417f0",
            "native_signature": "showTrialpayOfferwall([B)V",
        },
    ],
}


JAVA_NOOP_METHODS = [
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "connectToDistimoService([B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "connectToTapJoyService([B[B)Z",
        "behavior": "returns false",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "fabzatSetResourcePath([B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "initFabzatStore([B[B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "initTrialpay([B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "isFabzatSupported()Z",
        "behavior": "returns false",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "isTapJoyEnabled()Z",
        "behavior": "returns false",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "isTrialpaySupported()Z",
        "behavior": "returns false",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "registerPurchaseToDistimo([B[B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "setDistimoRegisteredUser()V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "setTrialpayAgeAndGender(I[B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "setTrialpayCampaign([B[B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "showFabzatStore()V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "showTapJoyOffers([B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "showTrialpayOfferwall([B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "buyAmazonInAppPurchase([B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "buyMobirooInAppPurchase([B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "requestAmazonPurchaseHistory([B)V",
        "behavior": "returns immediately",
    },
    {
        "class": "com.quattroplay.GraalClassic.Natives",
        "method": "requestMobirooInAppData([B)V",
        "behavior": "returns immediately",
    },
]


OBSERVATIONS = [
    {
        "classification": "partner integration disabled at Java boundary",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "Natives.isTapJoyEnabled(), isTrialpaySupported(), and isFabzatSupported() return false without consulting an SDK.",
            "Natives.connectToTapJoyService() returns false, while the corresponding Distimo, Fabzat, and TrialPay operations return immediately.",
            "The native JNI wrappers call these Natives methods by their exact names and signatures.",
        ],
        "interpretation": "The partner callback table is present for compatibility, but the stock APK does not implement an active TapJoy, TrialPay, Fabzat, or Distimo flow through these entries.",
    },
    {
        "classification": "TapJoy configuration retained in native memory",
        "confidence": "confirmed-static-plus-ida",
        "evidence": [
            "settapjoysecret at 0x2401f4 assigns its TString argument to qword_391210.",
            "settapjoyapplicationid at 0x240204 assigns its TString argument to qword_391218.",
            "connectToTapJoyService reads both globals before calling the Java method that returns false.",
        ],
        "interpretation": "A script can place arbitrary TapJoy configuration text in process memory, but this APK does not pass it to a functioning Java TapJoy service. The values are still sensitive if a future patch activates the bridge.",
    },
    {
        "classification": "Fabzat callback stubs",
        "confidence": "confirmed-static-plus-inventory",
        "evidence": [
            "Five script-table entries at 0x2401e0 through 0x2401f0 point to four-byte native nullsubs.",
            "The table inventory identifies these callbacks as the Fabzat logo, share URL, font, and texture setters.",
        ],
        "interpretation": "Those callbacks have no side effects in this library and cannot configure a live Fabzat UI.",
    },
    {
        "classification": "unused legacy Java classes",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The DEX contains OnePF/OpenIAB and several vendor billing classes.",
            "The active com.quattroplay.GraalClassic.Natives partner methods are no-ops and no Java native declarations for the Amazon or Mobiroo reverse callbacks were found in that class.",
        ],
        "interpretation": "Bundled legacy classes should not be treated as proof that their stores are active in the reviewed APK. Their presence increases maintenance and attack-surface complexity but does not establish a reachable service flow.",
    },
]


FINDINGS = [
    {
        "id": "ANDROID-PARTNER-001",
        "severity": "low",
        "confidence": "confirmed-static-plus-dex",
        "title": "The partner feature table is present but disabled by Java no-op stubs",
        "evidence": [
            "TapJoy, TrialPay, and Fabzat support probes return false.",
            "Distimo, Fabzat, TrialPay, and TapJoy operation methods in Natives return without performing work, except the TapJoy connection method which returns false.",
            "The native wrappers call those exact Natives methods rather than an independent partner SDK entrypoint.",
        ],
        "impact": "Scripts or game code that expect these providers can silently do nothing. This is a compatibility and feature-availability finding, not an evidence of a remote vulnerability.",
        "limits": "Other code or an external repackaging could add a provider implementation. The review is limited to this APK's original DEX and ARM64 library.",
    },
    {
        "id": "ANDROID-PARTNER-002",
        "severity": "low",
        "confidence": "confirmed-static-plus-ida",
        "title": "TapJoy configuration text is stored without a visible bound",
        "evidence": [
            "The script callbacks at 0x2401f4 and 0x240204 assign incoming TStrings to native globals.",
            "The setter functions do not validate or cap the input in their visible bodies.",
            "The only reviewed consumer is a TapJoy bridge that eventually calls a Java method returning false in this APK.",
        ],
        "impact": "An activated script can cause native allocation and retention of arbitrary configuration text, creating a small process-memory and availability surface. The stored values are not shown leaving the process in the stock package.",
        "limits": "The allocator behavior and remote reachability were not fuzzed. This is not a confirmed overflow or credential exfiltration path.",
    },
    {
        "id": "ANDROID-PARTNER-003",
        "severity": "informational",
        "confidence": "confirmed-static-plus-inventory",
        "title": "Bundled vendor billing classes are not proof of an active Amazon or Mobiroo path",
        "evidence": [
            "Amazon and Mobiroo helper methods in Natives return immediately.",
            "The active 44-entry Android script table contains no Amazon or Mobiroo entries.",
            "The native Amazon and Mobiroo callback symbols are not referenced by the script callback inventory.",
        ],
        "impact": "This prevents a false lead during compatibility work. Re-enabling those old libraries would require a separate, explicit integration review.",
        "limits": "A Java caller outside the reviewed class could theoretically use a bundled helper directly. No such caller was found in the scoped package review.",
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
        "schema": "libqplay.original-partner-bridge-review.v1",
        "artifact": "original_partner_bridge_review_20260830",
        "scope": "read-only review of the original 1.8 TapJoy, Distimo, Fabzat, TrialPay, Amazon, and Mobiroo compatibility bridges",
        "network_contacted": False,
        "partner_ui_opened": False,
        "partner_service_bound": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "script_surface": SCRIPT_SURFACE,
        "java_noop_methods": JAVA_NOOP_METHODS,
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "The partner callbacks are compatibility remnants in the reviewed package, not an explanation for the native connector failing to reach its server.",
            "Fabzat's expired certificate resource should not be treated as an active trust anchor based on this pass, because the matching script and Java paths are stubs here.",
            "A repair should remove or clearly gate dead provider entries, bound configuration strings, and avoid reactivating vendor SDKs without an explicit privacy and trust review.",
        ],
    }
    output = os.environ.get("IDA_PARTNER_BRIDGE_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
