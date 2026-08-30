#!/usr/bin/env python3
"""Export the original 1.8 Google Play billing bridge review.

The exporter is read-only. It records the native functions that connect the
Android script table to the legacy Google Play billing helper, together with
behavior checked in the private DEX smali. It does not bind to a billing
service, launch a purchase flow, read a purchase, or contact Google Play.
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
    ("0x245f40", "main_android_initStaticScriptVars_void", "Android script table owner"),
    ("0xe9d30", "TGameEnvironment_script_getGooglePlay", "Google Play feature marker"),
    ("0x24090c", "JNI_initGooglePlay", "Google Play initialization bridge"),
    ("0x240eb8", "JNI_buyGooglePlayItem", "Google Play purchase bridge"),
    (
        "0x245768",
        "Java_com_quattroplay_GraalClassic_Natives_onGooglePlayInitialized",
        "Google Play setup callback",
    ),
    (
        "0x2457d4",
        "Java_com_quattroplay_GraalClassic_Natives_onGooglePlayPurchase",
        "Google Play purchase callback",
    ),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_billing_bridge_review_20260830.json"
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
    "source": "IDA script_table_inventory.json plus active IDA database",
    "relevant_entries": [
        {
            "script_name": "initgoogleplay",
            "callback_va": "0x24090c",
            "native_signature": "initGooglePlay()Z",
            "behavior": "Calls the activity's asynchronous legacy billing setup and returns its immediate Java Boolean.",
        },
        {
            "script_name": "buygoogleplayitem",
            "callback_va": "0x240eb8",
            "native_signature": "buyGooglePlayItem([B[B)Z",
            "behavior": "Passes script-supplied SKU and developer-payload text to the activity's in-app purchase flow.",
        },
    ],
}


JAVA_OBSERVATIONS = [
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "initGooglePlay()",
        "source": "original DEX smali",
        "behavior": [
            "Returns true immediately when a billing helper already exists.",
            "Constructs IabHelper with the embedded RSA public key, enables debug logging with the tag unixmad, and calls startSetup().",
            "Catches Exception around construction, logging, and setup invocation but still returns true.",
            "The setup callback later reports success or failure to native code and queries inventory after successful setup.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "buyGooglePlayItem(java.lang.String, java.lang.String)",
        "source": "original DEX smali",
        "behavior": [
            "Returns false when mBillingHelper is null.",
            "Passes the caller's SKU and developer payload to IabHelper.launchPurchaseFlow() as an inapp item with a fixed request code.",
            "Returns true after the asynchronous flow is launched, before the purchase result is known.",
            "Catches synchronous exceptions and returns false, while asynchronous failures arrive through the purchase callback.",
            "The reviewed activity method contains no product-ID allowlist.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.util.IabHelper",
        "method": "startSetup() and launchPurchaseFlow()",
        "source": "original DEX smali",
        "behavior": [
            "Binds the explicit com.android.vending billing service action and checks in-app billing version 3 support.",
            "Passes caller-supplied SKU and developer payload to the billing service getBuyIntent() call.",
            "The bindService Boolean result is not used to report an immediate failure.",
            "The purchase activity result is checked against the fixed request code before purchase data is parsed.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.util.Security",
        "method": "verifyPurchase(java.lang.String, java.lang.String, java.lang.String)",
        "source": "original DEX smali",
        "behavior": [
            "Rejects empty key, signed-data, or signature text.",
            "Decodes the embedded Base64 X.509 RSA public key and verifies the signed data with SHA1withRSA.",
            "Uses String.getBytes() without an explicit charset for the signed purchase JSON.",
            "IabHelper calls this verifier for both the immediate purchase result and inventory entries.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity$21",
        "method": "onIabPurchaseFinished(IabResult, Purchase)",
        "source": "original DEX smali",
        "behavior": [
            "Maps response code 7 to alreadyowned, any failure to failed, and a non-null successful purchase to success.",
            "Forwards the Purchase object to onGooglePlayPurchase() on all three paths when the listener provides one.",
            "Automatically consumes successful purchases whose SKU contains gralatspack, coinspack, or vippack, or starts with android.test.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "onGooglePlayPurchase(java.lang.String, Purchase)",
        "source": "original DEX smali",
        "behavior": [
            "Logs the result status and Purchase.toString() through stdout.",
            "Schedules a GL-thread callback carrying status, SKU, original purchase JSON, and signature.",
            "The native callback receives empty strings when the Purchase object is null.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity$20 and $22",
        "method": "inventory and consume callbacks",
        "source": "original DEX smali",
        "behavior": [
            "After successful setup, inventory entries are verified by IabHelper and then automatically consumed only for the same name-based SKU classes.",
            "Consumption reports consumesuccess or consumefailed through the same purchase event path.",
            "The inventory listener does not expose a separate native inventory event.",
        ],
    },
]


OBSERVATIONS = [
    {
        "address": "0x38b4e0",
        "classification": "script-visible billing setup",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The main_android script table maps initgoogleplay to JNI_initGooglePlay.",
            "The native wrapper calls QPlayActivity.initGooglePlay() and returns its immediate Java Boolean.",
            "The Java method starts legacy billing setup asynchronously and reports the eventual result through onGooglePlayInitialized.",
        ],
        "interpretation": "A true script return value means only that the helper setup call was accepted synchronously, not that a usable Play billing service is ready.",
    },
    {
        "address": "0x38b510",
        "classification": "script-controlled purchase launch",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The main_android script table maps buygoogleplayitem to JNI_buyGooglePlayItem.",
            "The JNI wrapper converts two native strings to Java byte arrays and calls buyGooglePlayItem([B[B)Z.",
            "The activity passes both values directly to IabHelper.launchPurchaseFlow(), which calls the billing service getBuyIntent() method.",
        ],
        "interpretation": "An activated script can request a store purchase for any SKU text it supplies. The store still controls product availability, account authorization, and the signed result.",
    },
    {
        "address": "0x2457d4",
        "classification": "purchase-data trust boundary",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "IabHelper verifies the purchase signature before reporting a successful result.",
            "When verification fails, IabHelper still calls the purchase listener with a constructed Purchase object and a failure result.",
            "QPlayActivity forwards the status, SKU, original JSON, and signature to the native onGooglePlayPurchase callback.",
            "The native callback invokes the script event onGooglePlayPurchase with four string arguments.",
        ],
        "interpretation": "Signature verification gates the success status, but it does not gate exposure of the purchase fields to native script code.",
    },
    {
        "address": "0x245768",
        "classification": "asynchronous setup result",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The Java setup listener schedules onGooglePlayInitialized on the GL thread.",
            "The native callback invokes the script event with the Boolean setup result.",
            "The result callback is the only reviewed path that distinguishes an available billing service from the optimistic initGooglePlay return value.",
        ],
        "interpretation": "Scripts need the later initialization event to know whether billing v3 was actually available on the device.",
    },
]


FINDINGS = [
    {
        "id": "ANDROID-IAB-001",
        "severity": "medium",
        "confidence": "confirmed-static-plus-dex",
        "title": "Activated scripts can launch purchases for caller-supplied SKUs",
        "evidence": [
            "buygoogleplayitem is registered in the Android script table.",
            "The activity passes the script-supplied SKU and developer payload directly to the legacy billing helper.",
            "No local product-ID allowlist appears in the reviewed activity method.",
        ],
        "impact": "A compromised or untrusted script can trigger arbitrary store purchase prompts and choose the developer-payload text sent with the request. This is a purchase-initiation capability, not a demonstrated way to obtain free goods: Google Play still decides whether the SKU exists and whether the account may buy it.",
        "limits": "The review did not launch a purchase, contact Google Play, or inspect server-side entitlement handling. The public artifact contains no developer payload, purchase JSON, order identifier, or signature.",
    },
    {
        "id": "ANDROID-IAB-002",
        "severity": "medium",
        "confidence": "confirmed-static-plus-dex",
        "title": "Purchase fields cross into script events even when verification fails",
        "evidence": [
            "IabHelper verifies signed purchase data with the embedded RSA public key.",
            "The verification-failure branch still passes its parsed Purchase object to the purchase listener with a failure result.",
            "QPlayActivity forwards status, SKU, original JSON, and signature to native code, and the native JNI callback emits them as onGooglePlayPurchase string arguments.",
        ],
        "impact": "Scripts can observe transaction metadata and signature material for failed as well as successful attempts. If a script checks only SKU or JSON and ignores the status argument, this boundary creates room for a client-side entitlement mistake. It also exposes more purchase data to script code than is needed to report a simple result.",
        "limits": "The static path does not show that the stock scripts grant an item on a failed status. Google Play signature verification remains in place for the success path, and no live purchase data was collected.",
    },
    {
        "id": "ANDROID-IAB-003",
        "severity": "low",
        "confidence": "confirmed-static-plus-dex",
        "title": "Billing initialization reports success before asynchronous setup completes",
        "evidence": [
            "initGooglePlay returns true after creating the helper and invoking startSetup(), even though setup is asynchronous.",
            "The outer method catches Exception and still returns true.",
            "The binding helper ignores the Boolean result from bindService(), while the later callback reports service availability or failure.",
        ],
        "impact": "A script can treat billing as ready when the device lacks the legacy Play service or when setup failed. This can produce missed purchase attempts, stale helper state, and misleading diagnostics on current Android builds.",
        "limits": "The later onGooglePlayInitialized event carries the actual setup result. This is a compatibility and state-reporting issue, not proof that the store service can be bypassed.",
    },
    {
        "id": "ANDROID-IAB-004",
        "severity": "low",
        "confidence": "confirmed-static-plus-dex",
        "title": "The client uses legacy SHA-1 purchase verification and name-based consumption",
        "evidence": [
            "Security.verify uses SHA1withRSA and the platform default charset for signed purchase text.",
            "The helper uses the legacy in-app billing v3 AIDL service.",
            "Automatic consumption is selected by substring checks for gralatspack, coinspack, and vippack, plus an android.test prefix, rather than a fixed catalog.",
        ],
        "impact": "The cryptographic and API choices create maintenance debt on newer platforms. The broad SKU substring rules can also consume a product whose identifier happens to contain one of those tokens, which could discard an entitlement before a game-specific handler uses it.",
        "limits": "The review did not demonstrate a forged signature, a charset mismatch in a real purchase, or an actual SKU collision. These are hardening and compatibility concerns, not a confirmed forgery path.",
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
        "schema": "libqplay.original-billing-bridge-review.v1",
        "artifact": "original_billing_bridge_review_20260830",
        "scope": "read-only review of the original 1.8 Google Play billing script, JNI, and legacy helper bridge",
        "network_contacted": False,
        "billing_service_bound": False,
        "purchase_flow_launched": False,
        "purchase_data_collected": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8",
        },
        "script_surface": SCRIPT_SURFACE,
        "java_observations": JAVA_OBSERVATIONS,
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "The billing bridge is separate from the native Graal connector and its CyaSSL trust bundle.",
            "The store's signature verification gates the successful IAB result, but the surrounding callback still forwards purchase fields to native script code on failure.",
            "The immediate init and buy Booleans are operation-start indicators. The asynchronous callbacks carry the meaningful billing result.",
            "A repair should allowlist product IDs, treat the asynchronous setup and purchase result as authoritative, pass only the minimum result data to scripts, and replace the legacy billing API when the service contract permits.",
        ],
    }
    output = os.environ.get("IDA_BILLING_BRIDGE_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
