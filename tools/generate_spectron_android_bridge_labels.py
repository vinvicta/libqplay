#!/usr/bin/env python3
"""Create reviewed labels for Spectron's Android bridge callbacks.

The 2.2 library contains an additional native script-function block for
notifications, Android metadata, Firebase, deep links, and Google Play
helpers. These callbacks have no demonstrated 1.8 source address in the
current archive, so the generated labels use a ``spectron_`` prefix and are
kept out of the 1.8-to-Spectron correspondence count.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x24b4ec",
        "0x39f180",
        "0x39f1a0",
        "spectron_deeplink_getdeeplinkdata",
        "DeepLink::getDeepLinkData",
        "returns the byte-string payload supplied by the Java GetIntentData method, or the literal not found when that method is absent",
    ),
    (
        "0x24b61c",
        "0x39f120",
        "0x39f140",
        "spectron_notifications_getpushnotificationdata",
        "notifications::getpushnotificationdata",
        "returns the byte-string payload supplied by the Java GetPushNotificationData method, or the literal not found when that method is absent",
    ),
    (
        "0x24b74c",
        "0x39efd0",
        "0x39eff0",
        "spectron_getandroidversionname",
        "getandroidversionname",
        "looks up the Android package-version name and returns it as a script string",
    ),
    (
        "0x24b958",
        "0x39f0c0",
        "0x39f0e0",
        "spectron_quattro_android_getinstallerpackagename",
        "quattro::android::getinstallerpackagename",
        "walks through ActivityThread, Application, PackageManager, PackageInfo, and signatures[0].toCharsString(); the body therefore retrieves a signing string even though the table label says getinstallerpackagename",
    ),
    (
        "0x24bfcc",
        "0x39e900",
        "0x39e920",
        "spectron_googleplayservicesavailable",
        "googleplayservicesavailable",
        "calls the Java GooglePlayServicesAvailable method and returns its boolean result",
    ),
    (
        "0x24cb68",
        "0x39efa0",
        "0x39efc0",
        "spectron_getandroidversioncode",
        "getandroidversioncode",
        "looks up the Android package-version code and returns the Java integer result",
    ),
    (
        "0x24cd60",
        "0x39f180",
        "0x39f1a0",
        "spectron_deeplink_cleardeeplinkdata",
        "DeepLink::clearDeepLinkData",
        "calls the Java ClearIntentDatas method to clear the pending deep-link payload",
    ),
    (
        "0x24cdd4",
        "0x39f150",
        "0x39f170",
        "spectron_notifications_clearpushnotificationdata",
        "notifications::clearpushnotificationdata",
        "calls the Java ClearPushNotificationData method",
    ),
    (
        "0x24ce48",
        "0x39f090",
        "0x39f0b0",
        "spectron_registerforpushnotifications",
        "registerforpushnotifications",
        "calls the Java AskNotificationPermission method used by the push-notification registration path",
    ),
    (
        "0x24cebc",
        "0x39f000",
        "0x39f020",
        "spectron_quattro_android_googleinappreview",
        "quattro::android::googleinappreview",
        "calls the Java GooglePlayRateApp method",
    ),
    (
        "0x24cf30",
        "0x39ef40",
        "0x39ef60",
        "spectron_clearallnotifications",
        "clearallnotifications",
        "calls the Java clearAllNotifications method",
    ),
    (
        "0x24d100",
        "0x39e8d0",
        "0x39e8f0",
        "spectron_checkgoogleplaylicensing",
        "checkgoogleplaylicensing",
        "calls the Java CheckGooglePlayLicensing method",
    ),
    (
        "0x24d33c",
        "0x39f210",
        "0x39f230",
        "spectron_notifications_unsubscribetotopic",
        "notifications::unsubscribetopic",
        "converts the topic string to a Java byte array and calls UnsubscribeFromTopic",
    ),
    (
        "0x24d458",
        "0x39f1e0",
        "0x39f200",
        "spectron_notifications_subscribetotopic",
        "notifications::subscribetotopic",
        "converts the topic string to a Java byte array and calls SubscribeToTopic",
    ),
    (
        "0x24d574",
        "0x39f060",
        "0x39f080",
        "spectron_firebase_addeventdata",
        "firebase::addeventdata",
        "converts two script strings to Java byte arrays and calls AddEventData",
    ),
    (
        "0x24d73c",
        "0x39f030",
        "0x39f050",
        "spectron_firebase_logevent",
        "firebase::logevent",
        "converts the event string to a Java byte array and calls LogEvent",
    ),
    (
        "0x24d858",
        "0x39ef10",
        "0x39ef30",
        "spectron_addnotification",
        "addnotification",
        "converts three script strings to Java byte arrays and calls addNotification",
    ),
    (
        "0x24efb4",
        "0x39e8a0",
        "0x39e8c0",
        "spectron_setsigningcertificate",
        "setsigningcertificate",
        "converts a script string to a Java byte array and calls SetSigningCertificate",
    ),
    (
        "0x24f0d0",
        "0x39e870",
        "0x39e890",
        "spectron_setgoogleplaykey",
        "setgoogleplaykey",
        "converts a script string to a Java byte array and calls SetGooglePlayKey",
    ),
    (
        "0x24fee4",
        "0x39e4e0",
        "0x39e500",
        "spectron_androidgetjavastaticstring",
        "androidgetjavastaticstring",
        "looks up a Java static string method for a requested class and method name, then returns the result or an error string",
    ),
    (
        "0x24fdfc",
        "0x39e510",
        "0x39e530",
        "spectron_androidgetjavastaticint",
        "androidgetjavastaticint",
        "looks up a Java static integer method for a requested class and method name, then returns the result",
    ),
    (
        "0x2531ec",
        "0x39e540",
        "0x39e560",
        "spectron_androidsystempropertyget",
        "androidsystempropertyget",
        "reads an Android system property through the Java bridge and returns the resulting string",
    ),
)

METRICS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"].lower(): row for row in document["functions"]}


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def make_label(target: dict, spec: tuple[str, ...]) -> dict:
    target_ea, table_record, callback_xref, proposed_name, script_name, operation = spec
    expected_name = "sub_" + target_ea[2:].upper()
    if target["name"] != expected_name:
        raise ValueError(f"unexpected target name at {target_ea}: {target['name']}")
    if target["end_ea"] is None:
        raise ValueError(f"missing target function boundary at {target_ea}")
    return {
        "target_ea": target_ea,
        "current_name": target["name"],
        "function_end": target["end_ea"],
        "proposed_name": proposed_name,
        "target_default_name": target.get("is_default_name", False),
        "target_metrics": metric_record(target),
        "target_string_refs": target.get("string_refs", []),
        "target_direct_call_names": target.get("direct_call_names", []),
        "script_name": script_name,
        "target_function_table_record": table_record,
        "target_callback_xref": callback_xref,
        "operation": operation,
        "source_counterpart": None,
        "source_counterpart_status": "not-demonstrated",
        "confidence": "high",
        "match_kind": "reviewed-target-only-android-bridge-label",
        "evidence": [
            f"The decoded target script-function table row for {script_name} is at {table_record}.",
            f"The row points to this callback through the target callback cell at {callback_xref}.",
            f"Target pseudocode shows that it {operation}.",
            "No 1.8 source address is claimed for this target-only label.",
        ],
        "name_action": "rename-with-spectron-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    spectron = by_ea(load(args.spectron_features))
    labels = []
    for spec in SPECS:
        target = spectron.get(spec[0])
        if target is None:
            raise ValueError(f"missing target feature row for {spec[0]}")
        labels.append(make_label(target, spec))

    proposed = [row["proposed_name"] for row in labels]
    if len(proposed) != len(set(proposed)):
        raise ValueError("target-only label names are not unique")

    result = {
        "schema_version": 1,
        "artifact": "spectron_android_bridge_target_only_labels_20260828",
        "scope": "reviewed descriptive labels for Spectron 2.2 Android bridge callbacks without demonstrated 1.8 source addresses",
        "network_contacted": False,
        "inputs": {
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "target_components": [
                "Spectron Android and notification script-function table at 0x39e000..0x39f230",
                "Spectron JNI bridge callback block at 0x24a9ec..0x253304",
            ],
            "resolution": "decoded target script-function names, direct callback cells, function boundaries, Java method strings, and reviewed pseudocode",
            "mapping_boundary": "These labels describe target behavior only. They are not 1.8-to-Spectron correspondences and are excluded from the source mapping count.",
        },
        "summary": {
            "label_count": len(labels),
            "high_confidence_count": sum(row["confidence"] == "high" for row in labels),
            "target_default_name_count": sum(row["target_default_name"] for row in labels),
            "source_counterpart_count": sum(row["source_counterpart"] is not None for row in labels),
            "target_only_count": len(labels),
        },
        "labels": labels,
        "interpretation": [
            "The spectron_ prefix marks a target-specific descriptive label rather than a restored 1.8 symbol.",
            "Several callbacks call newer Java methods that are not present in the original 1.8 native block.",
            "The getinstallerpackagename and getsignature table entries should be read together with their bodies because the observed callback behavior does not align with those two table labels.",
            "No source counterpart is counted for any row in this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
