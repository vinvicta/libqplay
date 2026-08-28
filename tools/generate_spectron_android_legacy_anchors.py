#!/usr/bin/env python3
"""Create reviewed anchors for legacy Android and TapJoy callbacks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x2401f4",
        "0x24a240",
        "MainAndroid_script_settapjoysecret",
        "MainAndroid_script_settapjoysecret",
        "0x38b450",
        "0x39e788",
        "sub_24A240",
        "the target stores the script string in the second TapJoy credential slot, which the target connector later passes as its second Java byte-array argument",
    ),
    (
        "0x240204",
        "0x24a254",
        "MainAndroid_script_settapjoyapplicationid",
        "MainAndroid_script_settapjoyapplicationid",
        "0x38b420",
        "0x39e758",
        "sub_24A254",
        "the target stores the script string in the first TapJoy credential slot, which the target connector later passes as its first Java byte-array argument",
    ),
    (
        "0x2410ac",
        "0x24c7e4",
        "JNI_connectToTapJoyService",
        "JNI_connectToTapJoyService",
        "0x38b480",
        "0x39e7b8",
        "sub_24C7E4",
        "the target resolves connectToTapJoyService([B[B)Z, converts the two cached credential strings, calls Java, releases both local arrays, and returns the boolean result",
    ),
    (
        "0x2435e8",
        "0x2502f4",
        "androidGetID_void",
        "androidGetID_void",
        "not registered in the 1.8 script table",
        "not registered in the Spectron script table",
        "_Z10_Sn_GaYH5Mv",
        "the target resolves Settings.Secure, obtains ANDROID_ID through the application content resolver, and returns the resulting string or its rebuilt failure value",
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
NORMALIZED_METRICS = ("opcode_shape_hash", "register_shape_hash", "shape_hash")


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


def make_anchor(source: dict, target: dict, spec: tuple[str, ...]) -> dict:
    (
        original_ea,
        target_ea,
        original_name,
        target_expected_name,
        source_table,
        target_table,
        target_current_name,
        operation,
    ) = spec
    if source["name"] != original_name:
        raise ValueError(f"unexpected source name at {original_ea}: {source['name']}")
    if target["name"] != target_current_name:
        raise ValueError(f"unexpected target name at {target_ea}: {target['name']}")
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    normalized_equal = all(
        source_metrics[field] == target_metrics[field] for field in NORMALIZED_METRICS
    )
    full_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    evidence = [
        f"The source callback or helper context is at {source_table}.",
        f"The target callback or helper context is at {target_table}.",
        f"Reviewed pseudocode preserves the same role: {operation}.",
        "The source and target addresses were checked against the same ARM64 build pair.",
    ]
    if full_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; remaining metric differences are recorded explicitly."
        )
    else:
        evidence.append(
            "The target uses rebuilt Android or string helpers, so metric differences are recorded explicitly."
        )
    return {
        "original_ea": original_ea,
        "original_name": original_name,
        "original_metrics": source_metrics,
        "original_function_end": source["end_ea"],
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target_ea,
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_function_end": target["end_ea"],
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + target_expected_name,
        "confidence": "high",
        "match_kind": "manual-legacy-android-semantic-anchor",
        "source_component": "original Android or TapJoy callback",
        "target_component": "Spectron rebuilt Android or TapJoy callback",
        "source_basis": "registration context where available, Java method strings, reviewed pseudocode, and cross-build feature comparison",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_equal,
        "metric_differences": differences,
        "source_table_context": source_table,
        "target_table_context": target_table,
        "operation": operation,
        "evidence": evidence,
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original = by_ea(load(args.original_features))
    spectron = by_ea(load(args.spectron_features))
    anchors = []
    for spec in SPECS:
        source = original.get(spec[0])
        target = spectron.get(spec[1])
        if source is None or target is None:
            raise ValueError(f"missing feature row for {spec[0]} or {spec[1]}")
        anchors.append(make_anchor(source, target, spec))

    result = {
        "schema_version": 1,
        "artifact": "spectron_android_legacy_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for legacy Android identity and TapJoy callbacks",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "source_components": [
                "MainAndroid TapJoy credential setters",
                "JNI TapJoy connector",
                "androidGetID Android identity helper",
            ],
            "target_components": [
                "Spectron TapJoy credential setters",
                "Spectron TapJoy connector",
                "Spectron rebuilt Android identity helper",
            ],
            "resolution": "decoded registration context where available, exact Java method strings, reviewed pseudocode, and cross-build feature metrics",
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({row["spectron_ea"] for row in anchors}),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "normalized_shape_exact_count": sum(row["normalized_shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(not row["normalized_shape_equal"] for row in anchors),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The target Android identity helper keeps its retained mangled name in the source evidence and receives a readable v18_ analysis alias in the disposable IDA copy.",
            "The target TapJoy credential slots are reversed in address order compared with the source, but their table names and connector argument order make the mapping clear.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
