#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for GUI and Android-facing code."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x1b15f0",
        "0x1b5cf8",
        "GuiCanvas_script_popdialog",
        "GuiCanvas_script_popdialog",
        "0x3805b0",
        "0x3935f8",
        "the target is the popdialog script callback registered in the GuiCanvas function table; it recognizes MessageBoxDialog, resolves MessageBoxDialog_Window, performs the close or pop transition, and updates the dialog state",
    ),
    (
        "0x210374",
        "0x216a64",
        "TGraalVar_script_trigger",
        "TGraalVar_script_trigger",
        "0x387cd0",
        "0x39ae38",
        "the target preserves the unknown_object check, universe ownership test, script-space event delivery, virtual dispatch, and temporary-array cleanup while using rebuilt obfuscated helper methods",
    ),
    (
        "0x246104",
        "0x253544",
        "MainAndroid_script_requestnewfacebookgraph2",
        "MainAndroid_script_requestnewfacebookgraph2",
        "0x38b6d8",
        "0x39eab0",
        "the target scans image or file entries, loads game resources, base64-encodes them, replaces the list entries, and calls Java requestNewFacebookGraph2",
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
        operation,
    ) = spec
    expected_target_default = "sub_" + target_ea[2:].upper()
    if source["name"] != original_name:
        raise ValueError(f"unexpected source name at {original_ea}: {source['name']}")
    if target["name"] != expected_target_default:
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
        f"The source registration or callback context is at {source_table}.",
        f"The target registration or callback context is at {target_table}.",
        f"Reviewed pseudocode preserves the same role: {operation}.",
        "The target callback was a default IDA name before this pass.",
    ]
    if full_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; remaining metric differences are recorded explicitly."
        )
    else:
        evidence.append(
            "The target uses a rebuilt wrapper or helper sequence, so the metric differences are recorded explicitly."
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
        "match_kind": "manual-gui-android-semantic-anchor",
        "source_component": "original GUI or Android-facing callback",
        "target_component": "Spectron rebuilt GUI or Android-facing callback",
        "source_basis": "registration context, target Java method strings, callback role, reviewed pseudocode, and cross-build feature comparison",
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
        "artifact": "spectron_gui_android_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for changed GUI and Android-facing callbacks",
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
                "GuiCanvas popdialog callback",
                "TGraalVar trigger callback",
                "MainAndroid Facebook graph upload callback",
            ],
            "target_components": [
                "Spectron GuiCanvas popdialog callback",
                "Spectron TGraalVar trigger callback",
                "Spectron MainAndroid Facebook graph upload callback",
            ],
            "resolution": "callback context, preserved operation, Java method strings where present, reviewed pseudocode, and cross-build feature metrics",
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
            "The Android bridge functions added or rebuilt in Spectron are documented separately as target-only labels.",
            "The GuiCanvas row is the popdialog callback, not the TGUIScriptLoader showMessageBox method. The target specifically handles MessageBoxDialog_Window during the pop transition, so it must keep a distinct label from the showMessageBox function.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
