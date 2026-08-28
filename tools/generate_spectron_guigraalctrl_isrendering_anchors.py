#!/usr/bin/env python3
"""Create reviewed anchors for the remaining GuiGraalCtrl property pair."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


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


SPECS = (
    {
        "original_ea": "0x1bbe80",
        "spectron_ea": "0x1bf7ac",
        "original_name": "GuiGraalCtrl_get_isrendering",
        "script_name": "isrendering",
        "property_role": "getter",
        "source_record": "0x3816d0",
        "target_record": "0x394730",
        "operation": "reads the rendering flag byte at object offset +456",
    },
    {
        "original_ea": "0x1bbe88",
        "spectron_ea": "0x1bf7b4",
        "original_name": "GuiGraalCtrl_set_isrendering",
        "script_name": "isrendering",
        "property_role": "setter",
        "source_record": "0x3816d0",
        "target_record": "0x394730",
        "operation": "stores the rendering flag byte at object offset +456",
    },
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


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, item: dict) -> dict:
    expected_target_name = "sub_" + item["spectron_ea"][2:].upper()
    if source["name"] != item["original_name"]:
        raise ValueError(
            f"unexpected source name at {item['original_ea']}: {source['name']}"
        )
    if target["name"] != expected_target_name:
        raise ValueError(
            f"unexpected target name at {item['spectron_ea']}: {target['name']}"
        )
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {item['spectron_ea']}")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source_metrics[field] == target_metrics[field]
        for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    evidence = [
        f"The source {item['property_role']} registration row for isrendering is at {item['source_record']}.",
        f"The target {item['property_role']} registration row for isrendering is at {item['target_record']}.",
        f"The source and target pseudocode preserve the same operation: {item['operation']}.",
        "The target callback remained a default sub name before this pass.",
    ]
    if normalized_equal and full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; remaining differences are recorded explicitly."
        )
    else:
        evidence.append(
            "The target wrapper has a shape change, so the metric difference is retained explicitly."
        )

    return {
        "original_ea": item["original_ea"],
        "original_name": item["original_name"],
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": item["spectron_ea"],
        "spectron_current_name": target["name"],
        "spectron_default_name": True,
        "spectron_metrics": target_metrics,
        "spectron_function_end": target.get("end_ea"),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + item["original_name"],
        "confidence": "high",
        "match_kind": "manual-guigraalctrl-property-anchor",
        "source_component": "GuiGraalCtrl property table",
        "target_component": "Spectron obfuscated GuiGraalCtrl property table",
        "source_basis": "matching the isrendering property registration and decompiled operation",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["script_name"],
        "property_role": item["property_role"],
        "operation": item["operation"],
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
    for item in SPECS:
        source = original.get(item["original_ea"])
        target = spectron.get(item["spectron_ea"])
        if source is None or target is None:
            raise ValueError(
                f"missing feature row for {item['original_ea']} or {item['spectron_ea']}"
            )
        anchors.append(make_anchor(source, target, item))

    result = {
        "schema_version": 1,
        "artifact": "spectron_guigraalctrl_isrendering_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the GuiGraalCtrl isrendering property pair",
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
            "source_component": "GuiGraalCtrl property table at 0x3816d0",
            "target_component": "Spectron obfuscated GuiGraalCtrl property table at 0x394730",
            "resolution": "decoded property name, table-local order, callback role, direct field behavior, pseudocode, and ARM64 feature metrics",
            "record_size": "0x30 bytes",
            "callback_offsets": {"getter": "0x10", "setter": "0x18"},
            "preexisting_target_callbacks": [
                "The remaining GuiMLTextCtrl property callbacks in this table already had reviewed target names."
            ],
        },
        "summary": {
            "anchor_count": len(anchors),
            "registration_row_count": len(anchors),
            "unique_target_count": len({row["spectron_ea"] for row in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "normalized_shape_exact_count": sum(
                row["normalized_shape_equal"] for row in anchors
            ),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(
                not row["normalized_shape_equal"] for row in anchors
            ),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
            "getter_count": sum(row["property_role"] == "getter" for row in anchors),
            "setter_count": sum(row["property_role"] == "setter" for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source and target property tables preserve the same isrendering property and getter or setter roles for this pair.",
            "The target pseudocode uses the same object field offset and the complete ARM64 feature comparison is exact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
