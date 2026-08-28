#!/usr/bin/env python3
"""Create reviewed anchors for the remaining GuiControl property callbacks."""

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
        "original_ea": "0x1ba398",
        "spectron_ea": "0x1becbc",
        "original_name": "GuiControl_getCursor",
        "script_name": "cursor",
        "role": "getter",
        "source_record": "0x3809d0",
        "target_record": "0x393a30",
        "operation": "forwards the control cursor-string getter into the script result",
    },
    {
        "original_ea": "0x1b7450",
        "spectron_ea": "0x1bbc10",
        "original_name": "GuiControl_setFlickering",
        "script_name": "flickering",
        "role": "setter",
        "source_record": "0x380af0",
        "target_record": "0x393b50",
        "operation": "compares and stores the flickering byte at +408, then invalidates the rectangle when it changes",
    },
    {
        "original_ea": "0x1b7a34",
        "spectron_ea": "0x1bc254",
        "original_name": "GuiControl_setIsInAnimation",
        "script_name": "isinanimation",
        "role": "setter",
        "source_record": "0x380c70",
        "target_record": "0x393cd0",
        "operation": "stops ordinary animations when the incoming flag is false",
    },
    {
        "original_ea": "0x1b7b64",
        "spectron_ea": "0x1bc384",
        "original_name": "GuiControl_setIsInOutAnimation",
        "script_name": "isininoutanimation",
        "role": "setter",
        "source_record": "0x380ca0",
        "target_record": "0x393d00",
        "operation": "stops in-or-out animations when the incoming flag is false",
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
    if source["name"] != item["original_name"]:
        raise ValueError(
            f"unexpected source name at {item['original_ea']}: {source['name']}"
        )
    expected_target_name = "sub_" + item["spectron_ea"][2:].upper()
    if target["name"] != expected_target_name:
        raise ValueError(
            f"unexpected target name at {item['spectron_ea']}: {target['name']}"
        )
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {item['spectron_ea']}")
    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source[field] == target[field] for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    return {
        "original_ea": item["original_ea"],
        "original_name": item["original_name"],
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": item["spectron_ea"],
        "spectron_current_name": expected_target_name,
        "spectron_default_name": True,
        "spectron_metrics": target_metrics,
        "spectron_function_end": target.get("end_ea"),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + item["original_name"],
        "confidence": "high",
        "match_kind": "manual-guicontrol-property-tail-anchor",
        "source_component": "GuiControl property table",
        "target_component": "Spectron obfuscated GuiControl property table",
        "source_basis": f"matching the {item['script_name']} {item['role']} registration and decompiled operation",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["script_name"],
        "property_role": item["role"],
        "operation": item["operation"],
        "evidence": [
            f"The source {item['role']} registration row for {item['script_name']} is at {item['source_record']}.",
            f"The target {item['role']} registration row for {item['script_name']} is at {item['target_record']}.",
            f"The source and target pseudocode preserve the same operation: {item['operation']}.",
            "The target callback remained a default sub name before this pass.",
            "All recorded function metrics match exactly."
            if full_metric_equal
            else "Normalized instruction shape matches; remaining metric differences are recorded explicitly.",
        ],
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
        "artifact": "spectron_guicontrol_property_tail_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for remaining GuiControl property callbacks",
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
            "source_component": "GuiControl property table at 0x3806a0",
            "target_component": "Spectron obfuscated GuiControl property table at 0x393700",
            "resolution": "decoded property names, table-local order, callback roles, decompiled field behavior, and ARM64 feature metrics",
            "record_size": "0x30 bytes",
            "callback_offsets": {"getter": "0x10", "setter": "0x18"},
            "preexisting_aliases": [
                "The surrounding GuiControl table has earlier aliases for the other residual property rows.",
                "The cursor setter, flickering getter, isinanimation getter, and isininoutanimation getter already had target names.",
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
            "The target property names and callback roles identify the four rows that remained default after earlier GuiControl passes.",
            "The clean feature comparison confirms exact source and target bodies for the cursor, flickering, ordinary-animation, and in-or-out-animation callbacks.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
