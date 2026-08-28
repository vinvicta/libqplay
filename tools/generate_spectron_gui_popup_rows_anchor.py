#!/usr/bin/env python3
"""Create the reviewed Spectron anchor for the popup rows accessor."""

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


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def row_at(document: dict, ea: str) -> dict:
    for row in document["functions"]:
        if row["ea"] == ea:
            return row
    raise ValueError(f"missing feature row at {ea}")


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    source = row_at(load(args.original_features), "0x1d9404")
    target = row_at(load(args.spectron_features), "0x1de3c4")
    if source["name"] != "GuiPopUpMenuCtrl_get_rows":
        raise ValueError(f"unexpected source name: {source['name']}")
    if target["name"] != "sub_1DE3C4":
        raise ValueError(f"unexpected target name: {target['name']}")
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    normalized_equal = all(
        source[field] == target[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    if normalized_equal:
        raise ValueError("the popup rows wrapper unexpectedly has normalized-equal shape")

    anchor = {
        "original_ea": "0x1d9404",
        "original_name": source["name"],
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": "0x1de3c4",
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_GuiPopUpMenuCtrl_get_rows",
        "confidence": "high",
        "match_kind": "manual-gui-popup-rows-anchor",
        "source_component": "GuiPopUpMenuCtrl",
        "target_component": "SyVo2a61z",
        "source_basis": "popup property-table rows lookup through the owned hash list",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": source_metrics == target_metrics,
        "metric_differences": [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ],
        "evidence": [
            "The source rows accessor is the popup property-table entry at 0x382ed8.",
            "The target rows accessor is the matching popup property-table entry at 0x395f38.",
            "Both bodies build the literal rows key, compute its hash, and look it up in the owned profile hash list.",
            "The target changes only the rebuilt string and hash-list helper family, so the normalized-shape difference is recorded explicitly.",
        ],
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_popup_rows_manual_translation_anchor_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the residual GuiPopUpMenuCtrl rows accessor",
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
            "source_component": "GuiPopUpMenuCtrl",
            "target_component": "SyVo2a61z",
            "source_property_table_xref": "0x382ed8",
            "target_property_table_xref": "0x395f38",
            "resolution": "property-table role, class-local popup block, identical literal, and decompiled hash-list behavior",
        },
        "summary": {
            "anchor_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": int(anchor["spectron_default_name"]),
            "normalized_shape_exact_count": int(normalized_equal),
            "full_metric_exact_count": int(anchor["full_metric_equal"]),
            "layout_change_count": int(not normalized_equal),
            "register_detail_difference_count": int(
                "register_detail_hash" in anchor["metric_differences"]
            ),
        },
        "anchors": [anchor],
        "reviewed_target_only_rows": [],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a recovered stripped debug symbol.",
            "The v18_ label preserves the readable 1.8 role while the target ABI name remains in the evidence row.",
            "The target wrapper change is retained as an explicit metric difference rather than being hidden by the alias.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
