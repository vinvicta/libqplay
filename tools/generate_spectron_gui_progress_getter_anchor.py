#!/usr/bin/env python3
"""Create the reviewed Spectron progress-property getter anchor."""

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

    source = row_at(load(args.original_features), "0x1dbfa0")
    target = row_at(load(args.spectron_features), "0x1dfd3c")
    if source["name"] != "GuiProgressCtrl_get_progress":
        raise ValueError(f"unexpected source name: {source['name']}")
    if target["name"] != "sub_1DFD3C":
        raise ValueError(f"unexpected target name: {target['name']}")

    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    normalized_equal = all(
        source[field] == target[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    if not normalized_equal or source_metrics != target_metrics:
        raise ValueError("progress getter feature records do not match exactly")

    anchor = {
        "original_ea": "0x1dbfa0",
        "original_name": source["name"],
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": "0x1dfd3c",
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_GuiProgressCtrl_get_progress",
        "confidence": "high",
        "match_kind": "manual-gui-progress-property-anchor",
        "source_component": "GuiProgressCtrl",
        "target_component": "EYKlVaL7UR",
        "source_basis": "progress property getter reads float at receiver offset +456",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": True,
        "metric_differences": [],
        "evidence": [
            "The source progress property record is at 0x383078 and stores the getter at 0x383088.",
            "The target progress property record is at 0x3960d8 and stores the getter at 0x3960e8.",
            "The source and target pseudocode both return the float at receiver offset +456.",
            "All recorded normalized and complete function metrics match exactly.",
        ],
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_progress_getter_manual_translation_anchor_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the residual GuiProgressCtrl progress getter",
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
            "source_component": "GuiProgressCtrl",
            "target_component": "EYKlVaL7UR",
            "source_property_table_record": "0x383078",
            "target_property_table_record": "0x3960d8",
            "resolution": "progress property registration, class-local block, identical receiver offset, and exact normalized metrics",
        },
        "summary": {
            "anchor_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": int(anchor["spectron_default_name"]),
            "normalized_shape_exact_count": 1,
            "full_metric_exact_count": 1,
            "layout_change_count": 0,
            "register_detail_difference_count": 0,
        },
        "anchors": [anchor],
        "reviewed_target_only_rows": [],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a recovered stripped debug symbol.",
            "The v18_ label preserves the readable 1.8 role while the target ABI name remains in the evidence row.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
