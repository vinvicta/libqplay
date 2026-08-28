#!/usr/bin/env python3
"""Create reviewed anchors for the text-list selection script methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x1df918",
        "0x1e3794",
        "GuiTextListCtrl_script_setselectedrows",
        "sub_1E3794",
        "setselectedrows",
        "0x383c50",
        "0x396cb0",
    ),
    (
        "0x1dfa48",
        "0x1e38c8",
        "GuiTextListCtrl_script_setselectedbyids",
        "sub_1E38C8",
        "setselectedbyids",
        "0x383bc0",
        "0x396c20",
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
    return {row["ea"]: row for row in document["functions"]}


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, spec: tuple[str, ...]) -> dict:
    source_ea, target_ea, source_name, target_name, script_name, source_table, target_table = spec
    if source["name"] != source_name:
        raise ValueError(f"unexpected source name at {source_ea}: {source['name']}")
    if target["name"] != target_name:
        raise ValueError(f"unexpected target name at {target_ea}: {target['name']}")
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    normalized_equal = all(
        source[field] == target[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    if normalized_equal or source_metrics == target_metrics:
        raise ValueError(f"expected a wrapper-change row at {source_ea}")
    return {
        "original_ea": source_ea,
        "original_name": source_name,
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target_ea,
        "spectron_current_name": target_name,
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source_name,
        "confidence": "high",
        "match_kind": "manual-gui-text-list-selection-script-anchor",
        "source_component": "GuiTextListCtrl",
        "target_component": "s_YwgafWlw",
        "source_basis": f"script table entry {script_name}; comma-list selection behavior",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": source_metrics == target_metrics,
        "metric_differences": [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ],
        "source_script_table_record": source_table,
        "target_script_table_record": target_table,
        "evidence": [
            f"The source script registration record for {script_name} is at {source_table}.",
            f"The target script registration record for {script_name} is at {target_table}.",
            "Both bodies parse a comma-separated integer list and preserve the source single-selection and multi-selection branches.",
            "The target preserves deselection, selected-cell updates, and invalid-ID handling through rebuilt helper classes.",
            "The target adds one wrapper instruction and changes helper names, so the layout difference is recorded explicitly.",
        ],
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
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
        "artifact": "spectron_gui_text_list_selection_script_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual text-list selection script methods",
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
            "source_component": "GuiTextListCtrl",
            "target_component": "s_YwgafWlw",
            "resolution": "decoded script-table names, table records, class-local order, decompiled selection logic, and explicit wrapper-change accounting",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "normalized_shape_exact_count": sum(row["normalized_shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(not row["normalized_shape_equal"] for row in anchors),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
        },
        "anchors": anchors,
        "reviewed_target_only_rows": [],
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ labels preserve readable 1.8 roles while the target ABI and helper names remain in each row.",
            "The source and target method-table order differs, so the decoded registration name is retained as the primary table anchor.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
