#!/usr/bin/env python3
"""Create exact reviewed anchors for drawing-panel script callbacks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x1e00e4",
        "0x1e3fd8",
        "GuiDrawingPanel_script_setdrawpalette",
        "sub_1E3FD8",
        "setdrawpalette",
        "0x384070",
        "0x3970d0",
        "TDrawingPanel_setDrawPaletteNamed",
    ),
    (
        "0x1e00ec",
        "0x1e3fe0",
        "GuiDrawingPanel_script_maskimage",
        "sub_1E3FE0",
        "maskimage",
        "0x384040",
        "0x3970a0",
        "TDrawingPanel_maskImage_Impl",
    ),
    (
        "0x1e00f4",
        "0x1e3fe8",
        "GuiDrawingPanel_script_filterrectangle",
        "sub_1E3FE8",
        "filterrectangle",
        "0x384010",
        "0x397070",
        "TDrawingPanel_filterRectangle_Impl",
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
    (
        source_ea,
        target_ea,
        source_name,
        target_name,
        script_name,
        source_table,
        target_table,
        forwarded_role,
    ) = spec
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
    if not normalized_equal or source_metrics != target_metrics:
        raise ValueError(f"expected an exact feature match at {source_ea}")
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
        "match_kind": "manual-gui-drawing-panel-script-anchor",
        "source_component": "GuiDrawingPanel",
        "target_component": "V8fxgahcBw",
        "source_basis": f"script table entry {script_name}; forwards to {forwarded_role}",
        "normalized_shape_equal": True,
        "full_metric_equal": True,
        "metric_differences": [],
        "source_script_table_record": source_table,
        "target_script_table_record": target_table,
        "evidence": [
            f"The source script registration record for {script_name} is at {source_table}.",
            f"The target script registration record for {script_name} is at {target_table}.",
            f"Both bodies forward the same drawing-panel operation, {forwarded_role}.",
            "All recorded normalized and complete function metrics match exactly.",
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
        "artifact": "spectron_gui_drawing_panel_script_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual drawing-panel script callbacks",
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
            "source_component": "GuiDrawingPanel",
            "target_component": "V8fxgahcBw",
            "resolution": "decoded script-table names, table records, class-local order, decompiled forwarding behavior, and exact ARM64 feature equality",
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
            "The v18_ labels preserve readable 1.8 roles while the target ABI names remain in each row.",
            "The target table order differs from the source, so the decoded callback name and record address are retained explicitly.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
