#!/usr/bin/env python3
"""Create reviewed anchors for the next residual GUI text-list methods.

These rows sit beside the v219 property accessors. The target class-local
order and the registered property or method-table entry identify each role;
the decompiled bodies then confirm the corresponding sort, text, geometry, or
profile operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = [
    ("0x1dca48", "0x1e07e4", "GuiTextListCtrl_get_sortorder", "sub_1E07E4", "sort-order string from index at +544"),
    ("0x1dca84", "0x1e0820", "GuiTextListCtrl_get_sortmode", "sub_1E0820", "sort-mode string from index at +540"),
    ("0x1dcac0", "0x1e085c", "GuiTextListCtrl_get_groupsortorder", "sub_1E085C", "group-sort string from index at +548"),
    ("0x1dcb08", "0x1e08a4", "GuiTextListEntry_set_hint", "sub_1E08A4", "string assignment at +128"),
    ("0x1dcb5c", "0x1e08f8", "GuiTextListEntry_get_hint", "sub_1E08F8", "string copy from +128"),
    ("0x1dcb8c", "0x1e0928", "GuiTextListEntry_get_position", "sub_1E0928", "TPoint conversion from +184"),
    ("0x1dcbb0", "0x1e094c", "GuiTextListEntry_get_extent", "sub_1E094C", "TPoint conversion from +192"),
    ("0x1dcc68", "0x1e0a04", "GuiTextListCtrl_set_sortorder", "sub_1E0A04", "sort-order parse into +544"),
    ("0x1dcdb4", "0x1e0b50", "GuiTextListCtrl_set_groupsortorder", "sub_1E0B50", "group-sort parse into +548"),
    ("0x1dd94c", "0x1e16e8", "GuiTextListEntry_set_profile", "sub_1E16E8", "profile dynamic-cast and assignment"),
]


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


def by_ea(document: dict) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in document["functions"]}


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, spec: tuple[str, ...]) -> dict:
    source_ea, target_ea, source_name, target_name, role = spec
    if source["name"] != source_name:
        raise ValueError(f"source name mismatch at {source_ea}: {source['name']}")
    if target["name"] != target_name:
        raise ValueError(f"target name mismatch at {target_ea}: {target['name']}")
    normalized_equal = all(
        source[field] == target[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    if not normalized_equal:
        raise ValueError(f"normalized shape mismatch at {source_ea}")
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
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
        "match_kind": "manual-gui-text-list-residual-anchor",
        "source_component": "GuiTextListEntry or GuiTextListCtrl",
        "target_component": "RZNxgaOF2w or u0eyga1eqx",
        "source_basis": role,
        "normalized_shape_equal": True,
        "full_metric_equal": source_metrics == target_metrics,
        "metric_differences": [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ],
        "evidence": [
            "The source and target methods occupy the same local GUI text-list class block.",
            "The target property or method table points at the reviewed target address.",
            "The decompiled target body preserves the source sort, text, geometry, or profile operation.",
            "Normalized ARM64 feature fields match; wrapper substitutions and register allocation differences are retained in the metric record.",
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
        source = original.get(int(spec[0], 16))
        target = spectron.get(int(spec[1], 16))
        if source is None or target is None:
            raise ValueError(f"missing feature row for {spec[0]} or {spec[1]}")
        anchors.append(make_anchor(source, target, spec))

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate target address")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name")

    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_text_list_residual_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual GUI text-list sort, text, geometry, and profile methods",
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
            "source_components": ["GuiTextListEntry", "GuiTextListCtrl"],
            "target_components": ["RZNxgaOF2w", "u0eyga1eqx"],
            "resolution": "class-local order, property or method-table references, decompiled behavior, and normalized ARM64 feature equality",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "normalized_shape_exact_count": sum(row["normalized_shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ labels preserve readable 1.8 roles while the target ABI names remain in each row.",
            "The property-table and method-table references make the compact rows independently reviewable.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
