#!/usr/bin/env python3
"""Create reviewed anchors for residual array and popup GUI callbacks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


# The rows are ordered by the source and target callback tables.  get_rows is
# a reviewed wrapper change: the target uses rebuilt string and hash-list
# helpers, so its normalized instruction shape is intentionally not claimed
# as equal even though the table role and decompiled behavior agree.
SPECS = [
    ("0x1d5f04", "0x1dab5c", "GuiArrayCtrl_get_allowmultipleselections", "sub_1DAB5C", "read allow-multiple-selections byte at +480", "GuiArrayCtrl", "s_YwgafWlw", True),
    ("0x1d85ac", "0x1dd334", "GuiContextMenuCtrl_get_rows", "sub_1DD334", "look up the rows object through the owned profile hash list", "GuiContextMenuCtrl", "c3fygag7qx", False),
    ("0x1d9104", "0x1dde40", "GuiPopUpMenuCtrl_script_forceonaction", "sub_1DDE40", "dispatch force-on-action through virtual slot 832", "GuiPopUpMenuCtrl", "SyVo2a61z", True),
    ("0x1d9124", "0x1dde60", "GuiPopUpMenuCtrl_script_forceclose", "sub_1DDE60", "dispatch force-close through virtual slot 904", "GuiPopUpMenuCtrl", "SyVo2a61z", True),
    ("0x1d91e4", "0x1ddf20", "GuiPopUpMenuCtrl_script_rowcount", "sub_1DDF20", "return the embedded text-list row count", "GuiPopUpMenuCtrl", "SyVo2a61z", True),
    ("0x1d91f0", "0x1ddf2c", "GuiPopUpMenuCtrl_script_getselected", "sub_1DDF2C", "return the embedded text-list selected ID", "GuiPopUpMenuCtrl", "SyVo2a61z", True),
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
    (
        source_ea,
        target_ea,
        source_name,
        target_name,
        role,
        source_component,
        target_component,
        normalized_expected,
    ) = spec
    if source["name"] != source_name:
        raise ValueError(f"source name mismatch at {source_ea}: {source['name']}")
    if target["name"] != target_name:
        raise ValueError(f"target name mismatch at {target_ea}: {target['name']}")
    normalized_equal = all(
        source[field] == target[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    if normalized_equal != normalized_expected:
        raise ValueError(
            f"unexpected normalized shape result at {source_ea}: "
            f"expected {normalized_expected}, got {normalized_equal}"
        )
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
        "match_kind": "manual-gui-array-popup-residual-anchor",
        "source_component": source_component,
        "target_component": target_component,
        "source_basis": role,
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": source_metrics == target_metrics,
        "metric_differences": [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ],
        "evidence": [
            "The source and target callbacks occupy the same local GUI callback table block.",
            "The target property or method table points at the reviewed target address.",
            "The decompiled target body preserves the source field access, hash lookup, or virtual dispatch.",
            "The rows with rebuilt string-wrapper code retain their metric differences explicitly instead of being treated as exact instruction matches.",
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

    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_array_popup_residual_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual GuiArrayCtrl and popup/context-menu callbacks",
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
            "source_components": ["GuiArrayCtrl", "GuiContextMenuCtrl", "GuiPopUpMenuCtrl"],
            "target_components": ["s_YwgafWlw", "c3fygag7qx", "SyVo2a61z"],
            "resolution": "callback-table references, class-local order, decompiled behavior, and explicit wrapper-change accounting",
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
        "reviewed_target_only_rows": [
            {
                "spectron_ea": "0x1dded4",
                "current_name": "sub_1DDED4",
                "reason": "target-only static C8THgaTQxF cleanup called by GuiPopUpMenuCtrl_setIconSize; no 1.8 source counterpart was demonstrated",
            }
        ],
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ labels preserve readable 1.8 roles while the target ABI names remain in each row.",
            "GuiContextMenuCtrl_get_rows is a high-confidence wrapper correspondence with an explicit normalized-shape difference caused by rebuilt target helpers.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
