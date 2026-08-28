#!/usr/bin/env python3
"""Create reviewed anchors for the residual GUI text-list property block.

The source build exposes these accessors as readable symbols. Spectron keeps
the same property-table order and field operations, but its local accessors
are stripped and appear as ``sub_`` functions. This generator records the
correspondence without changing an IDA database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = [
    ("0x1dc82c", "0x1e05c8", "GuiTextListEntry_get_active", "sub_1E05C8", "byte getter at +140"),
    ("0x1dc834", "0x1e05d0", "GuiTextListEntry_set_active", "sub_1E05D0", "byte setter at +140"),
    ("0x1dc83c", "0x1e05d8", "GuiTextListEntry_get_flickering", "sub_1E05D8", "byte getter at +141"),
    ("0x1dc844", "0x1e05e0", "GuiTextListEntry_set_flickering", "sub_1E05E0", "byte setter at +141"),
    ("0x1dc86c", "0x1e0608", "GuiTextListEntry_get_height", "sub_1E0608", "integer getter at +196"),
    ("0x1dc874", "0x1e0610", "GuiTextListEntry_get_id", "sub_1E0610", "integer getter at +136"),
    ("0x1dc87c", "0x1e0618", "GuiTextListEntry_set_id", "sub_1E0618", "integer setter at +136"),
    ("0x1dc884", "0x1e0620", "GuiTextListEntry_get_image", "sub_1E0620", "integer getter at +176"),
    ("0x1dc88c", "0x1e0628", "GuiTextListEntry_set_image", "sub_1E0628", "integer setter at +176"),
    ("0x1dc8a8", "0x1e0644", "GuiTextListEntry_get_sortgroup", "sub_1E0644", "integer getter at +216"),
    ("0x1dc8b0", "0x1e064c", "GuiTextListEntry_set_sortgroup", "sub_1E064C", "integer setter at +216"),
    ("0x1dc8b8", "0x1e0654", "GuiTextListEntry_get_sortvalue", "sub_1E0654", "integer getter at +220"),
    ("0x1dc8c0", "0x1e065c", "GuiTextListEntry_set_sortvalue", "sub_1E065C", "integer setter at +220"),
    ("0x1dc8c8", "0x1e0664", "GuiTextListEntry_get_selectedimage", "sub_1E0664", "integer getter at +180"),
    ("0x1dc8d0", "0x1e066c", "GuiTextListEntry_set_selectedimage", "sub_1E066C", "integer setter at +180"),
    ("0x1dc8d8", "0x1e0674", "GuiTextListEntry_get_useownprofile", "sub_1E0674", "pointer-presence getter at +208"),
    ("0x1dc8e8", "0x1e0684", "GuiTextListEntry_get_width", "sub_1E0684", "integer getter at +192"),
    ("0x1dc8f0", "0x1e068c", "GuiTextListEntry_get_x", "sub_1E068C", "integer getter at +184"),
    ("0x1dc8f8", "0x1e0694", "GuiTextListEntry_get_y", "sub_1E0694", "integer getter at +188"),
    ("0x1dc900", "0x1e069c", "GuiTextListCtrl_get_clipcolumntext", "sub_1E069C", "byte getter at +531"),
    ("0x1dc908", "0x1e06a4", "GuiTextListCtrl_set_clipcolumntext", "sub_1E06A4", "byte setter at +531"),
    ("0x1dc910", "0x1e06ac", "GuiTextListCtrl_get_enumerate", "sub_1E06AC", "byte getter at +528"),
    ("0x1dc918", "0x1e06b4", "GuiTextListCtrl_set_enumerate", "sub_1E06B4", "byte setter at +528"),
    ("0x1dc920", "0x1e06bc", "GuiTextListCtrl_get_fitparentwidth", "sub_1E06BC", "byte getter at +530"),
    ("0x1dc928", "0x1e06c4", "GuiTextListCtrl_set_fitparentwidth", "sub_1E06C4", "byte setter at +530"),
    ("0x1dc930", "0x1e06cc", "GuiTextListCtrl_get_iconheight", "sub_1E06CC", "integer getter at +536"),
    ("0x1dc938", "0x1e06d4", "GuiTextListCtrl_get_iconwidth", "sub_1E06D4", "integer getter at +532"),
    ("0x1dc940", "0x1e06dc", "GuiTextListCtrl_get_resizecell", "sub_1E06DC", "byte getter at +529"),
    ("0x1dc948", "0x1e06e4", "GuiTextListCtrl_set_resizecell", "sub_1E06E4", "byte setter at +529"),
    ("0x1dc950", "0x1e06ec", "GuiTextListCtrl_get_sortcolumn", "sub_1E06EC", "integer-presence getter at +552"),
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
    proposed_name = "v18_" + source_name
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
        "proposed_name": proposed_name,
        "confidence": "high",
        "match_kind": "manual-gui-property-table-anchor",
        "source_component": "GuiTextListEntry or GuiTextListCtrl",
        "target_component": "RZNxgaOF2w or u0eyga1eqx",
        "source_basis": role,
        "normalized_shape_equal": True,
        "full_metric_equal": source_metrics == target_metrics,
        "metric_differences": [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ],
        "evidence": [
            "The source property table and target property table keep the same accessor order.",
            "The source and target pseudocode perform the same field read or write, including the same byte or integer offset.",
            "The target function is a residual sub_ function and the adjacent named functions identify the same GUI text-list class block.",
            "The target property-table xref confirms that the short function is used as the registered getter or setter.",
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

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    original = by_ea(original_document)
    spectron = by_ea(spectron_document)
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
        "artifact": "spectron_gui_text_list_entry_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GuiTextListEntry and GuiTextListCtrl property accessors",
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
            "resolution": "property-table order, field offsets in decompiled bodies, target xrefs, and normalized ARM64 feature equality",
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
            "The addresses are valid only in the exact hashed Spectron library represented by the feature export.",
            "The v18_ labels preserve readable 1.8 roles while keeping the target ABI name available in this artifact and in the IDA database history.",
            "The two property tables explain why otherwise tiny residual functions can be named without guessing from size alone.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
