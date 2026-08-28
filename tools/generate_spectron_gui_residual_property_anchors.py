#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron property anchors.

The rows in this artifact cover two small GUI property blocks that remained
default-named in the Spectron database: drawing-panel rectangle/cache
properties and show-image control properties.  The source and target feature
records are checked before the artifact is written so a later database drift
cannot silently change the reviewed correspondences.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = [
    ("0x1e0030", "0x1e3f24", "GuiDrawingPanel_get_partx", "sub_1E3F24", "read TDrawingPanel partx at +172", "GuiDrawingPanel", "V8fxgahcBw"),
    ("0x1e003c", "0x1e3f30", "GuiDrawingPanel_get_party", "sub_1E3F30", "read TDrawingPanel party at +176", "GuiDrawingPanel", "V8fxgahcBw"),
    ("0x1e0048", "0x1e3f3c", "GuiDrawingPanel_get_partw", "sub_1E3F3C", "read TDrawingPanel partw at +180", "GuiDrawingPanel", "V8fxgahcBw"),
    ("0x1e0054", "0x1e3f48", "GuiDrawingPanel_get_parth", "sub_1E3F48", "read TDrawingPanel parth at +184", "GuiDrawingPanel", "V8fxgahcBw"),
    ("0x1e0060", "0x1e3f54", "GuiDrawingPanel_get_enablecache", "sub_1E3F54", "read TDrawingPanel enable-cache byte at +140", "GuiDrawingPanel", "V8fxgahcBw"),
    ("0x1e0090", "0x1e3f84", "GuiDrawingPanel_get_availablefilters", "sub_1E3F84", "build the available-filter list from the panel filter-name string", "GuiDrawingPanel", "V8fxgahcBw"),
    ("0x1e0e48", "0x1e4d3c", "GuiShowImgCtrl_get_offsetx", "sub_1E4D3C", "read control offsetx at +472", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e0e50", "0x1e4d44", "GuiShowImgCtrl_get_offsety", "sub_1E4D44", "read control offsety at +476", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e0e64", "0x1e4d58", "GuiShowImgCtrl_set_layer", "sub_1E4D58", "forward layer assignment to the owned TShowImg", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e0e6c", "0x1e4d60", "GuiShowImgCtrl_get_layer", "sub_1E4D60", "read layer from the owned TShowImg", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e0e74", "0x1e4d68", "GuiShowImgCtrl_get_dir", "sub_1E4D68", "read particle direction from the owned TShowImg data", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e0e80", "0x1e4d74", "GuiShowImgCtrl_get_ani", "sub_1E4D74", "return the owned TShowImg animation string", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e1088", "0x1e4f7c", "GuiShowImgCtrl_set_dir", "sub_1E4F7C", "forward direction assignment and clear player-look mode", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e10d0", "0x1e4fc4", "GuiShowImgCtrl_set_ani", "sub_1E4FC4", "forward animation assignment and clear player-look mode", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e1564", "0x1e5434", "GuiShowImgCtrl_set_offsety", "sub_1E5434", "write offsety and refresh image position", "GuiShowImgCtrl", "VGk7faT0Ma"),
    ("0x1e156c", "0x1e543c", "GuiShowImgCtrl_set_offsetx", "sub_1E543C", "write offsetx and refresh image position", "GuiShowImgCtrl", "VGk7faT0Ma"),
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
    source_ea, target_ea, source_name, target_name, role, source_component, target_component = spec
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
        "match_kind": "manual-gui-residual-property-anchor",
        "source_component": source_component,
        "target_component": target_component,
        "source_basis": role,
        "normalized_shape_equal": True,
        "full_metric_equal": source_metrics == target_metrics,
        "metric_differences": [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ],
        "evidence": [
            "The source and target methods occupy the same local GUI class block.",
            "The target property table points at the reviewed target address.",
            "The decompiled target body preserves the source field access or forwarding behavior.",
            "Normalized ARM64 feature fields match; wrapper substitutions and register allocation differences remain visible in the metric record.",
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
        "artifact": "spectron_gui_drawing_showimg_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual drawing-panel and show-image GUI properties",
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
            "source_components": ["GuiDrawingPanel", "GuiShowImgCtrl"],
            "target_components": ["V8fxgahcBw", "VGk7faT0Ma"],
            "resolution": "class-local order, property-table references, decompiled behavior, and normalized ARM64 feature equality",
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
            "component_counts": {
                component: sum(row["source_component"] == component for row in anchors)
                for component in ("GuiDrawingPanel", "GuiShowImgCtrl")
            },
        },
        "anchors": anchors,
        "reviewed_target_only_rows": [
            {
                "spectron_ea": "0x1e3f60",
                "current_name": "sub_1E3F60",
                "reason": "target-only static filter-string cleanup called by GuiDrawingPanel_onRender; no 1.8 source counterpart was assigned",
            },
            {
                "spectron_ea": "0x1e4d4c",
                "current_name": "sub_1E4D4C",
                "reason": "target-only static animation-string cleanup called by GuiShowImgCtrl_onRender; no 1.8 source counterpart was assigned",
            },
        ],
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ labels preserve readable 1.8 roles while the target ABI names remain in each row.",
            "Two nearby target-only cleanup helpers are recorded explicitly so they are not mistaken for omitted source mappings.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
