#!/usr/bin/env python3
"""Create a reviewed anchor for the TGUIRender border-color initializer.

The source callback has no useful ELF name, but its five RGBA defaults are
consumed by the named renderBorder method. Spectron keeps the same values and
consumer while adding one neighboring string object to the static-state
sequence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "register_detail_hash",
    "shape_hash",
    "string_refs_hash",
)


SOURCE_EA = 0xE0984
TARGET_EA = 0xE0F0C
SOURCE_NAME = "sub_E0984"
TARGET_NAME = "sub_E0F0C"
SOURCE_TABLE_EA = "0x35d288"
TARGET_TABLE_EA = "0x36fad0"
SOURCE_COLOR_BASE_EA = "0x38f9e8"
TARGET_COLOR_BASE_EA = "0x3a33a0"


EVIDENCE = [
    "The source callback sub_E0984 at 0xe0984 is referenced by source static-initializer table slot 0x35d288 and writes twenty RGBA float defaults beginning at 0x38f9e8 before returning 1.0.",
    "The source defaults form five ordered colors: white [1.0, 1.0, 1.0, 1.0], black [0.0, 0.0, 0.0, 1.0], 75% gray [0.75, 0.75, 0.75, 1.0], 50% gray [0.5, 0.5, 0.5, 1.0], and 25% gray [0.25, 0.25, 0.25, 1.0].",
    "The source color block is consumed by TGUIRender_renderBorder_TRectangle_const_GuiControlProfile at 0x1cb5e4, which pushes the global color values for the border-style cases.",
    "The target callback sub_E0F0C at 0xe0f0c is referenced by target static-initializer table slot 0x36fad0 and writes the same twenty RGBA defaults beginning at 0x3a33a0 before returning 1.0.",
    "The target color block is consumed by v18_TGUIRender_renderBorder_TRectangle_const_GuiControlProfile at 0x1d016c. Its pseudocode preserves the same four border-style branches and pushes the corresponding target color globals.",
    "The target callback additionally initializes qword_3A33C0 as an empty CanTfaz6bZ string. Target cleanup sub_E0070 at 0xe0070, referenced by cleanup table slot 0x36feb0, clears that neighboring string. This added lifetime explains the larger target body without changing the color-default role.",
]


COLORS = [
    {
        "name": "white",
        "rgba": [1.0, 1.0, 1.0, 1.0],
        "source_address": "0x38f9e8",
        "spectron_address": "0x3a33a0",
    },
    {
        "name": "black",
        "rgba": [0.0, 0.0, 0.0, 1.0],
        "source_address": "0x38f9f8",
        "spectron_address": "0x3a33b0",
    },
    {
        "name": "gray_75_percent",
        "rgba": [0.75, 0.75, 0.75, 1.0],
        "source_address": "0x38fa08",
        "spectron_address": "0x3a33c8",
    },
    {
        "name": "gray_50_percent",
        "rgba": [0.5, 0.5, 0.5, 1.0],
        "source_address": "0x38fa18",
        "spectron_address": "0x3a33d8",
    },
    {
        "name": "gray_25_percent",
        "rgba": [0.25, 0.25, 0.25, 1.0],
        "source_address": "0x38fa28",
        "spectron_address": "0x3a33e8",
    },
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(functions: list[dict]) -> dict[int, dict]:
    return {int(function["ea"], 16): function for function in functions}


def metrics(function: dict) -> dict:
    return {field: function.get(field) for field in METRIC_FIELDS}


def delta_text(target_ea: int, source_ea: int) -> str:
    delta = target_ea - source_ea
    sign = "+" if delta >= 0 else "-"
    return "%s0x%x" % (sign, abs(delta))


def existing_manual_sources(artifact_root: Path, output: Path) -> set[int]:
    result = set()
    for path in artifact_root.glob("spectron_*_manual_translation_anchors_*.json"):
        if path.resolve() == output.resolve():
            continue
        try:
            document = load(path)
        except (OSError, json.JSONDecodeError):
            continue
        for anchor in document.get("anchors", []):
            value = anchor.get("original_ea")
            if isinstance(value, str):
                try:
                    result.add(int(value, 16))
                except ValueError:
                    pass
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    source = original.get(SOURCE_EA)
    target = spectron.get(TARGET_EA)
    if source is None or target is None:
        raise ValueError("missing source or target feature row")
    if source.get("name") != SOURCE_NAME:
        raise ValueError("unexpected source name at 0x%x" % SOURCE_EA)
    if target.get("name") != TARGET_NAME:
        raise ValueError("unexpected target name at 0x%x" % TARGET_EA)
    if not source.get("is_default_name") or not target.get("is_default_name"):
        raise ValueError("source and target must retain default IDA names")

    semantic_sources = {
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    if SOURCE_EA in semantic_sources or TARGET_EA in semantic_targets:
        raise ValueError("TGUIRender color initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("TGUIRender color initializer is already manually anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    if target.get("direct_call_names", []) != ["._ZN10CanTfaz6bZaSEPKc"]:
        raise ValueError("unexpected target string-initializer call set")
    if source.get("direct_call_names", []):
        raise ValueError("unexpected source direct calls")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics == target_metrics:
        raise ValueError("TGUIRender color initializer unexpectedly has an exact shape")
    metric_differences = [
        field
        for field in METRIC_FIELDS
        if source_metrics[field] != target_metrics[field]
    ]
    anchor = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "original_static_initializer_table_ea": SOURCE_TABLE_EA,
        "spectron_ea": target["ea"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_static_initializer_table_ea": TARGET_TABLE_EA,
        "proposed_name": "v18_TGUIRender_initializeBorderColors",
        "confidence": "high",
        "match_kind": "manual-tgui-render-color-initializer-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TGUIRender border-color default initializer",
        "context_group": "TGUIRender border rendering and color state",
        "target_class": "TGUIRender",
        "source_color_base_ea": SOURCE_COLOR_BASE_EA,
        "spectron_color_base_ea": TARGET_COLOR_BASE_EA,
        "source_fields": [
            {
                "name": "dword_38F9E8",
                "address": "0x38f9e8",
                "role": "first RGBA default color",
            },
            {
                "name": "dword_38F9F8",
                "address": "0x38f9f8",
                "role": "second RGBA default color",
            },
            {
                "name": "dword_38FA08",
                "address": "0x38fa08",
                "role": "third RGBA default color",
            },
            {
                "name": "dword_38FA18",
                "address": "0x38fa18",
                "role": "fourth RGBA default color",
            },
            {
                "name": "dword_38FA28",
                "address": "0x38fa28",
                "role": "fifth RGBA default color",
            },
        ],
        "spectron_fields": [
            {
                "name": "dword_3A33A0",
                "address": "0x3a33a0",
                "role": "first RGBA default color",
            },
            {
                "name": "dword_3A33B0",
                "address": "0x3a33b0",
                "role": "second RGBA default color",
            },
            {
                "name": "dword_3A33C8",
                "address": "0x3a33c8",
                "role": "third RGBA default color",
            },
            {
                "name": "dword_3A33D8",
                "address": "0x3a33d8",
                "role": "fourth RGBA default color",
            },
            {
                "name": "dword_3A33E8",
                "address": "0x3a33e8",
                "role": "fifth RGBA default color",
            },
        ],
        "source_consumer": {
            "ea": "0x1cb5e4",
            "name": "TGUIRender_renderBorder_TRectangle_const_GuiControlProfile",
        },
        "spectron_consumer": {
            "ea": "0x1d016c",
            "name": "v18_TGUIRender_renderBorder_TRectangle_const_GuiControlProfile",
        },
        "colors": COLORS,
        "target_only_field": {
            "name": "qword_3A33C0",
            "type": "CanTfaz6bZ",
            "role": "adjacent string initialized to empty and cleared during teardown",
        },
        "target_cleanup": {
            "ea": "0xe0070",
            "name": "sub_E0070",
            "table_ea": "0x36feb0",
        },
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-reviewed-role",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_tgui_render_colors_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TGUIRender border-color initializer",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "summary": {
            "anchor_count": 1,
            "high_confidence_count": 1,
            "already_in_semantic_map": 0,
            "new_context_anchor_count": 1,
            "exact_shape_anchor_count": 0,
            "layout_change_anchor_count": 1,
            "target_default_name_count": 1,
        },
        "context": {
            "source_class": "TGUIRender",
            "target_class": "TGUIRender",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_consumer": "TGUIRender_renderBorder_TRectangle_const_GuiControlProfile",
            "spectron_consumer": "v18_TGUIRender_renderBorder_TRectangle_const_GuiControlProfile",
            "resolution": "matching twenty RGBA defaults, border-render consumer, static-table slots, and target-only adjacent string initialization",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The source and target callbacks publish the same five border-color defaults consumed by the corresponding TGUIRender renderBorder routine.",
            "The v18_ alias describes the recovered role while the evidence retains the default names, color field ranges, consumer addresses, and target-only string cleanup.",
            "The alias is valid only for the exact hashed Spectron library recorded in this artifact. It changes the IDA analysis copy only; no APK or native library is modified.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
