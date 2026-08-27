#!/usr/bin/env python3
"""Create a reviewed anchor for the GUI button type-list initializer.

The source callback is default-named in the symbolized database, but the
property table and its three button-type strings identify its role. Spectron
keeps the same table and property behavior under obfuscated globals.
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


SOURCE_EA = 0xE090C
TARGET_EA = 0xE0D10
SOURCE_NAME = "sub_E090C"
TARGET_NAME = "sub_E0D10"
SOURCE_TABLE_EA = "0x35d270"
TARGET_TABLE_EA = "0x36fa68"
SOURCE_PROPERTY_TABLE_EA = "0x3803a0"
TARGET_PROPERTY_TABLE_EA = "0x393400"


EVIDENCE = [
    "The source callback sub_E090C at 0xe090c is referenced by source static-initializer table slot 0x35d270, sets the button-type count to three, points qword_38F790 at the table beginning 0x3804c0, and returns the table address.",
    "The source table at 0x3804c0 contains the three ordered entries PushButton, ToggleButton, and RadioButton with values 1, 2, and the third entry's associated value. The GuiButtonBaseCtrl property table at 0x3803a0 points to the matching get_buttontype and set_buttontype methods.",
    "The target callback sub_E0D10 at 0xe0d10 is referenced by target static-initializer table slot 0x36fa68, sets dword_3A30D8 to three, points qword_3A30E0 at 0x393520, and returns the table address.",
    "The target table at 0x393520 preserves the same PushButton, ToggleButton, and RadioButton order and values. The target property table at 0x393400 points to the translated GuiButtonBaseCtrl property constructor and the target getter and setter at 0x1b1438 and 0x1b1478.",
    "The target callback also initializes qword_3A30E8 as an empty CanTfaz6bZ string. Target cleanup sub_DFFB8 at 0xdffb8, referenced by cleanup table slot 0x36fe48, clears that neighboring string. The extra string lifetime explains the larger target body without changing the button-type table role.",
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
        raise ValueError("GUI button type initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("GUI button type initializer is already manually anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    if target.get("direct_call_names", []) != ["._ZN10CanTfaz6bZaSEPKc"]:
        raise ValueError("unexpected target string-initializer call set")
    if source.get("direct_call_names", []):
        raise ValueError("unexpected source direct calls")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics == target_metrics:
        raise ValueError("GUI button type initializer unexpectedly has an exact shape")
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
        "original_property_table_ea": SOURCE_PROPERTY_TABLE_EA,
        "spectron_ea": target["ea"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_static_initializer_table_ea": TARGET_TABLE_EA,
        "spectron_property_table_ea": TARGET_PROPERTY_TABLE_EA,
        "proposed_name": "v18_GuiButtonBaseCtrl_initializeButtonTypes",
        "confidence": "high",
        "match_kind": "manual-gui-button-type-list-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "GuiButtonBaseCtrl button-type list initializer",
        "context_group": "GuiButtonBaseCtrl property metadata and button-type state",
        "target_class": "GuiButtonBaseCtrl",
        "source_fields": [
            {
                "name": "dword_38F788",
                "address": "0x38f788",
                "role": "button-type count",
            },
            {
                "name": "qword_38F790",
                "address": "0x38f790",
                "role": "button-type table pointer",
            },
            {
                "name": "unk_3804C0",
                "address": "0x3804c0",
                "role": "three-entry button-type table",
            },
        ],
        "spectron_fields": [
            {
                "name": "dword_3A30D8",
                "address": "0x3a30d8",
                "role": "button-type count",
            },
            {
                "name": "qword_3A30E0",
                "address": "0x3a30e0",
                "role": "button-type table pointer",
            },
            {
                "name": "unk_3A30F0",
                "address": "0x393520",
                "role": "three-entry button-type table",
            },
        ],
        "source_button_types": [
            {"name": "PushButton", "value": 0},
            {"name": "ToggleButton", "value": 1},
            {"name": "RadioButton", "value": 2},
        ],
        "spectron_button_types": [
            {"name": "PushButton", "value": 0},
            {"name": "ToggleButton", "value": 1},
            {"name": "RadioButton", "value": 2},
        ],
        "target_only_field": {
            "name": "qword_3A30E8",
            "type": "CanTfaz6bZ",
            "role": "adjacent string initialized to empty and cleared during teardown",
        },
        "target_cleanup": {
            "ea": "0xdffb8",
            "name": "sub_DFFB8",
            "table_ea": "0x36fe48",
        },
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-reviewed-role",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_button_types_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the GuiButtonBaseCtrl button-type list initializer",
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
            "source_class": "GuiButtonBaseCtrl",
            "target_class": "GuiButtonBaseCtrl",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_property_table": SOURCE_PROPERTY_TABLE_EA,
            "spectron_property_table": TARGET_PROPERTY_TABLE_EA,
            "resolution": "matching three-entry PushButton, ToggleButton, and RadioButton tables, count and pointer fields, property callbacks, and target-only adjacent string initialization",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The source and target callbacks build the same three-entry button-type table and preserve its property getter and setter role.",
            "The v18_ alias describes the recovered role while the evidence retains the default names, table addresses, field names, and target-only string cleanup.",
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
