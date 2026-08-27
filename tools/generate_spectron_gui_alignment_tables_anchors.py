#!/usr/bin/env python3
"""Create a reviewed anchor for the GuiGraalCtrl alignment tables.

The source callback has no useful ELF name, but its two five-entry tables and
the adjacent GuiGraalCtrl property metadata make the cross-build role clear.
Spectron keeps those tables and adds a neighboring string object to the same
static-state sequence.
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


SOURCE_EA = 0xE0930
TARGET_EA = 0xE0DAC
SOURCE_NAME = "sub_E0930"
TARGET_NAME = "sub_E0DAC"
SOURCE_TABLE_EA = "0x35d278"
TARGET_TABLE_EA = "0x36fa88"
SOURCE_PROPERTY_TABLE_EA = "0x3816d0"
TARGET_PROPERTY_TABLE_EA = "0x394730"


EVIDENCE = [
    "The source callback sub_E0930 at 0xe0930 is referenced by source static-initializer table slot 0x35d278, sets both alignment-list counts to five, publishes the vertical table at 0x381680, publishes the horizontal table at 0x381630, and returns the vertical table address.",
    "The source horizontal table at 0x381630 contains right, width, left, center, and relative with values zero through four. The source vertical table at 0x381680 contains bottom, height, top, center, and relative with the same values.",
    "The source alignment tables sit immediately before the GuiGraalCtrl property record at 0x3816d0. The source GuiGraalCtrlProperties constructor at 0x1bbfc8 registers that record, tying the tables to the GuiGraalCtrl property family rather than to an unrelated list initializer.",
    "The target callback sub_E0DAC at 0xe0dac is referenced by target static-initializer table slot 0x36fa88, sets both alignment-list counts to five, publishes the vertical table at 0x3946e0, publishes the horizontal table at 0x394690, and returns the vertical table address.",
    "The target tables at 0x394690 and 0x3946e0 preserve the same horizontal and vertical label order and values. The target GuiGraalCtrl property record at 0x394730 is registered by v18_GuiGraalCtrlProperties_GuiGraalCtrlProperties_void at 0x1bf8f4.",
    "The target callback also initializes qword_3A31D8 as an empty CanTfaz6bZ string. Target cleanup sub_DFFF0 at 0xdfff0, referenced by cleanup table slot 0x36fe68, clears that neighboring string. This added lifetime explains the larger target body without changing the alignment-table role.",
]


HORIZONTAL_ENTRIES = [
    {"name": "right", "value": 0},
    {"name": "width", "value": 1},
    {"name": "left", "value": 2},
    {"name": "center", "value": 3},
    {"name": "relative", "value": 4},
]

VERTICAL_ENTRIES = [
    {"name": "bottom", "value": 0},
    {"name": "height", "value": 1},
    {"name": "top", "value": 2},
    {"name": "center", "value": 3},
    {"name": "relative", "value": 4},
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
        raise ValueError("alignment initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("alignment initializer is already manually anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    if target.get("direct_call_names", []) != ["._ZN10CanTfaz6bZaSEPKc"]:
        raise ValueError("unexpected target string-initializer call set")
    if source.get("direct_call_names", []):
        raise ValueError("unexpected source direct calls")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics == target_metrics:
        raise ValueError("alignment initializer unexpectedly has an exact shape")
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
        "proposed_name": "v18_GuiGraalCtrl_initializeAlignmentTables",
        "confidence": "high",
        "match_kind": "manual-gui-graal-alignment-table-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "GuiGraalCtrl horizontal and vertical alignment table initializer",
        "context_group": "GuiGraalCtrl property metadata and alignment state",
        "target_class": "GuiGraalCtrl",
        "source_fields": [
            {
                "name": "dword_38F830",
                "address": "0x38f830",
                "role": "vertical alignment count",
            },
            {
                "name": "qword_38F838",
                "address": "0x38f838",
                "role": "vertical alignment table pointer",
            },
            {
                "name": "dword_38F840",
                "address": "0x38f840",
                "role": "horizontal alignment count",
            },
            {
                "name": "qword_38F848",
                "address": "0x38f848",
                "role": "horizontal alignment table pointer",
            },
            {
                "name": "unk_381630",
                "address": "0x381630",
                "role": "five-entry horizontal alignment table",
            },
            {
                "name": "unk_381680",
                "address": "0x381680",
                "role": "five-entry vertical alignment table",
            },
            {
                "name": "unk_2D8E48",
                "address": "0x3816d0",
                "role": "GuiGraalCtrl property metadata record",
            },
        ],
        "spectron_fields": [
            {
                "name": "dword_3A31A0",
                "address": "0x3a31a0",
                "role": "vertical alignment count",
            },
            {
                "name": "qword_3A31A8",
                "address": "0x3a31a8",
                "role": "vertical alignment table pointer",
            },
            {
                "name": "dword_3A31B0",
                "address": "0x3a31b0",
                "role": "horizontal alignment count",
            },
            {
                "name": "qword_3A31B8",
                "address": "0x3a31b8",
                "role": "horizontal alignment table pointer",
            },
            {
                "name": "unk_394690",
                "address": "0x394690",
                "role": "five-entry horizontal alignment table",
            },
            {
                "name": "unk_3946E0",
                "address": "0x3946e0",
                "role": "five-entry vertical alignment table",
            },
            {
                "name": "unk_2E6548",
                "address": "0x394730",
                "role": "GuiGraalCtrl property metadata record",
            },
        ],
        "source_horizontal_entries": HORIZONTAL_ENTRIES,
        "spectron_horizontal_entries": HORIZONTAL_ENTRIES,
        "source_vertical_entries": VERTICAL_ENTRIES,
        "spectron_vertical_entries": VERTICAL_ENTRIES,
        "target_only_field": {
            "name": "qword_3A31D8",
            "type": "CanTfaz6bZ",
            "role": "adjacent string initialized to empty and cleared during teardown",
        },
        "target_cleanup": {
            "ea": "0xdfff0",
            "name": "sub_DFFF0",
            "table_ea": "0x36fe68",
        },
        "source_property_constructor": {
            "ea": "0x1bbfc8",
            "name": "GuiGraalCtrlProperties_GuiGraalCtrlProperties_void",
        },
        "spectron_property_constructor": {
            "ea": "0x1bf8f4",
            "name": "v18_GuiGraalCtrlProperties_GuiGraalCtrlProperties_void",
        },
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-reviewed-role",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_alignment_tables_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the GuiGraalCtrl alignment-table initializer",
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
            "source_class": "GuiGraalCtrl",
            "target_class": "GuiGraalCtrl",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_property_table": SOURCE_PROPERTY_TABLE_EA,
            "spectron_property_table": TARGET_PROPERTY_TABLE_EA,
            "resolution": "matching five-entry horizontal and vertical alignment tables, count and pointer fields, GuiGraalCtrl property metadata, and target-only adjacent string initialization",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The source and target callbacks build the same horizontal and vertical alignment tables and preserve their GuiGraalCtrl property-registration role.",
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
