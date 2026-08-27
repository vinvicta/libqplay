#!/usr/bin/env python3
"""Create a reviewed anchor for the GuiStretchCtrl mode table initializer.

The source callback is default-named, but its three ordered mode entries and
the nearby GuiStretchCtrl property record identify the role. Spectron keeps
the same table and adds one neighboring string object to the static-state
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


SOURCE_EA = 0xE0960
TARGET_EA = 0xE0E54
SOURCE_NAME = "sub_E0960"
TARGET_NAME = "sub_E0E54"
SOURCE_TABLE_EA = "0x35d280"
TARGET_TABLE_EA = "0x36faa8"
SOURCE_PROPERTY_TABLE_EA = "0x382090"
TARGET_PROPERTY_TABLE_EA = "0x3950f0"


EVIDENCE = [
    "The source callback sub_E0960 at 0xe0960 is referenced by source static-initializer table slot 0x35d280, sets the mode count at dword_38F8F8 to three, publishes the table at 0x382060 through qword_38F900, and returns the table address.",
    "The source table at 0x382060 contains the ordered alwaysOn, alwaysOff, and dynamic entries with values zero, one, and two. The following property record at 0x382090 is registered by GuiStretchCtrlProperties_GuiStretchCtrlProperties_void at 0x1c5470 with a three-record property table.",
    "The target callback sub_E0E54 at 0xe0e54 is referenced by target static-initializer table slot 0x36faa8, sets dword_3A3288 to three, publishes the table at 0x3950c0 through qword_3A3290, and returns the table address.",
    "The target table at 0x3950c0 preserves the same alwaysOn, alwaysOff, and dynamic order and values. The target property record at 0x3950f0 is registered by v18_GuiStretchCtrlProperties_GuiStretchCtrlProperties_void at 0x1c9f4c, and its decoded properties remain clientextent, clientheight, and clientwidth.",
    "The target callback also initializes qword_3A32D8 as an empty CanTfaz6bZ string. Target cleanup sub_E0028 at 0xe0028, referenced by cleanup table slot 0x36fe88, clears that neighboring string. This added lifetime explains the larger target body without changing the mode-table role.",
]


MODE_ENTRIES = [
    {"name": "alwaysOn", "value": 0},
    {"name": "alwaysOff", "value": 1},
    {"name": "dynamic", "value": 2},
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
        raise ValueError("stretch-mode initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("stretch-mode initializer is already manually anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    if target.get("direct_call_names", []) != ["._ZN10CanTfaz6bZaSEPKc"]:
        raise ValueError("unexpected target string-initializer call set")
    if source.get("direct_call_names", []):
        raise ValueError("unexpected source direct calls")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics == target_metrics:
        raise ValueError("stretch-mode initializer unexpectedly has an exact shape")
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
        "proposed_name": "v18_GuiStretchCtrl_initializeSizingModes",
        "confidence": "high",
        "match_kind": "manual-gui-stretch-mode-table-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "GuiStretchCtrl mode-table initializer",
        "context_group": "GuiStretchCtrl property metadata and sizing mode state",
        "target_class": "GuiStretchCtrl",
        "source_fields": [
            {
                "name": "dword_38F8F8",
                "address": "0x38f8f8",
                "role": "sizing-mode count",
            },
            {
                "name": "qword_38F900",
                "address": "0x38f900",
                "role": "sizing-mode table pointer",
            },
            {
                "name": "unk_382060",
                "address": "0x382060",
                "role": "three-entry sizing-mode table",
            },
            {
                "name": "unk_2D8C10",
                "address": "0x382090",
                "role": "GuiStretchCtrl property metadata record",
            },
        ],
        "spectron_fields": [
            {
                "name": "dword_3A3288",
                "address": "0x3a3288",
                "role": "sizing-mode count",
            },
            {
                "name": "qword_3A3290",
                "address": "0x3a3290",
                "role": "sizing-mode table pointer",
            },
            {
                "name": "unk_3950C0",
                "address": "0x3950c0",
                "role": "three-entry sizing-mode table",
            },
            {
                "name": "unk_2E6310",
                "address": "0x3950f0",
                "role": "GuiStretchCtrl property metadata record",
            },
        ],
        "source_mode_entries": MODE_ENTRIES,
        "spectron_mode_entries": MODE_ENTRIES,
        "source_property_names": ["clientextent", "clientheight", "clientwidth"],
        "spectron_property_names": ["clientextent", "clientheight", "clientwidth"],
        "target_only_field": {
            "name": "qword_3A32D8",
            "type": "CanTfaz6bZ",
            "role": "adjacent string initialized to empty and cleared during teardown",
        },
        "target_cleanup": {
            "ea": "0xe0028",
            "name": "sub_E0028",
            "table_ea": "0x36fe88",
        },
        "source_property_constructor": {
            "ea": "0x1c5470",
            "name": "GuiStretchCtrlProperties_GuiStretchCtrlProperties_void",
        },
        "spectron_property_constructor": {
            "ea": "0x1c9f4c",
            "name": "v18_GuiStretchCtrlProperties_GuiStretchCtrlProperties_void",
        },
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-reviewed-role",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_stretch_modes_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the GuiStretchCtrl mode-table initializer",
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
            "source_class": "GuiStretchCtrl",
            "target_class": "GuiStretchCtrl",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_property_table": SOURCE_PROPERTY_TABLE_EA,
            "spectron_property_table": TARGET_PROPERTY_TABLE_EA,
            "resolution": "matching three-entry alwaysOn, alwaysOff, and dynamic mode tables, count and pointer fields, GuiStretchCtrl property metadata, and target-only adjacent string initialization",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The source and target callbacks build the same three-entry GuiStretchCtrl mode table and preserve its property-registration context.",
            "The v18_ alias describes the recovered role while the evidence retains the default names, table addresses, field names, decoded property names, and target-only string cleanup.",
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
