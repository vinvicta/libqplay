#!/usr/bin/env python3
"""Create a reviewed anchor for the TOptions window-position initializer.

The source callback writes -1 to both window-position coordinates. Spectron
keeps the same two-coordinate initialization in the obfuscated K7FLgag3II
options state and adds initialization for an adjacent string field.
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


SOURCE_EA = 0xE08E4
TARGET_EA = 0xE0B3C
SOURCE_NAME = "TOptions_initializeWindowPosition"
TARGET_NAME = "sub_E0B3C"
SOURCE_TABLE_EA = "0x35d260"
TARGET_TABLE_EA = "0x36f9f0"


EVIDENCE = [
    "The source callback TOptions_initializeWindowPosition at 0xe08e4 is referenced by source static-initializer table slot 0x35d260 and writes -1 to both TOptions::windowpos coordinates at 0x38e0c0 and 0x38e0c4.",
    "The target function sub_E0B3C at 0xe0b3c is referenced by target static-initializer table slot 0x36f9f0 and writes -1 to the adjacent K7FLgag3II fields y3nkMaCRLg at 0x3a1988 and dword_3A198C at 0x3a198c.",
    "K7FLgag3II is independently established as the Spectron TOptions class by the translated options methods and static initializer, including the target fields used by account, credential, GUI-style, and option-persistence paths.",
    "The target callback also initializes qword_3A1918 as an empty CanTfaz6bZ string. This is a target-only neighboring field and explains the additional assignment call and larger body without changing the two-coordinate role.",
    "Both callbacks return the address of the first initialized coordinate. The source is a six-instruction direct store sequence, while the target preserves the two -1 stores but includes the target string assignment before them.",
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
    if not target.get("is_default_name"):
        raise ValueError("target is not a default IDA name")

    semantic_sources = {
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    if SOURCE_EA in semantic_sources or TARGET_EA in semantic_targets:
        raise ValueError("window-position initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("window-position initializer is already manually anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    expected_target_calls = ["._ZN10CanTfaz6bZaSEPKc"]
    if target.get("direct_call_names", []) != expected_target_calls:
        raise ValueError("unexpected target string-initializer call set")
    if source.get("direct_call_names", []):
        raise ValueError("unexpected source direct calls")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics == target_metrics:
        raise ValueError("window-position initializer unexpectedly has an exact shape")
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
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-options-window-position-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TOptions window-position static initializer",
        "context_group": "TOptions global state and static initialization",
        "target_class": "K7FLgag3II",
        "source_fields": [
            {
                "name": "data_TOptions_windowpos",
                "address": "0x38e0c0",
                "role": "window position first coordinate",
            },
            {
                "name": "dword_38E0C4",
                "address": "0x38e0c4",
                "role": "window position second coordinate",
            },
        ],
        "spectron_fields": [
            {
                "name": "y3nkMaCRLg",
                "address": "0x3a1988",
                "role": "window position first coordinate",
            },
            {
                "name": "dword_3A198C",
                "address": "0x3a198c",
                "role": "window position second coordinate",
            },
        ],
        "target_only_field": {
            "name": "qword_3A1918",
            "type": "CanTfaz6bZ",
            "role": "adjacent string initialized to empty",
        },
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_options_window_position_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TOptions window-position static initializer",
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
            "source_class": "TOptions",
            "target_class": "K7FLgag3II",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "resolution": "matching two -1 coordinate stores, target options class, static-table references, and target-only adjacent string initialization",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The target keeps the two window-position defaults but initializes an adjacent CanTfaz6bZ field in the same callback, which accounts for the larger implementation.",
            "The v18_ alias preserves the readable source role while the evidence retains the obfuscated target class, fields, and default name.",
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
