#!/usr/bin/env python3
"""Create a reviewed anchor for the displayed-GIF static initializer.

The source callback initializes the shared displayed-GIF pointer. Spectron
keeps the same state role under an obfuscated global, but also initializes a
neighboring string object in the same callback.
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


SOURCE_EA = 0xE08FC
TARGET_EA = 0xE0B80
SOURCE_NAME = "initializeDisplayedGif"
TARGET_NAME = "sub_E0B80"
SOURCE_TABLE_EA = "0x35d268"
TARGET_TABLE_EA = "0x36f9f8"
SOURCE_CLEANUP_EA = "0xe05e0"
SOURCE_CLEANUP_TABLE_EA = "0x35d2e0"
TARGET_CLEANUP_EA = "0xdfed4"
TARGET_CLEANUP_TABLE_EA = "0x36fdd8"


EVIDENCE = [
    "The source callback initializeDisplayedGif at 0xe08fc is referenced by source static-initializer table slot 0x35d268 and stores null through displayedgif_ptr at 0x374cd8 into displayedgif at 0x38ede8 before returning its address.",
    "The target function sub_E0B80 at 0xe0b80 is referenced by target static-initializer table slot 0x36f9f8 and initializes DiZVgajboR through DiZVgajboR_ptr at 0x387d08 before returning its address.",
    "The source displayedgif global and target DiZVgajboR global are consumed by the same translated player, server-player, explosion, bomb, carry, and extra-object draw families, including the same pointer-indirection pattern.",
    "The source cleanup callback sub_E05E0 at 0xe05e0 is referenced by cleanup table slot 0x35d2e0 and clears displayedgif. The target cleanup callback sub_DFED4 at 0xdfed4 is referenced by slot 0x36fdd8 and clears DiZVgajboR before clearing the neighboring target-only CanTfaz6bZ object at qword_3A26A8.",
    "The target callback also initializes qword_3A26A8 as an empty CanTfaz6bZ string. This target-only neighboring field explains the additional assignment call and larger body while the displayed-GIF pointer remains the returned state value.",
]


SOURCE_CONSUMERS = [
    {
        "name": "TPlayer_drawSpriteAbsoluteOffset_int_int_int_int_int",
        "ea": "0x17ba34",
    },
    {"name": "TPlayer_drawStatusBar_void", "ea": "0x17c57c"},
    {"name": "TPlayer_draw_TPlayer", "ea": "0x17ff04"},
    {"name": "TServerPlayer_drawCarry_TPlayer", "ea": "0x18bfac"},
    {"name": "TServerPlayer_draw_TPlayer", "ea": "0x18d0fc"},
    {"name": "TExplosion_draw_TPlayer", "ea": "0x23c910"},
    {"name": "TServerBomb_draw_TPlayer", "ea": "0x23d02c"},
    {"name": "TServerCarry_draw_TPlayer", "ea": "0x23d4d8"},
    {"name": "TServerExtra_draw_TPlayer", "ea": "0x23e7cc"},
]

TARGET_CONSUMERS = [
    {
        "name": "v18_TPlayer_drawSpriteAbsoluteOffset_int_int_int_int_int",
        "ea": "0x17fddc",
    },
    {"name": "v18_TPlayer_drawStatusBar_void", "ea": "0x180924"},
    {"name": "v18_TPlayer_draw_TPlayer", "ea": "0x18446c"},
    {"name": "v18_TServerPlayer_drawCarry_TPlayer", "ea": "0x19085c"},
    {"name": "v18_TServerPlayer_draw_TPlayer", "ea": "0x1919fc"},
    {"name": "v18_TExplosion_draw_TPlayer", "ea": "0x2467c0"},
    {"name": "v18_TServerBomb_draw_TPlayer", "ea": "0x246f44"},
    {"name": "v18_TServerCarry_draw_TPlayer", "ea": "0x2473f0"},
    {"name": "v18_TServerExtra_draw_TPlayer", "ea": "0x248754"},
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
        raise ValueError("displayed-GIF initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("displayed-GIF initializer is already manually anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    if target.get("direct_call_names", []) != ["._ZN10CanTfaz6bZaSEPKc"]:
        raise ValueError("unexpected target string-initializer call set")
    if source.get("direct_call_names", []):
        raise ValueError("unexpected source direct calls")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics == target_metrics:
        raise ValueError("displayed-GIF initializer unexpectedly has an exact shape")
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
        "original_cleanup_ea": "0xe05e0",
        "original_cleanup_table_ea": SOURCE_CLEANUP_TABLE_EA,
        "spectron_ea": target["ea"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_static_initializer_table_ea": TARGET_TABLE_EA,
        "spectron_cleanup_ea": "0xdfed4",
        "spectron_cleanup_table_ea": TARGET_CLEANUP_TABLE_EA,
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-displayed-gif-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "shared displayed-GIF static initializer and cleanup",
        "context_group": "displayed GIF state and draw consumers",
        "source_fields": [
            {
                "name": "displayedgif",
                "address": "0x38ede8",
                "pointer_slot": "0x374cd8",
                "role": "shared displayed-GIF state",
            }
        ],
        "spectron_fields": [
            {
                "name": "DiZVgajboR",
                "address": "0x3a26c8",
                "pointer_slot": "0x387d08",
                "role": "shared displayed-GIF state",
            }
        ],
        "target_only_field": {
            "name": "qword_3A26A8",
            "type": "CanTfaz6bZ",
            "role": "adjacent string initialized to empty and cleared during teardown",
        },
        "source_consumers": SOURCE_CONSUMERS,
        "spectron_consumers": TARGET_CONSUMERS,
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_displayed_gif_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the displayed-GIF static initializer",
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
            "source_state": "displayedgif",
            "target_state": "DiZVgajboR",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_cleanup_table": SOURCE_CLEANUP_TABLE_EA,
            "spectron_cleanup_table": TARGET_CLEANUP_TABLE_EA,
            "resolution": "matching initializer and cleanup state, pointer indirection, draw-consumer family, and target-only adjacent string initialization",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The target keeps the shared displayed-GIF state but initializes an adjacent CanTfaz6bZ field in the same callback, which accounts for the larger implementation.",
            "The v18_ alias preserves the readable source role while the evidence retains the obfuscated target global, pointer slot, cleanup callback, and default name.",
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
