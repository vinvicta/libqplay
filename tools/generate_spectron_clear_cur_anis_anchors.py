#!/usr/bin/env python3
"""Create a reviewed anchor for the current-animation-state cleanup.

The 1.8 callback clears a 248-byte current-animation state object with
vector stores. Spectron initializes the corresponding 248-byte RGiAvaPk9a
object and releases its string fields individually from a later cleanup
table, so the correspondence is semantic rather than an exact instruction
shape match.
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
    "shape_hash",
    "string_refs_hash",
)


SOURCE_EA = 0xE083C
TARGET_EA = 0xDFE08
SOURCE_NAME = "clearCurAnis"
TARGET_NAME = "sub_DFE08"
SOURCE_CALLBACK_TABLE_EA = "0x35d250"
TARGET_CLEANUP_TABLE_EA = "0x36fda0"
TARGET_INITIALIZER_EA = "0xe09e0"
SOURCE_STATE_SLOT_EA = "0x38d5e8"
TARGET_STATE_SLOT_EA = "0x3a0e80"
TARGET_EXTRA_STRING_EA = "0x3a0e70"


EVIDENCE = [
    "The source callback clearCurAnis at 0xe083c is referenced by the source static callback table at 0x35d250 and clears the complete 248-byte curanis state object with vector stores.",
    "The target initializer sub_E09E0 at 0xe09e0 writes the corresponding 248-byte RGiAvaPk9a state object at 0x3a0e80 and is referenced by the target static initializer table at 0x36f9c0.",
    "The target cleanup callback sub_DFE08 at 0xdfe08 is referenced by the target cleanup table at 0x36fda0. Its loop calls C8THgaTQxF::clear on each string-sized field from RGiAvaPk9a through the final field at 0x3a0f70, covering the same 248-byte state extent.",
    "The target cleanup then clears the adjacent CanTfaz6bZ object at qword_3A0E70. The target initializer sets that object to the empty byte_2EA8F0 string before initializing RGiAvaPk9a, so it is part of the same target-side animation-state lifetime group.",
    "The RGiAvaPk9a object is consumed by the target TGraalAni, TPlayer, TServerNPC, TServerPlayer, and TServerFlying animation paths. This matches the source curanis cross-reference family and distinguishes the callback from unrelated static string cleanup.",
    "The target uses explicit C8THgaTQxF and CanTfaz6bZ cleanup calls instead of the source vector-zero implementation. The source and target therefore have different sizes, control flow, call sets, and normalized hashes, but the state extent, initializer, cleanup-table references, and animation consumers provide a high-confidence layout correspondence.",
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
        raise ValueError("current-animation cleanup is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("current-animation cleanup is already manually anchored")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics == target_metrics:
        raise ValueError("current-animation cleanup unexpectedly has an exact shape")
    metric_differences = [
        field
        for field in METRIC_FIELDS
        if source_metrics[field] != target_metrics[field]
    ]
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    if target.get("direct_call_names", []) != ["._ZN10C8THgaTQxF5clearEv"]:
        raise ValueError("unexpected target cleanup call set")

    anchor = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "original_callback_table_ea": SOURCE_CALLBACK_TABLE_EA,
        "spectron_ea": target["ea"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_cleanup_table_ea": TARGET_CLEANUP_TABLE_EA,
        "spectron_initializer_ea": TARGET_INITIALIZER_EA,
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-current-animation-state-cleanup-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "current animation state cleanup",
        "context_group": "current-animation state initialization, cleanup, and consumers",
        "source_state": {
            "slot_ea": SOURCE_STATE_SLOT_EA,
            "logical_name": "curanis",
            "size": 248,
            "last_zeroed_ea": "0x38d6d8",
        },
        "spectron_state": {
            "slot_ea": TARGET_STATE_SLOT_EA,
            "logical_name": "RGiAvaPk9a",
            "size": 248,
            "last_cleared_ea": "0x3a0f70",
            "extra_adjacent_string_ea": TARGET_EXTRA_STRING_EA,
            "extra_adjacent_string_type": "CanTfaz6bZ",
        },
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_clear_cur_anis_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the current-animation-state cleanup callback",
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
            "source_callback_table": SOURCE_CALLBACK_TABLE_EA,
            "source_state": "curanis, 248 bytes",
            "spectron_cleanup_table": TARGET_CLEANUP_TABLE_EA,
            "spectron_initializer": "sub_E09E0 at 0xe09e0",
            "spectron_state": "RGiAvaPk9a, 248 bytes, plus adjacent CanTfaz6bZ",
            "resolution": "matching state extent, target initializer, cleanup-table reference, and animation consumer family",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The target implementation releases string fields individually and clears one adjacent target-only string object, while the source uses vector stores over the same 248-byte state extent.",
            "The v18_ alias preserves the readable source role while the evidence retains the obfuscated target names, addresses, and cleanup implementation.",
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
