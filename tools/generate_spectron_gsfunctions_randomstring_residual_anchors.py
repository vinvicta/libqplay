#!/usr/bin/env python3
"""Create a reviewed anchor for the residual randomstring callback."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source row is GSFunctionsInitstaticscriptvars_script_randomstring at 0x20cd34. Its source script-table code pointer is stored at 0x3872c0, immediately after the strequals callback in the same static GSFunctions table.",
    "The target table stores the corresponding code pointer at 0x39a3e0, immediately after the target strequals entry at 0x210f58. The target callback begins at 0x2130c4 and remains a normal IDA function boundary.",
    "Both bodies recognize a trailing comma, remove it before constructing a TStringList, choose an entry with rand modulo the list count, append the selected string to the output, and destroy the temporary list. The target uses C8THgaTQxF and vuuHgangcF wrappers for the same operations.",
    "The target grows from 260 to 264 bytes and from 65 to 66 instructions while preserving 9 basic blocks, 17 branches, 12 calls, one return, and the same table role. This is a high-confidence table-order correspondence with a small wrapper-induced layout change.",
]


SOURCE_EA = 0x20CD34
TARGET_EA = 0x2130C4
SOURCE_NAME = "GSFunctionsInitstaticscriptvars_script_randomstring"
TARGET_NAME = "sub_2130C4"


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
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
        )
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
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
        raise ValueError("missing source or target feature")
    if source.get("name") != SOURCE_NAME or target.get("name") != TARGET_NAME:
        raise ValueError("unexpected source or target name")
    semantic_sources = {int(row["original_ea"], 16) for row in semantic_document.get("matches", [])}
    semantic_targets = {int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])}
    if SOURCE_EA in semantic_sources or TARGET_EA in semantic_targets:
        raise ValueError("randomstring is already in the semantic map")
    shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
    if shape_equal:
        raise ValueError("randomstring unexpectedly has exact normalized shape")

    anchor = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": "0x%x" % TARGET_EA,
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-gsfunctions-randomstring-table-context-anchor",
        "semantic_match_already_present": False,
        "source_basis": "GSFunctions script callback %s" % source["name"],
        "context_group": "GSFunctions randomstring residual callback",
        "context_order": 1,
        "target_delta": "+0x%x" % (TARGET_EA - SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": shape_equal,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_gsfunctions_randomstring_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the residual GSFunctions randomstring callback",
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
            "target_default_name_count": int(target.get("is_default_name", False)),
            "materialized_target_function_count": 0,
        },
        "context": {
            "source_sequence": "0x20cd34 randomstring after the 0x20ad58 strequals table entry",
            "target_sequence": "0x2130c4 randomstring after the 0x210f58 strequals table entry",
            "source_class": "GSFunctions static script callback table",
            "target_class": "obfuscated C8THgaTQxF and vuuHgangcF string-list wrappers",
            "target_only_boundaries": [],
            "following_target_boundary": "the later GSFunctions table entries continue after the randomstring slot",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ label preserves the readable 1.8 script role while retaining the target default name in the evidence row.",
            "The small size and instruction-count difference is treated as a layout change caused by the target string and list wrappers, not as a role mismatch.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
