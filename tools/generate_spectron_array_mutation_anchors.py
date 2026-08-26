#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for array mutation helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x21c4d8",
        "original_name": "TScriptMachine_setArrayCell_void",
        "spectron_ea": "0x224560",
        "target_name_fragment": "mTAogaaEip10PmFMOaYpykEv",
        "source_basis": "single array-cell assignment",
        "evidence": [
            "Both consume and normalize the array index, resolve the value entry, dispatch numeric, string, or object writes through the array vtable, and unwind the remaining stack entries.",
            "Both preserve the same 19-block assignment flow. The target grows from 332 to 368 bytes around changed array and string wrappers while retaining the type-specific setter order.",
        ],
    },
    {
        "original_ea": "0x21c7c0",
        "original_name": "TScriptMachine_setArrayCell2_void",
        "spectron_ea": "0x224868",
        "target_name_fragment": "mTAogaaEip10LFsMOaTJnkEv",
        "source_basis": "two-dimensional array-cell assignment",
        "evidence": [
            "Both normalize two indexes, resolve the nested array value, handle the quoted string special case, and dispatch numeric, string, or object writes through the typed array setter.",
            "Both unwind four consumed stack values and preserve the same 26-block nested-array control flow. The target grows from 568 to 636 bytes around changed wrappers.",
        ],
    },
    {
        "original_ea": "0x21cd88",
        "original_name": "TScriptMachine_arrayReplace_void",
        "spectron_ea": "0x224e78",
        "target_name_fragment": "mTAogaaEip10DVzLOadQDjEv",
        "source_basis": "array replacement assignment",
        "evidence": [
            "Both normalize the replacement index, resolve the destination array and value, and use the typed setter for float, string, or object values.",
            "Both preserve the out-of-range replacement behavior, stack unwinding, and 30-block branch structure. The target grows from 528 to 556 bytes around changed value wrappers.",
        ],
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
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "mnemonic_hash",
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
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        target_name = target.get("name", "")
        if spec["target_name_fragment"] not in target_name:
            raise ValueError(
                "target %s does not retain expected signature fragment: %s"
                % (spec["spectron_ea"], spec["target_name_fragment"])
            )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target_name,
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-array-mutation-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in array-mutation anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_array_mutation_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for single-cell, two-dimensional, and replacement array mutation",
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
            "anchor_count": len(anchors),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": sum(
                row["semantic_match_already_present"] for row in anchors
            ),
            "new_context_anchor_count": sum(
                not row["semantic_match_already_present"] for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated 2.2 name in the evidence row.",
            "The changed-size rows rely on typed setter order, stack unwinding, class-local sequence, and pseudocode behavior rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
