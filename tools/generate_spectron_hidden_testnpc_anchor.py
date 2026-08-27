#!/usr/bin/env python3
"""Create the reviewed anchor for Spectron's hidden testnpc callback body."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_EA = "0x1a4e98"
SOURCE_NAME = "TServerLevel_script_testNPC"
TARGET_EA = "0x1a9bb0"
TARGET_NAME = "sub_1A9BB0"
EXACT_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "mnemonic_hash",
    "register_shape_hash",
    "shape_hash",
)


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
    return {field: function.get(field) for field in EXACT_FIELDS}


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
    source = original.get(int(SOURCE_EA, 16))
    target = spectron.get(int(TARGET_EA, 16))
    if source is None:
        raise ValueError("missing original testnpc feature")
    if target is None:
        raise ValueError("missing materialized Spectron testnpc feature")
    if source.get("name") != SOURCE_NAME:
        raise ValueError("unexpected original testnpc name")
    if target.get("name") != TARGET_NAME:
        raise ValueError("unexpected materialized Spectron testnpc name")
    if target.get("end_ea") != "0x1a9c2c":
        raise ValueError("unexpected materialized Spectron testnpc end")
    for field in EXACT_FIELDS:
        if source.get(field) != target.get(field):
            raise ValueError("%s mismatch between source and hidden target" % field)
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    if int(TARGET_EA, 16) in semantic_targets:
        raise ValueError("hidden Spectron testnpc target is already in the semantic map")

    anchor = {
        "original_ea": SOURCE_EA,
        "original_name": SOURCE_NAME,
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "spectron_ea": TARGET_EA,
        "spectron_current_name": TARGET_NAME,
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "proposed_name": "v18_" + SOURCE_NAME,
        "confidence": "high",
        "match_kind": "manual-hidden-function-exact-context-anchor",
        "semantic_match_already_present": False,
        "source_basis": "server-level testnpc callback",
        "evidence": [
            "The source callback record at 0x380100 decodes to testnpc and calls the server-level isOnNPC method before returning the matching NPC index.",
            "The target range 0x1a9bb0 through 0x1a9c2c is an unnamed 124-byte code body between the target isOnNPC and getOnNPC methods. Materializing that range gives the same seven-block callback shape.",
            "The target pseudocode calls zF9VgaBKxR::FQ9UgaXTHQ, the obfuscated isOnNPC equivalent, checks the action-player, action-NPC, and universe globals, and returns the matching list index.",
            "All exported body metrics match exactly: 124 bytes, 31 instructions, seven basic blocks, and identical normalized hashes.",
        ],
        "name_action": "rename-with-v18-prefix",
        "target_boundary_materialized": True,
        "target_range_end": "0x1a9c2c",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_hidden_testnpc_manual_translation_anchor_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the unnamed Spectron server-level testnpc callback body",
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
            "target_default_name_count": 1,
            "target_boundary_materialized_count": 1,
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed exact correspondence, not a restored original debug symbol.",
            "The target function boundary was absent from clean IDA, so the explicit 0x1a9bb0 to 0x1a9c2c range is materialized before applying the v18_ label.",
            "The address is valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ label preserves the readable 1.8 role while the evidence row retains the original target default name and boundary range.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
