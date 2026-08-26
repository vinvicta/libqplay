#!/usr/bin/env python3
"""Record a reviewed Spectron tail-thunk whose function boundary was missing."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_EA = 0x1E96C0
SOURCE_NAME = "TClient_parseSetEncryptionIn_TString_const"
TARGET_EA = 0x1EDB80
TARGET_END_EA = 0x1EDB9C
TARGET_NAME = "_Z10YvswSaABVtRK10C8THgaTQxF"
TARGET_HEX = (
    "e10300aac00c00f000e040f9000040f9400000b44bb9fb17c0035fd6"
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--spectron-binary", required=True, type=Path)
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
    next_target = spectron.get(TARGET_END_EA)
    if source is None:
        raise ValueError("missing original feature at 0x1e96c0")
    if source.get("name") != SOURCE_NAME:
        raise ValueError("unexpected original function name at 0x1e96c0")
    if target is None or target.get("name") != TARGET_NAME:
        raise ValueError("unexpected target thunk feature at 0x1edb80")
    for field, expected in (
        ("size", TARGET_END_EA - TARGET_EA),
        ("instruction_count", 7),
        ("basic_block_count", 4),
    ):
        if target.get(field) != expected:
            raise ValueError(
                "target thunk %s mismatch: expected %s, got %s"
                % (field, expected, target.get(field))
            )
    if next_target is None or next_target.get("name") != "sub_1EDB9C":
        raise ValueError("target thunk end does not meet the next helper boundary")

    target_bytes = args.spectron_binary.read_bytes()[TARGET_EA:TARGET_END_EA]
    target_hex = target_bytes.hex()
    if target_hex != TARGET_HEX:
        raise ValueError(
            "target thunk bytes changed: expected %s, got %s"
            % (TARGET_HEX, target_hex)
        )

    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    anchor = {
        "original_ea": "0x1e96c0",
        "original_name": SOURCE_NAME,
        "original_size": source["size"],
        "original_instruction_count": source["instruction_count"],
        "original_basic_block_count": source["basic_block_count"],
        "original_string_refs": source.get("string_refs", []),
        "spectron_ea": "0x1edb80",
        "spectron_end_ea": "0x1edb9c",
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_size": target["size"],
        "spectron_instruction_count": target["instruction_count"],
        "spectron_basic_block_count": target["basic_block_count"],
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_target_boundary_before_apply": "present in the exported IDA function list",
        "target_function_kind": "tail-thunk",
        "target_bytes_hex": target_hex,
        "target_bytes_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "proposed_name": "v18_" + SOURCE_NAME,
        "confidence": "high",
        "match_kind": "manual-reconstructed-tail-thunk",
        "semantic_match_already_present": TARGET_EA in semantic_targets,
        "source_basis": "client encryption-in forwarding wrapper",
        "evidence": [
            "The source loads the global client object, checks it, and forwards the supplied TString to the connection encryption-in parser.",
            "The target block is a seven-instruction AArch64 wrapper with the same global-client load, null check, and tail branch shape.",
            "IDA had not assigned the target block a function boundary; it ends exactly at the next reviewed event helper at 0x1edb9c.",
            "The raw bytes are recorded so the reconstructed boundary can be checked independently of the IDA export.",
        ],
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_parse_wrapper_manual_translation_anchor_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 tail-thunk for client encryption-in forwarding",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "summary": {
            "anchor_count": 1,
            "high_confidence_count": 1,
            "already_in_semantic_map": int(TARGET_EA in semantic_targets),
            "new_context_anchor_count": int(TARGET_EA not in semantic_targets),
            "target_default_name_count": 0,
            "tail_thunk_count": 1,
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed tail-thunk correspondence, not a recovered original debug symbol.",
            "The target address and end address are valid only for the exact hashed Spectron library named in this artifact.",
            "The stored raw bytes provide an independent check for the tail-thunk boundary and prevent a later IDA reanalysis from silently moving it.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
