#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for lookup helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1e7650",
        "original_name": "TClient_getGlobalPlayerByID_int",
        "spectron_ea": "0x1eb9d8",
        "target_name": "_ZN10w6qzgacqqy10IaubyaF_gnEi",
        "expected_target_size": 132,
        "expected_target_instruction_count": 33,
        "expected_target_basic_block_count": 6,
        "source_basis": "active-player list lookup by numeric id",
        "evidence": [
            "Both bodies scan the active-player list from index zero, compare the player id field, and return the matching object or null.",
            "The target preserves the six-block loop shape and the same relative position between the client constructor and account-name lookup helpers.",
            "Only the obfuscated class, list, field, and helper names differ between the decompilations.",
        ],
    },
    {
        "original_ea": "0x1e7794",
        "original_name": "TClient_getDeletedPlayerByID_int",
        "spectron_ea": "0x1ebb1c",
        "target_name": "_ZN10w6qzgacqqy10x2BbyaRCnnEi",
        "expected_target_size": 132,
        "expected_target_instruction_count": 33,
        "expected_target_basic_block_count": 6,
        "source_basis": "deleted-player list lookup by numeric id",
        "evidence": [
            "Both bodies scan the deleted-player list from index zero, compare the player id field, and return the matching object or null.",
            "The target preserves the six-block loop shape and its position before the already translated cached-player lookup wrapper.",
            "The target uses a distinct obfuscated deleted-player list static while retaining the same loop and object-field offsets relative to its build.",
        ],
    },
    {
        "original_ea": "0x1e8150",
        "original_name": "TClient_findDownloadFile_TString_const",
        "spectron_ea": "0x1ec56c",
        "target_name": "_ZN10w6qzgacqqy10MiD5xayGliERK10C8THgaTQxF",
        "expected_target_size": 156,
        "expected_target_instruction_count": 39,
        "expected_target_basic_block_count": 6,
        "source_basis": "download-file list lookup by case-insensitive name",
        "evidence": [
            "Both bodies scan the download-file list, compare each stored name case-insensitively with the requested string, and return the matching entry or null.",
            "The target preserves the six-block loop and sits immediately before the already translated download-progress helper.",
            "The target signature retains the one const TString reference and only the obfuscated container and comparison helper names differ.",
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
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: expected %s, got %s"
                % (spec["spectron_ea"], spec["target_name"], target.get("name"))
            )
        for field in ("size", "instruction_count", "basic_block_count"):
            expected = spec["expected_target_" + field]
            if target.get(field) != expected:
                raise ValueError(
                    "target %s %s mismatch: expected %s, got %s"
                    % (spec["spectron_ea"], field, expected, target.get(field))
                )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_size": source["size"],
                "original_instruction_count": source["instruction_count"],
                "original_basic_block_count": source["basic_block_count"],
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_size": target["size"],
                "spectron_instruction_count": target["instruction_count"],
                "spectron_basic_block_count": target["basic_block_count"],
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-lookup-helper-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in lookup helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_lookup_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for player and download list lookup helpers",
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
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated target name in the evidence row.",
            "The lookup bodies preserve their loops and list roles even though the obfuscated build changes static and helper names.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
