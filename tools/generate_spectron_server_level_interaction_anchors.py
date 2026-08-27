#!/usr/bin/env python3
"""Create reviewed anchors for Spectron server-level interaction helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x19fcdc",
        "original_name": "TServerLevelLink_getDestY",
        "spectron_ea": "0x1a49b4",
        "target_name_fragment": "sub_1A49B4",
        "source_basis": "server-level-link destination Y getter",
        "source_basic_block_count": 7,
        "spectron_basic_block_count": 7,
        "required_string_refs": ["playerx", "playery"],
        "exact_metrics": True,
        "evidence": [
            "Both return the explicit destination Y value unless it is the playerx or playery token, in which case they forward the matching active-player coordinate; they fall back to numeric string conversion when no active player exists.",
            "The source callback record at 0x37fa10 decodes to desty and has no setter; the target keeps the corresponding level-link getter and the playerx and playery literals.",
            "All exported body metrics match exactly: 172 bytes, 43 instructions, seven blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19fd88",
        "original_name": "TServerLevelLink_getDestX",
        "spectron_ea": "0x1a4a60",
        "target_name_fragment": "sub_1A4A60",
        "source_basis": "server-level-link destination X getter",
        "source_basic_block_count": 7,
        "spectron_basic_block_count": 7,
        "required_string_refs": ["playerx", "playery"],
        "exact_metrics": True,
        "evidence": [
            "Both return the explicit destination X value unless it is the playerx or playery token, in which case they forward the matching active-player coordinate; they fall back to numeric string conversion when no active player exists.",
            "The source callback record at 0x37f9e0 decodes to destx and has no setter; the target keeps the corresponding level-link getter and the playerx and playery literals.",
            "All exported body metrics match exactly: 172 bytes, 43 instructions, seven blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19ff84",
        "original_name": "TServerLevel_script_removeExplo",
        "spectron_ea": "0x1a4c5c",
        "target_name_fragment": "sub_1A4C5C",
        "source_basis": "server-level indexed explosion removal",
        "source_basic_block_count": 5,
        "spectron_basic_block_count": 5,
        "required_string_refs": [],
        "exact_metrics": True,
        "evidence": [
            "Both reject negative or out-of-range indexes, delete the indexed explosion from the same logical list, and invoke the removed object's virtual cleanup path.",
            "The source callback record at 0x37ffb0 decodes exactly to the legacy script name removeexplo; the target keeps the matching indexed-list callback reference.",
            "All exported body metrics match exactly: 100 bytes, 25 instructions, five blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19ffe8",
        "original_name": "TServerLevel_script_removeBomb",
        "spectron_ea": "0x1a4cc0",
        "target_name_fragment": "sub_1A4CC0",
        "source_basis": "server-level indexed bomb removal and client notification",
        "source_basic_block_count": 10,
        "spectron_basic_block_count": 8,
        "required_string_refs": [],
        "exact_metrics": False,
        "evidence": [
            "Both reject negative or out-of-range indexes, delete the indexed bomb from the action-player level list, read its coordinates, notify the client with the remove-bomb packet when a client exists, and release the removed object.",
            "The source callback record at 0x37ff80 decodes to removebomb; the target has the matching callback reference at 0x392ff8.",
            "The target changes the body from 196 bytes and 10 blocks to 196 bytes and eight blocks. Its pseudocode preserves the same list, coordinate, notification, and cleanup phases with rebuilt wrappers.",
        ],
    },
    {
        "original_ea": "0x1a00ac",
        "original_name": "TServerLevel_script_removeArrow",
        "spectron_ea": "0x1a4d84",
        "target_name_fragment": "sub_1A4D84",
        "source_basis": "server-level indexed arrow removal",
        "source_basic_block_count": 5,
        "spectron_basic_block_count": 5,
        "required_string_refs": [],
        "exact_metrics": True,
        "evidence": [
            "Both reject negative or out-of-range indexes, delete the indexed arrow from the same logical list, and invoke the removed object's virtual cleanup path.",
            "The source callback record at 0x37ff50 decodes to removearrow; the target keeps the matching callback reference at 0x392fc8.",
            "All exported body metrics match exactly: 100 bytes, 25 instructions, five blocks, and identical normalized hashes.",
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
    exact_fields = (
        "size",
        "instruction_count",
        "basic_block_count",
        "mnemonic_hash",
        "register_shape_hash",
        "shape_hash",
    )

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
        if spec["exact_metrics"]:
            for field in exact_fields:
                if source.get(field) != target.get(field):
                    raise ValueError(
                        "%s mismatch at %s to %s"
                        % (field, spec["original_ea"], spec["spectron_ea"])
                    )
        elif target.get("basic_block_count") != spec["spectron_basic_block_count"]:
            raise ValueError(
                "unexpected target basic-block count at %s" % spec["spectron_ea"]
            )
        if source.get("basic_block_count") != spec["source_basic_block_count"]:
            raise ValueError(
                "unexpected source basic-block count at %s" % spec["original_ea"]
            )
        for literal in spec["required_string_refs"]:
            if literal not in source.get("string_refs", []):
                raise ValueError(
                    "source %s lacks required string reference %s"
                    % (spec["original_ea"], literal)
                )
            if literal not in target.get("string_refs", []):
                raise ValueError(
                    "target %s lacks required string reference %s"
                    % (spec["spectron_ea"], literal)
                )
        if spectron_ea in semantic_targets:
            raise ValueError(
                "target %s is already present in the semantic map" % spec["spectron_ea"]
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
                "match_kind": "manual-server-level-interaction-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in server-level interaction anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_level_interaction_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for server-level NPC predicates, level-link coordinates, and indexed object removal",
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
            "The exact rows are supported by matching body hashes, callback-table references, and direct pseudocode. The bomb-removal row is a reviewed context match because its rebuilt target reduces the block count while preserving the state transitions.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
