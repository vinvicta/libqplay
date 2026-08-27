#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron player level-entry methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x178558",
        "original_name": "TPlayer_enterLevelMain_TString_const_bool",
        "spectron_ea": "0x17c7f8",
        "target_name_fragment": "W6NzgawMJy10dFumxafpxGERK10C8THgaTQxFb",
        "source_basis": "main level-entry state transition and object cleanup",
        "source_basic_block_count": 56,
        "spectron_basic_block_count": 57,
        "evidence": [
            "Both notify the client, derive the side-level offset, detect a changed map, clear objects from the previous level, load side levels, detach a server player when required, update map position, and stop stale weapon particles and sounds.",
            "Both recalculate the player position relative to the new level, update board coordinates, stop outside NPC scripts, invoke player-enter callbacks, update tiles, initialize or reuse the render buffer, and resolve the restart position from the level list.",
            "Both finish by resetting action mode for the same encoded action states. The target expands one small branch and shifts player fields for the larger 2.2 object, but retains the 56-block source shape with 57 target blocks and the same call order.",
        ],
    },
    {
        "original_ea": "0x178a18",
        "original_name": "TPlayer_enterServerLevel_TString_const_bool",
        "spectron_ea": "0x17cd00",
        "target_name_fragment": "W6NzgawMJy10XqHzwam9D0ERK10C8THgaTQxFb",
        "source_basis": "server-level entry setup and server-modification handoff",
        "source_basic_block_count": 32,
        "spectron_basic_block_count": 32,
        "evidence": [
            "Both refresh the encoded player state, ensure a positive health or power value, swap the current level name with the requested server level, and create or load the TServerLevel object when it is absent.",
            "Both update the client or NPC server-level globals, clear the same three server-level object lists when requested, reset the attached player coordinates, and dispatch the matching server-modification routine for the requested level.",
            "Both store the new level name and call the main level-entry method with the saved previous name. The target changes wrapper and field names for the rebuilt 2.2 layout while preserving the source and target 32-block control-flow shape.",
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
        if source.get("basic_block_count") != spec["source_basic_block_count"]:
            raise ValueError(
                "unexpected source basic-block count at %s" % spec["original_ea"]
            )
        if target.get("basic_block_count") != spec["spectron_basic_block_count"]:
            raise ValueError(
                "unexpected target basic-block count at %s" % spec["spectron_ea"]
            )
        semantic_match_already_present = spectron_ea in semantic_targets
        if semantic_match_already_present:
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
                "match_kind": "manual-player-level-entry-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in player-level-entry anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_player_level_entry_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for player main-level and server-level entry",
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
            "The correspondence relies on the preserved class-local call sequence, matching level-list cleanup and handoff behavior, compatible block counts, and reviewed pseudocode rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
