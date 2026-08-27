#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron player animation and link paths."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x16f090",
        "original_name": "TPlayer_animateLevel_void",
        "spectron_ea": "0x172e78",
        "target_name_fragment": "W6NzgawMJy10ac5QwaUZgfEv",
        "source_basis": "side-level and active-level animation update",
        "source_basic_block_count": 16,
        "spectron_basic_block_count": 18,
        "required_string_refs": ["PlayerTimer_AnimateLevel"],
        "evidence": [
            "Both initialize and use the same PlayerTimer_AnimateLevel profiler scope, walk the side-level objects, animate each available level, animate the active level, and close the profiler scope.",
            "The target iterates the expanded seven-by-seven side-level grid instead of the source three-by-three grid and uses rebuilt profiler and level wrappers, which accounts for the two extra blocks.",
            "The distinctive profiler literal and the class-local position immediately after map-link helpers make this a direct correspondence.",
        ],
    },
    {
        "original_ea": "0x16f1b8",
        "original_name": "TPlayer_testForMapLinks_void",
        "spectron_ea": "0x17303c",
        "target_name_fragment": "W6NzgawMJy10ilACwavb42Ev",
        "source_basis": "nearby side-level link detection and client notification",
        "source_basic_block_count": 17,
        "spectron_basic_block_count": 12,
        "required_string_refs": [],
        "evidence": [
            "Both require an active map and reject attached players, derive the side-level row and column from the inherited X and Y coordinates, and ignore the center cell.",
            "Both test the selected side-level pointer and cached filename, calculate the position relative to the side-level origin, and send the level-link packet when a client exists.",
            "The target delegates coordinate normalization to the two target-only side-level helpers added by the seven-by-seven layout, reducing the body from 17 to 12 blocks while preserving the same class-local link path.",
        ],
    },
    {
        "original_ea": "0x16f338",
        "original_name": "TPlayer_testForLinks_void",
        "spectron_ea": "0x1731a8",
        "target_name_fragment": "W6NzgawMJy10BViCwabxQ2Ev",
        "source_basis": "general map-link and level-object traversal state machine",
        "source_basic_block_count": 90,
        "spectron_basic_block_count": 102,
        "required_string_refs": [],
        "evidence": [
            "Both reject missing player state, disallowed links, attached players, and failed nearby map-link checks before scanning the active level object list.",
            "Both preserve the four edge-direction cases, movement-vector and direction checks, obstacle bounds checks, calculated link destinations, and final client level-link notification.",
            "The target expands the direction arithmetic into explicit switches and routes string and client operations through rebuilt wrappers, producing 102 blocks versus 90 while retaining the complete source state machine and class-local order.",
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
                "match_kind": "manual-player-link-traversal-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in player-link-traversal anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_player_link_traversal_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for player level animation and map-link traversal",
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
            "The target expands the side-level grid and splits coordinate normalization into target-only helpers, while preserving the animation and level-link state machines reviewed here.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
