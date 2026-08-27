#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron server-animation cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x23caec",
        "original_name": "TExplosion_animate_void",
        "spectron_ea": "0x24699c",
        "target_name_fragment": "Dq2rua2Ece10MzWVgaRTlREv",
        "source_basis": "explosion collision and player-damage state machine",
        "source_basic_block_count": 26,
        "spectron_basic_block_count": 36,
        "required_string_refs": ["explosion"],
        "evidence": [
            "Both require an active player and level, mark the target NPC with action 13, reject mismatched levels, no-hurt state, distant coordinates, and protected levels, then decrement the explosion lifetime on the exit path.",
            "Both derive damage from the explosion direction, call the player hurt routine with the explosion label, and notify the client about a player-kill state when the victim reaches zero health.",
            "The target expands the direction-table read into a small explicit switch and uses rebuilt wrappers, which accounts for 36 target blocks versus 26 source blocks while preserving the same state transitions and offsets.",
        ],
    },
    {
        "original_ea": "0x23d774",
        "original_name": "TServerCarry_animate_void",
        "spectron_ea": "0x24768c",
        "target_name_fragment": "fJ8VgaKXwR10MzWVgaRTlREv",
        "source_basis": "carry movement, obstacle, damage, and bomb state machine",
        "source_basic_block_count": 70,
        "spectron_basic_block_count": 82,
        "required_string_refs": ["blackstone", "bush", "sign", "stone", "vase"],
        "evidence": [
            "Both advance the carry by the same direction-dependent velocity, detect edge crossings, move the object between adjacent level lists, and preserve the same tile-coordinate fields.",
            "Both handle throw walls, NPC actions, the five carry sprite families represented by blackstone, bush, sign, stone, and vase, player hurt checks, and bush damage with the same distance and protection guards.",
            "Both emit water leaps, select the same bomb sprite family, attach and position the carried player, send the bomb packet when a client exists, and return the player to the level list. The target grows from 70 to 82 blocks because of rebuilt wrappers and explicit direction-vector logic.",
        ],
    },
    {
        "original_ea": "0x23eeb0",
        "original_name": "TServerFlying_animate_void",
        "spectron_ea": "0x248e38",
        "target_name_fragment": "gId5RaV8_610MzWVgaRTlREv",
        "source_basis": "flying projectile direction, collision, and combat state machine",
        "source_basic_block_count": 106,
        "spectron_basic_block_count": 106,
        "required_string_refs": ["arrow", "arrowon.wav", "bomb.wav"],
        "evidence": [
            "Both derive the dominant movement direction, update position, detect screen-edge level changes, and advance the same four-frame projectile animation.",
            "Both preserve the shield-direction interaction, arrow damage path, PK notification, arrow-on sound, bomb sound and explosion path, NPC action 14 collision, wall checks, and overlap scan against level objects.",
            "The target retains all three distinctive projectile literals and the exact 106-block control-flow shape. Its changed player offsets and wrapper calls are consistent with the rebuilt target class layout.",
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
                "match_kind": "manual-server-animation-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in server-animation anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_animation_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for explosion, carry, and flying server animations",
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
            "The changed-size rows rely on class-local order, distinctive sprite and sound literals, preserved field offsets, matching movement and collision branches, and reviewed pseudocode behavior rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
