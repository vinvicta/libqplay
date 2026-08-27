#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron player movement and item cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x197e2c",
        "original_name": "TPlayer_pullStones_void",
        "spectron_ea": "0x19c954",
        "target_name_fragment": "W6NzgawMJy10VNJBwaM8l2Ev",
        "source_basis": "pull-stone trigger and client notification",
        "source_basic_block_count": 8,
        "spectron_basic_block_count": 20,
        "required_string_refs": ["pulled"],
        "evidence": [
            "Both require an action-capable player, use the facing direction to test the adjacent tile, and reject coordinates outside the 64 by 64 level range.",
            "Both build the pulled trigger action with the facing direction and send the same client notification when a client exists.",
            "The target expands direction handling into explicit switches and routes the action through rebuilt array, string, player, and client wrappers while preserving the pulled literal and coordinate flow.",
        ],
    },
    {
        "original_ea": "0x1980d0",
        "original_name": "TPlayer_moveStones_void",
        "spectron_ea": "0x19cc50",
        "target_name_fragment": "W6NzgawMJy10hPIBwaJjl2Ev",
        "source_basis": "push-stone trigger and client notification",
        "source_basic_block_count": 8,
        "spectron_basic_block_count": 20,
        "required_string_refs": ["pushed"],
        "evidence": [
            "Both require an action-capable player, calculate the facing-dependent push position, and reject positions outside the 64 by 64 level range.",
            "Both build the pushed trigger action with the current direction and send the same client notification after dispatching the local action.",
            "The target makes direction offsets explicit and uses rebuilt array, string, player, and client wrappers, but keeps the pushed literal and the source coordinate checks.",
        ],
    },
    {
        "original_ea": "0x198300",
        "original_name": "TPlayer_canJump_void",
        "spectron_ea": "0x19ced8",
        "target_name_fragment": "W6NzgawMJy10fKQBwaAZr2Ev",
        "source_basis": "jump tile and wall availability test",
        "source_basic_block_count": 6,
        "spectron_basic_block_count": 18,
        "required_string_refs": [],
        "evidence": [
            "Both reject the legacy server branch and players without an action level before testing the tile one and a half units ahead of the player.",
            "Both require tile type 21 and then test the second jump position against a wall, returning the inverse of that wall result.",
            "The target preserves the same two tile probes and facing offsets through explicit switches, with shifted player fields and rebuilt level wrappers.",
        ],
    },
    {
        "original_ea": "0x198bb8",
        "original_name": "TPlayer_movementAction_int",
        "spectron_ea": "0x19d7f8",
        "target_name_fragment": "W6NzgawMJy10RIGCwapy92Ei",
        "source_basis": "main player movement and interaction state machine",
        "source_basic_block_count": 233,
        "spectron_basic_block_count": 240,
        "required_string_refs": ["jump.wav", "steps", "steps2", "stonemove.wav", "water"],
        "evidence": [
            "Both are the large movement dispatcher with the same sound literals, movement-direction state, action-mode transitions, and player interaction branches.",
            "The target calls the reviewed pull, push, can-jump, link, and action-mode helpers from the same movement state machine, alongside the corresponding water, wall, animation, and NPC interaction paths.",
            "The target grows by a small number of blocks because direction arithmetic and wrapper calls were rebuilt, while the distinctive five-literal set and class-local call graph remain intact.",
        ],
    },
    {
        "original_ea": "0x19ad78",
        "original_name": "TPlayer_itemAvailable_int",
        "spectron_ea": "0x19f9a0",
        "target_name_fragment": "W6NzgawMJy10ifslwaynFPEi",
        "source_basis": "inventory and weapon availability query",
        "source_basic_block_count": 51,
        "spectron_basic_block_count": 49,
        "required_string_refs": [
            "shield",
            "shield1.",
            "shield2.",
            "shield3.",
            "sword",
            "sword1.",
            "sword2.",
            "sword3.",
            "sword4.",
        ],
        "evidence": [
            "Both reject the legacy server branch and implement the same item cases for hearts, shields, swords, power, light, gloves, and the encoded state check.",
            "Both use the same shield and sword prefix tests, inventory thresholds, special sword and shield cases, and case 19 count threshold.",
            "The target copies the player strings into temporary rebuilt wrappers before testing them, which reduces the block count slightly while preserving all distinctive item literals and branches.",
        ],
    },
    {
        "original_ea": "0x19bbd8",
        "original_name": "TPlayer_animateJumping_void",
        "spectron_ea": "0x1a0844",
        "target_name_fragment": "W6NzgawMJy10kiUQwa6Y6eEv",
        "source_basis": "directional jump animation frame update",
        "source_basic_block_count": 11,
        "spectron_basic_block_count": 11,
        "required_string_refs": [],
        "evidence": [
            "Both switch on the facing direction, update the horizontal and vertical animation coordinates from direction-specific tables, decrement the jump counter, and leave jump mode when the counter reaches zero.",
            "Both use the same four directional cases and the same two coordinate setter vtable slots, with only the target field offsets and wrapper names shifted.",
            "The exact eleven-block shape and the matching counter and action-mode behavior make this a stable class-local correspondence.",
        ],
    },
    {
        "original_ea": "0x19c9e0",
        "original_name": "TPlayer_loseItem_int",
        "spectron_ea": "0x1a1650",
        "target_name_fragment": "W6NzgawMJy10UbLlwaHjVPEi",
        "source_basis": "inventory consumption and weapon or shield downgrade",
        "source_basic_block_count": 72,
        "spectron_basic_block_count": 70,
        "required_string_refs": [
            "shield",
            "shield1.",
            "shield1.png",
            "shield2.",
            "shield2.png",
            "shield3.",
            "sword",
            "sword1.",
            "sword1.png",
            "sword2.",
            "sword2.png",
            "sword3.",
            "sword3.png",
            "sword4.",
        ],
        "evidence": [
            "Both implement the same consumable cases, decrement the corresponding inventory counts, remove power or light state, and clear the selected item when required.",
            "Both preserve the shield and sword downgrade paths, protected prefix checks, previous-image storage, replacement PNG names, and selected-index updates.",
            "The target keeps the complete fourteen-literal weapon and shield set, shifts player fields and wrappers, and reduces the control-flow count by two blocks without changing the item transitions.",
        ],
    },
    {
        "original_ea": "0x19dfa4",
        "original_name": "TPlayer_hurtPlayer_double_double_double_TString_const_TServerPlayer",
        "spectron_ea": "0x1a2c60",
        "target_name_fragment": "W6NzgawMJy10iPzUgaQKcQEdddRK10C8THgaTQxFP10MpGzgariDy",
        "source_basis": "player damage, knockback, and hurt event dispatch",
        "source_basic_block_count": 17,
        "spectron_basic_block_count": 17,
        "required_string_refs": [],
        "evidence": [
            "Both reject the legacy server branch, invulnerability, and the client ghost-mode case before starting the hurt animation and setting hurt action state.",
            "Both reduce power, store and normalize the knockback vector, build the damage, image, and optional attacker arguments, and dispatch the same event index.",
            "The exact seventeen-block shape and matching square-root normalization identify the target despite rebuilt event-array and string wrappers and shifted fields.",
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
                "match_kind": "manual-player-movement-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in player-movement anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_player_movement_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for player movement, item availability, item loss, and hurt handling",
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
            "The correspondence relies on the preserved movement state machine, item literals, hurt-event flow, compatible block counts, and reviewed pseudocode rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
