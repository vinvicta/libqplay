#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron player weapon state cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1742cc",
        "original_name": "TPlayer_resetAttributes_void",
        "spectron_ea": "0x1782fc",
        "target_name_fragment": "W6NzgawMJy10salcLavq_jEv",
        "source_basis": "player attribute, weapon, and visual-state reset",
        "source_basic_block_count": 17,
        "spectron_basic_block_count": 19,
        "required_string_refs": ["letters.png"],
        "evidence": [
            "Both clear the current, active, and side-level pointers, reset player visual and attribute state, clear weapons, reset the selected sword, clear carrying and cached triggers, and initialize the thirty GANI parameters.",
            "Both restore the default letters.png body asset, reset the nickname from options, refresh encoded state buffers, zero the emoticon coordinates, and restore the same visual color and scale defaults.",
            "The target shifts fields for the larger player object and routes reset operations through rebuilt wrappers. It preserves the source reset sequence and grows from 17 to 19 blocks.",
        ],
    },
    {
        "original_ea": "0x1746f0",
        "original_name": "TPlayer_deleteSelectedWeapon_void",
        "spectron_ea": "0x178828",
        "target_name_fragment": "W6NzgawMJy10xmonwaG6hREv",
        "source_basis": "selected weapon deletion with protected weapon check",
        "source_basic_block_count": 8,
        "spectron_basic_block_count": 8,
        "required_string_refs": ["*-"] ,
        "evidence": [
            "Both read the selected weapon index, locate the weapon in the player weapon list, and reject missing or empty weapon names before deletion.",
            "Both search the weapon name for the protected *- marker, send a delete packet when a client exists, and release the selected weapon object only when the marker is absent.",
            "The target preserves the exact eight-block shape and the distinctive *- literal while changing only list, string, client, and field wrappers.",
        ],
    },
    {
        "original_ea": "0x1747b4",
        "original_name": "TPlayer_setSelectedWeapon_int",
        "spectron_ea": "0x178910",
        "target_name_fragment": "W6NzgawMJy10daxnwaawpREi",
        "source_basis": "selected weapon cycling and name update",
        "source_basic_block_count": 13,
        "spectron_basic_block_count": 13,
        "required_string_refs": [],
        "evidence": [
            "Both accept a negative selection as a direct state update, handle empty weapon lists, and clear the selected weapon name when the requested index is outside the list.",
            "Both cycle forward through protected * weapon entries, wrap by the weapon-list count, store the resolved index, and copy the selected weapon name into the player state.",
            "The target preserves the exact 13-block control-flow shape and changes only the weapon-list, player-field, and string-wrapper names for the rebuilt layout.",
        ],
    },
    {
        "original_ea": "0x175850",
        "original_name": "TPlayer_getWeapon_TString_const",
        "spectron_ea": "0x179af8",
        "target_name_fragment": "W6NzgawMJy10fPzXwaNKJkERK10C8THgaTQxF",
        "source_basis": "weapon list lookup by name",
        "source_basic_block_count": 6,
        "spectron_basic_block_count": 6,
        "required_string_refs": [],
        "evidence": [
            "Both iterate the player weapon list through the list count, stop at the first matching weapon name, and return the weapon object or null when no match exists.",
            "Both guard each list entry against a null object before comparing its weapon-name field, preserving the same loop termination and return behavior.",
            "The target preserves the exact six-block shape and the source method’s class-local position after weapon construction helpers, with only the rebuilt list and string wrappers changed.",
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
                "match_kind": "manual-player-weapon-state-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in player-weapon-state anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_player_weapon_state_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for player attribute reset and weapon selection",
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
            "The correspondence relies on the preserved weapon-list state machines, reset sequence, distinctive literals, compatible block counts, and reviewed pseudocode rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
