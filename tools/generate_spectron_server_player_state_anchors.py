#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron server-player state cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x18b010",
        "original_name": "TServerPlayer_setHead_TString_const",
        "spectron_ea": "0x18f8c0",
        "target_name_fragment": "MpGzgariDy10cPsmwaERvQERK10C8THgaTQxF",
        "source_basis": "server-player head string setter",
        "source_basic_block_count": 4,
        "spectron_basic_block_count": 3,
        "required_string_refs": [],
        "evidence": [
            "Both compare the incoming head string with the player head field and assign it only when the value changed.",
            "The target first copies the current string into a temporary rebuilt wrapper before comparing, which reduces the block count while preserving the same conditional assignment.",
            "The target method is called by the reviewed player head setter and uses the same class-local head field offset of 384 bytes.",
        ],
    },
    {
        "original_ea": "0x18ba6c",
        "original_name": "TServerPlayer_initPlayerVars_void",
        "spectron_ea": "0x190334",
        "target_name_fragment": "MpGzgariDy10rnVBqbkTv_Ev",
        "source_basis": "server-player state initialization and default assets",
        "source_basic_block_count": 10,
        "spectron_basic_block_count": 10,
        "required_string_refs": [
            "English",
            "body.png",
            "head26.png",
            "shield1.png",
            "sword1.png",
        ],
        "evidence": [
            "Both initialize the same movement, action, health, timing, language, status, and player-state defaults through the class vtable.",
            "Both restore English, sword1.png, shield1.png, the default head, and the default body, while clearing level, side-level, inventory, and status fields.",
            "The target shifts fields for the larger player object and uses rebuilt string wrappers, but keeps the exact ten-block initialization shape and distinctive default assets.",
        ],
    },
    {
        "original_ea": "0x18ccf8",
        "original_name": "TServerPlayer_playerEnteredLevel_void",
        "spectron_ea": "0x1915a8",
        "target_name_fragment": "MpGzgariDy10ljzVpbYj2pEv",
        "source_basis": "server-player level and side-level membership update",
        "source_basic_block_count": 25,
        "spectron_basic_block_count": 25,
        "required_string_refs": [".gmap"],
        "evidence": [
            "Both remove the player from prior level and side-level lists, inspect the level extension, and split between gmap and regular-level handling.",
            "Both load the gmap, clamp coordinates to map bounds, add the player to the active map, resolve the current level cell, and add the player to that level list.",
            "The regular-level branch resets side-level state, loads the named level, adds the player, and starts the loading timer when needed. The target preserves the exact 25-block shape with shifted map and list wrappers.",
        ],
    },
    {
        "original_ea": "0x18dea0",
        "original_name": "TServerPlayer_setNick_TString_const",
        "spectron_ea": "0x1927a0",
        "target_name_fragment": "MpGzgariDy10zyGwKaIp6KERK10C8THgaTQxF",
        "source_basis": "server-player nickname normalization and change events",
        "source_basic_block_count": 29,
        "spectron_basic_block_count": 29,
        "required_string_refs": [],
        "evidence": [
            "Both replace the nickname, clear the cached wrapped form, derive the parenthesized guild portion when present, and update the admin-guild flag.",
            "Both invoke the player-change event with the same oi argument shape and propagate a changed wrapped nickname to other players when the player is fully active.",
            "The target uses rebuilt string, list, and event wrappers and stores the expanded player fields at shifted offsets, while preserving the exact 29-block control-flow shape.",
        ],
    },
    {
        "original_ea": "0x18e168",
        "original_name": "TServerPlayer_setProperties_TString_const",
        "spectron_ea": "0x192ac8",
        "target_name_fragment": "MpGzgariDy10Q3v7IaUAWzERK10C8THgaTQxF",
        "source_basis": "encoded server-player property parser",
        "source_basic_block_count": 263,
        "spectron_basic_block_count": 265,
        "required_string_refs": [".gif", ".png", "head", "head0.png", "os", "setani"],
        "evidence": [
            "Both parse the compact encoded property stream with the same switch cases for nickname, power, head and body images, weapon images, GANI state, attachment, coordinates, chat, and status fields.",
            "Both call the reviewed nickname, level-entry, movement, animation, and weapon-image paths from the property parser and dispatch player-change or hit-detection work after parsing.",
            "The target preserves the distinctive image and setani literals and the large 263 to 265 block shape, with only rebuilt wrappers, shifted fields, and a few target-specific helper calls added.",
        ],
    },
    {
        "original_ea": "0x19004c",
        "original_name": "TServerPlayer_setWeaponImgs_TString_const",
        "spectron_ea": "0x194a54",
        "target_name_fragment": "MpGzgariDy10yn9_RaxvK2ERK10C8THgaTQxF",
        "source_basis": "encoded player weapon show-image parser",
        "source_basic_block_count": 65,
        "spectron_basic_block_count": 65,
        "required_string_refs": [],
        "evidence": [
            "Both parse the compact weapon-image stream, locate or create show-image objects, and apply the same position, frame, image-part, color, zoom, and mode directives.",
            "Both remove stale show images that were not present in the new stream and clear the temporary list at function exit.",
            "The exact 65-block shape and matching directive loop identify the target despite rebuilt show-image, list, string, and player wrappers.",
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
                "match_kind": "manual-server-player-state-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in server-player-state anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_player_state_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for server-player initialization, level membership, properties, nicknames, and weapon images",
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
            "The correspondence relies on the preserved server-player state machines, encoded property cases, distinctive literals, compatible block counts, and reviewed pseudocode rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
