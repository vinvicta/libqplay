#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for client action packets."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1f3fe8",
        "original_name": "TClient_sendLevelWarpModtime_double_double_TString_const_uint",
        "spectron_ea": "0x1f7968",
        "target_name_fragment": "EddRK10C8THgaTQxFj",
        "source_basis": "level-warp modification-time packet encoding",
        "required_target_strings": ["ddsu"],
        "evidence": [
            "The target has the same double, double, string, unsigned-integer signature shape in its mangled name.",
            "It retains the ddsu protocol format, the connector-versus-game-server output split, and the compact five-character coordinate encoding.",
            "The target clamps and encodes the same level coordinates before dispatching the packet through the client send slot.",
        ],
    },
    {
        "original_ea": "0x1f59e4",
        "original_name": "TClient_sendBoardModify_int_int_int_int_int_int",
        "spectron_ea": "0x1fa098",
        "target_name_fragment": "EiiiiiPi",
        "source_basis": "board-modification packet serialization",
        "required_target_strings": ["iiiiis"],
        "evidence": [
            "The target mangled signature retains six integer-like parameters followed by the board payload pointer.",
            "It serializes the same iiiiis protocol fields and encodes the board data as two-character tile values.",
            "The target keeps the connector diagnostic path and the ordinary game-server packet path in the same routine.",
        ],
    },
    {
        "original_ea": "0x1f5bf8",
        "original_name": "TClient_sendBoardModify2_TString_const_int_int_int_int_int_int",
        "spectron_ea": "0x1fa3b0",
        "target_name_fragment": "ERK10C8THgaTQxFiiiiiPi",
        "source_basis": "named board-modification packet serialization",
        "required_target_strings": ["siiiiis"],
        "evidence": [
            "The target mangled signature retains a leading string reference, five integer-like fields, and a board payload pointer.",
            "It serializes the same siiiiis protocol fields and preserves the long-board-data escape form.",
            "The target's extra board dimensions and payload loop match the second board-modification role rather than the six-integer helper.",
        ],
    },
    {
        "original_ea": "0x1f5ec8",
        "original_name": "TClient_sendBomb_double_double_int_int_bool_TString_const",
        "spectron_ea": "0x1fa7a4",
        "target_name_fragment": "EddiibRK10C8THgaTQxF",
        "source_basis": "bomb placement packet serialization",
        "required_target_strings": ["ffiibs"],
        "evidence": [
            "The target mangled signature retains two floating-point coordinates, two integers, a boolean, and a string payload.",
            "It preserves the ffiibs diagnostic format and the game packet's coordinate, flag, and string encoding.",
            "The target also keeps the same coordinate rounding, optional text payload, and client send dispatch.",
        ],
    },
    {
        "original_ea": "0x1f6808",
        "original_name": "TClient_sendTriggerAction_TServerNPC_double_double_TString_const_TString_const",
        "spectron_ea": "0x1fb89c",
        "target_name_fragment": "EP10LBgVgaqANQddRK10C8THgaTQxFS4_",
        "source_basis": "NPC trigger-action packet serialization",
        "required_target_strings": ["offss"],
        "evidence": [
            "The target mangled signature retains an NPC object, two coordinates, and two string arguments.",
            "It serializes the same offss diagnostic event format before the normal packet path.",
            "The target clamps the trigger coordinates to the same 0 through 220 range and appends the optional text field before dispatch.",
        ],
    },
    {
        "original_ea": "0x1f6b10",
        "original_name": "TClient_sendProjectile_double_double_double_double_double_double_double_TString_const_TString_const_TString_const",
        "spectron_ea": "0x1fbc80",
        "target_name_fragment": "EdddddddRK10C8THgaTQxFS2_S2_",
        "source_basis": "projectile packet serialization",
        "required_target_strings": ["dddddddsss"],
        "evidence": [
            "The target mangled signature retains seven floating-point values followed by three string references.",
            "It preserves the dddddddsss diagnostic format and the same encoded projectile field order.",
            "The surrounding target sequence is the projectile send helper, and the body keeps the long-string escape and client dispatch paths.",
        ],
    },
    {
        "original_ea": "0x1f77c4",
        "original_name": "TClient_sendShot_double_double_int_int_int_bool_bool",
        "spectron_ea": "0x1fcdc8",
        "target_name_fragment": "Eddiiibb",
        "source_basis": "shot packet serialization",
        "required_target_strings": ["ddiiibb"],
        "evidence": [
            "The target mangled signature retains two floating-point values, three integers, and two booleans.",
            "It preserves the ddiiibb diagnostic format and the same packed shot fields.",
            "The target body follows the common connector diagnostic branch and normal packet dispatch used by the source helper.",
        ],
    },
    {
        "original_ea": "0x1f7b88",
        "original_name": "TClient_sendPlayerHurt_TServerPlayer_TServerNPC_double_double_int",
        "spectron_ea": "0x1fd43c",
        "target_name_fragment": "EP10MpGzgariDyP10LBgVgaqANQddi",
        "source_basis": "player-hurt packet serialization",
        "required_target_strings": ["ooddi"],
        "evidence": [
            "The target mangled signature retains a player object, an NPC object, two coordinates, and an integer.",
            "It preserves the ooddi diagnostic format and the same object and coordinate fields.",
            "The target body retains the distance and direction calculations that precede the player-hurt packet dispatch.",
        ],
    },
    {
        "original_ea": "0x1f7f48",
        "original_name": "TClient_sendWeaponHit_double_double_double_TServerNPC",
        "spectron_ea": "0x1fd8e0",
        "target_name_fragment": "EdddP10LBgVgaqANQ",
        "source_basis": "weapon-hit packet serialization",
        "required_target_strings": ["dddo"],
        "evidence": [
            "The target mangled signature retains three floating-point values and an NPC object.",
            "It preserves the dddo diagnostic format and the same weapon-hit payload shape.",
            "The target remains in the ordered action-packet cluster immediately after the player-hurt helper.",
        ],
    },
    {
        "original_ea": "0x1f8288",
        "original_name": "TClient_sendExplosion_int_int_double_double_bool",
        "spectron_ea": "0x1fdde0",
        "target_name_fragment": "Eiiddb",
        "source_basis": "explosion packet serialization",
        "required_target_strings": ["iiddb"],
        "evidence": [
            "The target mangled signature retains two integers, two floating-point values, and a boolean.",
            "It preserves the iiddb diagnostic format and the same explosion payload order.",
            "The target body keeps the coordinate rounding, optional flag, and normal client send dispatch.",
        ],
    },
    {
        "original_ea": "0x1f8750",
        "original_name": "TClient_sendSetText_TString_const_TString_const_TString_const_TString_const",
        "spectron_ea": "0x1fe670",
        "target_name_fragment": "ERK10C8THgaTQxFS2_S2_S2_",
        "source_basis": "four-string text packet serialization",
        "required_target_strings": ["ssss"],
        "evidence": [
            "The target mangled signature retains four string references.",
            "It preserves the ssss diagnostic format and the same four text fields before dispatch.",
            "The target also retains the long-string container used by the source helper for text values beyond the compact encoding limit.",
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
        if spec["target_name_fragment"] not in target.get("name", ""):
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        target_strings = set(target.get("string_refs", []))
        missing_strings = sorted(set(spec["required_target_strings"]) - target_strings)
        if missing_strings:
            raise ValueError(
                "target %s is missing expected strings: %s"
                % (spec["spectron_ea"], ", ".join(missing_strings))
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
                "match_kind": "manual-client-action-protocol-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in client-action anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_action_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for client action packet serializers",
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
            "These rows describe local packet serialization logic and do not establish compatibility with an external service.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
