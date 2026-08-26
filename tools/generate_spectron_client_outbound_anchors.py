#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for remaining client send helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1f3e28",
        "original_name": "TClient_sendLevelWarp_double_double_TString_const",
        "spectron_ea": "0x1f76b0",
        "target_name_fragment": "EddRK10C8THgaTQxF",
        "source_basis": "level-warp packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains two floating-point coordinates and a string reference.",
            "Its body rounds both coordinates, appends the level text, and dispatches through the same client send slot.",
            "It is the immediate target neighbor before the separately anchored level-warp modification-time helper.",
        ],
    },
    {
        "original_ea": "0x1f4238",
        "original_name": "TClient_sendLevelLinking_TString_const_double_double",
        "spectron_ea": "0x1f7c88",
        "target_name_fragment": "ERK10C8THgaTQxFdd",
        "source_basis": "level-linking packet and server-level transition",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains a string reference followed by two floating-point coordinates.",
            "Its body calls the two reviewed level-warp serializers, resolves level resources, and preserves the player level-entry path.",
            "The source and target both have 26 basic blocks, which is a useful control-flow check for this larger helper.",
        ],
    },
    {
        "original_ea": "0x1f4688",
        "original_name": "TClient_sendEnterLevel_void",
        "spectron_ea": "0x1f8110",
        "target_name_fragment": "Ev",
        "source_basis": "enter-level packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is a no-argument method in the same outbound level-packet cluster.",
            "Its body builds the compact enter-level packet and dispatches it through the client send slot.",
            "Its position follows level linking and precedes file download requests in the same order as the readable client methods.",
        ],
    },
    {
        "original_ea": "0x1f473c",
        "original_name": "TClient_sendDownloadFile_TString_const_TString_const_TString_const",
        "spectron_ea": "0x1f8290",
        "target_name_fragment": "ERK10C8THgaTQxFS2_S2_",
        "source_basis": "file-download request serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains three string references.",
            "Its body preserves compact and long-string encoding before dispatching the file request.",
            "It is the first file request helper after the target enter-level serializer and keeps the same client class context.",
        ],
    },
    {
        "original_ea": "0x1f4898",
        "original_name": "TClient_sendUploadStart_TString_const",
        "spectron_ea": "0x1f8514",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "upload-start packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is the first one-string serializer in the upload sequence.",
            "Its body preserves the connector diagnostic branch and normal client packet dispatch.",
            "Its placement follows the three-string download request and matches the source method order.",
        ],
    },
    {
        "original_ea": "0x1f494c",
        "original_name": "TClient_sendSaveFile_TString_const_int_TString_const",
        "spectron_ea": "0x1f86c0",
        "target_name_fragment": "ERK10C8THgaTQxFiS2_",
        "source_basis": "save-file packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains a string, an integer, and a second string reference.",
            "Its body encodes compact and long string data before sending the same save-file request.",
            "The target is between upload-start and upload-end helpers in the same outbound method sequence.",
        ],
    },
    {
        "original_ea": "0x1f4b00",
        "original_name": "TClient_sendUploadEnd_TString_const",
        "spectron_ea": "0x1f88e8",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "upload-end packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is the one-string serializer immediately after the save-file helper.",
            "Its body preserves the same output-mode checks and one-string packet dispatch.",
            "The target method order matches the complete upload sequence in the readable 1.8 client.",
        ],
    },
    {
        "original_ea": "0x1f4bb4",
        "original_name": "TClient_sendWantImage_TString_const",
        "spectron_ea": "0x1f8a94",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "image request packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is the one-string image request helper after the upload sequence.",
            "Its body preserves URL and resource handling before sending the image request.",
            "The target remains in the same outbound method cluster and uses the common client send slot.",
        ],
    },
    {
        "original_ea": "0x1f52b8",
        "original_name": "TClient_sendWantImageUpdate_TString_const",
        "spectron_ea": "0x1f943c",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "image-update request selection",
        "required_target_strings": [".gmap", ".gupd"],
        "evidence": [
            "The source and target have exactly the same size, instruction count, block count, and .gmap or .gupd discriminator set.",
            "The target selects the corresponding image-update path after checking resource extensions.",
            "The target is adjacent to the reviewed CRC and modification-time helpers, completing the image-update request family.",
        ],
    },
    {
        "original_ea": "0x1f5354",
        "original_name": "TClient_sendWantGaniScript_TString_const_uint",
        "spectron_ea": "0x1f94d8",
        "target_name_fragment": "ERK10C8THgaTQxFj",
        "source_basis": "gani-script request serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains a string reference and an unsigned integer.",
            "Its body builds the script request with the same string and revision fields used by the source helper.",
            "It is the first of the target's adjacent gani, weapon, and class request methods.",
        ],
    },
    {
        "original_ea": "0x1f54b0",
        "original_name": "TClient_sendWantWeaponScript_TString_const",
        "spectron_ea": "0x1f9724",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "weapon-script request serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is the one-string script request between the target gani and class helpers.",
            "Its body preserves compact string encoding and client packet dispatch.",
            "The ordered request family and matching one-string signature distinguish this role from the two revision-bearing helpers.",
        ],
    },
    {
        "original_ea": "0x1f5564",
        "original_name": "TClient_sendWantClassScript_TString_const_uint",
        "spectron_ea": "0x1f98d0",
        "target_name_fragment": "ERK10C8THgaTQxFj",
        "source_basis": "class-script request serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains a string reference and an unsigned integer.",
            "Its body preserves the class request's compact string and revision fields.",
            "It is the second revision-bearing member of the adjacent gani, weapon, and class request family.",
        ],
    },
    {
        "original_ea": "0x1f56c0",
        "original_name": "TClient_sendToAllChat_TString_const",
        "spectron_ea": "0x1f9b1c",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "all-chat packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is the next one-string outbound helper after the script request family.",
            "Its body preserves the long-string escape path and common packet dispatch.",
            "Its position and signature match the source chat serializer before the player-state actions.",
        ],
    },
    {
        "original_ea": "0x1f585c",
        "original_name": "TClient_sendIsPKer_TServerPlayer",
        "spectron_ea": "0x1f9d70",
        "target_name_fragment": "EP10MpGzgariDy",
        "source_basis": "player PK-state packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains a server-player object pointer.",
            "Its body obtains the player state and sends the same compact object-backed packet.",
            "The target follows the all-chat helper and precedes the no-argument carry-throw action in the same order.",
        ],
    },
    {
        "original_ea": "0x1f592c",
        "original_name": "TClient_sendCarryThrow_void",
        "spectron_ea": "0x1f9f14",
        "target_name_fragment": "Ev",
        "source_basis": "carry-throw packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is a no-argument outbound action method.",
            "Its body constructs the carry-throw packet and dispatches it through the client send slot.",
            "Its target position follows the player PK-state helper exactly as the source method order does.",
        ],
    },
    {
        "original_ea": "0x1f6108",
        "original_name": "TClient_sendRemoveBomb_double_double",
        "spectron_ea": "0x1faad0",
        "target_name_fragment": "Edd",
        "source_basis": "bomb-removal packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains two floating-point coordinates.",
            "Its body rounds both coordinates and emits the same two-field removal packet.",
            "It follows the bomb placement helper and precedes fire-spying in the target action cluster.",
        ],
    },
    {
        "original_ea": "0x1f6278",
        "original_name": "TClient_sendFireSpying_int_int",
        "spectron_ea": "0x1fad20",
        "target_name_fragment": "Eii",
        "source_basis": "fire-spying packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains two integer parameters.",
            "Its body packs the same integer pair into the compact fire-spying representation.",
            "The target follows bomb removal and precedes the preload-level helper in the source and target method order.",
        ],
    },
    {
        "original_ea": "0x1f6344",
        "original_name": "TClient_sendPreloadLevel_TServerLevel",
        "spectron_ea": "0x1faed8",
        "target_name_fragment": "EP10zF9VgaBKxR",
        "source_basis": "preload-level packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains a server-level object pointer.",
            "Its body reads the level filename, encodes the level identifier, and dispatches the same preload packet.",
            "The target sits directly after fire-spying and preserves the optional connector diagnostic branch.",
        ],
    },
    {
        "original_ea": "0x1f64c8",
        "original_name": "TClient_sendPlayerProperties_TString_const",
        "spectron_ea": "0x1fb194",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "player-properties packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is the first of two adjacent one-string property serializers.",
            "Its body preserves the diagnostic and normal packet paths for player properties.",
            "Its target order matches the player-properties method before the NPC-properties method in the source.",
        ],
    },
    {
        "original_ea": "0x1f657c",
        "original_name": "TClient_sendNPCProperties_TString_const",
        "spectron_ea": "0x1fb340",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "NPC-properties packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is the second adjacent one-string property serializer.",
            "Its body preserves the same diagnostic and normal packet paths with the NPC-specific packet selector.",
            "The paired target position distinguishes it from the preceding player-properties helper.",
        ],
    },
    {
        "original_ea": "0x1f6630",
        "original_name": "TClient_sendFlag_TString_const",
        "spectron_ea": "0x1fb4ec",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "client flag packet serialization",
        "required_target_strings": ["client."],
        "evidence": [
            "The target retains the client. prefix check before serializing the flag value.",
            "Its body preserves the diagnostic and normal one-string packet paths.",
            "It is the first member of the adjacent flag and unset-flag pair, matching the source method order.",
        ],
    },
    {
        "original_ea": "0x1f671c",
        "original_name": "TClient_sendUnsetFlag_TString_const",
        "spectron_ea": "0x1fb6c4",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "client unset-flag packet serialization",
        "required_target_strings": ["client."],
        "evidence": [
            "The target retains the client. prefix check before serializing the unset value.",
            "Its body has the same one-string diagnostic and normal paths as the source unset-flag helper.",
            "Its paired position after the flag serializer and distinct target function establish the separate role.",
        ],
    },
    {
        "original_ea": "0x1f7198",
        "original_name": "TClient_sendExtra_double_double_int",
        "spectron_ea": "0x1fc440",
        "target_name_fragment": "Eddi",
        "source_basis": "extra-item pickup packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains two floating-point values and an integer.",
            "Its body serializes the same three-field extra-item action through the client send slot.",
            "It is the first of the adjacent extra, take-extra, and remove-extra target helpers.",
        ],
    },
    {
        "original_ea": "0x1f7360",
        "original_name": "TClient_sendTakeExtra_double_double_int",
        "spectron_ea": "0x1fc6e0",
        "target_name_fragment": "Eddi",
        "source_basis": "extra-item take packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains the same two floating-point values and integer as the source take-extra helper.",
            "Its body is the paired action serializer with the distinct target packet selector.",
            "Its position directly after the extra helper matches the source method order.",
        ],
    },
    {
        "original_ea": "0x1f7528",
        "original_name": "TClient_sendRemoveExtra_double_double",
        "spectron_ea": "0x1fc980",
        "target_name_fragment": "Edd",
        "source_basis": "extra-item removal packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains two floating-point coordinates.",
            "Its body serializes the paired removal action with the same coordinate encoding.",
            "It is the third member of the contiguous extra-action helper cluster.",
        ],
    },
    {
        "original_ea": "0x1f76c0",
        "original_name": "TClient_sendOpenChest_int_int",
        "spectron_ea": "0x1fcbf0",
        "target_name_fragment": "Eii",
        "source_basis": "open-chest packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains two integer parameters.",
            "Its body serializes the same chest coordinates or identifiers and dispatches the action packet.",
            "Its target position immediately precedes the separately anchored shot helper.",
        ],
    },
    {
        "original_ea": "0x1f7a00",
        "original_name": "TClient_sendDeleteWeapon_TServerWeapon",
        "spectron_ea": "0x1fd0e0",
        "target_name_fragment": "EP10pTy_fadYe4",
        "source_basis": "weapon-deletion packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains a weapon object pointer in the action cluster.",
            "Its body reads the object fields needed for the same delete-weapon packet.",
            "It is followed by the distinct NPC-deletion target and then the player-hurt and weapon-hit helpers.",
        ],
    },
    {
        "original_ea": "0x1f7aa0",
        "original_name": "TClient_sendDeleteNPC_TServerNPC",
        "spectron_ea": "0x1fd280",
        "target_name_fragment": "EP10LBgVgaqANQ",
        "source_basis": "NPC-deletion packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target mangled signature retains an NPC object pointer.",
            "Its body serializes the object-backed delete action and uses the preceding weapon-delete helper where needed.",
            "Its target order matches the source NPC-deletion method immediately before player hurt.",
        ],
    },
    {
        "original_ea": "0x1f8178",
        "original_name": "TClient_sendServerWarp_TString_const",
        "spectron_ea": "0x1fdbe0",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "server-warp packet serialization",
        "required_target_strings": [],
        "evidence": [
            "The target is the one-string serializer between weapon-hit and explosion helpers, matching the source order.",
            "Its body preserves the compact warp text path and client send dispatch.",
            "The target remains in the same outbound action cluster and is separate from the inbound server-warp handler.",
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
                "match_kind": "manual-client-outbound-protocol-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in client-outbound anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_outbound_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for remaining client outbound packet serializers",
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
            "These rows describe local outbound packet serialization logic and do not establish compatibility with an external service.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
