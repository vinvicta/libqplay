#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for client script bridge helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x157d3c",
        "original_name": "GSFunctionsClient_script_uploadfile",
        "spectron_ea": "0x15ab64",
        "expected_target_size": 240,
        "expected_target_instruction_count": 60,
        "expected_target_basic_block_count": 8,
        "source_basis": "script upload-file permission check and client upload dispatch",
        "required_target_strings": [],
        "evidence": [
            "The source checks the allowed-upload list, obtains script-access filenames when required, and otherwise removes an approved entry before upload.",
            "The target performs the same list check and calls its obfuscated client upload method after constructing the selected filename.",
            "The target is the first helper in the upload and terrain bridge sequence and retains the source eight-block shape.",
        ],
    },
    {
        "original_ea": "0x157e0c",
        "original_name": "GSFunctionsClient_script_updateterrain",
        "spectron_ea": "0x15ac54",
        "expected_target_size": 24,
        "expected_target_instruction_count": 6,
        "expected_target_basic_block_count": 4,
        "source_basis": "active-player terrain or buffer refresh",
        "required_target_strings": [],
        "evidence": [
            "The source is the short active-player guard that invokes the player terrain-buffer refresh method.",
            "The target is the matching short active-player guard immediately before the reviewed update-board helper and calls the obfuscated player refresh method.",
            "The target preserves the source six-instruction and four-block wrapper shape despite the changed class and method names.",
        ],
    },
    {
        "original_ea": "0x157e58",
        "original_name": "GSFunctionsClient_script_triggeraction",
        "spectron_ea": "0x15aca0",
        "expected_target_size": 400,
        "expected_target_instruction_count": 100,
        "expected_target_basic_block_count": 9,
        "source_basis": "NPC trigger action and client packet forwarding",
        "required_target_strings": [],
        "evidence": [
            "The source checks the active player and action NPC, invokes the player trigger-action method, converts coordinates, and forwards the event to the client packet helper.",
            "The target preserves the same active-player and action-NPC selection, coordinate adjustment, optional text conversion, and two-stage dispatch.",
            "The target remains directly after the terrain and board helpers, matching the source script bridge order.",
        ],
    },
    {
        "original_ea": "0x1583d0",
        "original_name": "GSFunctionsClient_script_setsleevecolor",
        "spectron_ea": "0x15b260",
        "expected_target_size": 116,
        "expected_target_instruction_count": 29,
        "expected_target_basic_block_count": 3,
        "source_basis": "action-player sleeve color setter",
        "required_target_strings": [],
        "evidence": [
            "The source selects appearance slot 2 and invokes the color setter on the action player's appearance object.",
            "The target selects the same slot 2 and invokes the corresponding virtual setter after an action-player guard.",
            "The target is the first member of the five-function color setter cluster in the same source order.",
        ],
    },
    {
        "original_ea": "0x158420",
        "original_name": "GSFunctionsClient_script_setskincolor",
        "spectron_ea": "0x15b2d4",
        "expected_target_size": 116,
        "expected_target_instruction_count": 29,
        "expected_target_basic_block_count": 3,
        "source_basis": "action-player skin color setter",
        "required_target_strings": [],
        "evidence": [
            "The source selects appearance slot 0 and invokes the color setter on the action player's appearance object.",
            "The target selects the same slot 0 and preserves the same guarded virtual setter call.",
            "The target is the second member of the contiguous color setter cluster, following sleeve color as in the source.",
        ],
    },
    {
        "original_ea": "0x158470",
        "original_name": "GSFunctionsClient_script_setshoecolor",
        "spectron_ea": "0x15b348",
        "expected_target_size": 116,
        "expected_target_instruction_count": 29,
        "expected_target_basic_block_count": 3,
        "source_basis": "action-player shoe color setter",
        "required_target_strings": [],
        "evidence": [
            "The source selects appearance slot 3 and invokes the color setter on the action player's appearance object.",
            "The target selects the same slot 3 and retains the same one-argument appearance setter body.",
            "The target is the third member of the ordered color setter cluster.",
        ],
    },
    {
        "original_ea": "0x1584c0",
        "original_name": "GSFunctionsClient_script_setcoatcolor",
        "spectron_ea": "0x15b3bc",
        "expected_target_size": 116,
        "expected_target_instruction_count": 29,
        "expected_target_basic_block_count": 3,
        "source_basis": "action-player coat color setter",
        "required_target_strings": [],
        "evidence": [
            "The source selects appearance slot 1 and invokes the color setter on the action player's appearance object.",
            "The target selects the same slot 1 and retains the same guarded virtual setter body.",
            "The target is the fourth member of the ordered color setter cluster.",
        ],
    },
    {
        "original_ea": "0x158510",
        "original_name": "GSFunctionsClient_script_setbeltcolor",
        "spectron_ea": "0x15b430",
        "expected_target_size": 116,
        "expected_target_instruction_count": 29,
        "expected_target_basic_block_count": 3,
        "source_basis": "action-player belt color setter",
        "required_target_strings": [],
        "evidence": [
            "The source selects appearance slot 4 and invokes the color setter on the action player's appearance object.",
            "The target selects the same slot 4 and retains the same guarded virtual setter body.",
            "The target is the fifth and final member of the ordered color setter cluster.",
        ],
    },
    {
        "original_ea": "0x158560",
        "original_name": "GSFunctionsClient_script_callweapon",
        "spectron_ea": "0x15b4a4",
        "expected_target_size": 440,
        "expected_target_instruction_count": 109,
        "expected_target_basic_block_count": 13,
        "source_basis": "weapon index validation and action-NPC weapon callback",
        "required_target_strings": [],
        "evidence": [
            "The source validates the weapon index, action player, and action NPC, converts the script argument to a string, and invokes the selected weapon callback.",
            "The target preserves the same index and object checks, compact or long argument conversion, and virtual weapon callback dispatch.",
            "The target follows the five color setters and retains the source thirteen-block call shape.",
        ],
    },
    {
        "original_ea": "0x1589e0",
        "original_name": "GSFunctionsClient_script_requesttext",
        "spectron_ea": "0x15b958",
        "expected_target_size": 348,
        "expected_target_instruction_count": 87,
        "expected_target_basic_block_count": 14,
        "source_basis": "clientrc authorization and request-text dispatch",
        "required_target_strings": ["graalengine", "clientrc", "Unauthorized attempt to use clientrc"],
        "evidence": [
            "The source rejects clientrc from a graalengine context unless the script is authorized, reports an unauthorized attempt, and otherwise sends the request through the client.",
            "The target retains all three security strings, the same authorization branch, and the obfuscated client request-text method.",
            "The target function remains a 14-block request bridge directly before the replacement-animation helper family.",
        ],
    },
    {
        "original_ea": "0x159574",
        "original_name": "GSFunctionsClient_script_findlevel",
        "spectron_ea": "0x15c51c",
        "expected_target_size": 224,
        "expected_target_instruction_count": 56,
        "expected_target_basic_block_count": 6,
        "source_basis": "case-insensitive map lookup with current-level fallback",
        "required_target_strings": [],
        "evidence": [
            "The source lowercases the requested filename, scans the map list, compares normalized map names, and falls back to the current level when no map matches.",
            "The target performs the same normalized map-list scan and fallback through its obfuscated file and level helpers.",
            "The target retains the source six-block lookup shape and sits between image-pixel and pause-control script helpers.",
        ],
    },
    {
        "original_ea": "0x159a8c",
        "original_name": "GSFunctionsClient_script_adventure_openserverlist",
        "spectron_ea": "0x15ca50",
        "expected_target_size": 160,
        "expected_target_instruction_count": 39,
        "expected_target_basic_block_count": 4,
        "source_basis": "adventure server-list event",
        "required_target_strings": [],
        "evidence": [
            "The source requires the client and universe objects, then invokes the onOpenServerList event.",
            "The target preserves the same client and universe guards and builds the corresponding server-list event string before dispatch.",
            "The target is immediately before the account-name script helper, matching the readable bridge order.",
        ],
    },
    {
        "original_ea": "0x15a2ac",
        "original_name": "GSFunctionsClient_script_sendtext",
        "spectron_ea": "0x15d400",
        "expected_target_size": 584,
        "expected_target_instruction_count": 144,
        "expected_target_basic_block_count": 18,
        "source_basis": "text-command filtering and set-text packet forwarding",
        "required_target_strings": ["add", "delete", "graalengine", "irc", "lister"],
        "evidence": [
            "The source filters add, delete, irc, and lister commands, rejects graalengine-originated traffic, converts the optional text argument, and sends the four-string text packet.",
            "The target retains all five discriminator strings, the same command filter, the graalengine guard, and the obfuscated client send-text method.",
            "The target's 18-block body preserves the source's complete command-to-packet bridge despite the rebuilt implementation.",
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
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
        ):
            expected = spec["expected_target_" + field]
            if target.get(field) != expected:
                raise ValueError(
                    "target %s %s mismatch: expected %s, got %s"
                    % (spec["spectron_ea"], field, expected, target.get(field))
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
                "match_kind": "manual-script-bridge-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script bridge anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_bridge_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for client script bridge helpers",
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
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the target default name in the evidence row.",
            "These rows describe local script bridge behavior; they do not establish compatibility with an external service.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
