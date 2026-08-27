#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron player visual setters."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x16df08",
        "original_name": "TPlayer_setDrawRect_void",
        "spectron_ea": "0x171bf8",
        "target_name_fragment": "W6NzgawMJy10wOIPwa7i7dEv",
        "source_basis": "player draw-rectangle calculation from window and local-player layout",
        "source_basic_block_count": 14,
        "spectron_basic_block_count": 14,
        "required_string_refs": [],
        "evidence": [
            "Both choose the game-control origin and dimensions when available, fall back to the main window, use the local-player index to select the draw quadrant, and calculate aligned tile bounds from the screen rectangle.",
            "Both preserve the one-player, two-player, and additional-player branches, including the half-width and half-height choices and the same four-pixel alignment operations.",
            "The target keeps the exact 14-block control-flow shape and adds only the target draw-state callback at the return path, while shifting player fields and window wrappers for the rebuilt layout.",
        ],
    },
    {
        "original_ea": "0x17ae84",
        "original_name": "TPlayer_setHead_TString_const",
        "spectron_ea": "0x17f1c8",
        "target_name_fragment": "W6NzgawMJy10cPsmwaERvQERK10C8THgaTQxF",
        "source_basis": "head-name change notification and inherited setter",
        "source_basic_block_count": 4,
        "spectron_basic_block_count": 3,
        "required_string_refs": [],
        "evidence": [
            "Both compare the incoming head name with the stored head field, set the head-change flag only when the value differs, and then call the inherited head setter.",
            "The target makes the temporary string copy explicit and routes the inherited call through the rebuilt player base class, while preserving the same field role and neighboring method order.",
            "The target reduces the body to three blocks because its wrapper lowering is simpler, but the source and target methods remain direct one-branch setters.",
        ],
    },
    {
        "original_ea": "0x17aec8",
        "original_name": "TPlayer_setBody_TString_const",
        "spectron_ea": "0x17f238",
        "target_name_fragment": "W6NzgawMJy10afFcHakjgYERK10C8THgaTQxF",
        "source_basis": "body-name change notification and inherited setter",
        "source_basic_block_count": 4,
        "spectron_basic_block_count": 3,
        "required_string_refs": [],
        "evidence": [
            "Both compare the incoming body name with the stored body field, set the body-change flag only when the value differs, and then call the inherited body setter.",
            "The target shifts the stored body and change-flag fields with the larger player object and routes the inherited call through the rebuilt GANI base class.",
            "The target reduces the body to three blocks because its wrapper lowering is simpler, while preserving the source direct-setter behavior and class-local placement.",
        ],
    },
    {
        "original_ea": "0x19dce8",
        "original_name": "TPlayer_setSword_TString_const",
        "spectron_ea": "0x1a295c",
        "target_name_fragment": "W6NzgawMJy10i6lowaZc6RERK10C8THgaTQxF",
        "source_basis": "normalized sword image update and change flag",
        "source_basic_block_count": 3,
        "spectron_basic_block_count": 3,
        "required_string_refs": [],
        "evidence": [
            "Both normalize the incoming filename, compare it with the stored sword image, update the stored value only when changed, and set the sword-change flag.",
            "The target preserves the same three-block branch and changes only the string wrapper, stored field, and change-flag offset for the rebuilt object layout.",
            "The target method sits in the corresponding late-player setter region and has the same one-update return behavior as the source.",
        ],
    },
    {
        "original_ea": "0x19dd4c",
        "original_name": "TPlayer_setShield_TString_const",
        "spectron_ea": "0x1a29e4",
        "target_name_fragment": "W6NzgawMJy10KVuowaeDdSERK10C8THgaTQxF",
        "source_basis": "normalized shield image update and change flag",
        "source_basic_block_count": 3,
        "spectron_basic_block_count": 3,
        "required_string_refs": [],
        "evidence": [
            "Both normalize the incoming filename, compare it with the stored shield image, update the stored value only when changed, and set the shield-change flag.",
            "The target preserves the same three-block branch and changes only the string wrapper, stored field, and change-flag offset for the rebuilt object layout.",
            "The target method sits beside the corresponding sword setter and keeps the source one-update return behavior.",
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
                "match_kind": "manual-player-visual-setter-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in player-visual-setter anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_player_visual_setter_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for player draw rectangle and visual setters",
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
            "The correspondence relies on preserved setter branches, shifted player fields, inherited-call roles, compatible block counts, and reviewed pseudocode rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
