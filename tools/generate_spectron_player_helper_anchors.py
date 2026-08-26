#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for compact TPlayer helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x16c760",
        "original_name": "TPlayer_setAttachedTo_TServerPlayer",
        "spectron_ea": "0x170318",
        "target_name": "_ZN10W6NzgawMJy10QL5FfaVs1NEP10MpGzgariDy",
        "source_basis": "player attachment setter",
        "evidence": [
            "Both bodies mark the player as changed when the attached player pointer changes, then store the new pointer.",
            "The source and target preserve the same 28-byte, seven-instruction, six-register-shape normalized body.",
        ],
    },
    {
        "original_ea": "0x1731f0",
        "original_name": "TPlayer_sendChanges_void",
        "spectron_ea": "0x1771f0",
        "target_name": "_ZN10W6NzgawMJy10_w0Tway3JhEv",
        "source_basis": "player property-change notification",
        "evidence": [
            "Both bodies test the global client object and call the player property test routine only when a client exists.",
            "The source and target preserve the same 24-byte, six-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x1764a8",
        "original_name": "TPlayer_setFreezeCounter_int",
        "spectron_ea": "0x17a778",
        "target_name": "_ZN10W6NzgawMJy10skVnwaVQJREi",
        "source_basis": "player freeze-counter setter",
        "evidence": [
            "Both bodies store the counter and clear the same freeze-state byte when the counter is negative.",
            "The source and target preserve the same 20-byte, five-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x17bcb8",
        "original_name": "TPlayer_drawSpriteAbsolute_int_int_int",
        "spectron_ea": "0x180060",
        "target_name": "_ZN10W6NzgawMJy10jZKyLaa8QCEiii",
        "source_basis": "absolute player sprite-draw wrapper",
        "evidence": [
            "Both wrappers forward the sprite index and coordinates to the same absolute-offset routine with zero offsets.",
            "The source and target preserve the same 20-byte, five-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x17bd88",
        "original_name": "TPlayer_drawSprite_int_float_float",
        "spectron_ea": "0x180130",
        "target_name": "_ZN10W6NzgawMJy10TfRVga8phREiff",
        "source_basis": "offset player sprite-draw wrapper",
        "evidence": [
            "Both wrappers forward the sprite index and floating-point coordinates to the same offset routine with zero offsets.",
            "The source and target preserve the same 12-byte, three-instruction, single-block normalized body.",
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
            raise ValueError("unexpected original name at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("unexpected Spectron name at %s" % spec["spectron_ea"])
        for field in ("size", "instruction_count", "basic_block_count"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
                )
        for field in ("mnemonic_hash", "register_shape_hash", "shape_hash"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
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
                "match_kind": "manual-player-helper-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in player helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_player_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact TPlayer attachment, update, freeze, and sprite helpers",
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
            "already_in_semantic_map": sum(row["semantic_match_already_present"] for row in anchors),
            "new_context_anchor_count": sum(not row["semantic_match_already_present"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The target bodies preserve the local player attachment, update, freeze, and sprite wrapper behavior with exact normalized function hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
