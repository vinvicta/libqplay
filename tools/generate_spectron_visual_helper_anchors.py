#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for compact visual helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x15d4f8",
        "original_name": "TGaniObject_getChildVisibilityInverted",
        "spectron_ea": "0x160588",
        "target_name": "sub_160588",
        "source_basis": "animation child visibility accessor",
        "evidence": [
            "Both bodies read the child object pointer and return the inverse of its visibility byte, or zero when there is no child.",
            "The source and target preserve the same 28-byte, seven-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x15d624",
        "original_name": "TGaniObject_setByteField500Clamped",
        "spectron_ea": "0x1606f4",
        "target_name": "sub_1606F4",
        "source_basis": "animation mode byte setter",
        "evidence": [
            "Both bodies clamp values above three to zero and store the result in the same logical animation field.",
            "The source and target preserve the same 20-byte, five-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x15d78c",
        "original_name": "TGaniObject_setz_double",
        "spectron_ea": "0x16085c",
        "target_name": "_ZN10ieJzgaIFFy10iZDhga9esjEd",
        "source_basis": "animation depth setter",
        "evidence": [
            "Both bodies compare the depth value, set the same changed flag when it differs, and store the new double.",
            "The source and target preserve the same 28-byte, seven-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x1c96f0",
        "original_name": "TGUIAnimation_get_alpha",
        "spectron_ea": "0x1ce270",
        "target_name": "sub_1CE270",
        "source_basis": "GUI animation alpha accessor",
        "evidence": [
            "Both bodies read the animation-properties pointer, return the alpha field when present, and use one as the null default.",
            "The source callback record identifies the alpha property in TGUIAnimationProperties.",
        ],
    },
    {
        "original_ea": "0x1c9758",
        "original_name": "TGUIAnimation_get_rotation",
        "spectron_ea": "0x1ce2d8",
        "target_name": "sub_1CE2D8",
        "source_basis": "GUI animation rotation accessor",
        "evidence": [
            "Both bodies read the animation-properties pointer, return the rotation field when present, and use zero as the null default.",
            "The source callback record identifies the rotation property in TGUIAnimationProperties.",
        ],
    },
    {
        "original_ea": "0x232b50",
        "original_name": "TParticleDataEx_getPartHeightInTiles_void",
        "spectron_ea": "0x23c900",
        "target_name": "_ZNK10tJIwIaYe8310tWnLFaUKtKEv",
        "source_basis": "particle height conversion",
        "evidence": [
            "Both bodies convert the particle height field from pixels to tiles with the same factor of one sixteenth.",
            "The source and target preserve the same 20-byte, five-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x232bd8",
        "original_name": "TParticleDataEx_getPartWidthInTiles_void",
        "spectron_ea": "0x23c988",
        "target_name": "_ZNK10tJIwIaYe8310CZfLFaz3mKEv",
        "source_basis": "particle width conversion",
        "evidence": [
            "Both bodies convert the particle width field from pixels to tiles with the same factor of one sixteenth.",
            "The source and target preserve the same 20-byte, five-instruction, single-block normalized body beside the height accessor.",
        ],
    },
    {
        "original_ea": "0x233190",
        "original_name": "TParticleDataEx_getPlayerLook_void",
        "spectron_ea": "0x23cf58",
        "target_name": "_ZNK10tJIwIaYe8310vcSNFa8czMEv",
        "source_basis": "particle player-look accessor",
        "evidence": [
            "Both bodies read the particle player pointer and return its look byte, or zero when the pointer is absent.",
            "The source and target preserve the same 24-byte, six-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x2341e0",
        "original_name": "TShowImg_set_mode",
        "spectron_ea": "0x23df38",
        "target_name": "sub_23DF38",
        "source_basis": "show-image mode setter",
        "evidence": [
            "Both bodies clamp modes at four to zero and store the result in the same show-image field.",
            "The source callback record identifies the mode property in TShowImgProperties.",
        ],
    },
    {
        "original_ea": "0x235548",
        "original_name": "TShowImg_setImageType_int",
        "spectron_ea": "0x23f3d0",
        "target_name": "_ZN10eODlJaQ5OL10jqR8WaJy3mEi",
        "source_basis": "show-image type setter",
        "evidence": [
            "Both bodies store the image type in the same field and then set level visibility true through the same helper call.",
            "The source and target preserve the same 12-byte, three-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x239950",
        "original_name": "TParticleEmitter_setNrofParticles_int",
        "spectron_ea": "0x2437f0",
        "target_name": "_ZN10pdnkJaZ8KK10Gt6lJaI3cMEi",
        "source_basis": "particle emitter count setter",
        "evidence": [
            "Both bodies clamp the particle count to the inclusive range zero through 1000 and store it in the same emitter field.",
            "The source and target preserve the same 28-byte, seven-instruction, single-block normalized body.",
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
                "match_kind": "manual-visual-helper-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in visual helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_visual_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact animation, particle, and show-image helpers",
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
            "The target visual helpers preserve the local animation, particle, and show-image behavior with exact normalized function hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
