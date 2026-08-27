#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron TShowImg serialization cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x2349e0",
        "original_name": "TShowImg_readString_void",
        "spectron_ea": "0x23e7d0",
        "target_name_fragment": "eODlJaQ5OL10VkenganG9nEv",
        "source_basis": "show-image wire string encoder",
        "required_string_refs": ["#", "%", "&", "0", "@"],
        "evidence": [
            "Both select output by show-image mode, emit the same @ text, # polygon, % textured-polygon, and & animation prefixes, and encode the same tile and gani fields.",
            "Both preserve the part-index and animation-parameter branches, including the zero-value fallback and five-value color or parameter loop. The target keeps the same class-local method and grows from 980 to 1132 bytes with one fewer basic block.",
        ],
    },
    {
        "original_ea": "0x236b8c",
        "original_name": "TShowImg_writeString_TString_const",
        "spectron_ea": "0x240a14",
        "target_name_fragment": "eODlJaQ5OL10m6pngaXzjoERK10CanTfaz6bZ",
        "source_basis": "show-image wire string dispatcher",
        "required_string_refs": ["ATTR", "PARAM"],
        "evidence": [
            "Both dispatch the first encoded character to showPoly, showTexturedPoly, showAni, or showText and use ATTR and PARAM prefixes to route attribute and parameter strings to the sprite path.",
            "Both fall back to the image path for empty, numeric, or unrecognized values and retain the same 27-block dispatcher. The target is 580 bytes versus 592 in the source after wrapper rebuilding.",
        ],
    },
    {
        "original_ea": "0x2372d8",
        "original_name": "TShowImg_getNetProperty_TServerPlayer_int",
        "spectron_ea": "0x241154",
        "target_name_fragment": "eODlJaQ5OL10fAkcNaaWZ_EP10MpGzgariDyi",
        "source_basis": "show-image network property encoder",
        "required_string_refs": [],
        "evidence": [
            "Both reject a missing player, switch over network property indexes 0 through 8, encode the image and image-part fields, and clamp numeric values into the same one-byte wire representation.",
            "Both use player-relative coordinates for the low image modes, preserve the rotation, alpha, color, speed, and layer calculations, and return the encoded string through the caller buffer. The target adds one basic block and grows from 1256 to 1288 bytes.",
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
                "match_kind": "manual-showimg-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in ShowImg anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_showimg_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TShowImg serialization and network properties",
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
            "The changed-size rows rely on class-local order, wire-format prefixes, field offsets, preserved property-index branches, and pseudocode behavior rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
