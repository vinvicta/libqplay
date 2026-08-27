#!/usr/bin/env python3
"""Create reviewed anchors for the large Gani frame and playback methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x163354",
        "original_name": "TGaniObject_setFrame_int",
        "spectron_ea": "0x16690c",
        "target_name_fragment": "ieJzgaIFFy8setFrameEi",
        "source_size": 6552,
        "target_size": 7068,
        "source_instruction_count": 1637,
        "target_instruction_count": 1765,
        "source_basic_block_count": 118,
        "target_basic_block_count": 128,
        "required_string_refs": [
            "0x",
            "ATTR",
            "PARAM",
            "ani",
            "attr",
            "body",
            "bold",
            "centered",
            "chat",
            "dir",
            "dx",
            "dy",
            "font",
            "head",
            "horse",
            "italic",
            "param",
            "playerlook",
            "rightaligned",
            "shaded",
            "shield",
            "sword",
            "sprite #",
            "strikeout",
            "text",
            "underline",
            "visible",
            "wordwrap",
        ],
        "source_basis": "Gani frame actor-modifier application",
        "evidence": [
            "Both begin by selecting the active actor frame and then query the same modifier keys: dx, dy, layer, visible, playerlook, dir, ani, chat, head, body, sword, shield, horse, attr, param, color, sprite #, file, text, font, zoom, and text-style flags.",
            "Both interpolate dx and dy between adjacent actor modifiers, map layer values through the parent level, update visibility and direction, start an animation override, parse chat text, and apply body, weapon, horse, attribute, parameter, and color changes.",
            "Both parse PARAM and ATTR sprite selectors, resolve a referenced sprite through the active Gani, load text and file fields, convert color components through the 0x prefix, interpolate zoom, and store bold, italic, centered, rightaligned, underline, strikeout, wordwrap, and shaded flags.",
            "The source and target retain the complete 28-string property inventory. The target is 7068 bytes, 1765 instructions, and 128 blocks versus 6552 bytes, 1637 instructions, and 118 blocks in 1.8. The additional target state and wrapper calls change layout but not the method role.",
        ],
    },
    {
        "original_ea": "0x164cf8",
        "original_name": "TGaniObject_playAnimation_void",
        "spectron_ea": "0x1684b0",
        "target_name_fragment": "ieJzgaIFFy10zE8FfaRT3NEv",
        "source_size": 1396,
        "target_size": 1452,
        "source_instruction_count": 349,
        "target_instruction_count": 363,
        "source_basic_block_count": 61,
        "target_basic_block_count": 62,
        "required_string_refs": ["ATTR", "PARAM"],
        "source_basis": "Gani frame playback, sound, and rollover",
        "evidence": [
            "Both update every child Gani, the NPC-backed child, and the object list through the same frame-update virtual slot before processing the current animation.",
            "Both advance the frame and animation counters, reset or loop them according to the loaded animation flags, and call the animation-start or frame-reset path when playback reaches the end.",
            "Both inspect active-player action entries, resolve PARAM and ATTR sound references, load the referenced resource file, calculate world coordinates from the object position and sound offsets, and play the sound through the same audio bridge.",
            "The target preserves the ATTR and PARAM literals and the 61-block playback structure. Its 1452-byte, 363-instruction body is 56 bytes and 14 instructions larger than the 1396-byte, 349-instruction 1.8 body because of target string temporaries and renamed list wrappers.",
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
        for side, function in (("source", source), ("target", target)):
            for field in ("size", "instruction_count", "basic_block_count"):
                expected = spec["%s_%s" % (side, field)]
                if function.get(field) != expected:
                    raise ValueError(
                        "unexpected %s %s at %s: %s"
                        % (side, field, spec["%s_ea" % side], function.get(field))
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
                "match_kind": "manual-gani-frame-playback-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in Gani frame-playback anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_gani_frame_playback_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for Gani frame application and playback",
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
            "The correspondence is supported by direct Hex-Rays pseudocode, class-local order, shared object fields, preserved property literals, and matching large-method roles.",
            "Changed byte sizes, instruction counts, and block counts are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
