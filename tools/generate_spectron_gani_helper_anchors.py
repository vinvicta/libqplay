#!/usr/bin/env python3
"""Create reviewed anchors for two compact Spectron Gani helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x15dc50",
        "original_name": "TColorVar_writeString_TString_const",
        "spectron_ea": "0x160dc0",
        "target_name_fragment": "HTugbItBu10m6pngaXzjoERK10CanTfaz6bZ",
        "source_size": 112,
        "target_size": 108,
        "source_instruction_count": 28,
        "target_instruction_count": 27,
        "source_basic_block_count": 3,
        "target_basic_block_count": 3,
        "source_basis": "Gani color-variable string setter",
        "evidence": [
            "Both first resolve the supplied string through the Gani color table and use the resulting color index when it is nonnegative.",
            "Both fall back to the shared string-to-integer parser for an unrecognized color name, then invoke the color-variable virtual setter at vtable slot 192.",
            "The target is the compact three-block helper immediately before the preserved Gani receive-event method. Its 108-byte, 27-instruction body is four bytes and one instruction smaller than the 112-byte, 28-instruction 1.8 body because the target normalizes through its rebuilt string wrapper.",
        ],
    },
    {
        "original_ea": "0x15de20",
        "original_name": "TGaniObject_getImageForSprite_TGraalAniSprite_bool",
        "spectron_ea": "0x160f8c",
        "target_name_fragment": "ieJzgaIFFy10DYcNfbKw0TEP10JQknDa08eKb",
        "source_size": 544,
        "target_size": 552,
        "source_instruction_count": 135,
        "target_instruction_count": 137,
        "source_basic_block_count": 32,
        "target_basic_block_count": 31,
        "source_basis": "Gani sprite image-name selection",
        "evidence": [
            "Both reject a null sprite, read its sprite type and index, and walk the child-Gani chain when the parent has children.",
            "Both handle type 8 through the indexed child list, require the selected image record's state field at offset 128 to equal 1, and copy the image name from offset 144.",
            "Both preserve the type 0 through type 9 switch, including the optional current-object update for type 1, the body strings at offsets 376 through 432, the global sprites and tiles filenames, and the indexed child-list lookup.",
            "The target is 552 bytes with 137 instructions and 31 blocks versus 544 bytes with 135 instructions and 32 blocks in 1.8. The changed block count comes from target compiler layout around the same field accesses and string assignments, so this is a semantic correspondence rather than an exact body match.",
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
                "match_kind": "manual-gani-helper-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in Gani helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_gani_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the Gani color setter and sprite image-name helper",
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
            "The correspondence is supported by direct Hex-Rays pseudocode, class-local order, shared object fields, and matching compact helper roles.",
            "Changed byte sizes, instruction counts, and block counts are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
