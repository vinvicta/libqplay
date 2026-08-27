#!/usr/bin/env python3
"""Create reviewed anchors for the Gani matrix, parameter, and start helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x15fe4c",
        "original_name": "TGaniObject_checkPush2DMatrix_TPlayer",
        "spectron_ea": "0x16323c",
        "target_name_fragment": "ieJzgaIFFy10oyT6Laxlp5EP10W6NzgawMJy",
        "source_size": 128,
        "target_size": 288,
        "source_instruction_count": 32,
        "target_instruction_count": 72,
        "source_basic_block_count": 9,
        "target_basic_block_count": 14,
        "required_string_refs": [],
        "source_basis": "Gani 2D draw-matrix setup",
        "evidence": [
            "Both read the Gani scale and rotation values, skip the identity case, and call the player draw-matrix helper with the transformed scale values and rotation.",
            "The target is immediately after the obfuscated getGaniOldSprite jump, matching the source class-local order immediately after the readable getGaniOldSprite jump.",
            "Spectron adds a target-side byte and float transform before the same push operation, which expands the body to 288 bytes and 14 blocks versus 128 bytes and nine blocks in 1.8. The output role and surrounding class order remain the same.",
        ],
    },
    {
        "original_ea": "0x160260",
        "original_name": "TGaniObject_setGaniParamOrAttr_bool_bool_int_TString_const",
        "spectron_ea": "0x1636f0",
        "target_name_fragment": "ieJzgaIFFy10Q8KcHachlYEbbiRK10C8THgaTQxF",
        "source_size": 228,
        "target_size": 268,
        "source_instruction_count": 57,
        "target_instruction_count": 67,
        "source_basic_block_count": 13,
        "target_basic_block_count": 13,
        "required_string_refs": [],
        "source_basis": "Gani parameter or attribute string setter",
        "evidence": [
            "Both select either the numbered parameter list or the attribute list from the boolean selector, apply the source's one-based or zero-based index convention, and reject invalid indexes.",
            "Both set the temporary visibility flag at object offset 160, assign the supplied string through the parameter virtual writer at slot 200, call the Gani visibility query at slot 432, update parameter visibility, and clear the temporary flag.",
            "The target preserves the source 13-block shape and expands from 228 to 268 bytes because its string assignment and list wrappers are rebuilt under obfuscated target classes.",
        ],
    },
    {
        "original_ea": "0x160344",
        "original_name": "TGaniObject_getGaniParamOrAttr_bool_int",
        "spectron_ea": "0x1637fc",
        "target_name_fragment": "ieJzgaIFFy10b6SzgaMYNyEbi",
        "source_size": 168,
        "target_size": 204,
        "source_instruction_count": 42,
        "target_instruction_count": 51,
        "source_basic_block_count": 13,
        "target_basic_block_count": 13,
        "required_string_refs": [],
        "source_basis": "Gani parameter or attribute numeric getter",
        "evidence": [
            "Both select the parameter or attribute list using the same boolean selector, preserve the different index bases, reject missing and out-of-range entries, and return an empty string for failure.",
            "Both call the selected variable's virtual value getter at slot 184 and return the resulting string through the hidden return object.",
            "The target preserves the source 13-block shape and expands from 168 to 204 bytes through the target string temporary and list wrapper calls.",
        ],
    },
    {
        "original_ea": "0x160534",
        "original_name": "TGaniObject_startAnimation_TString_const_TString_const_bool",
        "spectron_ea": "0x163a10",
        "target_name_fragment": "ieJzgaIFFy10eHoSJa2nncERK10C8THgaTQxFS2_b",
        "source_size": 2832,
        "target_size": 2880,
        "source_instruction_count": 706,
        "target_instruction_count": 718,
        "source_basic_block_count": 126,
        "target_basic_block_count": 126,
        "required_string_refs": ["def", "playerlook", "true"],
        "source_basis": "Gani animation load, parameter, and child-object rebuild",
        "evidence": [
            "Both trim the requested animation and parameter strings, fall back to the current animation and a comma separator, load the Gani resource, maintain the owner relationship, and reset frame state when the animation changes.",
            "Both parse bracketed frame metadata, rebuild numbered parameters from comma-separated input, create child Gani objects for the animation's show entries, and rebuild the special NPC-backed child object when needed.",
            "Both refresh the player-look child, copy the current animation name to the backing child, compare the full Gani name, and invoke the same reload hook when that name changes. The source and target retain the `def`, `playerlook`, and `true` literals.",
            "The target preserves the source 126-block shape and is 48 bytes and 12 instructions larger because the target wrappers and string temporaries expand individual operations. The direct pseudocode correspondence is strong despite the changed names and fields.",
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
                "match_kind": "manual-gani-runtime-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in Gani runtime anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_gani_runtime_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for Gani matrix setup, parameter access, and animation start",
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
            "The correspondence is supported by direct Hex-Rays pseudocode, class-local order, shared object fields, virtual slots, and preserved literals where applicable.",
            "Changed byte sizes, instruction counts, and block counts are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
