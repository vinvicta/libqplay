#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron player side-level cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x16e3d0",
        "original_name": "TPlayer_setSideLevels_void",
        "spectron_ea": "0x1720d0",
        "target_name_fragment": "W6NzgawMJy10MKZNwa6yFcEv",
        "source_basis": "side-level grid reset and neighboring level selection",
        "source_basic_block_count": 30,
        "spectron_basic_block_count": 26,
        "evidence": [
            "Both clear the player side-level string grid, reset the cached level pointers and availability flag, then derive neighboring level names from the current level position.",
            "Both use the level width and height to visit the same neighboring coordinate pattern, resolve available level objects, lower-case the current filename, and cache the current level pointer.",
            "The target expands the side-level grid from the 1.8 three-by-three layout to a seven-by-seven layout and replaces several wrapper calls, which reduces the block count from 30 to 26 while preserving the role and class-local position.",
        ],
    },
    {
        "original_ea": "0x16e634",
        "original_name": "TPlayer_loadSideLevels_void",
        "spectron_ea": "0x172404",
        "target_name_fragment": "W6NzgawMJy10NgRNwaNqycEv",
        "source_basis": "side-level object reuse, cleanup, and preload",
        "source_basic_block_count": 46,
        "spectron_basic_block_count": 38,
        "evidence": [
            "Both collect the old and newly selected side-level objects, call the side-level grid setup, and remove temporary objects from levels that are no longer needed.",
            "Both destroy objects from removed levels, preserve the same three-by-three side-level traversal concept, create missing side levels only when a client is present, mark them as side levels, load them, add them to the global level list, and send preload packets.",
            "The target uses a seven-by-seven side-level grid and rebuilt list and level wrappers, accounting for the smaller 38-block body while preserving the direct call from the reviewed main level-entry method.",
        ],
    },
    {
        "original_ea": "0x16e9e8",
        "original_name": "TPlayer_getSideLevel_int_int",
        "spectron_ea": "0x1727e0",
        "target_name_fragment": "W6NzgawMJy10KcGULan7hVEii",
        "source_basis": "side-level coordinate lookup with bounds rejection",
        "source_basic_block_count": 9,
        "spectron_basic_block_count": 4,
        "evidence": [
            "Both convert signed tile offsets into a side-level row and column, reject coordinates outside the available side-level range, and return the selected cached level object or null.",
            "The target stores the expanded grid with a seven-entry stride instead of the source three-entry stride and delegates each coordinate boundary conversion to two new target-only helpers immediately above this method.",
            "The target preserves the source method’s class-local order and lookup result while reducing the body to four blocks because the repeated boundary arithmetic was split into those helper methods.",
        ],
    },
    {
        "original_ea": "0x16ea50",
        "original_name": "TPlayer_SideLevelInDirection_int",
        "spectron_ea": "0x172854",
        "target_name_fragment": "W6NzgawMJy10HbDSwauAzgEi",
        "source_basis": "directional side-level occupancy lookup",
        "source_basic_block_count": 20,
        "spectron_basic_block_count": 16,
        "evidence": [
            "Both select the side-level row or column for one of the four directions, clamp invalid directions, and scan outward through the available side-level entries until a cached level is found.",
            "Both return true on the first occupied side-level slot and false when the directional range is exhausted. The target uses the expanded seven-entry grid and the same directional constant table with renamed target fields.",
            "The target preserves the source method’s neighboring position, occupancy semantics, and switch structure while reducing the body from 20 to 16 blocks through rebuilt wrappers and shared target constants.",
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
                "match_kind": "manual-player-side-level-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in player-side-level anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_player_side_level_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for player side-level grid setup, loading, and lookup",
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
            "The target adds two boundary-normalization helpers between the grid loader and the side-level lookup methods. They are target-only helpers and are intentionally not given a 1.8 name.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
