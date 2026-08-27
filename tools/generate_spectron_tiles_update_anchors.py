#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron tile update and draw cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x22f6f4",
        "original_name": "TTiles_UpdateTempTiles_TString_const",
        "spectron_ea": "0x239330",
        "target_name_fragment": "kyTzgazlOy10qq8UvaWHGsERK10C8THgaTQxF",
        "source_basis": "temporary tile reconciliation",
        "required_string_refs": [],
        "require_basic_block_match": True,
        "evidence": [
            "Both collect matching tile definitions, reconcile the temporary-tile list by filename and dimensions, delete stale entries, add missing entries, and refresh each temporary texture size.",
            "Both return a changed flag after the same temporary-list cleanup and preserve the 58-block reconciliation flow. The target grows from 1108 to 1136 bytes as its string and list wrappers are rebuilt.",
        ],
    },
    {
        "original_ea": "0x22fb48",
        "original_name": "TTiles_GetLevelTiles_TString_const",
        "spectron_ea": "0x2397a0",
        "target_name_fragment": "kyTzgazlOy10mKkUvaB3_rERK10C8THgaTQxF",
        "source_basis": "level tileset lookup",
        "required_string_refs": ["pics1.png"],
        "require_basic_block_match": False,
        "evidence": [
            "Both strip the incoming level filename, initialize the selected image to pics1.png, scan the tile definitions for the matching prefix, and accept only the same tile-definition types and positive image index.",
            "Both update the global tile-set type and return the selected image through the caller-provided string. The target adds static-string initialization and rebuilt wrappers, changing the body from 17 to 20 blocks and from 336 to 420 bytes.",
        ],
    },
    {
        "original_ea": "0x22fc98",
        "original_name": "TTiles_UpdateTiles_void",
        "spectron_ea": "0x239944",
        "target_name_fragment": "kyTzgazlOy10NOVzgaofQyEv",
        "source_basis": "active level tileset update",
        "required_string_refs": [],
        "require_basic_block_match": True,
        "evidence": [
            "Both derive the active player's lower-case level filename, compare the selected tileset with the current one, and update the current and original tile filenames when it changes.",
            "Both call the temporary-tile reconciler and reinitialize the active player's tile buffer when either the tileset or temporary tile dimensions change. The target retains the ten-block state-update flow and grows from 288 to 316 bytes.",
        ],
    },
    {
        "original_ea": "0x22fdb8",
        "original_name": "TTiles_AddTileDefinition_TString_const_TString_const_int_int_int",
        "spectron_ea": "0x239a80",
        "target_name_fragment": "kyTzgazlOy10IFgYvaQDjvERK10C8THgaTQxFS2_iii",
        "source_basis": "tile-definition insertion and replacement",
        "required_string_refs": [],
        "require_basic_block_match": False,
        "evidence": [
            "Both normalize the image and tile filenames, search for an existing definition with matching names and three numeric fields, and return without changing the list when the definition is already identical.",
            "Both remove conflicting entries, allocate the seven-field tile record, append it to the tile-definition list, mark definitions dirty, and call the tile update path. The target changes the maximum-entry guard from 9999 to 999999 and grows from 24 to 25 blocks and from 616 to 716 bytes.",
        ],
    },
    {
        "original_ea": "0x230040",
        "original_name": "TTiles_isTilesImage_TString_const",
        "spectron_ea": "0x239d6c",
        "target_name_fragment": "kyTzgazlOy10wLMzgaHDIyERK10C8THgaTQxF",
        "source_basis": "tile image membership test",
        "required_string_refs": [],
        "require_basic_block_match": True,
        "evidence": [
            "Both strip the filename and scan the tile-definition list for a definition whose image filename matches the normalized input.",
            "Both return immediately on the first match and return false after the same six-block scan. The target grows from 180 to 208 bytes only for rebuilt string-wrapper operations.",
        ],
    },
    {
        "original_ea": "0x230244",
        "original_name": "TTiles_LoadTileDefinitions_void",
        "spectron_ea": "0x239f8c",
        "target_name_fragment": "kyTzgazlOy10ZxfiLanHYoEv",
        "source_basis": "tile-definition file loading",
        "required_string_refs": ["levels", "tiledefs"],
        "require_basic_block_match": True,
        "evidence": [
            "Both clear existing definitions, build the server-specific levels/tiledefs path, load the text file, split each row by commas, and create records from the first five fields.",
            "Both skip short rows, add parsed definitions to the global list, destroy the temporary string lists, and finish by rebuilding the selected tiles. The target retains the eight-block loader flow and grows from 888 to 908 bytes.",
        ],
    },
    {
        "original_ea": "0x2306fc",
        "original_name": "TTiles_updateAnimatedTiles_TPlayer_TString_const",
        "spectron_ea": "0x23a598",
        "target_name_fragment": "kyTzgazlOy10cWUzgaxvPyEP10W6NzgawMJyRK10C8THgaTQxF",
        "source_basis": "animated temporary-tile refresh",
        "required_string_refs": [],
        "require_basic_block_match": False,
        "evidence": [
            "Both validate the player, tile buffer, and level filename, find the matching temporary tile, scan the visible 64-by-64 tile cells, and repaint cells whose source tile falls inside the temporary tile rectangle.",
            "Both stop each cell scan at 4096 entries and call the player offscreen-paint operation with the same repaint flags. The target uses its viewport-offset fields and changes the body from 22 to 25 blocks and from 504 to 724 bytes.",
        ],
    },
    {
        "original_ea": "0x231bb4",
        "original_name": "TTilesPanel_drawTilesOnScreen_int_int",
        "spectron_ea": "0x23bb2c",
        "target_name_fragment": "BEXWLaNNcX10XL8VLa1ZwWEii",
        "source_basis": "tile-panel screen rendering",
        "required_string_refs": ["Draw_Tiles"],
        "require_basic_block_match": False,
        "evidence": [
            "Both guard rendering by login state and active-player flags, create the Draw_Tiles profiler entry, walk the tile panel grid, skip transparent tiles, and draw black or textured cells through the graphics backend.",
            "The target changes the backend from the original vertex-array path to its newer quad and texture operations, but preserves the same grid bounds, 64-pixel cell geometry, transparent and black tile decisions, and profiler literal. The target is 32 blocks and 780 bytes versus 42 blocks and 1240 bytes in the source.",
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
        if spec["require_basic_block_match"] and (
            source.get("basic_block_count") != target.get("basic_block_count")
        ):
            raise ValueError(
                "basic-block count mismatch at %s to %s"
                % (spec["original_ea"], spec["spectron_ea"])
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
                "match_kind": "manual-tiles-update-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in tile-update anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tiles_update_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for tile selection, definition updates, temporary tiles, and screen rendering",
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
            "The changed-size rows rely on class-local order, tile-list state, distinctive literals, matching control-flow roles, and pseudocode behavior rather than byte identity.",
            "The two tile-block predicates used by the draw path were already recorded in the earlier core-helper anchor artifact and are intentionally not duplicated here.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
