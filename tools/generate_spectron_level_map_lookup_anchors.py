#!/usr/bin/env python3
"""Create reviewed anchors for Spectron level and map lookup helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1a02e4",
        "original_name": "getLevel_TString_const",
        "spectron_ea": "0x1a4fbc",
        "target_name_fragment": "OEizxa5ijRRK10C8THgaTQxF",
        "source_size": 208,
        "target_size": 216,
        "source_basic_block_count": 9,
        "target_basic_block_count": 9,
        "required_string_refs": [],
        "source_basis": "active server-level lookup by normalized filename",
        "evidence": [
            "Both normalize the requested filename, reject an empty normalized value, iterate the global level list, compare each level name at offset 128, and return the matching level or null.",
            "The target pseudocode uses RUnvgavJ0u for the same lowercase filename helper, iterates QYZugaRKGu::yOs_IafR9s, and compares each candidate's offset-128 name before returning it.",
            "The target keeps the source nine-block lookup shape and differs by only eight bytes because the 2.2 string wrapper and obfuscated list accessors expand the body slightly.",
        ],
    },
    {
        "original_ea": "0x1a03b4",
        "original_name": "getLevelPos_TString_const_TStringList",
        "spectron_ea": "0x1a5094",
        "target_name_fragment": "x_WogaefBpRK10CanTfaz6bZP10vuuHgangcF",
        "source_size": 120,
        "target_size": 48,
        "source_basic_block_count": 5,
        "target_basic_block_count": 6,
        "required_string_refs": [],
        "source_basis": "normalized level-name index lookup",
        "evidence": [
            "Both accept a level name and a string-list-like level collection, return -1 for an empty name or missing list, and return the collection index for the normalized name.",
            "The target is the thin wrapper at the corresponding level-list helper position. It validates the same inputs and forwards to vuuHgangcF::JtTLgaLhUI, the obfuscated indexOf equivalent.",
            "The target is 72 bytes smaller and has one additional block because Spectron moved lowercase normalization into its callers and kept this method as a compact index wrapper. This is a semantic role match, not a byte-for-byte claim.",
        ],
    },
    {
        "original_ea": "0x1a08e8",
        "original_name": "TServerLevelLink_getTStringRepresentation_void",
        "spectron_ea": "0x1a5580",
        "target_name_fragment": "yO8PSaf1tK10kI9vmbZMFyEv",
        "source_size": 1140,
        "target_size": 1164,
        "source_basic_block_count": 16,
        "target_basic_block_count": 16,
        "required_string_refs": [],
        "source_basis": "server-level link serialization",
        "evidence": [
            "Both build the link representation from the prefix at offset 112, four floating-point coordinates at offsets 120 through 144, and the two space-separated level fields at offsets 152 and 160.",
            "Both remove spaces from the two level fields, append them to the coordinate string, replace comma decimal separators with periods, and prepend the link prefix before returning the output string.",
            "The target preserves the source sixteen-block serialization shape and differs by 24 bytes because its renamed string methods and rebuilt wrappers use different instruction expansion.",
        ],
    },
    {
        "original_ea": "0x1a8404",
        "original_name": "checkForNewMap_TPlayer_TString_const",
        "spectron_ea": "0x1ad124",
        "target_name_fragment": "Ga8KmbJugLP10W6NzgawMJyRK10C8THgaTQxF",
        "source_size": 328,
        "target_size": 368,
        "source_basic_block_count": 16,
        "target_basic_block_count": 16,
        "required_string_refs": [],
        "source_basis": "player current-map selection and level-position refresh",
        "evidence": [
            "Both reject a missing player, normalize the requested map name, search the global map list by the map name at offset 128 or by its alias list at offset 312, and clear the player's cached map when no entry matches.",
            "Both leave the player unchanged when the selected map is already cached. When the map changes, both store the new map and call the update-map-position method for every loaded server level before returning true.",
            "The target preserves the source sixteen-block state transition and moves the player map pointer from the older offset 216 to the Spectron offset 219. The 40-byte size increase reflects changed wrappers and fields.",
        ],
    },
    {
        "original_ea": "0x1a8e88",
        "original_name": "LoadGraalMap_TPlayer_TString_const_bool",
        "spectron_ea": "0x1add28",
        "target_name_fragment": "B0Ozga8wKyP10W6NzgawMJyRK10C8THgaTQxFb",
        "source_size": 704,
        "target_size": 852,
        "source_basic_block_count": 35,
        "target_basic_block_count": 35,
        "required_string_refs": [".gmap"],
        "source_basis": "GMAP file resolution, loading, and map refresh",
        "evidence": [
            "Both normalize the input filename, append .gmap when it has no extension, search the global map list, optionally clear an existing map, and resolve a missing game file through the resource and download helpers.",
            "Both allocate a 0x198-byte server-level object for a new map, load the GMAP data, add the map to the global list, update the download record, and then refresh either the active player's side levels and board state or the affected loaded levels.",
            "The target pseudocode calls the target checkForNewMap, side-level, map-position, board, and buffer methods in the same order as the source. It preserves the 35-block state machine and .gmap literal while expanding by 148 bytes.",
        ],
    },
    {
        "original_ea": "0x1a9148",
        "original_name": "getMap_TString_const_bool",
        "spectron_ea": "0x1ae07c",
        "target_name_fragment": "sFYSSauERMRK10C8THgaTQxFb",
        "source_size": 344,
        "target_size": 348,
        "source_basic_block_count": 10,
        "target_basic_block_count": 10,
        "required_string_refs": [],
        "source_basis": "map lookup and optional placeholder construction",
        "evidence": [
            "Both normalize the requested map filename, compare it against the normalized filename field at offset 120 for every global map, and return an existing object before loading or creating anything.",
            "On a miss, both call the GMAP loader with the active player and false, then optionally allocate a 0x198-byte server-level object when the caller permits creation and the map list has at most 999 entries.",
            "Both mark the placeholder as a map, add the same built-in alias to its alias list, append it to the global map list, and return it. The target preserves the ten-block shape and is only four bytes larger.",
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
        if source.get("size") != spec["source_size"]:
            raise ValueError("unexpected source size at %s" % spec["original_ea"])
        if target.get("size") != spec["target_size"]:
            raise ValueError("unexpected target size at %s" % spec["spectron_ea"])
        if source.get("basic_block_count") != spec["source_basic_block_count"]:
            raise ValueError(
                "unexpected source basic-block count at %s" % spec["original_ea"]
            )
        if target.get("basic_block_count") != spec["target_basic_block_count"]:
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
                "match_kind": "manual-level-map-lookup-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in level-map anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_level_map_lookup_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for level lookup, link serialization, map selection, and GMAP loading",
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
            "The level lookup, link serialization, map selection, and GMAP loading matches are supported by direct pseudocode, class-local ordering, shared field offsets, preserved control-flow shapes, and the shared .gmap literal where applicable.",
            "Changed byte sizes and the thin getLevelPos wrapper are recorded as version differences. No exact byte identity is claimed for these six pairs.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
