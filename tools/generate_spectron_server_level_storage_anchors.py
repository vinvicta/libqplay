#!/usr/bin/env python3
"""Create reviewed anchors for Spectron server-level construction and storage."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1a854c",
        "original_name": "TServerLevel_TServerLevel_TString_const",
        "spectron_ea": "0x1ad294",
        "target_name_fragment": "zF9VgaBKxRC2ERK10C8THgaTQxF",
        "source_size": 2364,
        "target_size": 2708,
        "source_basic_block_count": 38,
        "target_basic_block_count": 38,
        "required_string_refs": [
            "arrows",
            "board",
            "bombs",
            "chests",
            "explos",
            "items",
            "links",
            "projectiles",
            "signs",
            "tilelayers",
            "tiles",
        ],
        "source_basis": "server-level constructor and child-array initialization",
        "evidence": [
            "Both lower-case and store the supplied level name, initialize the same base and server-level fields, create the tile-layer and board children, and allocate the same collection slots.",
            "Both construct the tiles child, register the arrows, bombs, chests, explosions, items, signs, links, and projectiles script children, then initialize the level trees, map coordinates, and update-map hook.",
            "The source and target reference the same eleven child-array strings and preserve the 38-block constructor shape. The target is larger because the 2.2 wrappers and obfuscated class fields are rebuilt, so this is a semantic context anchor rather than an exact byte match.",
        ],
    },
    {
        "original_ea": "0x1a1f50",
        "original_name": "TServerLevel_SaveEncrypted_uint",
        "spectron_ea": "0x1a6c00",
        "target_name_fragment": "zF9VgaBKxR10DXk2RaUeA4Ej",
        "source_size": 2516,
        "target_size": 2600,
        "source_basic_block_count": 98,
        "target_basic_block_count": 98,
        "required_string_refs": ["GR-V1.03", "GR-V1.05", "GWEBL001"],
        "source_basis": "encrypted server-level serialization",
        "evidence": [
            "Both derive the encrypted filename, build the GWEBL001 header, encode the server IP, signature, requested level version, and level name, and then serialize the level contents.",
            "Both select the GR-V1.03 or GR-V1.05 board format, serialize every tile layer, append link and baddie data, encode sign and object records, calculate the same seeded checksum, and finish through the coded-file save routine.",
            "The source and target preserve the 98-block control-flow shape and the same GR-V1.03, GR-V1.05, and GWEBL001 literals. The target is 84 bytes larger because its rebuilt wrappers and fields have different instruction expansion.",
        ],
    },
    {
        "original_ea": "0x1aa198",
        "original_name": "TServerLevel_LoadEncrypted_void",
        "spectron_ea": "0x1af2a0",
        "target_name_fragment": "zF9VgaBKxR10GGiB_ayk_gEv",
        "source_size": 1200,
        "target_size": 1272,
        "source_basic_block_count": 31,
        "target_basic_block_count": 31,
        "required_string_refs": ["GR-V1.03", "GR-V1.04", "GR-V1.05", "GWEBL001"],
        "source_basis": "encrypted server-level deserialization",
        "evidence": [
            "Both derive the level filename and checksum seed, load the coded file, validate the GWEBL001 header, server identity, signature, level name, and supported GR-V1 format.",
            "Both handle the GR-V1.03 single-board path and the GR-V1.05 multi-layer path, then read links, baddies, NPCs, chests, and signs before releasing the coded stream.",
            "The source and target preserve the 31-block validation and load state machine and the same four format literals. The target is 72 bytes larger because of rebuilt 2.2 wrappers and field accessors.",
        ],
    },
    {
        "original_ea": "0x1a3ee0",
        "original_name": "TServerLevel_invokePlayerEnters_TString_const_int_int_int_int",
        "spectron_ea": "0x1a8be0",
        "target_name_fragment": "zF9VgaBKxR10b9PRwaiuUfERK10C8THgaTQxFiiii",
        "source_size": 668,
        "target_size": 692,
        "source_basic_block_count": 33,
        "target_basic_block_count": 31,
        "required_string_refs": [],
        "source_basis": "player-enter event dispatch across NPCs and baddies",
        "evidence": [
            "Both gate the callback on client and active-level state, compare the entered level name, and scan the server-level NPC list and baddie list for objects affected by the old and new coordinates.",
            "Both invoke each object's virtual callback with the same empty event string when the coordinate windows match, and return the list result through the same final path.",
            "The target preserves the source callback filtering and list traversal but reduces the body to 31 blocks through rebuilt wrappers and obfuscated field access. The signature retains the level string plus four integer arguments.",
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
                "match_kind": "manual-server-level-storage-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in server-level storage anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_level_storage_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for server-level construction, encrypted storage, and player-enter dispatch",
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
            "The constructor, save, load, and player-enter matches are supported by direct pseudocode, preserved block counts, stable level-list and child-array roles, and the shared serialized-format literals.",
            "Changed byte sizes are recorded as version differences. No exact byte identity is claimed for these four pairs.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
