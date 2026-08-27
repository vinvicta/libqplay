#!/usr/bin/env python3
"""Create reviewed anchors for compact Spectron server-level properties."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x19f938",
        "original_name": "TServerLevel_set_preloadleveldefaulttile",
        "spectron_ea": "0x1a4608",
        "target_name_fragment": "sub_1A4608",
        "source_basis": "server-level preload tile static setter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both assign the incoming integer to the same logical preloadleveldefaulttile static variable and return the value.",
            "The source static-script-variable table comment places preloadleveldefaulttile at 0x380160, and the target has the matching one-block setter reference from its rebuilt table at 0x3931d8.",
            "All exported body metrics match exactly: 16 bytes, four instructions, one block, and identical mnemonic, register-shape, and control-flow hashes.",
        ],
    },
    {
        "original_ea": "0x19f948",
        "original_name": "TServerLevel_getHeight",
        "spectron_ea": "0x1a4618",
        "target_name_fragment": "sub_1A4618",
        "source_basis": "server-level height property getter",
        "source_basic_block_count": 3,
        "spectron_basic_block_count": 3,
        "required_string_refs": [],
        "evidence": [
            "Both select the active layer when present, return its height in 64-pixel units, and fall back to 64 when no active layer is available.",
            "The source property record at 0x37fce0 is documented as height in TServerLevelProperties; the target reference at 0x392d50 occupies the matching property sequence.",
            "All exported body metrics match exactly: 48 bytes, 12 instructions, three blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19f978",
        "original_name": "TServerLevel_getNoPKZone",
        "spectron_ea": "0x1a4648",
        "target_name_fragment": "sub_1A4648",
        "source_basis": "server-level no-PK zone getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both read the no-PK zone byte at the same logical server-level field, offset 298 in each build.",
            "The source getter is shared by the isnopkzone and nopkzone property records at 0x37fd10 and 0x37fd70; the target has both matching table references at 0x392d80 and 0x392de0.",
            "All exported body metrics match exactly: eight bytes, two instructions, one block, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19f980",
        "original_name": "TServerLevel_setNoPKZone",
        "spectron_ea": "0x1a4650",
        "target_name_fragment": "sub_1A4650",
        "source_basis": "server-level no-PK zone setter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both store the script boolean directly in the no-PK zone byte at logical offset 298 and return the object.",
            "The source setter is shared by the isnopkzone and nopkzone property records at 0x37fd10 and 0x37fd70; the target has the matching setter references at 0x392d88 and 0x392de8.",
            "All exported body metrics match exactly: eight bytes, two instructions, one block, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19f988",
        "original_name": "TServerLevel_getSparringZone",
        "spectron_ea": "0x1a4658",
        "target_name_fragment": "sub_1A4658",
        "source_basis": "server-level sparring-zone getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both read the separate sparring-zone byte at logical offset 297.",
            "The source property record at 0x37fd40 decodes to issparringzone and points to this getter; the target has the matching one-block reference at 0x392db0.",
            "All exported body metrics match exactly: eight bytes, two instructions, one block, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19f990",
        "original_name": "TServerLevel_getTileLayerCount",
        "spectron_ea": "0x1a4660",
        "target_name_fragment": "sub_1A4660",
        "source_basis": "server-level tile-layer count getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both follow the server-level layer-list pointer at logical offset 112 and return its element count.",
            "The source property record at 0x37fda0 decodes to tilelayercount and points to this getter; the target has the matching reference at 0x392e10.",
            "All exported body metrics match exactly: 12 bytes, three instructions, one block, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19f99c",
        "original_name": "TServerLevel_getWidth",
        "spectron_ea": "0x1a466c",
        "target_name_fragment": "sub_1A466C",
        "source_basis": "server-level width property getter",
        "source_basic_block_count": 3,
        "spectron_basic_block_count": 3,
        "required_string_refs": [],
        "evidence": [
            "Both select the active layer when present, return its width in 64-pixel units, and fall back to 64 when no active layer is available.",
            "The source property record at 0x37fdd0 is documented as width in TServerLevelProperties; the target reference at 0x392e40 occupies the matching property sequence.",
            "All exported body metrics match exactly: 48 bytes, 12 instructions, three blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x19faa8",
        "original_name": "TServerLevelLink_getDestLevel",
        "spectron_ea": "0x1a46a0",
        "target_name_fragment": "sub_1A46A0",
        "source_basis": "server-level-link destination string getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both initialize the returned string wrapper, copy the destination-level string from the same logical object offset 112, and return the output wrapper.",
            "The source level-link property record at 0x37f9b0 decodes to destlevel and has no setter; the target has the matching one-block reference at 0x392a20.",
            "All exported body metrics match exactly: 48 bytes, 12 instructions, one block, and identical normalized hashes.",
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
    exact_fields = (
        "size",
        "instruction_count",
        "basic_block_count",
        "mnemonic_hash",
        "register_shape_hash",
        "shape_hash",
    )
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
        for field in exact_fields:
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
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
                "match_kind": "manual-server-level-property-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in server-level property anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_level_property_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact server-level properties and level-link destination access",
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
            "These eight pairs are exact exported body matches. The correspondence is additionally supported by script-property table records, direct pseudocode, and class-local order.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
