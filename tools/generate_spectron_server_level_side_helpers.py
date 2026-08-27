#!/usr/bin/env python3
"""Create reviewed anchors for Spectron server-level side helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1a92a0",
        "original_name": "TServerLevel_getSideLevelPos_int_int",
        "spectron_ea": "0x1ae1d8",
        "target_name_fragment": "zF9VgaBKxR10LiM2RarfX4EPiS0_",
        "source_basis": "server-level side-level position lookup",
        "source_size": 256,
        "target_size": 532,
        "source_basic_block_count": 21,
        "target_basic_block_count": 29,
        "evidence": [
            "Both accept a server-level object and two output integers, search the active player's cached side-level grid, and return the matching row and column or -1, -1 when the level is not present.",
            "The target preserves the same class-local side-level lookup position and expands the cached grid traversal from the 1.8 three-by-three arrangement to the seven-by-seven Spectron arrangement.",
            "The target pseudocode compares the candidate object against the active-player side-level slots and writes the discovered grid coordinates through the two output pointers, matching the source role despite the expanded layout and rebuilt field references.",
        ],
    },
    {
        "original_ea": "0x1a93a0",
        "original_name": "TServerLevel_getSideLevelInDirection_int",
        "spectron_ea": "0x1ae3ec",
        "target_name_fragment": "zF9VgaBKxR10rRAVgazC3QEi",
        "source_basis": "directional side-level lookup",
        "source_size": 212,
        "target_size": 408,
        "source_basic_block_count": 9,
        "target_basic_block_count": 20,
        "evidence": [
            "Both use the active player's map position, the server-level grid position, and the input movement vector to select a neighboring side-level slot.",
            "Both return the cached side-level object when the calculated row and column are in range and return null otherwise. The target expands the valid side-level range and uses the seven-entry stride introduced by the Spectron layout.",
            "The target keeps the source method's four-direction switch and current-level-relative coordinate calculation, with only the obfuscated fields, rebuilt globals, and expanded bounds changed.",
        ],
    },
    {
        "original_ea": "0x1a9480",
        "original_name": "TServerLevel_calcFlowers_void",
        "spectron_ea": "0x1ae584",
        "target_name_fragment": "zF9VgaBKxR10VicXmbBYpVEv",
        "source_basis": "server-level flower calculation hook",
        "exact_body_match": True,
        "evidence": [
            "Both are server-level void methods with an empty body in the reviewed ARM64 libraries.",
            "The target method follows the two side-level helpers and occupies the corresponding no-op hook position immediately before animateObjects in the same class-local cluster.",
            "All exported body metrics match exactly: four bytes, one instruction, one basic block, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x1a9484",
        "original_name": "TServerLevel_animateFlowers_void",
        "spectron_ea": "0x1ae588",
        "target_name_fragment": "zF9VgaBKxR10uLrpmbFY0sEv",
        "source_basis": "server-level flower animation hook",
        "exact_body_match": True,
        "evidence": [
            "Both are server-level void methods with an empty body in the reviewed ARM64 libraries.",
            "The target method is the second adjacent no-op hook in the corresponding class-local cluster and is followed by the already translated animateObjects method.",
            "All exported body metrics match exactly: four bytes, one instruction, one basic block, and identical normalized hashes.",
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
    exact_fields = (
        "size",
        "instruction_count",
        "basic_block_count",
        "mnemonic_hash",
        "register_shape_hash",
        "shape_hash",
    )

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
        if spec.get("exact_body_match"):
            for field in exact_fields:
                if source.get(field) != target.get(field):
                    raise ValueError(
                        "%s mismatch at %s to %s"
                        % (field, spec["original_ea"], spec["spectron_ea"])
                    )
        else:
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
                "match_kind": "manual-server-level-side-helper-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in server-level side-helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_level_side_helpers_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for server-level side-level and flower helper methods",
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
            "The side-level matches rely on direct pseudocode and the preserved class-local lookup order, with the target's seven-by-seven grid expansion recorded as an intentional version difference.",
            "The flower matches are exact body matches and remain separate hooks even though both are no-ops in these builds.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
