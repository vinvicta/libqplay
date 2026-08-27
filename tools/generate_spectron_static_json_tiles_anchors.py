#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron static, JSON, and tile helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x22d3dc",
        "original_name": "TStaticVar_TStaticVar_TString_const",
        "spectron_ea": "0x236ea0",
        "target_name_fragment": "NgNBgaN3oAC2ERK10C8THgaTQxF",
        "source_basis": "static script variable construction",
        "required_string_refs": [],
        "evidence": [
            "Both call the TGraalVar string constructor, mark the variable as initialized, install the static-variable vtable and properties, and attach the new variable to the global universe list.",
            "Both preserve the same null-universe fallback, previous-list-link update, and universe count increment. The target adds rebuilt string-wrapper calls and grows from 180 to 224 bytes while retaining the five-block constructor role.",
        ],
    },
    {
        "original_ea": "0x22e378",
        "original_name": "TGraalVar_writeJSONObject_yajl_gen_t_bool",
        "spectron_ea": "0x237ec8",
        "target_name_fragment": "G0gxgajWBw10tNsxZakQLnEP10yajl_gen_tb",
        "source_basis": "recursive TGraalVar JSON object writer",
        "required_string_refs": ["actionplayer", "initialized", "unknown_object", "xmlname"],
        "evidence": [
            "Both select between scalar, array, and object output, filter the same initialized, actionplayer, name, and unknown_object properties, and recurse through array children and object properties.",
            "Both preserve the same typed YAJL emission branches for booleans, strings, numbers, objects, and nulls, and retain the actionplayer, initialized, unknown_object, and xmlname literals. The target grows from 1692 to 1816 bytes but keeps the 77-block writer shape.",
        ],
    },
    {
        "original_ea": "0x22f32c",
        "original_name": "TTiles_SaveTileDefinitions_void",
        "spectron_ea": "0x238f48",
        "target_name_fragment": "kyTzgazlOy10e0CVvaMq5sEv",
        "source_basis": "tile-definition persistence",
        "required_string_refs": ["levels", "tiledefs"],
        "evidence": [
            "Both clear the save-pending flag, build the server-specific tiledefs text path beneath the levels directory, serialize each tile definition as comma-separated fields, and save the resulting string list.",
            "Both retain the levels and tiledefs literals, the same five-field serialization loop, forced-directory creation, and final list destruction. The target grows from 944 to 976 bytes while retaining the four-block persistence flow.",
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
        if source.get("basic_block_count") != target.get("basic_block_count"):
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
                "match_kind": "manual-static-json-tiles-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in static/JSON/tiles anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_static_json_tiles_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for static variables, JSON serialization, and tile-definition persistence",
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
            "The changed-size rows rely on class-local order, required strings, matching block structure, and pseudocode behavior rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
