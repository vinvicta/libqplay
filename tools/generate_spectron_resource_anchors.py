#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for resource resolver helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0xee524",
        "original_name": "TResourceFunctions_validateFileKey_TString_const",
        "spectron_ea": "0xef5a0",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "encoded resource-key validation and alternative refresh",
        "evidence": [
            "The source and target hash the encoded key, look up the matching resource, and mark the resource key as active.",
            "Both bodies obtain or create the resource alternative, attach the key object, and refresh the resource through the same client resource helper.",
            "The target retains the f6WHgaQkAF resource-function class context and the one-string mangled signature.",
        ],
    },
    {
        "original_ea": "0xee604",
        "original_name": "TResourceFunctions_getMatchingResourceObjects_TString_const_int_bool",
        "spectron_ea": "0xef69c",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "wildcard resource matching with limits and optional sorting",
        "evidence": [
            "The source and target both allocate a result list, handle a direct level-resource lookup, and otherwise iterate the resource hash list.",
            "Both paths match resource names, append linked alternatives, enforce the caller limit, and optionally sort the result list.",
            "The target signature retains a string, integer, and boolean shape and its 30-block body preserves the wildcard branch.",
        ],
    },
    {
        "original_ea": "0xee814",
        "original_name": "TResourceFunctions_getFilesForPattern_TString_const_int",
        "spectron_ea": "0xef8d4",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "resource pattern expansion into a file-name list",
        "evidence": [
            "The source and target extract the requested filename and path, build data and user search roots, and call the matching-resource helper.",
            "Both convert matching resource paths back to relative names and append them to a TStringList, with separate data-root and user-root handling.",
            "The target keeps the one-string and integer mangled signature and the same 23-block control-flow shape as the source.",
        ],
    },
    {
        "original_ea": "0xeeae8",
        "original_name": "TResourceFunctions_getResourceStream_TString_const_bool_bool",
        "spectron_ea": "0xefcd0",
        "target_name_fragment": "ERK10C8THgaTQxFbb",
        "source_basis": "resource stream lookup, update, and download fallback",
        "evidence": [
            "The source and target choose absolute-path or level-resource lookup based on the input path.",
            "Both check whether the resource can be loaded, optionally update it, return its stream, and request a download or allocate an empty stream when needed.",
            "The target retains two boolean parameters in its mangled signature and the same resource-class call sequence.",
        ],
    },
    {
        "original_ea": "0xeec64",
        "original_name": "TResourceFunctions_gamefileexists_TString_const",
        "spectron_ea": "0xefe58",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "source_basis": "game-file resource existence test",
        "evidence": [
            "The source is a one-line resource lookup predicate, and the target returns the corresponding resource lookup result as a boolean.",
            "The target is the short wrapper immediately before the target game-file path helper in the resource-function cluster.",
            "The one-string mangled signature and direct call to the target level-resource lookup distinguish this role from stream and path construction helpers.",
        ],
    },
    {
        "original_ea": "0xeec84",
        "original_name": "TResourceFunctions_getGameFile_TString_const_bool",
        "spectron_ea": "0xefe78",
        "target_name_fragment": "ERK10C8THgaTQxFb",
        "source_basis": "game-file path construction with download fallback",
        "evidence": [
            "The source and target resolve the level resource, compose its stored path and filename, and return the resulting game-file path.",
            "Both preserve the optional download call when the resource is absent and return an empty TString in that case.",
            "The target follows the resource-existence wrapper and retains the one-string plus boolean mangled signature.",
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
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_size": source["size"],
                "original_instruction_count": source["instruction_count"],
                "original_basic_block_count": source["basic_block_count"],
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target_name,
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_size": target["size"],
                "spectron_instruction_count": target["instruction_count"],
                "spectron_basic_block_count": target["basic_block_count"],
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-resource-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in resource anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_resource_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for resource matching, streams, and game-file resolution",
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
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated or default 2.2 name in the evidence row.",
            "These rows describe local resource resolution and loading logic; they do not establish compatibility with an external service.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
