#!/usr/bin/env python3
"""Create the reviewed Spectron TGaniObject constructor anchor."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_EA = "0x15e810"
SOURCE_NAME = "TGaniObject_TGaniObject_TServerLevel"
TARGET_EA = "0x161a24"
TARGET_NAME_FRAGMENT = "ieJzgaIFFyC1EP10zF9VgaBKxR"
EXACT_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "mnemonic_hash",
    "register_shape_hash",
    "shape_hash",
)
REQUIRED_STRINGS = ("attr", "black")


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
    return {field: function.get(field) for field in EXACT_FIELDS}


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
    source = original.get(int(SOURCE_EA, 16))
    target = spectron.get(int(TARGET_EA, 16))
    if source is None:
        raise ValueError("missing original TGaniObject constructor feature")
    if target is None:
        raise ValueError("missing Spectron TGaniObject constructor feature")
    if source.get("name") != SOURCE_NAME:
        raise ValueError("unexpected original TGaniObject constructor name")
    if TARGET_NAME_FRAGMENT not in target.get("name", ""):
        raise ValueError("unexpected Spectron TGaniObject constructor signature")
    for field in EXACT_FIELDS:
        if source.get(field) is None or target.get(field) is None:
            raise ValueError("missing constructor metric: %s" % field)
    for literal in REQUIRED_STRINGS:
        if literal not in source.get("string_refs", []):
            raise ValueError("source constructor lacks required string %s" % literal)
        if literal not in target.get("string_refs", []):
            raise ValueError("target constructor lacks required string %s" % literal)
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    if int(TARGET_EA, 16) in semantic_targets:
        raise ValueError("target constructor is already in the semantic map")

    anchor = {
        "original_ea": SOURCE_EA,
        "original_name": SOURCE_NAME,
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "spectron_ea": TARGET_EA,
        "spectron_current_name": target.get("name", ""),
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "proposed_name": "v18_" + SOURCE_NAME,
        "confidence": "high",
        "match_kind": "manual-gani-constructor-context-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TGaniObject construction from a server-level parent",
        "evidence": [
            "Both call the level-object base constructor, install the animation-object vtable, initialize the same child pointers and scalar state, and allocate the show-image list and parameter collections.",
            "Both create the attr variable, insert the built-in alias, construct 30 numbered TGaniParam children, create the colors variable, and add five configured color variables plus black.",
            "Both finish by initializing the animation scale, color, font, visibility, sprite, and lookup state. The target retains the source attr and black literals and the same 31-entry parameter loop.",
            "The target constructor is 1836 bytes and 18 blocks versus 1356 bytes and 11 blocks in 1.8. The added state includes Spectron's random seeds and encoded buffers, so the match is semantic rather than byte-identical.",
        ],
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_gani_constructor_manual_translation_anchor_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TGaniObject server-level constructor",
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
            "anchor_count": 1,
            "high_confidence_count": 1,
            "already_in_semantic_map": 0,
            "new_context_anchor_count": 1,
            "target_default_name_count": int(anchor["spectron_default_name"]),
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The address is valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ label preserves the readable 1.8 role while the evidence row retains the obfuscated 2.2 constructor name.",
            "Changed size, block count, random-seed state, and encoded buffers are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
