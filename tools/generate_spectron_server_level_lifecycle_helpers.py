#!/usr/bin/env python3
"""Create reviewed anchors for compact Spectron server-level helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1a17b8",
        "original_name": "TServerLevel_TServerLevel__2",
        "spectron_ea": "0x1a6468",
        "target_name_fragment": "zF9VgaBKxRD0Ev",
        "source_basis": "server-level deleting destructor wrapper",
        "required_string_refs": [],
        "evidence": [
            "Both call the complete server-level destructor and then pass the object to operator delete.",
            "The target retains the C++ ABI D0 destructor role while the source has the readable TServerLevel_TServerLevel__2 name.",
            "All exported body metrics match exactly: 32 bytes, eight instructions, two blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x1a45a8",
        "original_name": "TServerLevel_script_tileType",
        "spectron_ea": "0x1a92c0",
        "target_name_fragment": "sub_1A92C0",
        "source_basis": "server-level tiletype script wrapper",
        "required_string_refs": [],
        "evidence": [
            "Both are the double-valued tiletype script callback and forward the two script coordinates to the server-level getTileType method.",
            "The source callback comment identifies the record at 0x380130 as tiletype; the target has the matching callback reference at 0x3931a8.",
            "All exported body metrics match exactly: 12 bytes, three instructions, two blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x1a5760",
        "original_name": "TServerLevel_script_testItem",
        "spectron_ea": "0x1aa478",
        "target_name_fragment": "sub_1AA478",
        "source_basis": "server-level item collision test wrapper",
        "required_string_refs": [],
        "evidence": [
            "Both are the double-valued testitem script callback and forward the two script coordinates to the server-level isOnExtra method.",
            "The source callback comment identifies the record at 0x3800a0 as testitem; the target has the matching callback reference at 0x393118.",
            "All exported body metrics match exactly: 12 bytes, three instructions, two blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x1a5898",
        "original_name": "TServerLevel_script_testExplo",
        "spectron_ea": "0x1aa5b0",
        "target_name_fragment": "sub_1AA5B0",
        "source_basis": "server-level explosion collision test wrapper",
        "required_string_refs": [],
        "evidence": [
            "Both are the double-valued testexplo script callback and forward the two script coordinates to the server-level isOnExplosion method.",
            "The source callback comment identifies the record at 0x380070 as testexplo; the target has the matching callback reference at 0x3930e8.",
            "All exported body metrics match exactly: 12 bytes, three instructions, two blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x1a6d44",
        "original_name": "TServerLevel_animateCarries_void",
        "spectron_ea": "0x1aba5c",
        "target_name_fragment": "zF9VgaBKxR10X9ulmb3PHpEv",
        "source_basis": "server-level carry animation queue",
        "required_string_refs": [],
        "evidence": [
            "Both walk the carry list in reverse, animate each carry, remove completed entries, and invoke the removed object's virtual cleanup path.",
            "The source uses the carry list at logical slot 32 and the target preserves that slot and loop structure in the obfuscated class.",
            "All exported body metrics match exactly: 140 bytes, 35 instructions, eight blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x1a6dd0",
        "original_name": "TServerLevel_animateLeaps_void",
        "spectron_ea": "0x1abae8",
        "target_name_fragment": "zF9VgaBKxR10cBflmbYJupEv",
        "source_basis": "server-level leap animation queue",
        "required_string_refs": [],
        "evidence": [
            "Both walk the leap list in reverse, animate each leap, remove completed entries, and invoke the removed object's virtual cleanup path.",
            "The source uses the leap list at logical slot 30 and the target preserves that slot and loop structure in the obfuscated class.",
            "All exported body metrics match exactly: 140 bytes, 35 instructions, eight blocks, and identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x1a6e5c",
        "original_name": "TServerLevel_animateFlyingObjects_void",
        "spectron_ea": "0x1abb74",
        "target_name_fragment": "zF9VgaBKxR10AiIkmbgT1oEv",
        "source_basis": "server-level flying-object animation queue",
        "required_string_refs": [],
        "evidence": [
            "Both walk the flying-object list in reverse, animate each object, remove completed entries, and invoke the removed object's virtual cleanup path.",
            "The source uses the flying-object list at logical slot 33 and the target preserves that slot and loop structure in the obfuscated class.",
            "All exported body metrics match exactly: 140 bytes, 35 instructions, eight blocks, and identical normalized hashes.",
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
                "match_kind": "manual-server-level-lifecycle-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in server-level lifecycle anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_level_lifecycle_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact server-level lifecycle, script-test, and animation helpers",
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
            "These seven pairs are exact exported body matches. The correspondence is additionally supported by callback roles, direct pseudocode, and class-local order.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
