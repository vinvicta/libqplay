#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron TPlayer core cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


GROUP_EVIDENCE = {
    "net_property": [
        "Both methods implement the large network-property switch for the player, including the same property IDs, length-prefixed string encoding, coordinate packing, animation and head filename handling, five-color serialization, level-name selection, and default-space cases.",
        "The target retains the same class-local field offsets and packet literals `head`, three spaces, and four spaces. The target body grows from 3476 to 3668 bytes through rebuilt string and wrapper calls, while the 187 to 198 block change remains consistent with versioned helper expansion.",
        "The target sits in the corresponding player-method cluster immediately after the status and property accessors. Its obfuscated signature is the only name-level difference, so this is a direct semantic translation rather than a proximity-only guess.",
    ],
    "constructor": [
        "Both constructors call the server-player base constructor, install the derived vtable, initialize the repeated player property storage and translation state, publish the player properties object, and create the client and clientr child variables.",
        "Both continue through player-variable initialization, account and nickname setup, platform-name initialization, weapon and animation defaults, and the same class-local cleanup fields. The target retains all seven constructor literals: `android`, `client`, `clientr`, `idle`, `letters.png`, `selectedlistplayers`, and `weapons`.",
        "The target keeps the exact 46-block constructor structure. Its 4208-byte, 1044-instruction body is larger than the 3920-byte, 973-instruction source body because the target uses expanded wrappers, but the initialization order and class-local position are preserved. IDA records the target C2 name with a C1 alternative, confirming the constructor role.",
    ],
}


ANCHOR_SPECS = [
    {
        "original_ea": "0x1712b8",
        "original_name": "TPlayer_getNetProperty_int",
        "spectron_ea": "0x1751b8",
        "target_name": "_ZN10W6NzgawMJy10fAkcNaaWZ_Ei",
        "proposed_name": "v18_TPlayer_getNetProperty_int",
        "source_metrics": (3476, 867, 187),
        "target_metrics": (3668, 916, 198),
        "group": "net_property",
        "source_basis": "TPlayer network-property packet serialization",
        "required_string_refs": ("   ", "    ", "head"),
    },
    {
        "original_ea": "0x1748f0",
        "original_name": "TPlayer_TPlayer_int",
        "spectron_ea": "0x178a74",
        "target_name": "_ZN10W6NzgawMJyC2Ei",
        "proposed_name": "v18_TPlayer_TPlayer_int",
        "source_metrics": (3920, 973, 46),
        "target_metrics": (4208, 1044, 46),
        "group": "constructor",
        "source_basis": "TPlayer integer constructor and default state initialization",
        "required_string_refs": (
            "android",
            "client",
            "clientr",
            "idle",
            "letters.png",
            "selectedlistplayers",
            "weapons",
        ),
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
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        for side, function in (("source", source), ("target", target)):
            expected = spec["%s_metrics" % side]
            actual = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual != expected:
                raise ValueError(
                    "unexpected %s metrics at %s: %s"
                    % (side, spec["%s_ea" % side], actual)
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
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-player-core-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": GROUP_EVIDENCE[spec["group"]],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in TPlayer core anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in TPlayer core anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tplayer_core_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TPlayer network-property serialization and construction",
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
            "The network-property correspondence is supported by direct Hex-Rays pseudocode, shared property cases, preserved packet literals, field offsets, and class-local order.",
            "The constructor correspondence is supported by direct Hex-Rays pseudocode, the same initialization order, exact block-count parity, preserved literals, and the target C2/C1 constructor pair.",
            "Changed byte sizes and instruction counts are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
