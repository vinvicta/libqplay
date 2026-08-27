#!/usr/bin/env python3
"""Create reviewed anchors for the residual socket-cache support block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source support block contains TSocketConnection_initStaticVars at 0x207968, TSocketConnection_initStaticScriptVars at 0x207998, IsHostAndPortInList at 0x2079ac, and the TCachedHostAddress destructor pair at 0x207c54 and 0x207c68. Spectron keeps the same local order at 0x20dab4, 0x20db00, 0x20db14, 0x20ddc0, and 0x20ddd4.",
    "The target static initializer at 0x20dab4 creates the cached-host hash list and an additional target global object before returning. The source initializer creates the cached-host list only, so this pair is recorded as a layout change that preserves the source role while documenting the target's combined global setup.",
    "The script-variable initializer at 0x20db00 retains the source property-registration role, but the target passes a four-entry table where the source passes two entries. IsHostAndPortInList retains wildcard matching, comma-list parsing, host pattern comparison, single-port and range checks, and the same final predicate.",
    "The source TCachedHostAddress complete and deleting destructors clear the embedded TString field, restore the vtable, and optionally call operator delete. The target reub2aL2gs D1 and D0 functions perform the same cleanup with exact normalized shapes.",
    "The source and target IsHostAndPortInList rows both retain the wildcard string. The target makes C8THgaTQxF, vuuHgangcF, and comparison wrappers explicit, changing 680/170/20/49/37 to 684/171/20/49/37 for bytes, instructions, blocks, branches, and calls.",
]


SOURCE_TARGETS = {
    0x207968: 0x20DAB4,
    0x207998: 0x20DB00,
    0x2079AC: 0x20DB14,
    0x207C54: 0x20DDC0,
    0x207C68: 0x20DDD4,
}

EXPECTED_SOURCE_NAMES = {
    0x207968: "TSocketConnection_initStaticVars_void",
    0x207998: "TSocketConnection_initStaticScriptVars_void",
    0x2079AC: "IsHostAndPortInList_TString_const_TString_const_int",
    0x207C54: "TCachedHostAddress_TCachedHostAddress",
    0x207C68: "TCachedHostAddress_TCachedHostAddress__2",
}

EXPECTED_TARGET_NAMES = {
    0x20DAB4: "_Z10OYaS2aPQb1v",
    0x20DB00: "_Z10TO_L1aAs_5v",
    0x20DB14: "_Z10mNHZ0adswrRK10C8THgaTQxFS1_i",
    0x20DDC0: "_ZN10reub2aL2gsD1Ev",
    0x20DDD4: "_ZN10reub2aL2gsD0Ev",
}

EXACT_SHAPE_SOURCE_EAS = {0x207C54, 0x207C68}


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
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
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
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for order, (source_ea, target_ea) in enumerate(SOURCE_TARGETS.items(), 1):
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != EXPECTED_SOURCE_NAMES[source_ea]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != EXPECTED_TARGET_NAMES[target_ea]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        expected_shape_equal = source_ea in EXACT_SHAPE_SOURCE_EAS
        if shape_equal != expected_shape_equal:
            raise ValueError("unexpected socket-cache shape result at 0x%x" % source_ea)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": "0x%x" % target_ea,
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-socket-cache-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "socket cache support method %s" % source["name"],
                "context_group": "socket cache support residual block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_socket_cache_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual socket-cache support block",
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
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "layout_change_anchor_count": sum(not row["shape_equal"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_sequence": "0x207968 through 0x207c68 in the socket-cache support block",
            "target_sequence": "0x20dab4 through 0x20ddd4 in the target cache and host-list block",
            "source_class": "TSocketConnection and TCachedHostAddress",
            "target_classes": ["global support", "reub2aL2gs"],
            "target_delta": "+0x614c through +0x616c, with local target growth",
            "target_global_initializer_combines": ["cached-host hash list", "additional target global object"],
            "following_target_boundary": "0x20de04",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source roles while retaining the target obfuscated names in the evidence rows.",
            "The static initializer correspondence is a reviewed role match even though the target combines an additional global object setup with the source cached-host list initialization.",
            "The cached-host destructor pairs are exact normalized-shape matches. The property-registration initializer and IsHostAndPortInList are small layout changes that preserve their source roles while exposing target differences.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
