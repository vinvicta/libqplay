#!/usr/bin/env python3
"""Create reviewed anchors for the residual TSocket lifecycle block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source TSocket lifecycle sequence contains preDestroy, checkAllowBind, bind, checkScriptActive, and runScript at 0x205780 through 0x205bdc. Spectron keeps the same XJLBgarMnA class order at 0x20b78c through 0x20bc1c.",
    "preDestroy and checkScriptActive have exact normalized metrics. checkScriptActive is already present in the canonical semantic map, so this artifact records the four remaining rows only. checkAllowBind, bind, and runScript are larger in Spectron, but their state fields, connection calls, event branches, and class-local order remain aligned.",
    "checkAllowBind still compares the allowed-port field with the wildcard, parses the configured port list and ranges, and returns whether the current port is permitted. bind still creates or replaces the live connection, applies the port and SSL configuration, and dispatches onBind or onBindFailed behavior.",
    "runScript still advances the socket state, handles the connection states for connect, accepted clients, and close, adds accepted clients to the clients collection, and invokes the corresponding script events before and after the base runScript call.",
    "The source rows expose readable event and log strings including onBind, onBindFailed, onConnect, onConnectFailed, onNewClient, onClose, clients, and scripts. Spectron retains clients, onClose, and scripts in the clean export while constructing other values through encoded C8THgaTQxF and related wrappers.",
    "The target-only jump thunk at 0x20bbd4 corresponds to the source jump at 0x205b94 and remains an explicit boundary. The following TSocketProperties constructor and destructor block is also outside this lifecycle batch.",
]


SOURCE_TARGETS = {
    0x205780: 0x20B78C,
    0x2057A0: 0x20B7AC,
    0x205948: 0x20B958,
    0x205BDC: 0x20BC1C,
}

EXACT_SHAPE_SOURCE_EAS = {0x205780}


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
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        if target.get("is_default_name"):
            raise ValueError("unexpected default target name at 0x%x" % target_ea)
        if not target.get("name", "").startswith("_ZN10XJLBgarMnA"):
            raise ValueError("unexpected target class at 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        expected_shape_equal = source_ea in EXACT_SHAPE_SOURCE_EAS
        if shape_equal != expected_shape_equal:
            raise ValueError("unexpected lifecycle shape result at 0x%x" % source_ea)
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
                "match_kind": "manual-tsocket-lifecycle-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TSocket lifecycle method %s" % source["name"],
                "context_group": "TSocket residual lifecycle block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tsocket_lifecycle_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TSocket lifecycle block",
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
            "source_sequence": "0x205780 preDestroy through 0x205bdc runScript, excluding 0x205b98 already in the semantic map",
            "target_sequence": "0x20b78c through 0x20bc1c in the ordered XJLBgarMnA lifecycle block, excluding 0x20bbd8 already in the semantic map",
            "target_class": "XJLBgarMnA",
            "target_deltas": {
                "preDestroy": "+0x600c",
                "checkAllowBind": "+0x600c",
                "bind": "+0x6010",
                "runScript": "+0x6040",
            },
            "existing_semantic_anchor": {
                "source_ea": "0x205b98",
                "target_ea": "0x20bbd8",
                "name": "v18_TSocket_checkScriptActive_void",
                "target_delta": "+0x6040",
            },
            "source_jump_boundary": "0x205b94",
            "target_jump_boundary": "0x20bbd4",
            "following_target_properties_boundary": "0x20bfa0",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target names are resolved by the explicit class-local address map, lifecycle state behavior, connection fields, event dispatch, and representative pseudocode.",
            "Expanded target bodies are recorded as layout-change anchors, while preDestroy is an exact normalized-shape match. checkScriptActive is retained as an existing semantic-map boundary rather than duplicated here.",
            "The jump thunk and following TSocketProperties block remain explicit boundaries and are not silently folded into this batch.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
