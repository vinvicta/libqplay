#!/usr/bin/env python3
"""Create reviewed anchors for residual TSocket client-list helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)


ANCHOR_SPECS = (
    {
        "original_ea": 0x204C34,
        "original_name": "TSocket_removeFromClientList_void",
        "spectron_ea": 0x20AB0C,
        "spectron_name": "_ZN10XJLBgarMnA10nZIBgaeslAEv",
        "source_basis": "socket removal from the client's clients list",
        "target_class": "XJLBgarMnA",
        "context_order": 1,
        "match_kind": "manual-tsocket-client-list-layout-context-anchor",
    },
    {
        "original_ea": 0x204D74,
        "original_name": "TSocket_TSocket__2",
        "spectron_ea": 0x20AC44,
        "spectron_name": "_ZN10XJLBgarMnAD0Ev",
        "source_basis": "TSocket deleting destructor",
        "target_class": "XJLBgarMnA",
        "context_order": 2,
        "match_kind": "manual-tsocket-exact-shape-anchor",
    },
    {
        "original_ea": 0x204E4C,
        "original_name": "TSocket_getError",
        "spectron_ea": 0x20AD1C,
        "spectron_name": "sub_20AD1C",
        "source_basis": "socket error property adapter",
        "target_class": "XJLBgarMnA",
        "context_order": 3,
        "match_kind": "manual-tsocket-exact-shape-anchor",
    },
    {
        "original_ea": 0x204EA8,
        "original_name": "TSocket_getIP",
        "spectron_ea": 0x20AD78,
        "spectron_name": "sub_20AD78",
        "source_basis": "socket IP property adapter",
        "target_class": "XJLBgarMnA",
        "context_order": 4,
        "match_kind": "manual-tsocket-exact-shape-anchor",
    },
)


EVIDENCE = [
    "The source and target rows occupy the same local XJLBgarMnA or TSocket method cluster after the socket constructor and before the connection and SSL methods.",
    "The source removeFromClientList method looks up the clients hash entry, removes this socket from the associated client variable, invokes the related cleanup callback when present, and clears the client pointer. The target nZIBgaeslA method preserves that clients-string lookup and cleanup sequence through KKhLga4xoI and G0gxgajWBw, then clears the same client field.",
    "The source remove method is 160 bytes, 40 instructions, 8 basic blocks, 13 branches, and 7 calls. The target is 152 bytes, 37 instructions, 7 basic blocks, 11 branches, and 6 calls. Both retain the distinctive clients string reference, so this row is recorded as a high-confidence layout-context match.",
    "The source TSocket_TSocket__2 body is the deleting destructor wrapper. The target XJLBgarMnA D0 destructor at 0x20ac44 calls the target complete destructor and operator delete, and the complete normalized feature record matches.",
    "The source TSocket_getError and TSocket_getIP rows are one-block property adapters that call the underlying TSocket_getError_void and TSocket_getIP_void methods. The target sub_20AD1C and sub_20AD78 rows have the same complete normalized shape and call the already translated target gLmBgarL2z and YgoBgaY13z methods respectively.",
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
    return {field: function.get(field) for field in METRIC_FIELDS}


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
    semantic_sources = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        source_ea = spec["original_ea"]
        target_ea = spec["spectron_ea"]
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at 0x%x" % source_ea)
        if target.get("name") != spec["spectron_name"]:
            raise ValueError(
                "target name mismatch at 0x%x: expected %s, got %s"
                % (target_ea, spec["spectron_name"], target.get("name"))
            )
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("TSocket row is already in the semantic map")
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        shape_equal = source_metrics == target_metrics
        if spec["context_order"] == 1:
            if shape_equal:
                raise ValueError("removeFromClientList unexpectedly has an exact shape")
            if "clients" not in source.get("string_refs", []) or "clients" not in target.get("string_refs", []):
                raise ValueError("removeFromClientList must retain the clients string")
        elif not shape_equal:
            raise ValueError("exact-shape TSocket row changed at 0x%x" % source_ea)

        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": "0x%x" % target_ea,
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": spec["match_kind"],
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_class": spec["target_class"],
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tsocket_residual_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TSocket client-list, destructor, error, and IP methods",
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
            "source_cluster": "0x204c34 through 0x204ec8",
            "spectron_cluster": "0x20ab0c through 0x20ad98",
            "target_class": "XJLBgarMnA",
            "existing_context": {
                "target_complete_destructor": "0x20aba4",
                "target_error_method": "0x20acb4",
                "target_ip_method": "0x20ad3c",
            },
            "layout_change": "The removeFromClientList target is eight bytes and three instructions shorter, with one fewer block, two fewer branches, and one fewer direct call. The destructor and two property adapters are exact normalized-shape matches.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The removeFromClientList role is established by the clients string, hash-list lookup, client-variable cleanup, and target class context despite the small implementation change.",
            "The source constructor-like TSocket_TSocket__2 name is documented as the D0 deleting destructor because its body calls the complete destructor and operator delete.",
            "The two default target wrapper names are translated as readable overlays while the underlying target error and IP methods remain separately identified in the existing socket map.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
