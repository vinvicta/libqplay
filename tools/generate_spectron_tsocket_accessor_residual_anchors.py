#!/usr/bin/env python3
"""Create reviewed anchors for the residual TSocket accessor and factory block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source TSocket accessor block runs from 0x204630 through 0x2047e8. Spectron keeps the same ordered field-accessor block at 0x20a508 through 0x20a6c0, a fixed +0x5ed8 delta inside the obfuscated XJLBgarMnA class.",
    "The reviewed rows cover byte, dword, list-count, string-field, and allowed-socket accessors. The target bodies retain the same field roles and normalized metrics. The allowed-port setter changes only through the target C8THgaTQxF string wrapper and its obfuscated global field.",
    "TSocket_sendOutgoing_void at 0x204894 maps to 0x20a76c. Both bodies check the connection object and error state, send positive-length buffered data, and remove the transmitted prefix. The target replaces the named TSocketConnection and TString helpers with u3cBgayBVz and C8THgaTQxF wrappers.",
    "TSocket_create_TString_const at 0x204a70 maps to 0x20a948. Both factories allocate 0xf0 bytes, call the parameterized socket constructor, and return the object. The class-specific XJLBgarMnA constructor call resolves the factory role among generic allocator candidates.",
    "Eighteen reviewed pairs have exact normalized metrics, including mnemonic hash, opcode shape, register shape, and overall shape hash. The allowed-port setter is the only layout-change row. None of these functions has string references.",
]


SOURCE_EAS = [
    0x204630,
    0x204638,
    0x204650,
    0x204658,
    0x204660,
    0x204668,
    0x204670,
    0x204678,
    0x204688,
    0x204698,
    0x2046C8,
    0x2046F8,
    0x204728,
    0x204758,
    0x204788,
    0x2047B8,
    0x2047E8,
    0x204894,
    0x204A70,
]


TARGET_DELTA = 0x5ED8


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
    for order, source_ea in enumerate(SOURCE_EAS, 1):
        target_ea = source_ea + TARGET_DELTA
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected string references at 0x%x" % source_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        if source_ea != 0x204678 and not shape_equal:
            raise ValueError("unexpected metric difference at 0x%x" % source_ea)
        if source_ea == 0x204678 and shape_equal:
            raise ValueError("allowed-port setter unexpectedly has an exact shape")
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
                "match_kind": "manual-tsocket-accessor-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TSocket accessor, output, or factory method %s" % source["name"],
                "context_group": "TSocket residual accessor and factory block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tsocket_accessor_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TSocket accessor and factory block",
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
            "source_sequence": "0x204630 through 0x2047e8 accessors, 0x204894 sendOutgoing, and 0x204a70 create",
            "target_sequence": "0x20a508 through 0x20a6c0 accessors, 0x20a76c sendOutgoing, and 0x20a948 create",
            "target_class": "XJLBgarMnA",
            "target_delta": "+0x5ed8",
            "layout_change_source": "0x204678",
            "layout_change_target": "0x20a550",
            "factory_source": "0x204a70",
            "factory_target": "0x20a948",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target names are resolved by the fixed class-local delta, exact normalized shapes, field roles, and the socket factory call graph.",
            "The allowed-port setter is recorded as a layout-change anchor because Spectron replaces the source TString global with an obfuscated string wrapper and field.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
