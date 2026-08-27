#!/usr/bin/env python3
"""Create reviewed anchors for the residual TSocket receive methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source TSocket receive sequence contains checkDataPackages at 0x205328 and read at 0x2054c4. Spectron keeps the same XJLBgarMnA class order at 0x20b1f8 and 0x20b3f0, but the first target body grows and shifts the second address.",
    "checkDataPackages preserves the queued-data delimiter search at socket offsets 200 and 216, line splitting, array construction, and onReceiveDataPackage event dispatch. Spectron makes its C8THgaTQxF, CanTfaz6bZ, D6TlgajP1m, and G0gxgajWBw wrappers explicit.",
    "read preserves the connection guard at offset 176, connection error check, native read, state transition from 4 to 5, UDP flag at connection offset 8344, and the onConnect, onReceiveUDPData, and onReceiveData event paths. It still calls checkDataPackages after ordinary data delivery.",
    "The source event literals are onReceiveDataPackage, onConnect, onReceiveUDPData, and onReceiveData. Spectron constructs encoded target event values through C8THgaTQxF and KKhLga4xoI wrappers, so its clean feature export has no plain string references for these bodies.",
    "Both pairs are high-confidence layout-change anchors. checkDataPackages changes from 376 bytes, 94 instructions, 14 blocks, 24 branches, and 15 calls to 468/117/14/30/21. read changes from 548/137/15/38/29 to 772/193/16/56/47.",
]


SOURCE_TARGETS = {
    0x205328: 0x20B1F8,
    0x2054C4: 0x20B3F0,
}


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
        if not source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected receive-method string references at 0x%x" % source_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        if shape_equal:
            raise ValueError("receive method unexpectedly has an exact shape at 0x%x" % source_ea)
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
                "match_kind": "manual-tsocket-receive-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TSocket receive method %s" % source["name"],
                "context_group": "TSocket residual receive block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tsocket_receive_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TSocket receive block",
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
            "exact_shape_anchor_count": 0,
            "layout_change_anchor_count": len(anchors),
            "target_default_name_count": 0,
        },
        "context": {
            "source_sequence": "0x205328 checkDataPackages and 0x2054c4 read",
            "target_sequence": "0x20b1f8 xS6AgaBoQz and 0x20b3f0 read",
            "target_class": "XJLBgarMnA",
            "target_first_delta": "+0x5ed0",
            "target_second_delta": "+0x5f2c",
            "existing_target_ssl_send_block_end": "0x20b1b8",
            "existing_target_checkDataPackages_boundary": "0x20b3cc",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target names are resolved by class-local order, receive-event behavior, field offsets, and explicit wrapper roles.",
            "The target body growth is recorded as layout change because encoded event and temporary-variable wrappers are explicit in Spectron.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
