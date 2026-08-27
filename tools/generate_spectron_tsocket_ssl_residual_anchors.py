#!/usr/bin/env python3
"""Create reviewed anchors for the residual TSocket SSL configuration block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source TSocket SSL configuration methods form an ordered block at 0x205120, 0x20514c, and 0x2051a0. Spectron keeps the same order at 0x20aff0, 0x20b01c, and 0x20b070 inside XJLBgarMnA, with a fixed +0x5ed0 delta.",
    "setEnableSSL preserves the byte-140 state comparison, connection pointer at offset 176, state write, and conditional connection update. The target replaces TSocketConnection with u3cBgayBVz but retains the same normalized body.",
    "setSSLCipherList and setSSLProtocol preserve the socket string fields at offsets 144 and 152 and the live-connection propagation to offsets 8248 and 8256. Spectron uses C8THgaTQxF wrapper assignments.",
    "The source send wrapper at 0x205240 appends to the outgoing string at offset 168. Target 0x20b110 does the same through C8THgaTQxF::operator<<. The existing setSSLVerifyCert and sendUDP rows at 0x20b0c4 and 0x20b11c confirm the surrounding target sequence.",
    "All four reviewed pairs have exact size, instruction, block, branch, call, mnemonic, opcode-shape, register-shape, and overall-shape metrics. None has string references, and all target names are already non-default obfuscated symbols.",
]


SOURCE_TARGETS = {
    0x205120: 0x20AFF0,
    0x20514C: 0x20B01C,
    0x2051A0: 0x20B070,
    0x205240: 0x20B110,
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
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected string references at 0x%x" % source_ea)
        if target.get("is_default_name"):
            raise ValueError("unexpected default target name at 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        if not shape_equal:
            raise ValueError("source and target metrics differ at 0x%x" % source_ea)
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
                "match_kind": "manual-tsocket-ssl-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TSocket SSL or outgoing-buffer method %s" % source["name"],
                "context_group": "TSocket residual SSL configuration block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tsocket_ssl_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TSocket SSL configuration block",
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
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": 0,
        },
        "context": {
            "source_sequence": "0x205120 setEnableSSL, 0x20514c setSSLCipherList, 0x2051a0 setSSLProtocol, and 0x205240 send",
            "target_sequence": "0x20aff0, 0x20b01c, 0x20b070, and 0x20b110 in XJLBgarMnA",
            "target_class": "XJLBgarMnA",
            "target_delta": "+0x5ed0",
            "existing_target_setSSLVerifyCert": "0x20b0c4",
            "existing_target_sendUDP": "0x20b11c",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target names are resolved by the fixed class-local delta, exact normalized shapes, field offsets, and the adjacent translated SSL methods.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
