#!/usr/bin/env python3
"""Create reviewed anchors for the residual TSocket host and logging helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source TSocket helper sequence contains cacheHostAddress at 0x205ef8, logSocketMessage at 0x205fcc, sendPlain at 0x206010, recvPlain at 0x206080, and resolveHost at 0x206108. sendPlain and recvPlain are already in the canonical semantic map, leaving cacheHostAddress, logSocketMessage, and resolveHost as the new rows in this artifact.",
    "cacheHostAddress and resolveHost share the same cached-host object fields and the same case-insensitive host lookup path. The target keeps inet_addr in the cache writer and gethostbyname plus the one-hour timestamp check in the resolver, while making C8THgaTQxF, CanTfaz6bZ, KKhLga4xoI, J7zOgaf09K, and zYRMgaG0IJ wrappers explicit.",
    "The target helper at 0x20c018 is a small callback thunk that forwards the CyaSSL logging callback message into qjQMgaXCHJ::cWQMgaD8HJ. This is the target form of the source TSocket_logSocketMessage role, whose source body builds a temporary string and sends it through TLog_echo.",
    "The target has two adjacent helper insertions before the cache body. 0x20c008 clears a separate global string container, while 0x20c018 is the SSL logging callback thunk. The cache body begins at 0x20c020, so the explicit target order is retained rather than forced into one source-order delta.",
    "cacheHostAddress changes from 212 bytes, 53 instructions, 6 blocks, 12 branches, and 7 calls to 244/61/6/14/9. logSocketMessage changes from 68/17/1/4/3 to an 8-byte, 2-instruction, 2-block, 1-branch callback thunk with no ordinary call instruction. resolveHost changes from 300/75/15/18/8 to 344/86/15/20/10.",
]


SOURCE_TARGETS = {
    0x205EF8: 0x20C020,
    0x205FCC: 0x20C018,
    0x206108: 0x20C20C,
}

EXPECTED_SOURCE_NAMES = {
    0x205EF8: "TSocket_cacheHostAddress",
    0x205FCC: "TSocket_logSocketMessage",
    0x206108: "resolveHost_TString_const",
}

EXPECTED_TARGET_NAMES = {
    0x20C020: "sub_20C020",
    0x20C018: "sub_20C018",
    0x20C20C: "_Z10dsmb2ajvasRK10C8THgaTQxF",
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
        if source.get("name") != EXPECTED_SOURCE_NAMES[source_ea]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != EXPECTED_TARGET_NAMES[target_ea]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        if shape_equal:
            raise ValueError("host or logging helper unexpectedly has an exact shape at 0x%x" % source_ea)
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
                "match_kind": "manual-tsocket-host-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TSocket host or logging helper %s" % source["name"],
                "context_group": "TSocket residual host and logging block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tsocket_host_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TSocket host and logging helpers",
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
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_sequence": "0x205ef8 cacheHostAddress, 0x205fcc logSocketMessage, 0x206010 sendPlain, 0x206080 recvPlain, and 0x206108 resolveHost",
            "target_sequence": "0x20c018 logging callback, 0x20c020 cacheHostAddress body, 0x20c114 sendPlain, 0x20c184 recvPlain, and 0x20c20c resolveHost",
            "target_only_boundary": "0x20c008",
            "target_logging_callback": "0x20c018",
            "target_cache_body": "0x20c020",
            "target_resolver": "0x20c20c",
            "existing_semantic_send_plain": {
                "source_ea": "0x206010",
                "target_ea": "0x20c114",
                "name": "v18_TSocket_sendPlain",
            },
            "existing_semantic_recv_plain": {
                "source_ea": "0x206080",
                "target_ea": "0x20c184",
                "name": "v18_TSocket_recvPlain",
            },
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the target helper or free-function context in the evidence rows.",
            "cacheHostAddress and resolveHost are resolved by their shared cache fields, host lookup calls, timestamps, and wrapper structure. logSocketMessage is resolved by its direct use as the CyaSSL logging callback and its tail call into the target logger.",
            "All three pairs are recorded as layout-change anchors because target wrappers, helper factoring, and callback lowering change the normalized body shapes.",
            "sendPlain and recvPlain remain existing semantic-map anchors and are listed as boundaries rather than duplicated.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
