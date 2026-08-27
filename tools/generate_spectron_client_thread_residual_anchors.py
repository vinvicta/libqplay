#!/usr/bin/env python3
"""Create reviewed anchors for the residual client-thread helper block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source rows are the remaining client-thread synchronization, package cleanup, and send helpers at 0x208344, 0x208350, 0x20835c, 0x208478, 0x20858c, 0x2087a0, and 0x2088f8. Spectron preserves their local sequence at 0x20e4e0, 0x20e4ec, 0x20e4f8, 0x20e614, 0x20e728, 0x20e93c, and 0x20ea94.",
    "The lock and unlock wrappers call pthread_mutex_lock and pthread_mutex_unlock on the same client-socket mutex role. The target exposes that mutex as LN3ikbwOEH through E3UikbICwH and Tqmikbou3G.",
    "readIncomingData locks the client socket, calls the connection read method, and unlocks it. Spectron keeps the same three-step wrapper through E3UikbICwH, psSDxavq9U::read, and Tqmikbou3G.",
    "The incoming and outgoing clear helpers lock their list mutex, walk each stored package, clear its embedded string, delete the package, clear the list, and unlock. Spectron retains the same loop and cleanup through vy1JgaKVkH and C8THgaTQxF wrappers.",
    "disableClientThread returns the running byte and calls the thread-destroy helper only when the flag is set. sendOutgoingPackages uses the same lock, connection-send, and unlock wrapper as the source.",
    "All seven pairs have identical size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, and overall shape. The target functions already have non-default obfuscated names.",
]


SOURCE_TARGETS = {
    0x208344: 0x20E4E0,
    0x208350: 0x20E4EC,
    0x20835C: 0x20E4F8,
    0x208478: 0x20E614,
    0x20858C: 0x20E728,
    0x2087A0: 0x20E93C,
    0x2088F8: 0x20EA94,
}

EXPECTED_SOURCE_NAMES = {
    0x208344: "lockClientSocket_void",
    0x208350: "unlockClientSocket_void",
    0x20835C: "readIncomingData_void",
    0x208478: "clearIncomingPackages_void",
    0x20858C: "clearOutgoingPackages_void",
    0x2087A0: "disableClientThread_void",
    0x2088F8: "sendOutgoingPackages_void",
}

EXPECTED_TARGET_NAMES = {
    0x20E4E0: "_Z10E3UikbICwHv",
    0x20E4EC: "_Z10Tqmikbou3Gv",
    0x20E4F8: "_Z10LK7hkb_7RGv",
    0x20E614: "_Z10d5ahkbYW3Fv",
    0x20E728: "_Z10A0fhkbd57Fv",
    0x20E93C: "_Z10wlXykbJx0Uv",
    0x20EA94: "_Z10aC0C_aG7qiv",
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
        if not shape_equal:
            raise ValueError("unexpected client-thread shape result at 0x%x" % source_ea)
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
                "match_kind": "manual-client-thread-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "client-thread helper %s" % source["name"],
                "context_group": "TClient thread synchronization and package cleanup residual block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_thread_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual client-thread synchronization and package helpers",
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
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_sequence": "0x208344 lockClientSocket through 0x2088f8 sendOutgoingPackages, with existing mapped package and thread methods between the residual rows",
            "target_sequence": "0x20e4e0 lock, 0x20e4ec unlock, 0x20e4f8 read, 0x20e614 incoming clear, 0x20e728 outgoing clear, 0x20e93c disable, and 0x20ea94 send",
            "source_class": "TClient and client-thread helpers",
            "target_class": "w6qzgacqqy, vy1JgaKVkH, and related obfuscated helpers",
            "target_only_boundaries": ["0x20e520 addIncomingClientPackage", "0x20e5a4 getNextClientPackages", "0x20e6a4 sendClientPackage", "0x20e87c enableClientThread", "0x20e8ac destroyClientThread", "0x20e9dc processOutgoingPackages", "0x20eabc networkThreadMain"],
            "following_target_boundary": "0x20ec08 TUpdatePackage accessor block",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source client-thread roles while retaining the target obfuscated names in the evidence rows.",
            "All seven pairs are exact normalized-shape matches. The cleanup helpers retain the package loop, embedded-string cleanup, list clear, and mutex release sequence.",
            "Existing package-queue, thread lifecycle, and network-loop anchors remain explicit neighboring boundaries.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
