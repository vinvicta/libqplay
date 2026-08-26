#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for update and protocol helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1e8964",
        "original_name": "TClient_requestDownload_TString_const",
        "spectron_ea": "0x1ecd80",
        "source_basis": "download de-duplication, .gupd priority insertion, and image request dispatch",
        "required_target_strings": [".gupd"],
        "evidence": [
            "The candidate checks the same requested and modified-file hash tables before accepting a new download.",
            "It inserts .gupd files at the priority boundary, adds ordinary files normally, and dispatches the image request when the queue is below the same limit.",
            "Both builds retain 14 basic blocks and the distinctive .gupd branch; the target is a renamed obfuscated C++ function.",
        ],
    },
    {
        "original_ea": "0x1e8ab4",
        "original_name": "TClient_requestUpdate_TString_const",
        "spectron_ea": "0x1ecef0",
        "source_basis": "update-request de-duplication, .gupd priority insertion, and update request dispatch",
        "required_target_strings": [".gupd"],
        "evidence": [
            "The candidate checks the same modified-file, old-request, and global-request tables before queueing an update.",
            "It preserves .gupd priority insertion, update-list bookkeeping, and the sendWantImageUpdate dispatch when capacity allows.",
            "Both builds retain 13 basic blocks and the same .gupd discriminator in the corresponding update helper.",
        ],
    },
    {
        "original_ea": "0x1eab78",
        "original_name": "TClient_processServerModifies",
        "spectron_ea": "0xecba0",
        "source_basis": "server modification application and level-entry transition",
        "required_target_strings": [],
        "evidence": [
            "The candidate clears the leader state, checks the active player's pending map transition, and either enters the new level or applies server modifications.",
            "It preserves the same active-player state reset and server-level call sequence as the readable 1.8 body.",
            "The source and target have exactly the same size, instruction count, and eight basic blocks, and the target's yL3_IaDMFt class context matches the server-modification role.",
        ],
    },
    {
        "original_ea": "0x1f4cf8",
        "original_name": "TClient_sendWantImageUpdateCRC_TString_const",
        "spectron_ea": "0x1f8cc0",
        "source_basis": "resource checksum calculation and image-update request encoding",
        "required_target_strings": ["%058%047%047", ".gupd"],
        "evidence": [
            "The candidate resolves the level resource, computes a CRC for local .gupd content, and encodes the checksum with the same five-character transport format.",
            "It preserves URL-file handling, resource checksum fallback, outgoing request construction, and the offline onSendImageUpdateCRC event branch.",
            "The target is a larger rebuilt body, but it retains the exact format marker, .gupd discriminator, and w6qzgacqqy client context.",
        ],
    },
    {
        "original_ea": "0x1f5078",
        "original_name": "TClient_sendWantImageUpdateModTime_TString_const",
        "spectron_ea": "0x1f911c",
        "source_basis": "resource modification-time request encoding",
        "required_target_strings": ["%058%047%047"],
        "evidence": [
            "The candidate resolves the resource, handles URL-backed files, and encodes the same modification-time value before sending the request.",
            "It preserves the offline onSendImageUpdate callback branch and the last-file-request timestamp update.",
            "The exact format marker and neighboring checksum helper establish the target as the corresponding update-time routine despite the rebuilt size increase.",
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
        target_strings = set(target.get("string_refs", []))
        missing_strings = sorted(set(spec["required_target_strings"]) - target_strings)
        if missing_strings:
            raise ValueError(
                "target %s is missing expected strings: %s"
                % (spec["spectron_ea"], ", ".join(missing_strings))
            )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_size": source["size"],
                "original_instruction_count": source["instruction_count"],
                "original_basic_block_count": source["basic_block_count"],
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_size": target["size"],
                "spectron_instruction_count": target["instruction_count"],
                "spectron_basic_block_count": target["basic_block_count"],
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-update-protocol-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in update-protocol anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_update_protocol_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for download queues, update requests, server modifies, and image checksums",
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
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated or default 2.2 name in the evidence row.",
            "These rows describe local request and update logic; they do not establish compatibility with an external service.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
