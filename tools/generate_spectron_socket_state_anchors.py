#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for compact socket helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x2062b8",
        "original_name": "TSocketConnection_hasError_void",
        "spectron_ea": "0x20c404",
        "target_name": "_ZNK10u3cBgayBVz10nq1pgaTOvqEv",
        "source_basis": "socket status error predicate",
        "evidence": [
            "Both bodies report an error when the socket status field minus four is greater than two.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the socket helper sequence.",
        ],
    },
    {
        "original_ea": "0x2062cc",
        "original_name": "TSocketConnection_closeForSubProcesses_void",
        "spectron_ea": "0x20c418",
        "target_name": "_ZN10u3cBgayBVz10uRCZ1aIishEv",
        "source_basis": "socket subprocess-close no-op hook",
        "evidence": [
            "Both bodies are empty instance hooks with no side effects.",
            "The target is the one-instruction helper immediately between the status predicate and Nagle-delay method, with identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x206320",
        "original_name": "TSocketConnection_setNonBlocking_void",
        "spectron_ea": "0x20c46c",
        "target_name": "_ZN10u3cBgayBVz10InLZ1aBtzhEv",
        "source_basis": "fcntl nonblocking socket setup",
        "evidence": [
            "Both bodies invoke fcntl on the socket descriptor with command four and flag 2048.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes.",
        ],
    },
    {
        "original_ea": "0x206330",
        "original_name": "TSocketConnection_getIPNum_void",
        "spectron_ea": "0x20c47c",
        "target_name": "_ZNK10u3cBgayBVz10qYcf1arwpFEv",
        "source_basis": "numeric peer IP accessor",
        "evidence": [
            "Both bodies return the 32-bit IP field at socket-object offset eight.",
            "The target follows the nonblocking helper in the preserved socket sequence and has identical normalized hashes.",
        ],
    },
    {
        "original_ea": "0x2070f4",
        "original_name": "TSocketConnection_getIP_void",
        "spectron_ea": "0x20d234",
        "target_name": "_ZNK10u3cBgayBVz10YgoBgaY13zEv",
        "source_basis": "formatted peer IP accessor",
        "evidence": [
            "Both bodies pass the socket object's numeric IP field at offset eight to the IP-string helper and return the script result.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes; this corroborates the earlier medium-confidence semantic match.",
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
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: expected %s, got %s"
                % (spec["spectron_ea"], spec["target_name"], target.get("name"))
            )
        for field in ("size", "instruction_count", "basic_block_count"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s: %s versus %s"
                    % (
                        field,
                        spec["original_ea"],
                        spec["spectron_ea"],
                        source.get(field),
                        target.get(field),
                    )
                )
        for field in ("mnemonic_hash", "register_shape_hash", "shape_hash"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s" % (field, spec["original_ea"], spec["spectron_ea"])
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
                "match_kind": "manual-socket-state-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in socket-state anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_socket_state_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact socket status and address helpers",
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
            "The socket status, nonblocking, numeric address, and formatted address helpers preserve their local behavior across the two builds.",
            "The formatted IP row corroborates a medium-confidence semantic match using the surrounding socket helper sequence.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
