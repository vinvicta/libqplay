#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for HTTP response helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x200a70",
        "original_name": "THTTPRequest_read_void",
        "spectron_ea": "0x206414",
        "target_name": "_ZN10ZAuvgaUl6u4readEv",
        "source_basis": "HTTP response socket read and download-progress state",
        "evidence": [
            "The source rejects a missing or errored socket, reads through the request connection, appends or assigns the received bytes to the response stream, and updates both byte counters.",
            "The target preserves the same request connection field at offset 136, response stream field at offset 232, receive call, append-or-assign decision, and byte accounting sequence.",
            "The target updates the request and global web-download timestamps after new data arrives, matching the source state transition. Its rebuilt body omits the older progress-log branch, so the correspondence is recorded as a layout and implementation change rather than an exact-shape match.",
            "The target is the only read method in the ZAuvgaUl6u request-object cluster and sits immediately after the translated saveDownloadedData helper and before the download-progress accessor.",
        ],
    },
    {
        "original_ea": "0x2023fc",
        "original_name": "THTTPRequest_parseData_void",
        "spectron_ea": "0x207bec",
        "target_name": "_ZN10ZAuvgaUl6u10ZdIGHasPxmEv",
        "source_basis": "HTTP response data parsing and script-array dispatch",
        "evidence": [
            "The source clears the response stream when the request is not open, then loads the stream into a string list for non-binary, non-image responses.",
            "The source and target both look up the literal data key, clear the existing script variable, set the string and variable types, allocate the array holder, and invoke the variable callback once for each response line.",
            "The target uses the rebuilt vuuHgangcF line container and CanTfaz6bZ or G0gxgajWBw value helpers, but retains the same virtual callback slot at offset 288 and the same data-event role.",
            "The target is the response parser immediately before the already translated ZAuvgaUl6u runScript method and retains the distinctive data string reference.",
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


def metrics(function: dict) -> dict:
    return {
        "size": function["size"],
        "instruction_count": function["instruction_count"],
        "basic_block_count": function["basic_block_count"],
        "branch_count": function["branch_count"],
        "call_count": function["call_count"],
        "return_count": function["return_count"],
        "mnemonic_hash": function["mnemonic_hash"],
        "opcode_shape_hash": function["opcode_shape_hash"],
        "register_shape_hash": function["register_shape_hash"],
        "shape_hash": function["shape_hash"],
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
        if not target.get("name") or target.get("is_default_name"):
            raise ValueError("target must retain its obfuscated C++ name at %s" % spec["spectron_ea"])
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-http-request-response-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in HTTP response anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_http_request_receive_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for HTTP response reads and data parsing",
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
            "already_in_semantic_map": sum(row["semantic_match_already_present"] for row in anchors),
            "new_context_anchor_count": sum(not row["semantic_match_already_present"] for row in anchors),
            "layout_change_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The target implementation has changed around both methods, so the role is established by request-object class context, state fields, calls, and preserved data-event behavior rather than an exact normalized body hash.",
            "The labels describe local HTTP response plumbing and do not establish compatibility with an external service.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
