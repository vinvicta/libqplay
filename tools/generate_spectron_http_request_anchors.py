#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for THTTPRequest helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1ff04c",
        "original_name": "THTTPRequest_getStringField200",
        "spectron_ea": "0x20499c",
        "target_name": "sub_20499C",
        "source_basis": "HTTP request TString field accessor at offset 200",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 200.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ff07c",
        "original_name": "THTTPRequest_getStringField256",
        "spectron_ea": "0x2049cc",
        "target_name": "sub_2049CC",
        "source_basis": "HTTP request TString field accessor at offset 256",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 256.",
            "The target is the contiguous accessor between the offset-200 and offset-248 helpers and matches all normalized body hashes.",
        ],
    },
    {
        "original_ea": "0x1ff0ac",
        "original_name": "THTTPRequest_getStringField248",
        "spectron_ea": "0x2049fc",
        "target_name": "sub_2049FC",
        "source_basis": "HTTP request TString field accessor at offset 248",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 248.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ff0dc",
        "original_name": "THTTPRequest_getStringField280",
        "spectron_ea": "0x204a2c",
        "target_name": "sub_204A2C",
        "source_basis": "HTTP request TString field accessor at offset 280",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 280.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ff10c",
        "original_name": "THTTPRequest_getStringField264",
        "spectron_ea": "0x204a5c",
        "target_name": "sub_204A5C",
        "source_basis": "HTTP request TString field accessor at offset 264",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 264.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ff13c",
        "original_name": "THTTPRequest_getStringField216",
        "spectron_ea": "0x204a8c",
        "target_name": "sub_204A8C",
        "source_basis": "HTTP request TString field accessor at offset 216",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 216.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ff1a0",
        "original_name": "THTTPRequest_getStringField184",
        "spectron_ea": "0x204af0",
        "target_name": "sub_204AF0",
        "source_basis": "HTTP request TString field accessor at offset 184",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 184.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ff1d0",
        "original_name": "THTTPRequest_getStringField296",
        "spectron_ea": "0x204b20",
        "target_name": "sub_204B20",
        "source_basis": "HTTP request TString field accessor at offset 296",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 296.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ff200",
        "original_name": "THTTPRequest_getStringField288",
        "spectron_ea": "0x204b50",
        "target_name": "sub_204B50",
        "source_basis": "HTTP request TString field accessor at offset 288",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 288.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ff230",
        "original_name": "THTTPRequest_getStringField168",
        "spectron_ea": "0x204b80",
        "target_name": "sub_204B80",
        "source_basis": "HTTP request TString field accessor at offset 168",
        "evidence": [
            "Both bodies initialize the script return TString and copy the request field at offset 168.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes in the request-object accessor run.",
        ],
    },
    {
        "original_ea": "0x1ffd20",
        "original_name": "THTTPRequest_THTTPRequest__2",
        "spectron_ea": "0x205668",
        "target_name": "_ZN10ZAuvgaUl6uD0Ev",
        "source_basis": "HTTP request deleting destructor wrapper",
        "evidence": [
            "Both bodies call the request destructor and then operator delete on the same object.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes.",
        ],
    },
    {
        "original_ea": "0x1ffd6c",
        "original_name": "THTTPRequest_sendOutgoing_void",
        "spectron_ea": "0x2056b4",
        "target_name": "_ZN10ZAuvgaUl6u10da7AgaaEQzEv",
        "source_basis": "HTTP request outbound-buffer send helper",
        "evidence": [
            "Both bodies check the socket for errors, send the queued buffer, and remove the bytes successfully written.",
            "The source and target retain identical size, instruction, block, mnemonic, register, and control-flow hashes.",
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
                "match_kind": "manual-http-request-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in HTTP request anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_http_request_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for HTTP request field accessors and outbound helpers",
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
            "The request-object field accessors, deleting destructor, and outbound-buffer helper preserve their local behavior across the two builds.",
            "The offset-256 accessor corroborates a medium-confidence semantic match using its contiguous request-object context.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
