#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for THTMLAtom helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1cf240",
        "original_name": "THTMLAtom_THTMLAtom_THTMLPage",
        "spectron_ea": "0x1d3e94",
        "target_name": "_ZN10S2m6gab0Y_C1EP10AS80gaE4zW",
        "source_basis": "HTML atom constructor",
        "evidence": [
            "Both constructors clear the same atom fields, retain the page pointer, and call the atom clear routine.",
            "The source and target preserve the same 12-byte, three-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x1cf274",
        "original_name": "THTMLAtom_setTextInBuffer_uint_int",
        "spectron_ea": "0x1d3ec8",
        "target_name": "_ZN10S2m6gab0Y_10Vqz6gakq8_Eji",
        "source_basis": "HTML atom buffer start and length setter",
        "evidence": [
            "Both bodies store the supplied buffer start and length in the same two atom fields.",
            "The source and target preserve the same 12-byte, three-instruction, single-block normalized body in the THTMLAtom accessor sequence.",
        ],
    },
    {
        "original_ea": "0x1cf280",
        "original_name": "THTMLAtom_setLengthInBuffer_int",
        "spectron_ea": "0x1d3ed4",
        "target_name": "_ZN10S2m6gab0Y_10Cpq6gahQ0_Ei",
        "source_basis": "HTML atom buffer length setter",
        "evidence": [
            "Both bodies store the supplied length in the same atom field and return the object.",
            "The source and target preserve the same 8-byte, two-instruction, single-block normalized body beside the other buffer accessors.",
        ],
    },
    {
        "original_ea": "0x1cf290",
        "original_name": "THTMLAtom_getLengthInBuffer_void",
        "spectron_ea": "0x1d3ee4",
        "target_name": "_ZNK10S2m6gab0Y_10sVs6ga2W2_Ev",
        "source_basis": "HTML atom buffer length accessor",
        "evidence": [
            "Both bodies return the unsigned length field at the same logical atom offset.",
            "The source and target preserve the same 8-byte, two-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x1cf298",
        "original_name": "THTMLAtom_getEndInBuffer_void",
        "spectron_ea": "0x1d3eec",
        "target_name": "_ZNK10S2m6gab0Y_10EWu6gaZD4_Ev",
        "source_basis": "HTML atom buffer end accessor",
        "evidence": [
            "Both bodies return the sum of the same buffer start and length fields.",
            "The source and target preserve the same 16-byte, four-instruction, single-block normalized body at the end of the buffer accessor sequence.",
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
            raise ValueError("unexpected original name at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("unexpected Spectron name at %s" % spec["spectron_ea"])
        for field in ("size", "instruction_count", "basic_block_count"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
                )
        for field in ("mnemonic_hash", "register_shape_hash", "shape_hash"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
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
                "match_kind": "manual-html-atom-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in HTML atom anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_html_atom_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for THTMLAtom construction and buffer accessors",
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
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The target constructor and buffer accessors preserve the original THTMLAtom field layout and local behavior with exact normalized function hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
