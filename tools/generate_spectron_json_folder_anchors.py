#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron JSON and folder-loader anchors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x150a30",
        "original_name": "TBitmap_GIF_streamRead",
        "spectron_ea": "0x153570",
        "target_name": "sub_153570",
        "match_kind": "exact-normalized-callback",
        "source_basis": "GIF stream-read callback",
        "evidence": [
            "The original callback reads the TStream pointer from GIF user data at offset 104 and forwards the requested buffer and byte count to TStream::read.",
            "Spectron's GIF reader installs the target at its DGifOpen callback slot, and the target preserves the same two-argument forwarding body and normalized feature hashes.",
        ],
    },
    {
        "original_ea": "0x150ea0",
        "original_name": "TBitmap_JPEG_noopFlush",
        "spectron_ea": "0x153cc8",
        "target_name": "sub_153CC8",
        "match_kind": "exact-context-callback",
        "source_basis": "JPEG destination flush callback",
        "evidence": [
            "The original writeJPEG path installs this two-instruction callback in the JFFLUSH slot and the callback returns zero.",
            "Spectron's writeJPEG path installs sub_153CC8 in the same JFFLUSH slot, while the target body has the same size, instruction count, block count, and normalized hashes.",
        ],
    },
    {
        "original_ea": "0x150ea8",
        "original_name": "TBitmap_JPEG_noopError",
        "spectron_ea": "0x153cd0",
        "target_name": "sub_153CD0",
        "match_kind": "exact-context-callback",
        "source_basis": "JPEG error callback",
        "evidence": [
            "The original readJPEG and writeJPEG paths install this two-instruction callback in the JFERROR slot and the callback returns zero.",
            "Spectron's readJPEG and writeJPEG paths install sub_153CD0 in the same JFERROR slot, and the target body has the same size, instruction count, block count, and normalized hashes.",
        ],
    },
    {
        "original_ea": "0x213088",
        "original_name": "TGraalVar_loadFolderRecursive",
        "spectron_ea": "0x219978",
        "target_name": "sub_219978",
        "match_kind": "changed-size-class-context",
        "source_basis": "recursive folder loader",
        "evidence": [
            "The original helper enumerates TFiles entries, creates TGraalVar children, writes filesize and isfolder properties, and recursively descends into folders when requested.",
            "Spectron's loadFolder calls sub_219978 immediately after the same setup, and the target recursively calls itself while preserving the same child properties, 9999-entry guard, and 12-block control-flow shape.",
        ],
    },
    {
        "original_ea": "0x22dab4",
        "original_name": "TGraalVar_jsonStringCallback",
        "spectron_ea": "0x237598",
        "target_name": "sub_237598",
        "match_kind": "changed-size-callback-table",
        "source_basis": "YAJL string callback",
        "evidence": [
            "The original callback copies the incoming UTF-8 text, stores it as a scalar or current object value, and advances the parser context marker.",
            "Spectron's YAJL callback table stores sub_237598 in the string slot at 0x39af98, and its pseudocode preserves the same scalar, object, and array handling with only rebuilt string-wrapper calls added.",
        ],
    },
    {
        "original_ea": "0x22dbbc",
        "original_name": "TGraalVar_jsonNumberCallback",
        "spectron_ea": "0x23770c",
        "target_name": "sub_23770C",
        "match_kind": "changed-size-callback-table",
        "source_basis": "YAJL number callback",
        "evidence": [
            "The original callback validates numeric text, converts it to a float when possible, and stores either the float or the original text in the current TGraalVar value.",
            "Spectron's YAJL callback table stores sub_23770C in the number slot at 0x39af90, and its pseudocode preserves the same numeric validation, scalar/object writes, and context-marker update.",
        ],
    },
    {
        "original_ea": "0x22de60",
        "original_name": "TGraalVar_jsonStartArrayCallback",
        "spectron_ea": "0x237c78",
        "target_name": "sub_237C78",
        "match_kind": "changed-size-callback-table",
        "source_basis": "YAJL start-array callback",
        "evidence": [
            "The original callback creates an array TGraalVar child, marks its type and event fields, inserts it into the current array, and pushes a parser context node.",
            "Spectron's YAJL callback table stores sub_237C78 in the start-array slot at 0x39afb8, and its pseudocode preserves the same root, array-child, and context-chain branches.",
        ],
    },
    {
        "original_ea": "0x22e12c",
        "original_name": "TGraalVar_jsonStartMapCallback",
        "spectron_ea": "0x2379bc",
        "target_name": "sub_2379BC",
        "match_kind": "changed-size-callback-table",
        "source_basis": "YAJL start-map callback",
        "evidence": [
            "The original callback creates an object TGraalVar child, marks its type and event fields, inserts it into the current array when needed, and pushes a parser context node.",
            "Spectron's YAJL callback table stores sub_2379BC in the start-map slot at 0x39afa0, and its pseudocode preserves the same root, object-child, and context-chain branches.",
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
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "mnemonic_hash",
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
        if spec["match_kind"] in {"exact-normalized-callback", "exact-context-callback"}:
            for field in metrics(source):
                if source.get(field) != target.get(field):
                    raise ValueError(
                        "%s mismatch at %s to %s"
                        % (field, spec["original_ea"], spec["spectron_ea"])
                    )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": spec["match_kind"],
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in JSON/folder anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_json_folder_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for GIF/JPEG callbacks, recursive folder loading, and YAJL JSON callbacks",
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
            "exact_normalized_count": sum(row["match_kind"] == "exact-normalized-callback" for row in anchors),
            "exact_context_count": sum(row["match_kind"] == "exact-context-callback" for row in anchors),
            "changed_size_context_count": sum(row["match_kind"] == "changed-size-class-context" for row in anchors),
            "changed_size_callback_table_count": sum(row["match_kind"] == "changed-size-callback-table" for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The GIF and JPEG callbacks are exact normalized matches. The folder and JSON callbacks are tied to their callers and the YAJL callback table because Spectron changed their wrapper bodies.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
