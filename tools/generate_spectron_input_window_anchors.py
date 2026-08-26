#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for input and window helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x168fdc",
        "original_name": "TInput_getKeyState_int",
        "spectron_ea": "0x16c9dc",
        "target_name": "_ZN10GaA2gaD2MX10xiDpfajGaAEi",
        "source_basis": "input key-state accessor",
        "evidence": [
            "Both bodies index the same key-state table by the low byte of the input code.",
            "The source and target preserve the same 20-byte, four-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x169158",
        "original_name": "TInput_graalkeypressed_int_bool",
        "spectron_ea": "0x16cbac",
        "target_name": "_ZN10GaA2gaD2MX10MU1ofaqdGzEib",
        "source_basis": "input key-state setter",
        "evidence": [
            "Both bodies validate key indices through ten and store the boolean in the same key-state table.",
            "The source and target preserve the same 32-byte, seven-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x1066c8",
        "original_name": "TWindow_setCursorPosition_int_int",
        "spectron_ea": "0x108eb8",
        "target_name": "_ZN10LJyzga9Pwy10Ud7zgatH_yEii",
        "source_basis": "window cursor-position setter",
        "evidence": [
            "Both bodies convert the two integer coordinates to floats and store them in the same cursor fields.",
            "The source and target preserve the same 20-byte, five-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x106d30",
        "original_name": "TWindow_getScreenWidth_void",
        "spectron_ea": "0x109530",
        "target_name": "_ZN10LJyzga9Pwy10sUaPfacNFVEv",
        "source_basis": "window screen-width accessor",
        "evidence": [
            "Both bodies select the same width field based on the same window mode mask.",
            "The source and target preserve the same 28-byte, seven-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x106d4c",
        "original_name": "TWindow_getScreenHeight_void",
        "spectron_ea": "0x10954c",
        "target_name": "_ZN10LJyzga9Pwy10ZQLOfagSjVEv",
        "source_basis": "window screen-height accessor",
        "evidence": [
            "Both bodies select the same height field based on the same window mode mask.",
            "The source and target preserve the same 28-byte, seven-instruction, single-block normalized body beside the width accessor.",
        ],
    },
    {
        "original_ea": "0x107154",
        "original_name": "TWindow_getCanvasControl_void",
        "spectron_ea": "0x109954",
        "target_name": "_ZN10LJyzga9Pwy10ggIZgagRwUEv",
        "source_basis": "window canvas-control lookup",
        "evidence": [
            "Both bodies replace the main window with null when appropriate and call the canvas-for-window lookup with the same main-window object.",
            "The source and target preserve the same 24-byte, six-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x107f58",
        "original_name": "TWindow_init_void",
        "spectron_ea": "0x10a8a8",
        "target_name": "_ZN10LJyzga9Pwy4initEv",
        "source_basis": "window initialization wrapper",
        "evidence": [
            "Both bodies normalize the same negative window state to two and call the drawing-panel creation routine.",
            "The source and target preserve the same 24-byte, six-instruction, single-block normalized body.",
        ],
    },
    {
        "original_ea": "0x1081f4",
        "original_name": "TWindow_getPreferredPosition_void",
        "spectron_ea": "0x10ab44",
        "target_name": "_ZN10LJyzga9Pwy10Z0uAgaCIjzEv",
        "source_basis": "window preferred-position initializer",
        "evidence": [
            "Both bodies return a zeroed two-coordinate result structure.",
            "The source and target preserve the same 16-byte, four-instruction, single-block normalized body.",
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
                "match_kind": "manual-input-window-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in input/window anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_input_window_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact TInput and TWindow helpers",
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
            "The target input and window helpers preserve the local key, cursor, surface, initialization, and dimension behavior with exact normalized function hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
