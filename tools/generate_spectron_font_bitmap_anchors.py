#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's font and bitmap loaders."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


GROUP_EVIDENCE = {
    "font_char": [
        "Both methods attach the font object, clamp glyph dimensions, clear the previous glyph bitmap and texture, choose the UTF-8 path when enabled, copy the glyph pixels row by row, construct the same `Font ` and code-name texture key, and fall back to a raw bitmap allocation when needed.",
        "The target preserves the distinctive `Font ` and `#` literals and the same 14-block structure. It is 716 bytes and 178 instructions, compared with 688 bytes and 171 instructions in 1.8.",
        "The target class-local method has the same arguments, field offsets, bitmap dimensions, palette setup, texture creation, and final pixel-copy path. The expanded target string and bitmap wrappers explain the small body increase.",
    ],
    "font_bitmap": [
        "Both generate the font atlas by walking character data, placing glyphs into the texture, reporting when a glyph cannot fit, and logging the resulting graphics texture dimensions.",
        "The target retains all four distinctive literals: ` in texture of `, `, size `, `Couldn't fit font `, and `graphics`. Both bodies have 26 blocks. The target is 1052 bytes and 261 instructions, compared with 1016 bytes and 252 instructions in 1.8.",
        "The target preserves the same atlas placement branches and calls the corresponding font-character setup method. This is a direct class-local translation with wrapper expansion.",
    ],
    "font_data": [
        "Both load a font from a system or resource path, choose a file stream or memory stream, initialize FreeType once, attempt the matching face constructor, release failed streams, clear the face on error, and report the same graphics error message.",
        "The target retains `Failed to load font ` and `graphics`. The source has 36 blocks, 256 instructions, and 1032 bytes. The target has 34 blocks, 208 instructions, and 840 bytes because target resource and FreeType wrapper paths fold several source branches together.",
        "The target still uses the same font path fields, resource update and download boundary, stream lifetime, FreeType initialization, and error cleanup. The semantic evidence is stronger than the changed block count.",
    ],
    "bitmap_loader": [
        "Both reject resources that cannot be loaded, create the guarded `LoadBitmap` profiler entry, obtain and validate the stream, guess a file type when the extension is absent, load the bitmap, retry with the guessed type when necessary, and force a redownload after failure.",
        "The target preserves `LoadBitmap`, `Failed to load `, and `graphics`. Both bodies have 25 blocks. The source is 808 bytes and 199 instructions; the target is 932 bytes and 229 instructions.",
        "The target keeps the same resource-object and stream fields, profiler push and pop, bitmap allocation, retry branch, error cleanup, and redownload call. The changed helper names are wrapper substitutions only.",
    ],
}


ANCHOR_SPECS = [
    {
        "original_ea": "0x10d038",
        "original_name": "TFontCharInfo_setData_TFont_uchar_const_int_int_int_int_int_int",
        "spectron_ea": "0x10f988",
        "target_name": "_ZN10DFeOfaFXSU10u6glKaa0vBEP10TZf6gaQ3S_PKhiiiiii",
        "proposed_name": "v18_TFontCharInfo_setData_TFont_uchar_const_int_int_int_int_int_int",
        "source_metrics": (688, 171, 14),
        "target_metrics": (716, 178, 14),
        "group": "font_char",
        "source_basis": "font glyph bitmap and texture setup",
        "required_string_refs": ("Font ", "#"),
    },
    {
        "original_ea": "0x10d4cc",
        "original_name": "TFont_generateFontBitmap_void",
        "spectron_ea": "0x10fe58",
        "target_name": "_ZN10TZf6gaQ3S_10fl7q4asNqlEv",
        "proposed_name": "v18_TFont_generateFontBitmap_void",
        "source_metrics": (1016, 252, 26),
        "target_metrics": (1052, 261, 26),
        "group": "font_bitmap",
        "source_basis": "font atlas generation and placement",
        "required_string_refs": (
            " in texture of ",
            ", size ",
            "Couldn't fit font ",
            "graphics",
        ),
    },
    {
        "original_ea": "0x110ca0",
        "original_name": "TFontData_load_void",
        "spectron_ea": "0x113540",
        "target_name": "_ZN10fUWH_a_9zm4loadEv",
        "proposed_name": "v18_TFontData_load_void",
        "source_metrics": (1032, 256, 36),
        "target_metrics": (840, 208, 34),
        "group": "font_data",
        "source_basis": "font resource, stream, and FreeType loading",
        "required_string_refs": ("Failed to load font ", "graphics"),
    },
    {
        "original_ea": "0x115464",
        "original_name": "TBitmapLoader_load_TResourceObject",
        "spectron_ea": "0x117e4c",
        "target_name": "_ZN10kM00HafgtE4loadEP10bNZvga2Awv",
        "proposed_name": "v18_TBitmapLoader_load_TResourceObject",
        "source_metrics": (808, 199, 25),
        "target_metrics": (932, 229, 25),
        "group": "bitmap_loader",
        "source_basis": "resource bitmap loading and retry",
        "required_string_refs": ("LoadBitmap", "Failed to load ", "graphics"),
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
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        for side, function in (("source", source), ("target", target)):
            expected = spec["%s_metrics" % side]
            actual = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual != expected:
                raise ValueError(
                    "unexpected %s metrics at %s: %s"
                    % (side, spec["%s_ea" % side], actual)
                )
        for literal in spec["required_string_refs"]:
            if literal not in source.get("string_refs", []):
                raise ValueError(
                    "source %s lacks required string reference %s"
                    % (spec["original_ea"], literal)
                )
            if literal not in target.get("string_refs", []):
                raise ValueError(
                    "target %s lacks required string reference %s"
                    % (spec["spectron_ea"], literal)
                )
        if spectron_ea in semantic_targets:
            raise ValueError(
                "target %s is already present in the semantic map" % spec["spectron_ea"]
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
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-font-bitmap-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": GROUP_EVIDENCE[spec["group"]],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in font bitmap anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in font bitmap anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_font_bitmap_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for glyph data, font atlases, font resources, and bitmap loading",
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
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated 2.2 name in the evidence row.",
            "The correspondences are supported by direct Hex-Rays pseudocode, distinctive font and bitmap literals, shared field use, class-local calls, and close control-flow metrics.",
            "The target font-resource loader has a smaller block count because target resource and FreeType wrappers fold source branches together. That explicit version difference is recorded rather than hidden.",
            "Changed byte sizes and instruction counts are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
