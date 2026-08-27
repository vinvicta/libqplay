#!/usr/bin/env python3
"""Create reviewed anchors for residual screen-panel and GLES-window methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The remaining TScreenPanelOpenGL polygon-font stub sits in the same target SU3JfaCUmR method sequence as the already translated text and font methods.",
    "The source TWindowGLES rows form one local block of flip, resize, destructor, pixel-buffer factory, and native-mode methods. The target StGQIaOlWk class preserves that order and exposes the corresponding D1 and D0 destructor forms.",
    "The target pixel-buffer factory allocates the same object size and forwards the same window, name, dimensions, and format arguments. The target native-mode method returns true, while the flip and resize hooks remain empty in both builds.",
    "Every reviewed source and target pair has matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. The rows are not already present in the semantic translation map.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x10c5e4",
        "original_name": "TScreenPanelOpenGL_drawPolygonFont_TFont_int_int_char_const_int_int_TFontOptions_const",
        "spectron_ea": "0x10ef34",
        "target_name": "_ZN10SU3JfaCUmR10zBSOfaeypVEP10TZf6gaQ3S_iiPKciiRK10KcKRganuPN",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_drawPolygonFont_TFont_int_int_char_const_int_int_TFontOptions_const",
        "metrics": (4, 1, 1),
        "source_basis": "screen-panel polygon-font hook",
        "context_group": "TScreenPanelOpenGL residual font hook",
        "context_order": 1,
    },
    {
        "original_ea": "0x10cc10",
        "original_name": "TWindowGLES_flipOffscreen_void",
        "spectron_ea": "0x10f560",
        "target_name": "_ZN10StGQIaOlWk10cRcoIakqZXEv",
        "target_prefix": "_ZN10StGQIaOlWk10",
        "proposed_name": "v18_TWindowGLES_flipOffscreen_void",
        "metrics": (4, 1, 1),
        "source_basis": "GLES offscreen-flip hook",
        "context_group": "TWindowGLES residual lifecycle block",
        "context_order": 1,
    },
    {
        "original_ea": "0x10cc14",
        "original_name": "TWindowGLES_setSizeImpl_bool",
        "spectron_ea": "0x10f564",
        "target_name": "_ZN10StGQIaOlWk10WLjAga6eazEb",
        "target_prefix": "_ZN10StGQIaOlWk10",
        "proposed_name": "v18_TWindowGLES_setSizeImpl_bool",
        "metrics": (4, 1, 1),
        "source_basis": "GLES resize hook",
        "context_group": "TWindowGLES residual lifecycle block",
        "context_order": 2,
    },
    {
        "original_ea": "0x10cc18",
        "original_name": "TWindowGLES_TWindowGLES",
        "spectron_ea": "0x10f568",
        "target_name": "_ZN10StGQIaOlWkD1Ev",
        "target_prefix": "_ZN10StGQIaOlWk",
        "proposed_name": "v18_TWindowGLES_TWindowGLES",
        "metrics": (20, 5, 2),
        "source_basis": "GLES complete destructor",
        "context_group": "TWindowGLES residual lifecycle block",
        "context_order": 3,
    },
    {
        "original_ea": "0x10cc2c",
        "original_name": "TWindowGLES_TWindowGLES__2",
        "spectron_ea": "0x10f57c",
        "target_name": "_ZN10StGQIaOlWkD0Ev",
        "target_prefix": "_ZN10StGQIaOlWk",
        "proposed_name": "v18_TWindowGLES_TWindowGLES__2",
        "metrics": (32, 8, 2),
        "call_count": 1,
        "source_basis": "GLES deleting destructor",
        "context_group": "TWindowGLES residual lifecycle block",
        "context_order": 4,
    },
    {
        "original_ea": "0x10cc4c",
        "original_name": "TWindowGLES_createPixelBuffer_TString_const_int_int_int",
        "spectron_ea": "0x10f59c",
        "target_name": "_ZN10StGQIaOlWk10OQhoIa5C2XERK10C8THgaTQxFiii",
        "target_prefix": "_ZN10StGQIaOlWk10",
        "proposed_name": "v18_TWindowGLES_createPixelBuffer_TString_const_int_int_int",
        "metrics": (100, 25, 1),
        "call_count": 2,
        "source_basis": "window-backed OpenGL pixel-buffer factory",
        "context_group": "TWindowGLES residual lifecycle block",
        "context_order": 5,
    },
    {
        "original_ea": "0x10cd70",
        "original_name": "TWindowGLES_isNative_void",
        "spectron_ea": "0x10f6c0",
        "target_name": "_ZN10StGQIaOlWk10aZ9nIa7_WXEv",
        "target_prefix": "_ZN10StGQIaOlWk10",
        "proposed_name": "v18_TWindowGLES_isNative_void",
        "metrics": (8, 2, 1),
        "source_basis": "GLES native-mode predicate",
        "context_group": "TWindowGLES residual lifecycle block",
        "context_order": 6,
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
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        source = original.get(int(spec["original_ea"], 16))
        target = spectron.get(int(spec["spectron_ea"], 16))
        if source is None or target is None:
            raise ValueError("missing source or target feature for %s" % spec["original_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("original name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
        if not target["name"].startswith(spec["target_prefix"]):
            raise ValueError("target class context mismatch at %s" % spec["spectron_ea"])
        for side, function in (("source", source), ("target", target)):
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual_metrics != spec["metrics"]:
                raise ValueError(
                    "unexpected %s metrics at %s: %s"
                    % (
                        side,
                        spec["original_ea" if side == "source" else "spectron_ea"],
                        actual_metrics,
                    )
                )
            if function.get("call_count") != spec.get("call_count", 0):
                raise ValueError(
                    "unexpected %s call count at %s"
                    % (side, spec["original_ea" if side == "source" else "spectron_ea"])
                )
            if function.get("string_refs", []):
                raise ValueError("unexpected string references at %s" % spec["original_ea"])
        if any(
            source.get(field) != target.get(field)
            for field in (
                "branch_count",
                "mnemonic_hash",
                "opcode_shape_hash",
                "register_shape_hash",
                "shape_hash",
            )
        ):
            raise ValueError("source and target shape mismatch at %s" % spec["original_ea"])
        if int(spec["spectron_ea"], 16) in semantic_targets:
            raise ValueError("target is already present in the semantic map")
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
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-screen-panel-window-gles-residual-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "context_group": spec["context_group"],
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_screen_panel_window_gles_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual screen-panel polygon-font hook and TWindowGLES lifecycle methods",
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
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "target_classes": {
                "SU3JfaCUmR": "one residual polygon-font hook at 0x10ef34",
                "StGQIaOlWk": "GLES lifecycle and pixel-buffer methods at 0x10f560 through 0x10f6c0",
            },
            "source_sequence": "The source screen-panel polygon-font stub is followed by the TWindowGLES offscreen, resize, destructor, factory, and native-mode methods.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable source roles while retaining the obfuscated target names and changed target class names in the evidence rows.",
            "The source TWindowGLES destructor names are IDA's constructor-style aliases for D1 and D0 forms; the target's explicit D1 and D0 names resolve that ambiguity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
