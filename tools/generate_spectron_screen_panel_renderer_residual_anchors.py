#!/usr/bin/env python3
"""Create reviewed anchors for residual screen-panel renderer methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source methods form a contiguous residual tail around the concrete TScreenPanelOpenGL implementation. The target keeps the same sequence in the SU3JfaCUmR class, with the target-only class layout reflected by shifted matrix-field offsets.",
    "The texture predicate belongs to the target uzN1fatj75 pixel-buffer class. Both versions test the texture handle field, while the target field is shifted by one four-byte slot in the changed object layout.",
    "The matrix getters and setters preserve their roles and complete 4 by 4 copy operations. The target writes the same projection and model matrix regions and sets the corresponding validity bytes at shifted offsets.",
    "The triangle-strip hook, shader capability hook, shader setter, and shader clearer have the same empty or zero-return behavior in both libraries. The alpha-reference wrapper calls glAlphaFunc with the same constant and forwards the threshold unchanged.",
    "Every reviewed source and target pair has matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. The rows are not already present in the semantic translation map.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x109c34",
        "original_name": "TPixelBufferOpenGL_hasTexture_void",
        "spectron_ea": "0x10c584",
        "target_name": "_ZN10uzN1fatj7510gDNYgaImLTEv",
        "target_prefix": "_ZN10uzN1fatj7510",
        "proposed_name": "v18_TPixelBufferOpenGL_hasTexture_void",
        "metrics": (16, 4, 1),
        "source_basis": "OpenGL pixel-buffer texture-handle predicate",
        "context_group": "TPixelBufferOpenGL residual predicate",
        "context_order": 1,
    },
    {
        "original_ea": "0x109c44",
        "original_name": "TScreenPanelOpenGL_getProjMatrix_void",
        "spectron_ea": "0x10c594",
        "target_name": "_ZN10SU3JfaCUmR10CJDIfa019PEv",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_getProjMatrix_void",
        "metrics": (44, 11, 1),
        "source_basis": "screen-panel projection-matrix getter",
        "context_group": "TScreenPanelOpenGL residual matrix block",
        "context_order": 1,
    },
    {
        "original_ea": "0x109c70",
        "original_name": "TScreenPanelOpenGL_getModelMatrix_void",
        "spectron_ea": "0x10c5c0",
        "target_name": "_ZN10SU3JfaCUmR10sToJfagyOQEv",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_getModelMatrix_void",
        "metrics": (44, 11, 1),
        "source_basis": "screen-panel model-matrix getter",
        "context_group": "TScreenPanelOpenGL residual matrix block",
        "context_order": 2,
    },
    {
        "original_ea": "0x109c9c",
        "original_name": "TScreenPanelOpenGL_setProjMatrix_MatrixF_const",
        "spectron_ea": "0x10c5ec",
        "target_name": "_ZN10SU3JfaCUmR10FA8HfaAQKPERK10lKR7faAPdb",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_setProjMatrix_MatrixF_const",
        "metrics": (48, 12, 1),
        "source_basis": "screen-panel projection-matrix setter",
        "context_group": "TScreenPanelOpenGL residual matrix block",
        "context_order": 3,
    },
    {
        "original_ea": "0x109ccc",
        "original_name": "TScreenPanelOpenGL_setModelMatrix_MatrixF_const",
        "spectron_ea": "0x10c61c",
        "target_name": "_ZN10SU3JfaCUmR10JcBJfasVYQERK10lKR7faAPdb",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_setModelMatrix_MatrixF_const",
        "metrics": (48, 12, 1),
        "source_basis": "screen-panel model-matrix setter",
        "context_group": "TScreenPanelOpenGL residual matrix block",
        "context_order": 4,
    },
    {
        "original_ea": "0x109d2c",
        "original_name": "TScreenPanelOpenGL_drawTriangleStripPanel_TDrawingPanelPort_float_int_float_float_bool",
        "spectron_ea": "0x10c67c",
        "target_name": "_ZN10SU3JfaCUmR10OZ5KfaLEeSEP10OYYKfaPU7RPfiS2_S2_b",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_drawTriangleStripPanel_TDrawingPanelPort_float_int_float_float_bool",
        "metrics": (4, 1, 1),
        "source_basis": "screen-panel triangle-strip hook",
        "context_group": "TScreenPanelOpenGL residual state and shader block",
        "context_order": 1,
    },
    {
        "original_ea": "0x109d40",
        "original_name": "TScreenPanelOpenGL_canUseShader_void",
        "spectron_ea": "0x10c690",
        "target_name": "_ZN10SU3JfaCUmR10EMsIfazP0PEv",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_canUseShader_void",
        "metrics": (8, 2, 1),
        "source_basis": "screen-panel shader capability predicate",
        "context_group": "TScreenPanelOpenGL residual state and shader block",
        "context_order": 2,
    },
    {
        "original_ea": "0x109d48",
        "original_name": "TScreenPanelOpenGL_setShader_TOpenGLShaderProgram",
        "spectron_ea": "0x10c698",
        "target_name": "_ZN10SU3JfaCUmR10AixzfagDvIEP10MiAzfay9xI",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_setShader_TOpenGLShaderProgram",
        "metrics": (4, 1, 1),
        "source_basis": "screen-panel shader selection hook",
        "context_group": "TScreenPanelOpenGL residual state and shader block",
        "context_order": 3,
    },
    {
        "original_ea": "0x109d4c",
        "original_name": "TScreenPanelOpenGL_clearShader_void",
        "spectron_ea": "0x10c69c",
        "target_name": "_ZN10SU3JfaCUmR10pxczfaO9dIEv",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_clearShader_void",
        "metrics": (4, 1, 1),
        "source_basis": "screen-panel shader clear hook",
        "context_group": "TScreenPanelOpenGL residual state and shader block",
        "context_order": 4,
    },
    {
        "original_ea": "0x109d64",
        "original_name": "TScreenPanelOpenGL_setAlphaReference_float",
        "spectron_ea": "0x10c6b4",
        "target_name": "_ZN10SU3JfaCUmR10uwBIfa2a8PEf",
        "target_prefix": "_ZN10SU3JfaCUmR10",
        "proposed_name": "v18_TScreenPanelOpenGL_setAlphaReference_float",
        "metrics": (8, 2, 2),
        "source_basis": "screen-panel alpha-reference OpenGL wrapper",
        "context_group": "TScreenPanelOpenGL residual state and shader block",
        "context_order": 5,
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
            if function.get("call_count") != 0:
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
                "match_kind": "manual-screen-panel-renderer-residual-context-anchor",
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
        "artifact": "spectron_screen_panel_renderer_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual pixel-buffer and concrete screen-panel renderer methods",
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
                "uzN1fatj75": "one residual texture predicate at 0x10c584",
                "SU3JfaCUmR": "projection, model, and residual state or shader methods at 0x10c594 through 0x10c6b4",
            },
            "source_sequence": "The source TPixelBufferOpenGL texture predicate is followed by the concrete TScreenPanelOpenGL matrix and renderer state methods.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable source roles while retaining the obfuscated target names and changed target class names in the evidence rows.",
            "The target matrix methods use shifted object offsets, which is consistent with the changed SU3JfaCUmR layout and does not weaken the method correspondence.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
