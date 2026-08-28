#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg one-pass quantizer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)
NORMALIZED_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)


SPECS = (
    {
        "source_ea": "0x294f44",
        "target_ea": "0x2a23b4",
        "role": "color_quantize",
        "target_context": "selected for non-dithered quantization when the output has a general component count",
        "target_install_sites": ["0x2a29b4"],
        "operation": "maps each input sample through the per-component color-index tables and accumulates the resulting palette index",
        "evidence": [
            "The target one-pass quantizer start-pass routine installs this callback for the plain general-component path when ordered and Floyd-Steinberg dithering are disabled.",
            "The target body walks input rows and pixels, looks up every component in the color-index tables, and writes the accumulated palette value to the output row.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x294fd0",
        "target_ea": "0x2a2440",
        "role": "color_quantize3",
        "target_context": "selected for non-dithered quantization when the output has exactly three components",
        "target_install_sites": ["0x2a2efc"],
        "operation": "maps three input components through the three color-index tables using the RGB fast path",
        "evidence": [
            "The target one-pass quantizer start-pass routine installs this callback for the plain three-component path when dithering is disabled.",
            "The target body advances through RGB triples and combines the three indexed palette contributions for each output sample.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x295050",
        "target_ea": "0x2a24c0",
        "role": "quantize3_ord_dither",
        "target_context": "selected for ordered dithering when the output has exactly three components",
        "target_install_sites": ["0x2a2ef0"],
        "operation": "quantizes RGB rows with the three-component ordered-dither tables and advances the dither row phase",
        "evidence": [
            "The target one-pass quantizer start-pass routine selects this callback when dither_mode is ordered and the output has three components.",
            "The target body applies the per-row ordered-dither offsets to each RGB component, performs the indexed lookups, and updates the sixteen-row dither phase.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x295138",
        "target_ea": "0x2a25a8",
        "role": "finish_pass_1_quant",
        "target_context": "installed as the one-pass quantizer finish-pass callback",
        "target_install_sites": ["0x2a2fc8", "0x2a2fd0"],
        "operation": "performs the one-pass quantizer finish callback, which is intentionally empty",
        "evidence": [
            "The target one-pass quantizer initializer stores this no-op in the finish-pass callback slot.",
            "Both source and target are the same four-byte nullsub body and have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29513c",
        "target_ea": "0x2a25ac",
        "role": "new_color_map_1_quant",
        "target_context": "installed as the one-pass quantizer new-color-map callback",
        "target_install_sites": ["0x2a2fd8", "0x2a2fe0"],
        "operation": "reports that changing the color map is unsupported by setting the JPEG error code and dispatching the error handler",
        "evidence": [
            "The target one-pass quantizer initializer stores this callback in the new-color-map slot.",
            "The target body writes error code 46 and invokes the decompressor error callback, matching the standard jquant1 contract.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x295164",
        "target_ea": "0x2a25d4",
        "role": "quantize_fs_dither",
        "target_context": "selected for Floyd-Steinberg error-diffusion dithering",
        "target_install_sites": ["0x2a2910", "0x2a2918"],
        "operation": "quantizes rows with Floyd-Steinberg error diffusion, handling image-edge direction and propagating quantization error to neighboring samples",
        "evidence": [
            "The target one-pass quantizer start-pass routine installs this callback when dither_mode is Floyd-Steinberg.",
            "The target body clears output rows, processes each component in forward or reverse direction, applies the saved error workspace, and writes the propagated errors for the next row.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x295344",
        "target_ea": "0x2a27b4",
        "role": "quantize_ord_dither",
        "target_context": "selected for ordered dithering when the output has a general component count",
        "target_install_sites": ["0x2a29e4"],
        "operation": "quantizes general-component rows with the ordered-dither tables and advances the dither row phase",
        "evidence": [
            "The target one-pass quantizer start-pass routine selects this callback when dither_mode is ordered and the output has a general component count.",
            "The target body zeroes output rows, applies the component-specific sixteen-row dither tables, performs the color-index lookups, and advances the row phase.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29545c",
        "target_ea": "0x2a28cc",
        "role": "start_pass_1_quant",
        "target_context": "installed as the one-pass quantizer start-pass callback and dispatches the active quantization method",
        "target_install_sites": ["0x2a2fb8", "0x2a2fc0"],
        "operation": "initializes the output palette tables and dither workspace, then selects the plain, ordered, or Floyd-Steinberg row quantizer",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target one-pass quantizer initializer stores this routine in the public start-pass callback slot.",
            "The target body computes palette dimensions, allocates and fills color-index tables, prepares ordered-dither or error-diffusion state, and selects the correct row quantizer callback.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"].lower(): row for row in document["functions"]}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def auto_named(row: dict, expected_name: str) -> bool:
    """Treat IDA's nullsub label as an auto-generated name too."""
    return bool(row.get("is_default_name")) or row.get("name") == expected_name


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original_rows = by_ea(load(args.original_features))
    spectron_rows = by_ea(load(args.spectron_features))
    anchors = []
    for spec in SPECS:
        original = original_rows[spec["source_ea"]]
        spectron = spectron_rows[spec["target_ea"]]
        if not auto_named(original, "nullsub_4"):
            raise ValueError("source candidate is not an auto-generated name: %s" % spec["source_ea"])
        if not auto_named(spectron, "nullsub_4"):
            raise ValueError("target candidate is not an auto-generated name: %s" % spec["target_ea"])
        original_metrics = metrics(original)
        spectron_metrics = metrics(spectron)
        differences = [
            field
            for field in METRIC_FIELDS
            if original_metrics[field] != spectron_metrics[field]
        ]
        expected_differences = spec.get("expected_differences", [])
        if differences != expected_differences:
            raise ValueError(
                "unexpected metric differences for %s: %s"
                % (spec["role"], differences)
            )
        normalized_equal = all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        )
        if not normalized_equal:
            raise ValueError("normalized metrics do not match for %s" % spec["role"])
        anchors.append(
            {
                "original_ea": spec["source_ea"],
                "original_name": original["name"],
                "original_current_name": original["name"],
                "original_default_name": True,
                "original_metrics": original_metrics,
                "original_function_end": original.get("end_ea"),
                "original_string_refs": original.get("string_refs", []),
                "original_direct_call_names": original.get("direct_call_names", []),
                "spectron_ea": spec["target_ea"],
                "spectron_current_name": spectron["name"],
                "spectron_default_name": True,
                "spectron_metrics": spectron_metrics,
                "spectron_function_end": spectron.get("end_ea"),
                "spectron_string_refs": spectron.get("string_refs", []),
                "spectron_direct_call_names": spectron.get("direct_call_names", []),
                "proposed_name": "v18_jpeg_" + spec["role"],
                "confidence": "high",
                "match_kind": "manual-libjpeg-jquant1-role-anchor",
                "family": "libjpeg one-pass color quantizer",
                "source_name": spec["role"],
                "source_role": spec["role"],
                "source_file": "jquant1.c",
                "source_component": "jinit_1pass_quantizer_jpeg_decompress_struct at 0x295b18",
                "target_component": "v18_jinit_1pass_quantizer_jpeg_decompress_struct at 0x2a2f88",
                "source_basis": "libjpeg %s body and jinit_1pass_quantizer callback installation"
                % spec["role"],
                "source_parent": "jinit_1pass_quantizer_jpeg_decompress_struct at 0x295b18",
                "target_parent": "v18_jinit_1pass_quantizer_jpeg_decompress_struct at 0x2a2f88",
                "target_context": spec["target_context"],
                "target_install_sites": spec["target_install_sites"],
                "operation": spec["operation"],
                "normalized_shape_equal": normalized_equal,
                "full_metric_equal": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_one_pass_quantizer_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jquant1 one-pass color quantizer routines",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "source_controller": "jinit_1pass_quantizer_jpeg_decompress_struct at 0x295b18",
            "target_controller": "v18_jinit_1pass_quantizer_jpeg_decompress_struct at 0x2a2f88",
            "source_source_file": "jquant1.c",
            "target_source_file": "jquant1.c",
            "role_resolution": "standard libjpeg jquant1 callback contract, target start-pass dispatch, reviewed pseudocode, and complete or register-detail-only ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because both source and target functions retained IDA auto-generated names, including nullsub_4",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jquant1.c",
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({a["spectron_ea"] for a in anchors}),
            "high_confidence_count": sum(a["confidence"] == "high" for a in anchors),
            "target_default_name_count": sum(a["spectron_default_name"] for a in anchors),
            "source_default_name_count": sum(a["original_default_name"] for a in anchors),
            "normalized_shape_exact_count": sum(a["normalized_shape_equal"] for a in anchors),
            "full_metric_exact_count": sum(a["full_metric_equal"] for a in anchors),
            "register_detail_difference_count": sum(
                "register_detail_hash" in a["metric_differences"] for a in anchors
            ),
            "one_pass_quantizer_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target one-pass quantizer initializer preserves the source callback contract and dispatches the plain, ordered, and Floyd-Steinberg quantizers by component count and dither mode.",
            "All eight rows match the normalized ARM64 feature fields. Seven also match register allocation detail; the start-pass routine differs only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
