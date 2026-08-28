#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron JPEG prep and downsample stages."""

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
NORMALIZED_FIELDS = METRIC_FIELDS[:-1]


SPECS = (
    {
        "source_ea": "0x2aa4b8",
        "target_ea": "0x2b7928",
        "source_name": "start_pass_prep",
        "role": "start_pass_prep",
        "source_file": "jcprepct.c",
        "source_parent": "jinit_c_prep_controller_jpeg_compress_struct_int at 0x2aaa44",
        "target_parent": "v18_jinit_c_prep_controller_jpeg_compress_struct_int at 0x2b7eb4",
        "target_context": "installed as the compression preprocessing start-pass callback",
        "target_install_sites": ["0x2b7efc"],
        "operation": "validates pass-through mode and resets the source-row, conversion-buffer, and context-row state for a preprocessing pass",
        "evidence": [
            "The target prep-controller initializer stores this body in its public start-pass field at 0x2b7efc.",
            "The target body follows the standard jcprepct start-pass contract: it rejects a non-pass-through mode, records the image height, clears the next conversion-buffer row, and initializes the context counters.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2aa510",
        "target_ea": "0x2b7980",
        "source_name": "pre_process_context",
        "role": "pre_process_context",
        "source_file": "jcprepct.c",
        "source_parent": "jinit_c_prep_controller_jpeg_compress_struct_int at 0x2aaa44",
        "target_parent": "v18_jinit_c_prep_controller_jpeg_compress_struct_int at 0x2b7eb4",
        "target_context": "selected when the downsampler requests context rows",
        "target_install_sites": ["0x2b7fc0"],
        "operation": "fills the wrapped conversion buffer, creates top and bottom context rows, downsamples one row group at a time, and advances the circular buffer state",
        "evidence": [
            "The target prep-controller initializer assigns this body to the second public callback slot at 0x2b7fc0 when the downsampler reports need_context_rows.",
            "The target body color-converts input rows, duplicates the first and last rows for context, calls the downsampler with a wrapped row-group index, and updates the input and output counters exactly as the context-row jcprepct path requires.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2aa7a4",
        "target_ea": "0x2b7c14",
        "source_name": "pre_process_data",
        "role": "pre_process_data",
        "source_file": "jcprepct.c",
        "source_parent": "jinit_c_prep_controller_jpeg_compress_struct_int at 0x2aaa44",
        "target_parent": "v18_jinit_c_prep_controller_jpeg_compress_struct_int at 0x2b7eb4",
        "target_context": "selected when the downsampler does not request context rows",
        "target_install_sites": ["0x2b7f14"],
        "operation": "color-converts rows into a simple buffer, pads the bottom edge, invokes the downsampler, and pads output rows to a complete iMCU height",
        "evidence": [
            "The target prep-controller initializer assigns this body to the second public callback slot at 0x2b7f14 when need_context_rows is false.",
            "The target body tracks rows_to_go and next_buf_row, fills the conversion buffer through the color-conversion callback, repeats the last rows at the bottom, calls the downsampler, and repeats the last output row group when required.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2aae40",
        "target_ea": "0x2b82b0",
        "source_name": "sep_downsample",
        "role": "sep_downsample",
        "source_file": "jcsample.c",
        "source_parent": "jinit_downsampler_jpeg_compress_struct at 0x2abe58",
        "target_parent": "v18_jinit_downsampler_jpeg_compress_struct at 0x2b92c8",
        "target_context": "installed as the public downsampler callback",
        "target_install_sites": ["0x2b9310"],
        "operation": "walks the component list and dispatches each component through its selected one-plane downsampling method",
        "evidence": [
            "The target downsampler initializer stores this body in the public downsample callback slot at 0x2b9310.",
            "The target body iterates over num_components, computes each component's input and output row pointers, and invokes the per-component method table at the same structure offset used by sep_downsample.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2aaee4",
        "target_ea": "0x2b8354",
        "source_name": "int_downsample",
        "role": "int_downsample",
        "source_file": "jcsample.c",
        "source_parent": "jinit_downsampler_jpeg_compress_struct at 0x2abe58",
        "target_parent": "v18_jinit_downsampler_jpeg_compress_struct at 0x2b92c8",
        "target_context": "selected for arbitrary integral horizontal and vertical sampling ratios",
        "target_install_sites": ["0x2b9334", "0x2b934c"],
        "operation": "averages integral blocks of input samples with the standard rounding bias and emits one output row group",
        "evidence": [
            "The target downsampler initializer selects this body in the fallback integral-ratio branch at 0x2b9334 and 0x2b934c.",
            "The target body computes horizontal and vertical expansion factors, pads the input edge, accumulates each source block, and divides by the block area with the same alternating rounding behavior as int_downsample.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2ab2f4",
        "target_ea": "0x2b8764",
        "source_name": "h2v1_downsample",
        "role": "h2v1_downsample",
        "source_file": "jcsample.c",
        "source_parent": "jinit_downsampler_jpeg_compress_struct at 0x2abe58",
        "target_parent": "v18_jinit_downsampler_jpeg_compress_struct at 0x2b92c8",
        "target_context": "selected for 2:1 horizontal and 1:1 vertical sampling",
        "target_install_sites": ["0x2b948c", "0x2b9494"],
        "operation": "pads each input row to the output width and averages horizontal pairs using the alternating 0,1 rounding bias",
        "evidence": [
            "The target downsampler initializer selects this body when horizontal sampling is 2:1 and vertical sampling is unchanged at 0x2b948c and 0x2b9494.",
            "The target body duplicates the rightmost sample for padding, advances by two input samples per output sample, and toggles the horizontal rounding bias exactly as h2v1_downsample does.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2ab4a4",
        "target_ea": "0x2b8914",
        "source_name": "h2v2_downsample",
        "role": "h2v2_downsample",
        "source_file": "jcsample.c",
        "source_parent": "jinit_downsampler_jpeg_compress_struct at 0x2abe58",
        "target_parent": "v18_jinit_downsampler_jpeg_compress_struct at 0x2b92c8",
        "target_context": "selected for 2:1 horizontal and 2:1 vertical sampling without smoothing",
        "target_install_sites": ["0x2b9338", "0x2b9350"],
        "operation": "pads the input rows and averages each 2 by 2 source block with the alternating 1,2 rounding bias",
        "evidence": [
            "The target downsampler initializer selects this body for the standard 2:1 by 2:1 branch without smoothing at 0x2b9338 and 0x2b9350.",
            "The target body consumes two input rows and two input columns per output sample, toggles the 1,2 bias, and writes the component output row group.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2ab670",
        "target_ea": "0x2b8ae0",
        "source_name": "h2v2_smooth_downsample",
        "role": "h2v2_smooth_downsample",
        "source_file": "jcsample.c",
        "source_parent": "jinit_downsampler_jpeg_compress_struct at 0x2abe58",
        "target_parent": "v18_jinit_downsampler_jpeg_compress_struct at 0x2b92c8",
        "target_context": "selected for smoothed 2:1 horizontal and 2:1 vertical sampling",
        "target_install_sites": ["0x2b933c", "0x2b9354"],
        "operation": "pads the input context rows and computes the smoothed 2 by 2 output from the member block and its eight neighbors",
        "evidence": [
            "The target downsampler initializer selects this body in the smoothed 2:1 by 2:1 branch and marks need_context_rows at 0x2b933c and 0x2b9354.",
            "The target body reads the above, current, and below rows, applies the member and neighbor smoothing scales, and writes the rounded fixed-point output values described by h2v2_smooth_downsample.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2aba28",
        "target_ea": "0x2b8e98",
        "source_name": "fullsize_smooth_downsample",
        "role": "fullsize_smooth_downsample",
        "source_file": "jcsample.c",
        "source_parent": "jinit_downsampler_jpeg_compress_struct at 0x2abe58",
        "target_parent": "v18_jinit_downsampler_jpeg_compress_struct at 0x2b92c8",
        "target_context": "selected for smoothed full-size components",
        "target_install_sites": ["0x2b93c0", "0x2b93c8"],
        "operation": "pads the input context rows and computes a full-size output sample from the center value and its neighboring samples",
        "evidence": [
            "The target downsampler initializer selects this body in the full-size smoothing branch and marks need_context_rows at 0x2b93c0 and 0x2b93c8.",
            "The target body uses the previous, current, and next rows, applies the fixed-point member and neighbor weights, and handles the first and last columns with the same edge rules as fullsize_smooth_downsample.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2abcd0",
        "target_ea": "0x2b9140",
        "source_name": "fullsize_downsample",
        "role": "fullsize_downsample",
        "source_file": "jcsample.c",
        "source_parent": "jinit_downsampler_jpeg_compress_struct at 0x2abe58",
        "target_parent": "v18_jinit_downsampler_jpeg_compress_struct at 0x2b92c8",
        "target_context": "selected for full-size components without smoothing",
        "target_install_sites": ["0x2b947c"],
        "operation": "copies full-size component rows and repeats the rightmost sample to fill the rounded-up output width",
        "evidence": [
            "The target downsampler initializer selects this body for the full-size non-smoothed branch at 0x2b947c.",
            "The target body copies the component rows with jcopy_sample_rows, computes the padded output width from width_in_blocks, and duplicates the final sample across the right edge.",
            "The source and target functions have identical complete ARM64 feature metrics.",
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
        if not original.get("is_default_name"):
            raise ValueError("source candidate is not a default name: %s" % spec["source_ea"])
        if not spectron.get("is_default_name"):
            raise ValueError("target candidate is not a default name: %s" % spec["target_ea"])
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
                "match_kind": "manual-libjpeg-jcprepct-jcsample-role-anchor",
                "family": "libjpeg compressor preprocessing and downsampling",
                "source_name": spec["source_name"],
                "source_role": spec["role"],
                "source_file": spec["source_file"],
                "source_component": spec["source_parent"],
                "target_component": spec["target_parent"],
                "source_basis": "libjpeg %s body and callback installation" % spec["source_name"],
                "source_parent": spec["source_parent"],
                "target_parent": spec["target_parent"],
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
        "artifact": "spectron_jpeg_preprocessing_downsampling_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jcprepct and jcsample compressor routines",
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
            "source_prep_controller": "jinit_c_prep_controller_jpeg_compress_struct_int at 0x2aaa44",
            "target_prep_controller": "v18_jinit_c_prep_controller_jpeg_compress_struct_int at 0x2b7eb4",
            "source_downsampler": "jinit_downsampler_jpeg_compress_struct at 0x2abe58",
            "target_downsampler": "v18_jinit_downsampler_jpeg_compress_struct at 0x2b92c8",
            "source_source_files": ["jcprepct.c", "jcsample.c"],
            "target_source_files": ["jcprepct.c", "jcsample.c"],
            "role_resolution": "standard libjpeg callback contracts, target callback installation sites, reviewed source and target pseudocode, and exact ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because all ten source and target candidates retained IDA auto-generated names",
            "reference_sources": [
                "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jcprepct.c",
                "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jcsample.c",
            ],
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({a["spectron_ea"] for a in anchors}),
            "high_confidence_count": sum(a["confidence"] == "high" for a in anchors),
            "target_default_name_count": sum(a["spectron_default_name"] for a in anchors),
            "source_default_name_count": sum(a["original_default_name"] for a in anchors),
            "normalized_shape_exact_count": sum(a["normalized_shape_equal"] for a in anchors),
            "full_metric_exact_count": sum(a["full_metric_equal"] for a in anchors),
            "prep_controller_role_count": 3,
            "downsampler_role_count": 7,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target prep controller preserves the source split between context-row and simple preprocessing callbacks.",
            "The target downsampler preserves the source public dispatcher and its per-component selection of integral, 2:1, smoothed, and full-size routines.",
            "All ten rows match the complete recorded ARM64 feature set, which is stronger than a normalized shape match alone.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
