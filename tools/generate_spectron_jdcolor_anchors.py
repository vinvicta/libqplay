#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg color deconverter."""

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
        "source_ea": "0x29da68",
        "target_ea": "0x2aaed8",
        "source_name": "ycc_rgb_convert",
        "role": "ycc_rgb_convert",
        "target_context": "selected for YCbCr input and RGB output",
        "target_install_sites": ["0x2ab688"],
        "operation": "converts YCbCr samples to interleaved RGB using the precomputed range and chroma tables",
        "evidence": [
            "The target color-deconverter initializer installs this routine for the YCbCr-to-RGB case and allocates the four conversion tables it consumes.",
            "The target body reads three input planes, applies the YCbCr conversion tables, range-limits the results, and writes three interleaved output bytes per sample.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29db28",
        "target_ea": "0x2aaf98",
        "source_name": "null_convert",
        "role": "null_convert",
        "target_context": "selected when the input and output colorspaces require direct component interleave",
        "target_install_sites": ["0x2ab5d0", "0x2ab64c", "0x2ab664"],
        "operation": "copies separate component planes into the interleaved output representation without changing sample values",
        "evidence": [
            "The target initializer selects this routine for direct-copy colorspace combinations and its three incoming references correspond to those branches.",
            "The target body handles an arbitrary component count, walking each input plane and placing samples at the matching interleaved output position.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29dba4",
        "target_ea": "0x2ab014",
        "source_name": "gray_rgb_convert",
        "role": "gray_rgb_convert",
        "target_context": "selected for grayscale input and RGB output",
        "target_install_sites": ["0x2ab674"],
        "operation": "replicates each grayscale sample into the three interleaved RGB channels, including the vectorized wide-row path",
        "evidence": [
            "The target color-deconverter initializer selects this routine for the grayscale-to-RGB branch.",
            "The target body handles short rows with a scalar loop and wider rows with the retained ARM64 vector path, writing each gray sample to red, green, and blue.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29dee8",
        "target_ea": "0x2ab358",
        "source_name": "ycck_cmyk_convert",
        "role": "ycck_cmyk_convert",
        "target_context": "selected for YCCK input and CMYK output",
        "target_install_sites": ["0x2ab780"],
        "operation": "converts YCCK samples to CMYK, range-limits the inverted color channels, and preserves the black channel",
        "evidence": [
            "The target initializer selects this routine for the YCCK-to-CMYK case and allocates the same conversion tables used by the YCbCr path.",
            "The target body converts the first three planes through the range and chroma tables, inverts them for CMYK, and copies the fourth K sample unchanged.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29dfc8",
        "target_ea": "0x2ab438",
        "source_name": "start_pass_dcolor",
        "role": "start_pass_dcolor",
        "target_context": "installed as the color-deconverter start-pass callback",
        "target_install_sites": ["0x2ab480", "0x2ab488"],
        "operation": "performs no work because the color conversion tables and method selection are prepared during initialization",
        "evidence": [
            "The target initializer stores this four-byte empty routine in the public start-pass slot.",
            "The source and target retain the same IDA nullsub_6 body and identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29dfcc",
        "target_ea": "0x2ab43c",
        "source_name": "grayscale_convert",
        "role": "grayscale_convert",
        "target_context": "selected when only the luminance plane must be copied to grayscale output",
        "target_install_sites": ["0x2ab538", "0x2ab540"],
        "operation": "copies the first input component into the grayscale output rows through the shared sample-row helper",
        "evidence": [
            "The target initializer selects this short wrapper in the grayscale-output branches.",
            "The target body forwards the first input plane, output width, row count, and component width to the shared sample-row copy helper.",
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
        original_metrics = metrics(original)
        spectron_metrics = metrics(spectron)
        differences = [
            field
            for field in METRIC_FIELDS
            if original_metrics[field] != spectron_metrics[field]
        ]
        if differences:
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
                "original_default_name": bool(original.get("is_default_name")),
                "original_metrics": original_metrics,
                "original_function_end": original.get("end_ea"),
                "original_string_refs": original.get("string_refs", []),
                "original_direct_call_names": original.get("direct_call_names", []),
                "spectron_ea": spec["target_ea"],
                "spectron_current_name": spectron["name"],
                "spectron_default_name": bool(spectron.get("is_default_name")),
                "spectron_metrics": spectron_metrics,
                "spectron_function_end": spectron.get("end_ea"),
                "spectron_string_refs": spectron.get("string_refs", []),
                "spectron_direct_call_names": spectron.get("direct_call_names", []),
                "proposed_name": "v18_jpeg_" + spec["role"],
                "confidence": "high",
                "match_kind": "manual-libjpeg-jdcolor-role-anchor",
                "family": "libjpeg color deconverter",
                "source_name": spec["source_name"],
                "source_role": spec["source_name"],
                "source_file": "jdcolor.c",
                "source_component": "jinit_color_deconverter_jpeg_decompress_struct at 0x29dfe4",
                "target_component": "v18_jinit_color_deconverter_jpeg_decompress_struct at 0x2ab454",
                "source_basis": "libjpeg %s body and jinit_color_deconverter callback installation"
                % spec["source_name"],
                "source_parent": "jinit_color_deconverter_jpeg_decompress_struct at 0x29dfe4",
                "target_parent": "v18_jinit_color_deconverter_jpeg_decompress_struct at 0x2ab454",
                "target_context": spec["target_context"],
                "target_install_sites": spec["target_install_sites"],
                "operation": spec["operation"],
                "normalized_shape_equal": normalized_equal,
                "full_metric_equal": True,
                "metric_differences": [],
                "semantic_match_already_present": False,
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_color_deconverter_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdcolor conversion routines",
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
            "source_controller": "jinit_color_deconverter_jpeg_decompress_struct at 0x29dfe4",
            "target_controller": "v18_jinit_color_deconverter_jpeg_decompress_struct at 0x2ab454",
            "source_source_file": "jdcolor.c",
            "target_source_file": "jdcolor.c",
            "role_resolution": "standard libjpeg jdcolor callback contract, target initializer assignments, reviewed pseudocode, and complete ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because source and target candidates retained IDA names or auto-generated names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdcolor.c",
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({a["spectron_ea"] for a in anchors}),
            "high_confidence_count": sum(a["confidence"] == "high" for a in anchors),
            "target_default_name_count": sum(a["spectron_default_name"] for a in anchors),
            "source_default_name_count": sum(a["original_default_name"] for a in anchors),
            "normalized_shape_exact_count": sum(a["normalized_shape_equal"] for a in anchors),
            "full_metric_exact_count": sum(a["full_metric_equal"] for a in anchors),
            "register_detail_difference_count": 0,
            "color_deconverter_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because several source and target functions retained IDA auto-generated names.",
            "The target color-deconverter initializer preserves the source callback assignments for the supported grayscale, RGB, YCbCr, CMYK, and YCCK combinations.",
            "All six rows match the normalized and complete recorded ARM64 feature set, including the retained vectorized grayscale-to-RGB implementation and the shared nullsub_6 start-pass callback.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
