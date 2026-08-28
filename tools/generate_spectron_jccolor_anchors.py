#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron compressor-side color converter."""

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
        "source_ea": "0x2a2b0c",
        "target_ea": "0x2aff7c",
        "source_name": "rgb_ycc_start",
        "proposed_name": "v18_jpeg_rgb_ycc_start",
        "target_context": "installed as the RGB-to-YCbCr conversion-table initializer",
        "target_install_sites": ["0x2b0608", "0x2b0624", "0x2b0640"],
        "operation": "allocates and fills the fixed-point lookup tables used by the RGB-to-YCbCr and CMYK-to-YCCK conversion paths",
        "evidence": [
            "The target compressor color-converter initializer installs this routine in the RGB-to-YCbCr and CMYK-to-YCCK branches.",
            "The target body allocates a 2048-entry table and fills the seven fixed-point coefficient and range regions used by the conversion callbacks.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a2bd0",
        "target_ea": "0x2b0040",
        "source_name": "rgb_ycc_convert",
        "proposed_name": "v18_jpeg_rgb_ycc_convert",
        "target_context": "selected for RGB input and YCbCr output",
        "target_install_sites": ["0x2b0630"],
        "operation": "converts interleaved RGB samples into separate Y, Cb, and Cr output rows through the precomputed fixed-point tables",
        "evidence": [
            "The target initializer selects this routine for the RGB-to-YCbCr colorspace combination.",
            "The target body reads RGB triples, applies the three lookup-table regions, and writes one sample to each of the Y, Cb, and Cr output planes.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a2ca4",
        "target_ea": "0x2b0114",
        "source_name": "rgb_gray_convert",
        "proposed_name": "v18_jpeg_rgb_gray_convert",
        "target_context": "selected for RGB input and grayscale output",
        "target_install_sites": ["0x2b064c"],
        "operation": "converts interleaved RGB samples into a grayscale output row using the luminance lookup-table combination",
        "evidence": [
            "The target initializer selects this routine for the RGB-to-grayscale colorspace combination.",
            "The target body reads RGB triples, combines the luminance table contributions, and writes one output sample per pixel.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a2d1c",
        "target_ea": "0x2b018c",
        "source_name": "cmyk_ycck_convert",
        "proposed_name": "v18_jpeg_cmyk_ycck_convert",
        "target_context": "selected for CMYK input and YCCK output",
        "target_install_sites": ["0x2b0614"],
        "operation": "converts CMYK samples into YCCK by inverting the color inputs, applying the RGB-to-YCC tables, and copying the black channel",
        "evidence": [
            "The target initializer selects this routine for the CMYK-to-YCCK colorspace combination.",
            "The target body inverts the first three input components, applies the same table regions as the RGB path, writes Y, Cb, and Cr, and preserves K as the fourth output component.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a2e20",
        "target_ea": "0x2b0290",
        "source_name": "grayscale_convert",
        "proposed_name": "v18_jpeg_c_grayscale_convert",
        "target_context": "selected for direct grayscale input and grayscale output in the compressor",
        "target_install_sites": ["0x2b05a8"],
        "operation": "copies the grayscale input component into the output row while respecting the input component stride",
        "evidence": [
            "The target compressor initializer selects this short copy loop for grayscale-preserving colorspace combinations.",
            "The target body reads one input component at the configured input stride and writes a contiguous grayscale output row.",
            "The source and target functions have identical complete ARM64 feature metrics.",
            "The c_ qualifier is intentional because the decompressor-side jdcolor.c already uses v18_jpeg_grayscale_convert for a different function at 0x2ab43c.",
        ],
    },
    {
        "source_ea": "0x2a2e6c",
        "target_ea": "0x2b02dc",
        "source_name": "null_convert",
        "proposed_name": "v18_jpeg_c_null_convert",
        "target_context": "selected for direct multi-component input and output in the compressor",
        "target_install_sites": ["0x2b0518"],
        "operation": "copies interleaved input components into separate output planes without changing sample values",
        "evidence": [
            "The target compressor initializer selects this routine for direct-copy colorspace combinations with multiple components.",
            "The target body walks each component and row, reads samples at the configured input stride, and writes them to the corresponding output plane.",
            "The source and target functions have identical complete ARM64 feature metrics.",
            "The c_ qualifier is intentional because the decompressor-side jdcolor.c already uses v18_jpeg_null_convert for a different function at 0x2aaf98.",
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
        if differences:
            raise ValueError(
                "unexpected metric differences for %s: %s"
                % (spec["source_name"], differences)
            )
        normalized_equal = all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        )
        if not normalized_equal:
            raise ValueError("normalized metrics do not match for %s" % spec["source_name"])
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
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-libjpeg-jccolor-role-anchor",
                "family": "libjpeg compressor color converter",
                "source_name": spec["source_name"],
                "source_role": spec["source_name"],
                "source_file": "jccolor.c",
                "source_component": "jinit_color_converter_jpeg_compress_struct at 0x2a2ee4",
                "target_component": "v18_jinit_color_converter_jpeg_compress_struct at 0x2b0354",
                "source_basis": "libjpeg %s body and jinit_color_converter callback installation"
                % spec["source_name"],
                "source_parent": "jinit_color_converter_jpeg_compress_struct at 0x2a2ee4",
                "target_parent": "v18_jinit_color_converter_jpeg_compress_struct at 0x2b0354",
                "target_context": spec["target_context"],
                "target_install_sites": spec["target_install_sites"],
                "operation": spec["operation"],
                "normalized_shape_equal": normalized_equal,
                "full_metric_equal": True,
                "metric_differences": [],
                "semantic_match_already_present": False,
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix-and-source-qualifier",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_compressor_color_converter_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jccolor compressor color conversion routines",
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
            "source_controller": "jinit_color_converter_jpeg_compress_struct at 0x2a2ee4",
            "target_controller": "v18_jinit_color_converter_jpeg_compress_struct at 0x2b0354",
            "source_source_file": "jccolor.c",
            "target_source_file": "jccolor.c",
            "role_resolution": "standard libjpeg jccolor callback contract, target initializer assignments, reviewed target pseudocode, and complete ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role; compressor-side duplicate role names receive a c_ qualifier to remain unique beside jdcolor labels",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jccolor.c",
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
            "compressor_color_converter_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target compressor color-converter initializer preserves the source callback assignments for the supported grayscale, RGB, YCbCr, CMYK, and YCCK combinations.",
            "All six rows match the normalized and complete recorded ARM64 feature set.",
            "The c_ qualifiers distinguish compressor-side jccolor routines from same-named decompressor-side jdcolor routines already translated elsewhere in the database.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
