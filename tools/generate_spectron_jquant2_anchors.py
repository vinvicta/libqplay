#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg two-pass quantizer."""

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
        "source_ea": "0x296270",
        "target_ea": "0x2a36e0",
        "role": "prescan_quantize",
        "target_context": "selected for the histogram prescan pass",
        "target_install_sites": ["0x2a37a8"],
        "operation": "scans RGB input rows and increments the reduced-precision histogram cell for each pixel, with saturation on cell overflow",
        "evidence": [
            "The target two-pass start-pass routine installs this callback for its pre-scan branch.",
            "The target body shifts the three input components into histogram coordinates and increments each 16-bit cell without wrapping an overflowing cell.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2962f4",
        "target_ea": "0x2a3764",
        "role": "finish_pass2",
        "target_context": "installed as the second-pass finish callback",
        "target_install_sites": ["0x2a380c"],
        "operation": "performs the second-pass finish callback, which is intentionally empty",
        "evidence": [
            "The target two-pass start-pass routine stores this four-byte nullsub as the second-pass finish callback.",
            "Both source and target retain the IDA auto-generated nullsub_5 name and have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2962f8",
        "target_ea": "0x2a3768",
        "role": "new_color_map_2_quant",
        "target_context": "installed as the two-pass new-color-map callback",
        "target_install_sites": ["0x2a4fb0"],
        "operation": "marks the inverse color map for clearing before the next mapping pass",
        "evidence": [
            "The target two-pass quantizer initializer stores this callback in the public new-color-map slot.",
            "The target body sets the quantizer state flag that causes the histogram or inverse map to be zeroed on the next pass.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x296308",
        "target_ea": "0x2a3778",
        "role": "start_pass_2_quant",
        "target_context": "installed as the public two-pass start-pass callback and selects the active pass method",
        "target_install_sites": ["0x2a4fa0", "0x2a4fa8"],
        "operation": "switches between histogram prescan and palette mapping, initializes the inverse map and Floyd-Steinberg workspace, and selects the active finish callback",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target two-pass initializer stores this routine in the public start-pass callback slot.",
            "The target body forces unsupported ordered dithering to Floyd-Steinberg, chooses prescan or second-pass callbacks, validates the color count, clears the histogram when needed, and prepares error workspace.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x296620",
        "target_ea": "0x2a3a90",
        "role": "update_box",
        "target_context": "called by the two-pass finish path while shrinking and measuring palette boxes",
        "target_install_sites": ["0x2a4cd4", "0x2a4ce4"],
        "operation": "shrinks a histogram box to its nonzero bounds and recomputes its scaled volume and nonzero-cell population",
        "evidence": [
            "The target two-pass finish routine calls this helper after splitting a color-space box.",
            "The target body searches all six box faces for nonzero histogram cells, computes the weighted squared dimensions, and counts occupied cells.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x296a64",
        "target_ea": "0x2a3ed4",
        "role": "fill_inverse_cmap",
        "target_context": "called on an inverse-map cache miss by both second-pass row quantizers",
        "target_install_sites": ["0x2a440c", "0x2a4704"],
        "operation": "fills the inverse color map for the histogram subbox containing a requested input color",
        "evidence": [
            "Both target second-pass row routines call this helper when the requested histogram cell has no cached palette index.",
            "The target body computes nearby palette candidates, evaluates their scaled distances across the update box, and writes the best palette indexes into the inverse-map cells.",
            "The source and target functions have identical complete ARM64 feature metrics; the nearby-color and best-color loops are retained inside this compiled function boundary.",
        ],
    },
    {
        "source_ea": "0x296ee0",
        "target_ea": "0x2a4350",
        "role": "pass2_no_dither",
        "target_context": "selected for the second pass when Floyd-Steinberg dithering is disabled",
        "target_install_sites": ["0x2a37fc"],
        "operation": "maps each reduced-precision input color through the inverse cache and emits the nearest selected palette index",
        "evidence": [
            "The target two-pass start-pass routine selects this callback for a non-dithered second pass.",
            "The target body shifts each RGB input triplet into a histogram cell, fills the inverse map on a cache miss, and writes the cached palette index minus one.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x296fe4",
        "target_ea": "0x2a4454",
        "role": "pass2_fs_dither",
        "target_context": "selected for the second pass with Floyd-Steinberg error diffusion",
        "target_install_sites": ["0x2a3874"],
        "operation": "maps RGB rows with Floyd-Steinberg error diffusion, alternating scan direction and using the inverse color map for palette selection",
        "evidence": [
            "The target two-pass start-pass routine selects this callback for Floyd-Steinberg dithering.",
            "The target body alternates left-to-right and right-to-left scans, applies the error limiter, fills the inverse map on cache misses, and propagates three-component errors to neighboring pixels.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x297388",
        "target_ea": "0x2a47f8",
        "role": "finish_pass1",
        "target_context": "selected as the finish callback after the histogram prescan",
        "target_install_sites": ["0x2a37b4"],
        "operation": "selects representative palette colors from the histogram, writes the completed colormap, and marks the inverse map for the next pass",
        "evidence": [
            "The target two-pass start-pass routine installs this callback for the pre-scan finish path.",
            "The target body finds the occupied histogram bounds, splits the largest color-space boxes, computes representative colors, writes the colormap, updates the actual color count, and marks the inverse map for clearing.",
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
        if not auto_named(original, "nullsub_5"):
            raise ValueError("source candidate is not an auto-generated name: %s" % spec["source_ea"])
        if not auto_named(spectron, "nullsub_5"):
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
                "match_kind": "manual-libjpeg-jquant2-role-anchor",
                "family": "libjpeg two-pass color quantizer",
                "source_name": spec["role"],
                "source_role": spec["role"],
                "source_file": "jquant2.c",
                "source_component": "jinit_2pass_quantizer_jpeg_decompress_struct at 0x297b00",
                "target_component": "v18_jinit_2pass_quantizer_jpeg_decompress_struct at 0x2a4f70",
                "source_basis": "libjpeg %s body and jinit_2pass_quantizer callback installation"
                % spec["role"],
                "source_parent": "jinit_2pass_quantizer_jpeg_decompress_struct at 0x297b00",
                "target_parent": "v18_jinit_2pass_quantizer_jpeg_decompress_struct at 0x2a4f70",
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
        "artifact": "spectron_jpeg_two_pass_quantizer_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jquant2 two-pass color quantizer routines",
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
            "source_controller": "jinit_2pass_quantizer_jpeg_decompress_struct at 0x297b00",
            "target_controller": "v18_jinit_2pass_quantizer_jpeg_decompress_struct at 0x2a4f70",
            "source_source_file": "jquant2.c",
            "target_source_file": "jquant2.c",
            "role_resolution": "standard libjpeg jquant2 callback contract, target start-pass dispatch, reviewed pseudocode, and complete or register-detail-only ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because both source and target functions retained IDA auto-generated names, including nullsub_5",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jquant2.c",
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
            "two_pass_quantizer_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target two-pass quantizer initializer preserves the source pass callback contract and the target start-pass routine selects prescan, no-dither, or Floyd-Steinberg behavior.",
            "All nine rows match the normalized ARM64 feature fields. Eight also match register allocation detail; the start-pass routine differs only in register allocation detail.",
            "The source's nearby-color and best-color helper logic is represented inside the retained fill_inverse_cmap and finish_pass1 function boundaries in this build, so no unsupported extra target labels are invented for compiler-folded helpers.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
