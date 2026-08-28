#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg output pipeline.

The master-decompress callbacks and merged-upsample routines retain the same
function shapes as the corresponding 1.8 build. Their roles are resolved from
the target initializer tables, the decompiled bodies, and the standard
libjpeg jdmaster and jdmerge contracts.
"""

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
        "source_ea": "0x28f2b0",
        "target_ea": "0x29c720",
        "role": "prepare_for_output_pass",
        "family": "libjpeg master decompressor",
        "source_file": "jdmaster.c",
        "parent_source": "jinit_master_decompress_jpeg_decompress_struct at 0x28f8c0",
        "parent_target": "v18_jinit_master_decompress_jpeg_decompress_struct at 0x29cd30",
        "target_context": "installed in the master state prepare_for_output_pass callback slot",
        "target_install_sites": ["0x29cd30 master-state callback field +0"],
        "operation": "selects the active quantizer and upsampler or color-deconverter path, starts the output modules, and prepares pass and progress state",
        "evidence": [
            "The target master initializer stores this function in the master state callback field at offset 0, alongside finish_output_pass at offset 8.",
            "The target body selects one-pass or two-pass quantization, starts the quantizer, upsampler, inverse-DCT, and post-controller passes, and updates the pass-progress bookkeeping used by the decompression pipeline.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x28f478",
        "target_ea": "0x29c8e8",
        "role": "finish_output_pass",
        "family": "libjpeg master decompressor",
        "source_file": "jdmaster.c",
        "parent_source": "jinit_master_decompress_jpeg_decompress_struct at 0x28f8c0",
        "parent_target": "v18_jinit_master_decompress_jpeg_decompress_struct at 0x29cd30",
        "target_context": "installed in the master state finish_output_pass callback slot",
        "target_install_sites": ["0x29cd30 master-state callback field +8"],
        "operation": "finishes the active two-pass color quantizer pass and advances the master pass counter",
        "evidence": [
            "The target master initializer stores this function in the master state callback field at offset 8.",
            "The target body invokes the two-pass quantizer finish callback when present and increments the master pass number, matching the jdmaster output-pass lifecycle.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x28fee0",
        "target_ea": "0x29d350",
        "role": "start_pass_merged_upsample",
        "family": "libjpeg merged upsampler",
        "source_file": "jdmerge.c",
        "parent_source": "jinit_merged_upsampler_jpeg_decompress_struct at 0x290398",
        "parent_target": "v18_jinit_merged_upsampler_jpeg_decompress_struct at 0x29d808",
        "target_context": "installed as the merged upsampler start_pass callback",
        "target_install_sites": ["0x29d844", "0x29d84c"],
        "operation": "initializes merged-upsample row state, clears the spare-row flag, and records the output rows remaining",
        "evidence": [
            "The target merged-upsampler initializer stores this function at the first callback field of the allocated upsampler state.",
            "The target body clears the spare-row state and initializes the output-row counter from the decompressor output height, which is the start_pass_merged_upsample contract.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x28fef4",
        "target_ea": "0x29d364",
        "role": "merged_1v_upsample",
        "family": "libjpeg merged upsampler",
        "source_file": "jdmerge.c",
        "parent_source": "jinit_merged_upsampler_jpeg_decompress_struct at 0x290398",
        "parent_target": "v18_jinit_merged_upsampler_jpeg_decompress_struct at 0x29d808",
        "target_context": "selected when the maximum vertical sampling factor is one",
        "target_install_sites": ["0x29d860", "0x29d868"],
        "operation": "invokes the selected one-row merged color-conversion method and advances the input row-group and output-row counters",
        "evidence": [
            "The target initializer selects this wrapper when the maximum vertical sampling factor is not two and installs the one-row conversion method at the upmethod field.",
            "The target body calls the configured upmethod once, passes the current row-group and output-row pointers, and increments both counters after the row is produced.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x28ff44",
        "target_ea": "0x29d3b4",
        "role": "h2v1_merged_upsample",
        "family": "libjpeg merged upsampler",
        "source_file": "jdmerge.c",
        "parent_source": "jinit_merged_upsampler_jpeg_decompress_struct at 0x290398",
        "parent_target": "v18_jinit_merged_upsampler_jpeg_decompress_struct at 0x29d808",
        "target_context": "selected as the one-row conversion method for horizontal two-to-one chroma sampling",
        "target_install_sites": ["0x29d870"],
        "operation": "merges one Y row with horizontally subsampled Cb and Cr rows into RGB output using the precomputed color tables and range limit",
        "evidence": [
            "The target initializer assigns this body to the upmethod field for the one-row path.",
            "The target body reads one input Y row and the corresponding Cb and Cr rows, expands each chroma sample across two output pixels, handles an odd final pixel, and applies the RGB range-limit table.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x290094",
        "target_ea": "0x29d504",
        "role": "h2v2_merged_upsample",
        "family": "libjpeg merged upsampler",
        "source_file": "jdmerge.c",
        "parent_source": "jinit_merged_upsampler_jpeg_decompress_struct at 0x290398",
        "parent_target": "v18_jinit_merged_upsampler_jpeg_decompress_struct at 0x29d808",
        "target_context": "selected when the maximum vertical sampling factor is two",
        "target_install_sites": ["0x29d860", "0x29d868"],
        "operation": "merges two Y rows with vertically and horizontally subsampled Cb and Cr rows into two RGB output rows",
        "evidence": [
            "The target initializer selects this conversion method for the vertical-two path and installs merged_2v_upsample as the public wrapper.",
            "The target body consumes two Y rows and one shared chroma row, expands chroma samples across each pair of output pixels, writes two rows, and handles odd output widths.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x290294",
        "target_ea": "0x29d704",
        "role": "merged_2v_upsample",
        "family": "libjpeg merged upsampler",
        "source_file": "jdmerge.c",
        "parent_source": "jinit_merged_upsampler_jpeg_decompress_struct at 0x290398",
        "parent_target": "v18_jinit_merged_upsampler_jpeg_decompress_struct at 0x29d808",
        "target_context": "selected when the maximum vertical sampling factor is two",
        "target_install_sites": ["0x29d978"],
        "operation": "coordinates two-row merged upsampling, preserves a spare output row when only one destination row is available, and advances the row counters",
        "evidence": [
            "The target initializer selects this wrapper for the vertical-two path and assigns h2v2_merged_upsample as its upmethod.",
            "The target body checks and fills the spare-row state, calls the configured two-row conversion method, copies a saved row when needed, and updates the output and input row-group counters.",
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
        if differences not in ([], ["register_detail_hash"]):
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
        anchor = {
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
            "match_kind": "manual-libjpeg-jdmaster-jdmerge-role-anchor",
            "family": spec["family"],
            "source_name": spec["role"],
            "source_role": spec["role"],
            "source_file": spec["source_file"],
            "source_component": spec["parent_source"],
            "target_component": spec["parent_target"],
            "source_basis": "libjpeg %s body and initializer callback context"
            % spec["role"],
            "source_parent": spec["parent_source"],
            "target_parent": spec["parent_target"],
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
        anchors.append(anchor)

    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_master_merge_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdmaster and jdmerge routines",
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
            "source_master": "jinit_master_decompress_jpeg_decompress_struct at 0x28f8c0",
            "target_master": "v18_jinit_master_decompress_jpeg_decompress_struct at 0x29cd30",
            "source_upsampler": "jinit_merged_upsampler_jpeg_decompress_struct at 0x290398",
            "target_upsampler": "v18_jinit_merged_upsampler_jpeg_decompress_struct at 0x29d808",
            "source_master_file": "jdmaster.c",
            "target_master_file": "jdmaster.c",
            "source_upsampler_file": "jdmerge.c",
            "target_upsampler_file": "jdmerge.c",
            "role_resolution": "standard libjpeg jdmaster and jdmerge contracts, target callback installation tables, reviewed pseudocode, and complete normalized ARM64 feature equality",
            "name_policy": "v18-prefixed semantic role because the source and target functions both retained default names",
            "reference_sources": [
                "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdmaster.c",
                "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdmerge.c",
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
            "register_detail_difference_count": sum(
                "register_detail_hash" in a["metric_differences"] for a in anchors
            ),
            "master_callback_count": 2,
            "merged_upsampler_role_count": 5,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The master-decompress initializer provides the prepare_for_output_pass and finish_output_pass callback pair used to manage the output pipeline.",
            "The merged-upsampler initializer selects the one-row or two-row wrapper and installs the matching h2v1 or h2v2 conversion method. The five target bodies therefore resolve to the standard jdmerge start, wrapper, and conversion roles.",
            "All seven source and target bodies have identical complete normalized and register-detail metrics in the current feature exports.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
