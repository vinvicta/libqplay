#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg postprocessing controller."""

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
        "source_ea": "0x2916f8",
        "target_ea": "0x29eb68",
        "role": "start_pass_dpost",
        "family": "libjpeg decompression postprocessing controller",
        "source_file": "jdpostct.c",
        "parent_source": "jinit_d_post_controller_jpeg_decompress_struct_int at 0x291a90",
        "parent_target": "v18_jinit_d_post_controller_jpeg_decompress_struct_int at 0x29ef00",
        "target_context": "installed as the postprocessing start_pass callback",
        "target_install_sites": ["0x29ef38"],
        "operation": "selects the postprocessing callback for pass-through, one-pass quantization, two-pass prepass, or two-pass output and resets strip counters",
        "evidence": [
            "The target post-controller initializer stores this function in the public start_pass field.",
            "The target body switches on the buffer mode, selects the direct upsampler or one of the three postprocessing routines, allocates a virtual workspace when needed, and resets starting_row and next_row.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x291810",
        "target_ea": "0x29ec80",
        "role": "post_process_1pass",
        "family": "libjpeg decompression postprocessing controller",
        "source_file": "jdpostct.c",
        "parent_source": "jinit_d_post_controller_jpeg_decompress_struct_int at 0x291a90",
        "parent_target": "v18_jinit_d_post_controller_jpeg_decompress_struct_int at 0x29ef00",
        "target_context": "selected by start_pass_dpost for pass-through with one-pass color quantization",
        "target_install_sites": ["0x29ebb8", "0x29ebc0"],
        "operation": "fills a strip through the upsampler, color-quantizes the rows into the destination, and advances the output row counter",
        "evidence": [
            "The target start-pass switch selects this routine for the one-pass quantization path.",
            "The target body calls the upsampler into the post buffer, sends the produced rows to the color quantizer, and increments the caller's output-row count.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2918a0",
        "target_ea": "0x29ed10",
        "role": "post_process_prepass",
        "family": "libjpeg decompression postprocessing controller",
        "source_file": "jdpostct.c",
        "parent_source": "jinit_d_post_controller_jpeg_decompress_struct_int at 0x291a90",
        "parent_target": "v18_jinit_d_post_controller_jpeg_decompress_struct_int at 0x29ef00",
        "target_context": "selected by start_pass_dpost for the first pass of two-pass color quantization",
        "target_install_sites": ["0x29ebf8", "0x29ec00"],
        "operation": "loads a virtual strip, upsamples into it, lets the quantizer scan new rows without emitting pixels, and advances virtual-strip state",
        "evidence": [
            "The target start-pass switch selects this routine for the two-pass save-and-pass mode.",
            "The target body obtains the virtual strip when needed, invokes the upsampler, passes newly produced rows to the color quantizer with no output buffer, and advances starting_row and next_row when a strip is full.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2919a0",
        "target_ea": "0x29ee10",
        "role": "post_process_2pass",
        "family": "libjpeg decompression postprocessing controller",
        "source_file": "jdpostct.c",
        "parent_source": "jinit_d_post_controller_jpeg_decompress_struct_int at 0x291a90",
        "parent_target": "v18_jinit_d_post_controller_jpeg_decompress_struct_int at 0x29ef00",
        "target_context": "selected by start_pass_dpost for the second pass of two-pass color quantization",
        "target_install_sites": ["0x29ec20", "0x29ec28"],
        "operation": "reads rows from the virtual image strip, bounds the emission by strip, output-area, and image height, color-quantizes them, and advances virtual-strip state",
        "evidence": [
            "The target start-pass switch selects this routine for the two-pass crank-destination mode.",
            "The target body obtains the virtual strip for reading, computes the safe number of rows from all three output limits, sends them to the color quantizer, and advances the strip cursor.",
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
            "match_kind": "manual-libjpeg-jdpostct-role-anchor",
            "family": spec["family"],
            "source_name": spec["role"],
            "source_role": spec["role"],
            "source_file": spec["source_file"],
            "source_component": spec["parent_source"],
            "target_component": spec["parent_target"],
            "source_basis": "libjpeg %s body and post-controller mode dispatch"
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
        "artifact": "spectron_jpeg_postprocessing_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdpostct postprocessing controller routines",
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
            "source_controller": "jinit_d_post_controller_jpeg_decompress_struct_int at 0x291a90",
            "target_controller": "v18_jinit_d_post_controller_jpeg_decompress_struct_int at 0x29ef00",
            "source_source_file": "jdpostct.c",
            "target_source_file": "jdpostct.c",
            "role_resolution": "standard libjpeg jdpostct pass-mode contract, target callback installation table and dispatch sites, reviewed pseudocode, and normalized ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because the source and target functions both retained default names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdpostct.c",
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
            "postprocessing_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The post-controller start-pass routine dispatches to direct upsampling, one-pass quantization, two-pass prepass, or two-pass output according to the buffer mode.",
            "The source and target bodies have identical normalized metrics; three rows are complete metric matches and one differs only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
