#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg coefficient controller."""

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
        "source_ea": "0x29c6bc",
        "target_ea": "0x2a9b2c",
        "role": "dummy_consume_data",
        "target_context": "installed as the single-pass consume_data callback",
        "target_install_sites": ["0x2aae7c"],
        "operation": "returns the suspended status without consuming input because single-pass decoding keeps input and output in lockstep",
        "evidence": [
            "The target coefficient-controller initializer stores this eight-byte routine in the consume_data slot for the single-MCU path.",
            "The source and target bodies both return zero and have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29c6c4",
        "target_ea": "0x2a9b34",
        "role": "consume_data",
        "target_context": "installed as the full-image coefficient-buffer input callback",
        "target_install_sites": ["0x2aae04", "0x2aae0c"],
        "operation": "consumes one interleaved MCU row, builds pointers into the virtual coefficient arrays, decodes entropy data, and advances input state",
        "evidence": [
            "The target coefficient-controller initializer stores this routine in the consume_data slot when a full coefficient buffer is requested.",
            "The target body allocates per-component virtual-array row pointers, calls the entropy MCU decoder, handles suspension, advances MCU counters, and finishes the input pass at the final row.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29c9c8",
        "target_ea": "0x2a9e38",
        "role": "start_output_pass",
        "target_context": "installed as the coefficient-controller output-pass setup callback",
        "target_install_sites": ["0x2aad60"],
        "operation": "selects the normal or block-smoothing output callback for a buffered image pass and resets output state",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target coefficient-controller initializer stores this routine in the public start_output_pass slot.",
            "The target body checks the full-image coefficient buffer and smoothing prerequisites, selects either the smoothing or normal decompression callback, and resets the output scan row.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x29cb80",
        "target_ea": "0x2a9ff0",
        "role": "decompress_smooth_data",
        "target_context": "selected by start_output_pass when block smoothing is applicable",
        "target_install_sites": ["0x2a9fa8"],
        "operation": "reads buffered coefficient rows, estimates missing low-frequency values from neighboring blocks, applies inverse DCT, and emits a smoothed MCU row",
        "evidence": [
            "The target start_output_pass routine selects this callback after its smoothing checks succeed.",
            "The target body retains the large 5x5 neighboring-DC interpolation path, workspace copy, quantizer checks, inverse-DCT dispatch, and output-row progression of the source routine.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29d2f8",
        "target_ea": "0x2aa768",
        "role": "decompress_data",
        "target_context": "selected for normal output from a full-image coefficient buffer",
        "target_install_sites": ["0x2a9e5c", "0x2aae14"],
        "operation": "keeps input ahead of output, reads virtual coefficient rows, applies inverse DCT to each requested block, and advances the output MCU row",
        "evidence": [
            "The target start_output_pass routine uses this callback as the normal full-buffer output path.",
            "The target coefficient-controller initializer also installs it directly in the full-buffer branch.",
            "The target body drives input consumption until output is ready, accesses each component's virtual coefficient array, invokes the component inverse-DCT method, and returns row or scan completion status.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29d510",
        "target_ea": "0x2aa980",
        "role": "coef_start_input_pass",
        "source_name": "start_input_pass",
        "target_context": "installed as the coefficient-controller input-pass setup callback",
        "target_install_sites": ["0x2aad54"],
        "operation": "resets the input MCU row and coefficient-buffer cursors and initializes the first component row span",
        "evidence": [
            "The target coefficient-controller initializer stores this routine in the public start_input_pass slot.",
            "The target body resets the input row and chooses the final or ordinary row span for single-component scans, while using a one-row span for interleaved scans.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29d570",
        "target_ea": "0x2aa9e0",
        "role": "decompress_onepass",
        "target_context": "selected for output when no full coefficient buffer is needed",
        "target_install_sites": ["0x2aae88", "0x2aae94"],
        "operation": "decodes one MCU row at a time, invokes inverse DCT for each useful block, handles suspension, and advances the input and output rows",
        "evidence": [
            "The target coefficient-controller initializer stores this routine in the single-MCU output callback slot when full buffering is disabled.",
            "The target body clears the MCU buffer, invokes entropy decoding, skips unneeded components, dispatches inverse DCT for useful blocks, and reports suspension, row completion, or scan completion.",
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
                "match_kind": "manual-libjpeg-jdcoefct-role-anchor",
                "family": "libjpeg coefficient controller",
                "source_name": spec.get("source_name", spec["role"]),
                "source_role": spec.get("source_name", spec["role"]),
                "source_file": "jdcoefct.c",
                "source_component": "jinit_d_coef_controller_jpeg_decompress_struct_int at 0x29d8a8",
                "target_component": "v18_jinit_d_coef_controller_jpeg_decompress_struct_int at 0x2aad18",
                "source_basis": "libjpeg %s body and jinit_d_coef_controller callback installation"
                % spec.get("source_name", spec["role"]),
                "source_parent": "jinit_d_coef_controller_jpeg_decompress_struct_int at 0x29d8a8",
                "target_parent": "v18_jinit_d_coef_controller_jpeg_decompress_struct_int at 0x2aad18",
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
        "artifact": "spectron_jpeg_coefficient_controller_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdcoefct coefficient-controller routines",
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
            "source_controller": "jinit_d_coef_controller_jpeg_decompress_struct_int at 0x29d8a8",
            "target_controller": "v18_jinit_d_coef_controller_jpeg_decompress_struct_int at 0x2aad18",
            "source_source_file": "jdcoefct.c",
            "target_source_file": "jdcoefct.c",
            "role_resolution": "standard libjpeg jdcoefct callback contract, target initializer slots, reviewed pseudocode, and complete or register-detail-only ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because source and target candidates retained IDA auto-generated names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdcoefct.c",
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
            "coefficient_controller_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because the source and target candidates retained IDA auto-generated names.",
            "The target coefficient-controller initializer preserves the source callback contract for both full-buffer and single-MCU decoding paths.",
            "All seven rows match the normalized ARM64 feature fields. Six also match register allocation detail; start_output_pass differs only in register allocation detail because its smoothing decision is compiled into the retained function boundary.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
