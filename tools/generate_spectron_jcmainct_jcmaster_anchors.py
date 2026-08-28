#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron JPEG main and master controllers."""

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
        "source_ea": "0x2a563c",
        "target_ea": "0x2b2aac",
        "source_name": "process_data_simple_main",
        "role": "process_data_simple_main",
        "proposed_name": "v18_jpeg_c_process_data_simple_main",
        "source_file": "jcmainct.c",
        "source_parent": "jinit_c_main_controller_jpeg_compress_struct_int at 0x2a57bc",
        "target_parent": "v18_jinit_c_main_controller_jpeg_compress_struct_int at 0x2b2c2c",
        "target_context": "installed by the main-controller start-pass callback",
        "target_install_sites": ["0x2b2bf4"],
        "operation": "preprocesses input rows into the strip buffer, submits completed iMCU rows to the coefficient controller, and preserves input and suspension counters when compression pauses",
        "evidence": [
            "The target body takes the cinfo, input buffer, input-row counter, and available-row count used by the standard jcmainct process_data callback.",
            "The target body invokes the preprocessing callback, waits for a complete iMCU row, submits the strip buffer to the coefficient controller, and rolls back the input-row counter when the destination suspends.",
            "The target start-pass routine installs this body at 0x2b2bf4, matching the source callback relationship.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a575c",
        "target_ea": "0x2b2bcc",
        "source_name": "start_pass_main",
        "role": "start_pass_main",
        "proposed_name": "v18_jpeg_c_start_pass_main",
        "source_file": "jcmainct.c",
        "source_parent": "jinit_c_main_controller_jpeg_compress_struct_int at 0x2a57bc",
        "target_parent": "v18_jinit_c_main_controller_jpeg_compress_struct_int at 0x2b2c2c",
        "target_context": "installed as the compressor main-controller start-pass callback",
        "target_install_sites": ["0x2b2c60"],
        "expected_differences": ["register_detail_hash"],
        "operation": "resets the main-controller row state, validates pass-through buffer mode, saves the pass mode, and selects the simple row-processing callback",
        "evidence": [
            "The target main-controller initializer stores this routine in its public start-pass field at 0x2b2c60.",
            "The target body clears the iMCU row, row-group, and suspension state, rejects a non-pass-through mode with the same error path as the source, and stores process_data_simple_main in the controller callback field.",
            "The target body installs process_data_simple_main at 0x2b2bf4, tying the two jcmainct callbacks together.",
            "The source and target normalized ARM64 feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x2a5898",
        "target_ea": "0x2b2d08",
        "source_name": "initial_setup",
        "role": "initial_setup",
        "source_file": "jcmaster.c",
        "source_parent": "jinit_c_master_control_jpeg_compress_struct_int at 0x2a7058",
        "target_parent": "v18_jinit_c_master_control_jpeg_compress_struct_int at 0x2b44c8",
        "target_context": "called during compressor master-control initialization",
        "target_install_sites": ["0x2b4734"],
        "operation": "validates the JPEG component and scan configuration, computes derived image dimensions and sampling values, and rejects invalid quantization or progressive-scan state",
        "evidence": [
            "The target master-control initializer calls this body at 0x2b4734 after setting the derived image dimensions.",
            "The target body validates sampling factors, scan component references, quantization table indexes, and progressive scan parameters while producing the same libjpeg error-code paths as the source.",
            "The upstream jcmaster contract identifies initial_setup as the pre-master-selection validation and derived-value phase.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a6234",
        "target_ea": "0x2b36a4",
        "source_name": "pass_startup",
        "role": "pass_startup",
        "source_file": "jcmaster.c",
        "source_parent": "jinit_c_master_control_jpeg_compress_struct_int at 0x2a7058",
        "target_parent": "v18_jinit_c_master_control_jpeg_compress_struct_int at 0x2b44c8",
        "target_context": "installed as the compressor master-control pass-startup callback",
        "target_install_sites": ["0x2b4510"],
        "operation": "clears the destination suspension counter, emits the frame and scan headers through the marker controller, and returns to the active entropy pass",
        "evidence": [
            "The target master-control initializer stores this routine in the second public callback slot at 0x2b4510.",
            "The target body clears the destination manager suspension state, invokes the marker frame-header callback, and then invokes the marker scan-header callback.",
            "The upstream jcmaster contract defines pass_startup as the deferred header-emission hook used before the first scanline pass.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a6270",
        "target_ea": "0x2b36e0",
        "source_name": "finish_pass_master",
        "role": "finish_pass_master",
        "source_file": "jcmaster.c",
        "source_parent": "jinit_c_master_control_jpeg_compress_struct_int at 0x2a7058",
        "target_parent": "v18_jinit_c_master_control_jpeg_compress_struct_int at 0x2b44c8",
        "target_context": "installed as the compressor master-control finish-pass callback",
        "target_install_sites": ["0x2b451c", "0x2b4524"],
        "operation": "finishes the entropy pass and advances the master controller through main, Huffman-optimization, and output pass states",
        "evidence": [
            "The target master-control initializer stores this routine in the finish-pass callback slot at 0x2b451c and 0x2b4524.",
            "The target body invokes the entropy finish-pass callback, changes the pass type and scan number according to the active pass, and increments the pass counter.",
            "The upstream jcmaster contract defines finish_pass_master as the state transition hook after each compression pass.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a6324",
        "target_ea": "0x2b3794",
        "source_name": "prepare_for_pass",
        "role": "prepare_for_pass",
        "source_file": "jcmaster.c",
        "source_parent": "jinit_c_master_control_jpeg_compress_struct_int at 0x2a7058",
        "target_parent": "v18_jinit_c_master_control_jpeg_compress_struct_int at 0x2b44c8",
        "target_context": "installed as the compressor master-control prepare-for-pass callback",
        "target_install_sites": ["0x2b4500"],
        "operation": "selects scan parameters, starts the active color, sampling, DCT, entropy, coefficient, and main-controller passes, and updates the pass-startup and last-pass flags",
        "evidence": [
            "The target master-control initializer stores this routine in the first public callback slot at 0x2b4500.",
            "The target body selects the main, Huffman-optimization, or output pass, invokes the matching module start-pass callbacks, and updates call_pass_startup and is_last_pass.",
            "The upstream jcmaster contract defines prepare_for_pass as the per-pass module-selection and setup routine.",
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
                "proposed_name": spec.get("proposed_name", "v18_jpeg_" + spec["role"]),
                "confidence": "high",
                "match_kind": "manual-libjpeg-jcmainct-jcmaster-role-anchor",
                "family": "libjpeg compressor main and master controllers",
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
        "artifact": "spectron_jpeg_main_master_controller_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jcmainct and jcmaster compressor controller routines",
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
            "source_main_controller": "jinit_c_main_controller_jpeg_compress_struct_int at 0x2a57bc",
            "target_main_controller": "v18_jinit_c_main_controller_jpeg_compress_struct_int at 0x2b2c2c",
            "source_master_controller": "jinit_c_master_control_jpeg_compress_struct_int at 0x2a7058",
            "target_master_controller": "v18_jinit_c_master_control_jpeg_compress_struct_int at 0x2b44c8",
            "source_source_files": ["jcmainct.c", "jcmaster.c"],
            "target_source_files": ["jcmainct.c", "jcmaster.c"],
            "role_resolution": "standard libjpeg jcmainct and jcmaster callback contracts, target callback installation sites, reviewed source and target pseudocode, and exact ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because all six source and target candidates retained IDA auto-generated names",
            "name_disambiguation": "The compressor jcmainct callbacks use v18_jpeg_c_ names because the decompressor jdmainct family already occupies the unqualified v18_jpeg_process_data_simple_main and v18_jpeg_start_pass_main names.",
            "reference_sources": [
                "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jcmainct.c",
                "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jcmaster.c",
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
            "main_controller_role_count": 2,
            "master_controller_role_count": 4,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target jcmainct callbacks preserve the source relationship between start_pass_main and process_data_simple_main.",
            "The target jcmaster initializer preserves the source callback table for prepare_for_pass, pass_startup, and finish_pass_master, and calls initial_setup during initialization.",
            "All six rows match normalized ARM64 shape. The start_pass_main callback differs only in register allocation detail, while the other five callbacks match the complete recorded feature set.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
