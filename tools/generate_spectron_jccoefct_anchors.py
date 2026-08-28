#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron compressor coefficient controller."""

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
        "source_ea": "0x2a1b50",
        "target_ea": "0x2aefc0",
        "source_name": "start_iMCU_row",
        "role": "start_iMCU_row",
        "target_context": "shared helper called after each completed iMCU row",
        "target_install_sites": ["0x2af270", "0x2af6a0", "0x2afd14"],
        "operation": "resets the MCU-row counters and chooses the number of vertical MCU rows for the current scan position",
        "evidence": [
            "The target helper is called by the three compressor data paths at their iMCU-row boundaries.",
            "The target body selects one row for an interleaved scan or the component sampling or last-row height for a noninterleaved scan, then resets mcu_ctr and MCU_vert_offset.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a1bb4",
        "target_ea": "0x2af024",
        "source_name": "compress_output",
        "role": "compress_output",
        "target_context": "selected for the JBUF_CRANK_DEST multi-pass output path",
        "target_install_sites": ["0x2af8c8"],
        "operation": "reads the requested iMCU rows from virtual coefficient arrays, constructs each MCU block list, and sends it to the entropy encoder",
        "evidence": [
            "The target start-pass dispatcher selects this routine for the crank-destination buffer mode.",
            "The target body accesses each component's virtual coefficient rows, builds MCU_buffer pointers in scan order, calls the entropy encode_mcu callback, and advances the row state while preserving suspension counters.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a1e40",
        "target_ea": "0x2af2b0",
        "source_name": "compress_data",
        "role": "compress_data",
        "target_context": "selected for the JBUF_PASS_THRU single-pass path",
        "target_install_sites": ["0x2af880"],
        "operation": "forms MCU blocks from input sample planes, runs the forward DCT callback, fills right and bottom dummy blocks, and sends each MCU to the entropy encoder",
        "evidence": [
            "The target start-pass dispatcher selects this routine for the direct pass-through buffer mode.",
            "The target body walks iMCU rows and MCUs, invokes the forward-DCT method for each component, creates edge dummy blocks with repeated DC values, and handles entropy suspension state.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a2394",
        "target_ea": "0x2af804",
        "source_name": "start_pass_coef",
        "role": "start_pass_coef",
        "target_context": "installed as the compressor coefficient-controller start-pass callback",
        "target_install_sites": ["0x2afe64"],
        "operation": "resets the coefficient-controller row state and selects the pass-through, first-pass save, or crank-destination data callback",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target coefficient-controller initializer stores this routine in its public start-pass field.",
            "The dispatcher selects compress_data for pass-through, compress_output for crank-destination, and compress_first_pass for the full-buffer save-and-pass mode, matching the standard jccoefct buffer contract.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x2a24cc",
        "target_ea": "0x2af93c",
        "source_name": "compress_first_pass",
        "role": "compress_first_pass",
        "target_context": "selected for the JBUF_SAVE_AND_PASS full-buffer first pass",
        "target_install_sites": ["0x2afd14"],
        "operation": "runs forward DCT over the input image, pads the virtual coefficient arrays with dummy blocks, and emits the current strip through the entropy encoder",
        "evidence": [
            "The target start-pass dispatcher selects this routine for the full-buffer save-and-pass mode.",
            "The target body accesses each component's virtual coefficient rows, DCTs real input blocks, fills right and bottom padding with suitable DC values, and emits the loaded strip while preserving the controller state.",
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
                "match_kind": "manual-libjpeg-jccoefct-role-anchor",
                "family": "libjpeg compressor coefficient controller",
                "source_name": spec["source_name"],
                "source_role": spec["role"],
                "source_file": "jccoefct.c",
                "source_component": "jinit_c_coef_controller_jpeg_compress_struct_int at 0x2a29bc",
                "target_component": "v18_jinit_c_coef_controller_jpeg_compress_struct_int at 0x2afe2c",
                "source_basis": "libjpeg %s body and jinit_c_coef_controller callback installation"
                % spec["source_name"],
                "source_parent": "jinit_c_coef_controller_jpeg_compress_struct_int at 0x2a29bc",
                "target_parent": "v18_jinit_c_coef_controller_jpeg_compress_struct_int at 0x2afe2c",
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
        "artifact": "spectron_jpeg_compressor_coefficient_controller_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jccoefct compressor coefficient controller routines",
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
            "source_controller": "jinit_c_coef_controller_jpeg_compress_struct_int at 0x2a29bc",
            "target_controller": "v18_jinit_c_coef_controller_jpeg_compress_struct_int at 0x2afe2c",
            "source_source_file": "jccoefct.c",
            "target_source_file": "jccoefct.c",
            "role_resolution": "standard libjpeg jccoefct callback contract, target start-pass dispatch, reviewed source and target pseudocode, and ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because both source and target candidates retained IDA auto-generated names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jccoefct.c",
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
            "compressor_coefficient_controller_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target coefficient-controller start-pass dispatcher preserves the source mapping between pass-through, full-buffer first-pass, and crank-destination modes.",
            "All five rows match normalized ARM64 feature shape; four also match the complete recorded feature set, while start_pass_coef differs only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
