#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron forward-DCT manager."""

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
        "source_ea": "0x2a31f0",
        "target_ea": "0x2b0660",
        "source_name": "start_pass_fdctmgr",
        "role": "start_pass_fdctmgr",
        "target_context": "installed as the forward-DCT manager start-pass callback",
        "target_install_sites": ["0x2b10a0"],
        "operation": "walks the JPEG components and rebuilds the integer or floating-point quantization multiplier tables used by the selected forward-DCT path",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target forward-DCT initializer stores this routine in its public start-pass field at 0x2b10a0.",
            "The target body iterates over component quantization tables, selects the data-precision-specific multiplier setup, and reports the same unsupported precision error as the source path.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x2a3638",
        "target_ea": "0x2b0aa8",
        "source_name": "forward_DCT",
        "role": "forward_DCT",
        "target_context": "selected for the integer forward-DCT methods",
        "target_install_sites": ["0x2b1128", "0x2b1144"],
        "operation": "loads an 8 by 8 sample block, calls the selected integer forward-DCT method, quantizes the 64 coefficients, and writes them to the destination coefficient block",
        "evidence": [
            "The target initializer selects this routine for both the accurate and fast integer forward-DCT methods at 0x2b1128 and 0x2b1144.",
            "The target body centers unsigned input samples, invokes the manager's integer DCT method, applies the integer quantization divisors, and stores signed 16-bit JPEG coefficients.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a37a0",
        "target_ea": "0x2b0c10",
        "source_name": "forward_DCT_float",
        "role": "forward_DCT_float",
        "target_context": "selected for the floating-point forward-DCT method",
        "target_install_sites": ["0x2b110c"],
        "operation": "loads an 8 by 8 sample block, calls the floating-point forward-DCT method, applies floating quantization multipliers, and packs the resulting coefficients",
        "evidence": [
            "The target initializer selects this routine for the floating-point forward-DCT method at 0x2b110c.",
            "The target body converts centered samples to floats, invokes the manager's float DCT method, multiplies by the precomputed quantization values, rounds to integer coefficients, and writes the block in JPEG natural order.",
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
                "match_kind": "manual-libjpeg-jcdctmgr-role-anchor",
                "family": "libjpeg forward-DCT manager",
                "source_name": spec["source_name"],
                "source_role": spec["role"],
                "source_file": "jcdctmgr.c",
                "source_component": "jinit_forward_dct_jpeg_compress_struct at 0x2a3c00",
                "target_component": "v18_jinit_forward_dct_jpeg_compress_struct at 0x2b1070",
                "source_basis": "libjpeg %s body and jinit_forward_dct callback installation"
                % spec["source_name"],
                "source_parent": "jinit_forward_dct_jpeg_compress_struct at 0x2a3c00",
                "target_parent": "v18_jinit_forward_dct_jpeg_compress_struct at 0x2b1070",
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
        "artifact": "spectron_jpeg_forward_dct_manager_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jcdctmgr forward-DCT manager routines",
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
            "source_controller": "jinit_forward_dct_jpeg_compress_struct at 0x2a3c00",
            "target_controller": "v18_jinit_forward_dct_jpeg_compress_struct at 0x2b1070",
            "source_source_file": "jcdctmgr.c",
            "target_source_file": "jcdctmgr.c",
            "role_resolution": "standard libjpeg jcdctmgr callback contract, target forward-DCT initializer branches, reviewed source and target pseudocode, and ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because both source and target candidates retained IDA auto-generated names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jcdctmgr.c",
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
            "forward_dct_manager_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target forward-DCT initializer preserves the source split between one shared start-pass routine, one integer quantization routine, and one floating-point quantization routine.",
            "All three rows match normalized ARM64 feature shape; two also match the complete recorded feature set, while start_pass_fdctmgr differs only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
