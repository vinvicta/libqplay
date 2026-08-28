#!/usr/bin/env python3
"""Create the reviewed Spectron inverse-DCT manager anchor."""

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
    source_ea = "0x29e40c"
    target_ea = "0x2ab87c"
    original = original_rows[source_ea]
    spectron = spectron_rows[target_ea]
    original_metrics = metrics(original)
    spectron_metrics = metrics(spectron)
    differences = [
        field
        for field in METRIC_FIELDS
        if original_metrics[field] != spectron_metrics[field]
    ]
    if differences != ["register_detail_hash"]:
        raise ValueError("unexpected metric differences: %s" % differences)
    normalized_equal = all(
        original_metrics[field] == spectron_metrics[field]
        for field in NORMALIZED_FIELDS
    )
    if not normalized_equal:
        raise ValueError("normalized metrics do not match")

    anchor = {
        "original_ea": source_ea,
        "original_name": original["name"],
        "original_current_name": original["name"],
        "original_default_name": bool(original.get("is_default_name")),
        "original_metrics": original_metrics,
        "original_function_end": original.get("end_ea"),
        "original_string_refs": original.get("string_refs", []),
        "original_direct_call_names": original.get("direct_call_names", []),
        "spectron_ea": target_ea,
        "spectron_current_name": spectron["name"],
        "spectron_default_name": bool(spectron.get("is_default_name")),
        "spectron_metrics": spectron_metrics,
        "spectron_function_end": spectron.get("end_ea"),
        "spectron_string_refs": spectron.get("string_refs", []),
        "spectron_direct_call_names": spectron.get("direct_call_names", []),
        "proposed_name": "v18_jpeg_idct_start_pass",
        "confidence": "high",
        "match_kind": "manual-libjpeg-jddctmgr-role-anchor",
        "family": "libjpeg inverse-DCT manager",
        "source_name": "start_pass",
        "source_role": "start_pass",
        "source_file": "jddctmgr.c",
        "source_component": "jinit_inverse_dct_jpeg_decompress_struct at 0x29e7b0",
        "target_component": "v18_jinit_inverse_dct_jpeg_decompress_struct at 0x2abc20",
        "source_basis": "libjpeg start_pass body and jinit_inverse_dct callback installation",
        "source_parent": "jinit_inverse_dct_jpeg_decompress_struct at 0x29e7b0",
        "target_parent": "v18_jinit_inverse_dct_jpeg_decompress_struct at 0x2abc20",
        "target_context": "installed as the inverse-DCT manager start-pass callback",
        "target_install_sites": ["0x2abc5c"],
        "operation": "selects the scaled inverse-DCT implementation for each component and rebuilds method-specific multiplier tables from the quantization tables",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The target inverse-DCT initializer stores this routine in the public start_pass slot.",
            "The target body selects the 1x1, 2x2, 4x4, accurate integer, fast integer, or floating-point inverse-DCT method from component scale and global DCT method state.",
            "The target body rebuilds integer, floating-point, or fast multiplier tables when the selected method changes, matching the source manager contract.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_inverse_dct_manager_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the libjpeg inverse-DCT manager start-pass routine",
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
            "source_controller": "jinit_inverse_dct_jpeg_decompress_struct at 0x29e7b0",
            "target_controller": "v18_jinit_inverse_dct_jpeg_decompress_struct at 0x2abc20",
            "source_source_file": "jddctmgr.c",
            "target_source_file": "jddctmgr.c",
            "role_resolution": "inverse-DCT manager callback slot, reviewed pseudocode, and normalized plus register-detail-only ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because source and target candidates retained IDA auto-generated names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jddctmgr.c",
        },
        "summary": {
            "anchor_count": 1,
            "unique_target_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": 1,
            "source_default_name_count": 1,
            "normalized_shape_exact_count": 1,
            "full_metric_exact_count": 0,
            "register_detail_difference_count": 1,
            "inverse_dct_manager_role_count": 1,
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed libjpeg role label, not a restored original debug symbol, because the source and target start-pass routines retained IDA auto-generated names.",
            "The target initializer and body preserve the source inverse-DCT manager contract, including per-component method selection and multiplier-table setup.",
            "The normalized feature fields match exactly; the only difference is register allocation detail in this compiler build.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
