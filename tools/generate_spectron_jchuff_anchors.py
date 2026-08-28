#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron compressor Huffman encoder."""

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
        "source_ea": "0x2a3cf0",
        "target_ea": "0x2b1160",
        "source_name": "encode_mcu_gather",
        "role": "encode_mcu_gather",
        "target_context": "selected for the gather-statistics Huffman pass",
        "target_install_sites": ["0x2b2364", "0x2b236c"],
        "operation": "walks the MCU coefficient blocks and accumulates DC and AC Huffman symbol frequencies without emitting compressed bytes",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target start-pass dispatcher selects this routine in the gather-statistics branch at 0x2b2364 and 0x2b236c.",
            "The target body computes DC difference categories, traverses coefficients in JPEG natural order, counts zero runs and AC magnitude categories, and updates the per-table statistics arrays.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x2a3f30",
        "target_ea": "0x2b13a0",
        "source_name": "finish_pass_huff",
        "role": "finish_pass_huff",
        "target_context": "selected for the normal entropy-coded output pass",
        "target_install_sites": ["0x2b2510", "0x2b2518"],
        "operation": "flushes the saved Huffman bit buffer, emits byte-stuffing as needed, and preserves the destination suspension state at the end of a compressed scan",
        "evidence": [
            "The target start-pass dispatcher stores this routine as the normal finish-pass callback at 0x2b2510 and 0x2b2518.",
            "The target body drains the saved bit accumulator into the destination manager, handles 0xff byte stuffing, refills the output buffer on demand, and writes the updated entropy state.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a40b0",
        "target_ea": "0x2b1520",
        "source_name": "encode_mcu_huff",
        "role": "encode_mcu_huff",
        "target_context": "selected for the normal entropy-coded MCU path",
        "target_install_sites": ["0x2b2514", "0x2b251c"],
        "operation": "encodes each MCU's DC and AC coefficients with the derived Huffman tables, manages restart markers, handles byte stuffing, and saves state when output suspends",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target start-pass dispatcher selects this routine as the normal encode-mcu callback at 0x2b2514 and 0x2b251c.",
            "The target body emits restart markers, encodes DC differences and AC run-length symbols in natural order, writes stuffed bytes, and restores the saved bit state after a suspended destination write.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x2a4ec8",
        "target_ea": "0x2b2338",
        "source_name": "start_pass_huff",
        "role": "start_pass_huff",
        "target_context": "installed as the compressor Huffman encoder start-pass callback",
        "target_install_sites": ["0x2b2a58", "0x2b2a60"],
        "operation": "selects gather-statistics or normal Huffman callbacks, prepares derived or statistics tables for each component, resets DC predictions, and initializes bit and restart state",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target Huffman encoder initializer stores this routine in its public start-pass field at 0x2b2a58 and 0x2b2a60.",
            "The target body selects encode_mcu_gather with finish_pass_gather for the gather-statistics pass and encode_mcu_huff with finish_pass_huff for normal output, then initializes the per-component tables and restart state.",
            "The source and target normalized feature metrics match; only register allocation detail differs. The changed direct-call names are the expected target export names for shared helpers.",
        ],
    },
    {
        "source_ea": "0x2a54a4",
        "target_ea": "0x2b2914",
        "source_name": "finish_pass_gather",
        "role": "finish_pass_gather",
        "target_context": "selected for the end of the gather-statistics pass",
        "target_install_sites": ["0x2b2360", "0x2b2368"],
        "operation": "generates optimized DC and AC Huffman tables from the accumulated symbol counts and installs them for subsequent output passes",
        "evidence": [
            "The target start-pass dispatcher stores this routine as the gather-statistics finish callback at 0x2b2360 and 0x2b2368.",
            "The target body allocates missing Huffman tables, invokes the retained optimal-table generator once per used DC or AC table, and avoids regenerating duplicate tables.",
            "The source and target functions have identical complete ARM64 feature metrics; their direct-call names differ only because the target keeps a C++ export for the shared optimal-table helper.",
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
                "match_kind": "manual-libjpeg-jchuff-role-anchor",
                "family": "libjpeg compressor Huffman encoder",
                "source_name": spec["source_name"],
                "source_role": spec["role"],
                "source_file": "jchuff.c",
                "source_component": "jinit_huff_encoder_jpeg_compress_struct at 0x2a55bc",
                "target_component": "v18_jinit_huff_encoder_jpeg_compress_struct at 0x2b2a2c",
                "source_basis": "libjpeg %s body and jchuff start_pass callback installation"
                % spec["source_name"],
                "source_parent": "jinit_huff_encoder_jpeg_compress_struct at 0x2a55bc",
                "target_parent": "v18_jinit_huff_encoder_jpeg_compress_struct at 0x2b2a2c",
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
        "artifact": "spectron_jpeg_huffman_encoder_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jchuff compressor Huffman encoder routines",
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
            "source_encoder": "jinit_huff_encoder_jpeg_compress_struct at 0x2a55bc",
            "target_encoder": "v18_jinit_huff_encoder_jpeg_compress_struct at 0x2b2a2c",
            "source_source_file": "jchuff.c",
            "target_source_file": "jchuff.c",
            "role_resolution": "standard libjpeg jchuff callback contract, target start-pass dispatcher, reviewed source and target pseudocode, and ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because both source and target candidates retained IDA auto-generated names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jchuff.c",
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
            "huffman_encoder_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target Huffman start-pass dispatcher preserves the source split between gather-statistics and normal output passes, including their separate encode and finish callbacks.",
            "All five rows match normalized ARM64 feature shape; two also match the complete recorded feature set, while the other three differ only in register allocation detail or expected shared-helper export naming.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
