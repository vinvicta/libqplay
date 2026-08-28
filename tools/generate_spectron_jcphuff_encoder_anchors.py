#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron progressive-Huffman encoder."""

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
        "source_ea": "0x2a73fc",
        "target_ea": "0x2b486c",
        "source_name": "start_pass_phuff",
        "role": "start_pass_phuff",
        "target_context": "installed as the progressive-Huffman compressor start-pass callback",
        "target_install_sites": ["0x2b78f0", "0x2b78f8"],
        "operation": "selects the DC or AC first/refinement MCU encoder, chooses the gather or normal finish callback, prepares Huffman tables, and resets progressive, bit, and restart state",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target initializer stores this routine in the entropy object's start-pass field at 0x2b78f0 and 0x2b78f8.",
            "The target dispatcher checks Ss and Ah to select the DC-first, AC-first, DC-refinement, or AC-refinement encoder, then selects finish_pass_gather_phuff or finish_pass_phuff from gather_statistics.",
            "The target body prepares derived or statistics Huffman tables and resets EOBRUN, correction-bit, bit-buffer, and restart state.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x2a75dc",
        "target_ea": "0x2b4a4c",
        "source_name": "emit_eobrun",
        "role": "emit_eobrun",
        "target_context": "shared progressive-Huffman output helper called by the encoder and finish routines",
        "target_install_sites": [
            "0x2b50f0",
            "0x2b5d5c",
            "0x2b6214",
            "0x2b669c",
            "0x2b6f50",
        ],
        "operation": "emits or counts a pending end-of-band run, drains buffered correction bits, and clears the progressive entropy counters",
        "expected_differences": [],
        "evidence": [
            "The target body reads the EOBRUN counter, computes its Huffman category, emits the category and payload when not gathering statistics, drains the correction-bit buffer, and clears EOBRUN and BE.",
            "The helper is called by the progressive MCU encoders and by the normal finish path before final bit flushing.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a7c80",
        "target_ea": "0x2b50f0",
        "source_name": "encode_mcu_AC_refine",
        "role": "encode_mcu_AC_refine",
        "target_context": "selected when the progressive scan is AC and Ah is nonzero",
        "target_install_sites": ["0x2b4994", "0x2b499c"],
        "operation": "encodes AC successive-approximation refinement data, handles newly nonzero coefficients and correction bits, maintains EOBRUN, and updates restart state",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target start-pass dispatcher stores this routine as the AC callback in the Ah-nonzero, Ss-nonzero branch at 0x2b4994 and 0x2b499c.",
            "The target body performs the refinement prepass, separates newly nonzero coefficients from correction bits, emits run-length symbols and signs, flushes pending EOBRUN data, and preserves destination state across output-buffer refills.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x2a88ec",
        "target_ea": "0x2b5d5c",
        "source_name": "finish_pass_phuff",
        "role": "finish_pass_phuff",
        "target_context": "selected for the normal progressive-Huffman output pass",
        "target_install_sites": ["0x2b4988"],
        "operation": "flushes pending progressive entropy data, emits final fill bits and the marker terminator, and writes back the destination manager state",
        "expected_differences": [],
        "evidence": [
            "The target start-pass dispatcher stores this routine as the normal finish callback at 0x2b4988 when gather_statistics is false.",
            "The target body calls emit_eobrun, fills the partial byte with ones, writes the final marker byte when output is active, resets the bit accumulator, and saves the destination pointers.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a8aa4",
        "target_ea": "0x2b5f14",
        "source_name": "finish_pass_gather_phuff",
        "role": "finish_pass_gather_phuff",
        "target_context": "selected for the progressive-Huffman gather-statistics pass",
        "target_install_sites": ["0x2b48c0"],
        "operation": "generates optimized DC and AC Huffman tables from accumulated progressive-scan statistics and installs missing table objects",
        "expected_differences": [],
        "evidence": [
            "The target start-pass dispatcher stores this routine as the gather-statistics finish callback at 0x2b48c0.",
            "The target body walks the DC and AC table selections used by the scan, allocates missing tables, and invokes the optimal-table generator once for each table that has not already been processed.",
            "The source and target functions have identical complete ARM64 feature metrics; only the target's C++ export names for shared helpers differ in the call list.",
        ],
    },
    {
        "source_ea": "0x2a8da4",
        "target_ea": "0x2b6214",
        "source_name": "encode_mcu_DC_refine",
        "role": "encode_mcu_DC_refine",
        "target_context": "selected when the progressive scan is DC and Ah is nonzero",
        "target_install_sites": ["0x2b4978"],
        "operation": "emits one successive-approximation bit for each DC coefficient in the MCU, then preserves bit-buffer and restart state",
        "expected_differences": [],
        "evidence": [
            "The target start-pass dispatcher stores this routine as the DC callback in the Ah-nonzero, Ss-zero branch at 0x2b4978.",
            "The target body reads the Al-th bit from each MCU block's DC coefficient, emits it, writes back the destination pointers, and advances the restart counter.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a922c",
        "target_ea": "0x2b669c",
        "source_name": "encode_mcu_DC_first",
        "role": "encode_mcu_DC_first",
        "target_context": "selected when the progressive scan is DC and Ah is zero",
        "target_install_sites": ["0x2b48b0"],
        "operation": "computes point-transformed DC differences, emits their Huffman categories and signed magnitude bits, and updates predictors and restart state",
        "expected_differences": [],
        "evidence": [
            "The target start-pass dispatcher stores this routine as the DC callback in the Ah-zero, Ss-zero branch at 0x2b48b0.",
            "The target body walks the MCU membership list, computes each component's DC difference from its last predictor, emits the derived Huffman symbol and magnitude, and saves the destination state.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2a9ae0",
        "target_ea": "0x2b6f50",
        "source_name": "encode_mcu_AC_first",
        "role": "encode_mcu_AC_first",
        "target_context": "selected when the progressive scan is AC and Ah is zero",
        "target_install_sites": ["0x2b49c4"],
        "operation": "applies the point transform to the AC spectral band, emits run-length and magnitude symbols, accumulates EOBRUN for trailing zero coefficients, and updates restart state",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The target start-pass dispatcher stores this routine as the AC callback in the Ah-zero, Ss-nonzero branch at 0x2b49c4.",
            "The target body traverses the JPEG natural-order AC band, counts zero runs, emits ZRL and run/size symbols, emits signed coefficient bits, and accumulates trailing EOBRUN values.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
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
                "match_kind": "manual-libjpeg-jcphuff-role-anchor",
                "family": "libjpeg progressive Huffman encoder",
                "source_name": spec["source_name"],
                "source_role": spec["role"],
                "source_file": "jcphuff.c",
                "source_file_note": "Older libjpeg trees may use jphuff.c for this compressor module; the current upstream reference uses jcphuff.c.",
                "source_component": "jinit_phuff_encoder_jpeg_compress_struct at 0x2aa454",
                "target_component": "v18_jinit_phuff_encoder_jpeg_compress_struct at 0x2b78c4",
                "source_basis": "libjpeg %s body and progressive-Huffman start_pass callback installation"
                % spec["source_name"],
                "source_parent": "jinit_phuff_encoder_jpeg_compress_struct at 0x2aa454",
                "target_parent": "v18_jinit_phuff_encoder_jpeg_compress_struct at 0x2b78c4",
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
        "artifact": "spectron_jpeg_progressive_huffman_encoder_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the libjpeg progressive-Huffman compressor encoder",
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
            "source_encoder": "jinit_phuff_encoder_jpeg_compress_struct at 0x2aa454",
            "target_encoder": "v18_jinit_phuff_encoder_jpeg_compress_struct at 0x2b78c4",
            "source_source_file": "jcphuff.c",
            "target_source_file": "jcphuff.c",
            "role_resolution": "standard libjpeg progressive-Huffman callback contract, target start-pass dispatch assignments, reviewed source and target pseudocode, and ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because both source and target candidates retained IDA auto-generated names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jcphuff.c",
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
            "progressive_huffman_encoder_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained IDA auto-generated names.",
            "The target progressive-Huffman start-pass dispatcher preserves the source split between DC and AC first/refinement encoders and between gather-statistics and normal output passes.",
            "All eight rows match normalized ARM64 feature shape. Five also match the complete recorded feature set, while three differ only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
