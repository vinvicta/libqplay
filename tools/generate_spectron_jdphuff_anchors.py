#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron progressive-Huffman decoder."""

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
        "source_ea": "0x290538",
        "target_ea": "0x29d9a8",
        "role": "start_pass_phuff_decoder",
        "family": "libjpeg progressive Huffman decoder",
        "source_file": "jdphuff.c",
        "parent_source": "jinit_phuff_decoder_jpeg_decompress_struct at 0x2915dc",
        "parent_target": "v18_jinit_phuff_decoder_jpeg_decompress_struct at 0x29ea4c",
        "target_context": "installed as the progressive-Huffman entropy start_pass callback",
        "target_install_sites": ["0x29ea84"],
        "operation": "validates progressive scan parameters, updates coefficient progression state, selects the DC/AC first or refinement MCU decoder, builds derived Huffman tables, and resets bit and restart state",
        "evidence": [
            "The target phuff initializer stores this function in the entropy object's start_pass field.",
            "The target body checks Ss, Se, Ah, and Al, updates coef_bits, selects one of four decoder bodies based on DC versus AC and first versus refinement scans, prepares derived tables, and resets EOB, bit-buffer, insufficient-data, and restart state.",
            "The source and target functions differ only in register allocation detail and have identical normalized ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x29095c",
        "target_ea": "0x29ddcc",
        "role": "decode_mcu_AC_refine",
        "family": "libjpeg progressive Huffman decoder",
        "source_file": "jdphuff.c",
        "parent_source": "jinit_phuff_decoder_jpeg_decompress_struct at 0x2915dc",
        "parent_target": "v18_jinit_phuff_decoder_jpeg_decompress_struct at 0x29ea4c",
        "target_context": "selected by start_pass_phuff_decoder for an AC successive-approximation scan",
        "target_install_sites": ["0x29dcdc"],
        "operation": "decodes AC refinement symbols, appends correction bits to existing coefficients, records new nonzero coefficients for rollback on suspension, and maintains EOBRUN",
        "evidence": [
            "The target start-pass dispatcher selects this body when the scan is AC and Ah is nonzero.",
            "The target body handles EOBRUN, ZRL, new coefficient signs, correction bits for existing coefficients, natural-order placement, restart intervals, and undo of newly nonzero coefficients when input suspends.",
            "The source and target functions differ only in register allocation detail and have identical normalized ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x290e3c",
        "target_ea": "0x29e2ac",
        "role": "decode_mcu_AC_first",
        "family": "libjpeg progressive Huffman decoder",
        "source_file": "jdphuff.c",
        "parent_source": "jinit_phuff_decoder_jpeg_decompress_struct at 0x2915dc",
        "parent_target": "v18_jinit_phuff_decoder_jpeg_decompress_struct at 0x29ea4c",
        "target_context": "selected by start_pass_phuff_decoder for an AC first scan",
        "target_install_sites": ["0x29dbe4"],
        "operation": "decodes an AC first-scan band, handles zero runs and EOBRUN, dezigzags and scales nonzero coefficients, and preserves the bit and restart state",
        "evidence": [
            "The target start-pass dispatcher selects this body when the scan is AC and Ah is zero.",
            "The target body decodes the active AC table, processes run-length and size nibbles, writes coefficients through the natural-order table, handles ZRL and EOBr, and updates the saved EOBRUN and restart counter.",
            "The source and target functions differ only in register allocation detail and have identical normalized ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x291154",
        "target_ea": "0x29e5c4",
        "role": "decode_mcu_DC_refine",
        "family": "libjpeg progressive Huffman decoder",
        "source_file": "jdphuff.c",
        "parent_source": "jinit_phuff_decoder_jpeg_decompress_struct at 0x2915dc",
        "parent_target": "v18_jinit_phuff_decoder_jpeg_decompress_struct at 0x29ea4c",
        "target_context": "selected by start_pass_phuff_decoder for a DC successive-approximation scan",
        "target_install_sites": ["0x29dbd4"],
        "operation": "reads one refinement bit for each block's DC coefficient, applies the current Al bit mask, and updates the restart and bitread state",
        "evidence": [
            "The target start-pass dispatcher selects this body when the scan is DC and Ah is nonzero.",
            "The target body reads one bit per MCU block and ORs the current refinement bit into the DC coefficient, then saves the bit state and advances the restart counter.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2912f8",
        "target_ea": "0x29e768",
        "role": "decode_mcu_DC_first",
        "family": "libjpeg progressive Huffman decoder",
        "source_file": "jdphuff.c",
        "parent_source": "jinit_phuff_decoder_jpeg_decompress_struct at 0x2915dc",
        "parent_target": "v18_jinit_phuff_decoder_jpeg_decompress_struct at 0x29ea4c",
        "target_context": "selected by start_pass_phuff_decoder for a DC first scan",
        "target_install_sites": ["0x29dac0"],
        "operation": "decodes DC Huffman differences for each block, extends the signed value, updates the component predictor, scales the result by Al, and maintains restart state",
        "evidence": [
            "The target start-pass dispatcher selects this body when the scan is DC and Ah is zero.",
            "The target body reads the component DC table, decodes and sign-extends the difference, updates the saved last_dc_val predictor, writes the scaled DC coefficient, and handles restart intervals and input suspension.",
            "The source and target functions differ only in register allocation detail and have identical normalized ARM64 feature metrics.",
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
            "match_kind": "manual-libjpeg-jdphuff-role-anchor",
            "family": spec["family"],
            "source_name": spec["role"],
            "source_role": spec["role"],
            "source_file": spec["source_file"],
            "source_component": spec["parent_source"],
            "target_component": spec["parent_target"],
            "source_basis": "libjpeg %s body and progressive-Huffman dispatch context"
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
        "artifact": "spectron_jpeg_progressive_huffman_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdphuff progressive decoder routines",
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
            "source_decoder": "jinit_phuff_decoder_jpeg_decompress_struct at 0x2915dc",
            "target_decoder": "v18_jinit_phuff_decoder_jpeg_decompress_struct at 0x29ea4c",
            "source_source_file": "jdphuff.c",
            "target_source_file": "jdphuff.c",
            "role_resolution": "standard libjpeg jdphuff scan-mode contract, target start-pass dispatch assignments, reviewed source and target pseudocode, and normalized ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because the source and target functions both retained default names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdphuff.c",
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
            "progressive_huffman_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The target phuff initializer installs start_pass_phuff_decoder, and that dispatcher selects the four MCU decoders from the scan's DC or AC band and first or refinement mode.",
            "The source and target bodies have identical normalized metrics; one row is a complete metric match and four differ only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
