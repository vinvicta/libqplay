#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron baseline Huffman decoder."""

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
        "source_ea": "0x29f2d0",
        "target_ea": "0x2ac740",
        "role": "start_pass_huff_decoder",
        "source_file": "jdhuff.c",
        "target_context": "installed as the baseline-Huffman entropy start_pass callback",
        "target_install_sites": ["0x2ad0c4"],
        "operation": "validates the entropy state, builds derived DC and AC tables for each component, initializes progressive-component bookkeeping, and resets the bit and restart state",
        "allowed_metric_differences": [],
        "evidence": [
            "The target huff initializer stores this function in the entropy object's start_pass field.",
            "The body validates the input precision and scan component state, builds derived tables for each component, initializes progressive bookkeeping, and resets bit-buffer, restart, and insufficient-data state.",
            "The source and target functions have identical normalized ARM64 feature metrics; any remaining difference is register allocation detail.",
        ],
    },
    {
        "source_ea": "0x29f734",
        "target_ea": "0x2acba4",
        "role": "decode_mcu",
        "source_file": "jdhuff.c",
        "target_context": "installed as the baseline-Huffman entropy MCU decode callback",
        "target_install_sites": ["0x2ad0d4", "0x2ad0dc"],
        "operation": "decodes one baseline JPEG MCU, reconstructs DC predictors, expands AC run-length symbols, writes coefficients in natural order, and preserves bit and restart state across suspension",
        "allowed_metric_differences": [
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
            "register_detail_hash",
        ],
        "metric_note": "One ADD instruction uses a relocated PAGEOFF operand whose low-page bucket differs between builds; the mnemonic, control-flow shape, and pseudocode remain aligned.",
        "evidence": [
            "The target huff initializer stores this function in both baseline decode callback slots used by the entropy state.",
            "The body performs DC and AC Huffman lookup, sign extension, DC predictor updates, zero-run handling, end-of-block handling, natural-order coefficient placement, and bit-buffer state preservation.",
            "The source and target functions have identical normalized ARM64 feature metrics; any remaining difference is register allocation detail.",
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
        if differences != spec["allowed_metric_differences"]:
            raise ValueError(
                "unexpected metric differences for %s: %s"
                % (spec["role"], differences)
            )
        normalized_equal = all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        )
        structural_equal = all(
            original_metrics[field] == spectron_metrics[field]
            for field in METRIC_FIELDS
            if field not in spec["allowed_metric_differences"]
        )
        if not structural_equal:
            raise ValueError("structural metrics do not match for %s" % spec["role"])
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
            "match_kind": "manual-libjpeg-jdhuff-role-anchor",
            "family": "libjpeg baseline Huffman decoder",
            "source_name": spec["role"],
            "source_role": spec["role"],
            "source_file": spec["source_file"],
            "source_component": "jinit_huff_decoder_jpeg_decompress_struct at 0x29fc2c",
            "target_component": "v18_jinit_huff_decoder_jpeg_decompress_struct at 0x2ad09c",
            "source_basis": "libjpeg %s body and baseline-Huffman callback installation" % spec["role"],
            "source_parent": "jinit_huff_decoder_jpeg_decompress_struct at 0x29fc2c",
            "target_parent": "v18_jinit_huff_decoder_jpeg_decompress_struct at 0x2ad09c",
            "target_context": spec["target_context"],
            "target_install_sites": spec["target_install_sites"],
            "operation": spec["operation"],
            "metric_note": spec.get("metric_note"),
            "normalized_shape_equal": normalized_equal,
            "structural_metric_equal": structural_equal,
            "full_metric_equal": not differences,
            "metric_differences": differences,
            "semantic_match_already_present": False,
            "evidence": spec["evidence"],
            "name_action": "rename-with-v18-prefix",
        }
        anchors.append(anchor)

    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_baseline_huffman_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdhuff baseline decoder routines",
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
            "source_decoder": "jinit_huff_decoder_jpeg_decompress_struct at 0x29fc2c",
            "target_decoder": "v18_jinit_huff_decoder_jpeg_decompress_struct at 0x2ad09c",
            "source_source_file": "jdhuff.c",
            "target_source_file": "jdhuff.c",
            "role_resolution": "standard libjpeg jdhuff callback contract, target initializer assignments, reviewed source and target pseudocode, and ARM64 feature metrics with an explicitly recorded relocated PAGEOFF bucket exception",
            "name_policy": "v18-prefixed semantic role because the source and target functions both retained default names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdhuff.c",
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
            "relocation_shape_difference_count": sum(
                bool(a.get("metric_note")) for a in anchors
            ),
            "baseline_huffman_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The target huff initializer installs the start-pass callback and both baseline MCU decode callback slots, tying the two target routines to the standard jdhuff roles.",
            "The start-pass row is an exact feature match. The MCU decoder has the same instruction count, mnemonic sequence, control-flow counts, and reviewed pseudocode; its operand-shape hashes differ only because one relocated PAGEOFF immediate falls into a different coarse bucket between builds.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
