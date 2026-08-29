#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron bzip2 helper block."""

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


SPECS = (
    {
        "source_ea": "0x273350",
        "target_ea": "0x2807c0",
        "source_name": "default_bzfree",
        "proposed_name": "v18_bzip2_default_bzfree",
        "role": "bzip2 default allocator cleanup callback",
        "source_file": "bzlib.c",
        "topology": "the compression and decompression initializers install this two-argument callback in the stream's bzfree slot; cleanup paths call it for state buffers",
        "source_data": "called from BZ2_bzCompressInit and BZ2_bzDecompressInit through the bzfree callback slot",
        "target_data": "the corresponding target initializers retain the same bzfree callback installation and cleanup topology",
        "operation": "frees a bzip2 allocation when the address is non-null",
        "reference": "https://github.com/libarchive/bzip2/blob/master/bzlib.c",
    },
    {
        "source_ea": "0x273360",
        "target_ea": "0x2807d0",
        "source_name": "default_bzalloc",
        "proposed_name": "v18_bzip2_default_bzalloc",
        "role": "bzip2 default allocation callback",
        "source_file": "bzlib.c",
        "topology": "the compression and decompression initializers install this three-argument callback in the stream's bzalloc slot; state objects and work buffers request memory through it",
        "source_data": "called from BZ2_bzCompressInit and BZ2_bzDecompressInit through the bzalloc callback slot",
        "target_data": "the corresponding target initializers retain the same bzalloc callback installation and allocation topology",
        "operation": "allocates a zero-untyped block sized as items multiplied by element size",
        "reference": "https://github.com/libarchive/bzip2/blob/master/bzlib.c",
    },
    {
        "source_ea": "0x27336c",
        "target_ea": "0x2807dc",
        "source_name": "handle_compress",
        "proposed_name": "v18_bzip2_handle_compress",
        "role": "bzip2 streaming compression state machine",
        "source_file": "bzlib.c",
        "topology": "BZ2_bzCompress calls this helper for run, flush, and finish actions; it alternates input and output states, flushes run-length data, and invokes BZ2_compressBlock",
        "source_data": "called three times by BZ2_bzCompress for running, flushing, and finishing modes",
        "target_data": "the corresponding target BZ2_bzCompress routine calls the relocated helper for the same three compression modes",
        "operation": "moves input through run-length encoding and block compression while copying compressed output to the caller",
        "reference": "https://github.com/libarchive/bzip2/blob/master/bzlib.c",
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


def build_anchor(original: dict, spectron: dict, spec: dict) -> dict:
    original_metrics = metrics(original)
    spectron_metrics = metrics(spectron)
    differences = [
        field
        for field in METRIC_FIELDS
        if original_metrics[field] != spectron_metrics[field]
    ]
    if not original.get("is_default_name"):
        raise ValueError("source candidate is not a default name: %s" % spec["source_name"])
    if not spectron.get("is_default_name"):
        raise ValueError("target candidate is not a default name: %s" % spec["source_name"])
    if differences not in ([], ["register_detail_hash"]):
        raise ValueError(
            "%s unexpectedly differs in %s" % (spec["source_name"], differences)
        )

    return {
        "original_ea": spec["source_ea"],
        "original_name": original["name"],
        "original_current_name": original["name"],
        "original_default_name": original.get("is_default_name", False),
        "original_metrics": original_metrics,
        "original_function_end": original.get("end_ea"),
        "original_string_refs": original.get("string_refs", []),
        "original_direct_call_names": original.get("direct_call_names", []),
        "spectron_ea": spec["target_ea"],
        "spectron_current_name": spectron["name"],
        "spectron_default_name": spectron.get("is_default_name", False),
        "spectron_metrics": spectron_metrics,
        "spectron_function_end": spectron.get("end_ea"),
        "spectron_string_refs": spectron.get("string_refs", []),
        "spectron_direct_call_names": spectron.get("direct_call_names", []),
        "proposed_name": spec["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-bzip2-anchor",
        "family": "bundled bzip2 helpers",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "bundled bzip2 library",
        "target_component": "stripped Spectron bundled bzip2 library",
        "source_basis": "matching pseudocode, bzip2 caller topology, official bzip2 source role, and exact or register-detail-only ARM64 feature metrics",
        "operation": spec["operation"],
        "reference_sources": [spec["reference"]],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in METRIC_FIELDS[:-1]
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The source pseudocode identifies the allocator callback or compression state machine.",
            "The target retains the same bzip2 caller topology at the relocated address.",
            "The official bzip2 source defines the matching helper contract and operation.",
            "The source and target recorded ARM64 metrics are exact or differ only in register-detail allocation.",
        ],
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original_by_ea = by_ea(load(args.original_features))
    spectron_by_ea = by_ea(load(args.spectron_features))
    anchors = [
        build_anchor(
            original_by_ea[spec["source_ea"]],
            spectron_by_ea[spec["target_ea"]],
            spec,
        )
        for spec in SPECS
    ]
    result = {
        "schema_version": 1,
        "artifact": "spectron_bzip2_helpers_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the bundled bzip2 allocator and streaming-compression helpers",
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
            "source_region": "0x273350 through 0x273c18",
            "target_region": "0x2807c0 through 0x281088",
            "address_displacement": "0xb470",
            "role_resolution": "matching pseudocode, bzip2 caller topology, official source roles, and exact or register-detail-only ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": sorted({spec["reference"] for spec in SPECS}),
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({anchor["spectron_ea"] for anchor in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(anchor["spectron_default_name"] for anchor in anchors),
            "source_default_name_count": sum(anchor["original_default_name"] for anchor in anchors),
            "normalized_shape_exact_count": sum(anchor["normalized_shape_equal"] for anchor in anchors),
            "full_metric_exact_count": sum(anchor["full_metric_equal"] for anchor in anchors),
            "register_detail_only_count": sum(
                anchor["metric_differences"] == ["register_detail_hash"]
                for anchor in anchors
            ),
            "allocator_callback_count": 2,
            "compression_state_machine_count": 1,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed bzip2 role labels, not restored original debug symbols, because the target static helpers retained only IDA auto-generated names.",
            "The two short callbacks are the default bzalloc and bzfree hooks installed by the public compression and decompression initializers.",
            "The large helper is handle_compress, which implements the streaming input, output, run-length, and block-compression state transitions used by BZ2_bzCompress.",
            "All three source and target pairs match normalized shape. Two match the complete recorded feature set, while handle_compress differs only in register-detail allocation.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
