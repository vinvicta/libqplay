#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg marker writer block."""

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
        "source_ea": "0x2986c0",
        "target_ea": "0x2a5b30",
        "source_name": "write_marker_byte",
        "role": "write_marker_byte",
        "target_slot": "marker writer write_marker_byte field at +0x30",
        "operation": "writes one marker-parameter byte through the JPEG destination buffer",
        "evidence": [
            "The source marker-writer initializer stores this function in its write_marker_byte field at offset 0x30.",
            "The target v18_jinit_marker_writer initializer stores the target body in the corresponding field at offset 0x30.",
            "The body advances the destination pointer, decrements free space, and invokes empty_output_buffer when the buffer is full.",
        ],
    },
    {
        "source_ea": "0x29872c",
        "target_ea": "0x2a5b9c",
        "source_name": "write_file_trailer",
        "role": "write_file_trailer",
        "target_slot": "marker writer write_file_trailer field at +0x18",
        "operation": "emits the JPEG end-of-image marker",
        "evidence": [
            "The source marker-writer initializer stores this function in its write_file_trailer field at offset 0x18.",
            "The target v18_jinit_marker_writer initializer stores the target body in the corresponding field at offset 0x18.",
            "The body emits the two-byte FF D9 end-of-image marker through the destination buffer.",
        ],
    },
    {
        "source_ea": "0x2987f0",
        "target_ea": "0x2a5c60",
        "source_name": "write_marker_header",
        "role": "write_marker_header",
        "target_slot": "marker writer write_marker_header field at +0x28",
        "operation": "validates an arbitrary marker payload length and emits its marker code and two-byte length",
        "evidence": [
            "The source marker-writer initializer stores this function in its write_marker_header field at offset 0x28.",
            "The target v18_jinit_marker_writer initializer stores the target body in the corresponding field at offset 0x28.",
            "The body performs the 65533-byte safety check and emits the marker followed by the payload length.",
        ],
    },
    {
        "source_ea": "0x2989a0",
        "target_ea": "0x2a5e10",
        "source_name": "emit_dht",
        "role": "emit_dht",
        "target_parent": "write_scan_header at 0x2a72c4",
        "operation": "emits one Huffman table as a DHT marker when it has not already been sent",
        "evidence": [
            "The source write_scan_header routine calls this helper for each required DC and AC Huffman table.",
            "The target v18_jpeg_write_scan_header routine calls the corresponding body for the same scan-table loop.",
            "The body selects the DC or AC table, sums its code-length counts, emits the table bytes, and marks it sent.",
        ],
    },
    {
        "source_ea": "0x298e90",
        "target_ea": "0x2a6300",
        "source_name": "write_file_header",
        "role": "write_file_header",
        "target_slot": "marker writer write_file_header field at +0x00",
        "operation": "emits SOI and the optional JFIF and Adobe application markers",
        "evidence": [
            "The source marker-writer initializer stores this function in its write_file_header field at offset 0x00.",
            "The target v18_jinit_marker_writer initializer stores the target body in the corresponding field at offset 0x00.",
            "The body resets the restart interval after SOI and selects the optional JFIF and Adobe marker paths.",
        ],
    },
    {
        "source_ea": "0x299ac8",
        "target_ea": "0x2a6f38",
        "source_name": "emit_dqt",
        "role": "emit_dqt",
        "target_callers": [
            "write_frame_header at 0x2a72c4",
            "write_tables_only at 0x2a7748",
        ],
        "operation": "emits an unsent quantization table as a DQT marker and reports whether it uses 16-bit precision",
        "evidence": [
            "The source write_frame_header and write_tables_only routines call this helper for their quantization-table loops.",
            "The target v18_jpeg_write_frame_header and v18_jpeg_write_tables_only routines retain the same two caller paths.",
            "The body checks quantizer precision, writes the table in natural zigzag order, and marks the table sent.",
        ],
    },
    {
        "source_ea": "0x299e54",
        "target_ea": "0x2a72c4",
        "source_name": "write_frame_header",
        "role": "write_frame_header",
        "target_slot": "marker writer write_frame_header field at +0x08",
        "expected_differences": ["register_detail_hash"],
        "operation": "emits the frame quantization tables and selects the appropriate SOF marker",
        "evidence": [
            "The source marker-writer initializer stores this function in its write_frame_header field at offset 0x08.",
            "The target v18_jinit_marker_writer initializer stores the target body in the corresponding field at offset 0x08.",
            "The body calls emit_dqt for each component, checks baseline constraints, and dispatches to the correct sequential, progressive, arithmetic, or lossless SOF marker.",
        ],
    },
    {
        "source_ea": "0x29a2d8",
        "target_ea": "0x2a7748",
        "source_name": "write_tables_only",
        "role": "write_tables_only",
        "target_slot": "marker writer write_tables_only field at +0x20",
        "expected_differences": ["register_detail_hash"],
        "operation": "writes an abbreviated JPEG table stream containing SOI, all available DQT and DHT tables, and EOI",
        "evidence": [
            "The source marker-writer initializer stores this function in its write_tables_only field at offset 0x20.",
            "The target v18_jinit_marker_writer initializer stores the target body in the corresponding field at offset 0x20.",
            "The body iterates over defined quantization and Huffman tables and emits the abbreviated stream markers in the same order.",
        ],
    },
    {
        "source_ea": "0x29aa48",
        "target_ea": "0x2a7eb8",
        "source_name": "write_scan_header",
        "role": "write_scan_header",
        "target_slot": "marker writer write_scan_header field at +0x10",
        "operation": "emits DHT or DAC tables, an optional restart interval marker, and the scan SOS marker",
        "evidence": [
            "The source marker-writer initializer stores this function in its write_scan_header field at offset 0x10.",
            "The target v18_jinit_marker_writer initializer stores the target body in the corresponding field at offset 0x10.",
            "The body follows the arithmetic or Huffman branch, avoids redundant restart markers, and finishes with the SOS marker.",
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
            "match_kind": "manual-libjpeg-jcmarker-role-anchor",
            "family": "libjpeg compressor marker writer",
            "source_name": spec["source_name"],
            "source_role": spec["role"],
            "source_file": "jcmarker.c",
            "source_component": "jinit_marker_writer_jpeg_compress_struct",
            "target_component": "v18_jinit_marker_writer_jpeg_compress_struct",
            "source_basis": "libjpeg jcmarker role, marker-writer method table or caller topology, reviewed pseudocode, and exact or register-detail-only ARM64 feature metrics",
            "operation": spec["operation"],
            "normalized_shape_equal": normalized_equal,
            "full_metric_equal": not differences,
            "metric_differences": differences,
            "semantic_match_already_present": False,
            "evidence": spec["evidence"],
            "name_action": "rename-with-v18-prefix",
        }
        for key in ("target_slot", "target_parent", "target_callers"):
            if key in spec:
                anchor[key] = spec[key]
        anchors.append(anchor)

    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_marker_writer_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jcmarker marker-writer routines",
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
            "source_marker_writer": "jinit_marker_writer_jpeg_compress_struct at 0x29b708",
            "target_marker_writer": "v18_jinit_marker_writer_jpeg_compress_struct at 0x2a8b78",
            "source_source_file": "jcmarker.c",
            "target_source_file": "jcmarker.c",
            "source_region": "0x2986c0 through 0x29b708",
            "target_region": "0x2a5b30 through 0x2a8b78",
            "address_displacement": "0xd470",
            "role_resolution": "marker-writer method-table assignments, libjpeg caller topology, reviewed pseudocode, official jcmarker source roles, and exact or register-detail-only ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because every target candidate retained an IDA auto-generated name",
            "reference_sources": [
                "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jcmarker.c",
            ],
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
            "marker_method_count": 7,
            "internal_emitter_count": 2,
            "writer_body_count": 5,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because the target marker-writer bodies retained only IDA auto-generated names.",
            "The seven method-table rows are assigned by the source and target jinit_marker_writer pointer tables, while emit_dht and emit_dqt are assigned by their writer callers.",
            "The target preserves the complete marker-writer block at the same relative displacement as the source, including all public writer slots and the two internal table emitters.",
            "All nine rows match normalized ARM64 shape. Seven match the complete recorded feature set, while two differ only in register-detail allocation.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
