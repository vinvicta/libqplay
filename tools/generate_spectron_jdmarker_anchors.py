#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg marker reader.

The target retains the marker-reader initializer and the surrounding callback
table, while several small marker routines were compiled into the large
read_markers state machine. This artifact records both the direct callback
slots and the internal call sites used to resolve those roles.
"""

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
        "source_ea": "0x28cbb8",
        "target_ea": "0x29a028",
        "role": "get_sof",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "called by read_markers at 0x29b20c for SOF0, SOF1, SOF2, and SOF3 marker variants",
        "target_call_sites": ["0x29b3f4", "0x29b848", "0x29b9b4", "0x29bcc8"],
        "operation": "parses a SOF marker, validates dimensions and component count, allocates component metadata, and records sampling and quantization selectors",
        "evidence": [
            "The target function takes the three SOF mode flags used by read_markers and is called at four SOF dispatch sites inside the target marker loop.",
            "The target body reads precision, height, width, and component count, reports malformed image dimensions, allocates component records, and decodes each component's sampling and quantization bytes.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28cffc",
        "target_ea": "0x29a46c",
        "role": "examine_app0",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "called by target marker-save and APPn-processing paths at 0x29ae64 and 0x29b188",
        "target_call_sites": ["0x29ae64", "0x29b188"],
        "operation": "recognizes JFIF and JFXX APP0 payloads, records JFIF metadata, and reports thumbnail or extension details",
        "evidence": [
            "The target body checks for the JFIF and JFXX signatures and decodes the JFIF version, density unit, densities, and thumbnail dimensions.",
            "The target body is called from both the saved-marker and interesting-APPn paths where APP0 payloads are examined.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28d2ec",
        "target_ea": "0x29a75c",
        "role": "skip_variable",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "installed as the default COM and APPn processor when marker data is not being saved",
        "target_call_sites": ["0x29c4bc", "0x29c4c4", "0x29c61c"],
        "operation": "reads a variable-length marker size, reports the marker, and skips the remaining payload through the source manager",
        "evidence": [
            "The target marker initializer installs this function in the default COM and APPn processor slots.",
            "The target body reads the two-byte marker length, subtracts the length field, and delegates the remaining bytes to skip_input_data.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28d400",
        "target_ea": "0x29a870",
        "role": "reset_marker_reader",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "installed as the marker-reader reset callback",
        "target_call_sites": ["0x29c4d8"],
        "operation": "resets unread-marker, restart, APPn, COM, and saved-marker state for a new JPEG input",
        "evidence": [
            "The target marker initializer stores this function as the marker-reader reset callback.",
            "The target body clears the unread marker, input scan state, restart state, and saved-marker cursor fields that the marker reader owns.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28d424",
        "target_ea": "0x29a894",
        "role": "get_dht",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "called by read_markers at 0x29bc84 for DHT markers",
        "target_call_sites": ["0x29bc84"],
        "operation": "parses Huffman table counts and values, allocates missing tables, and stores the decoded table data",
        "evidence": [
            "The target marker loop calls this function for marker code 196, the JPEG DHT marker.",
            "The target body reads the 16 code-length counts and Huffman values, validates their total, chooses DC or AC table storage, and copies the table into an allocated Huffman object.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28d804",
        "target_ea": "0x29ac74",
        "role": "save_marker",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "selected by jpeg_save_markers for COM or APPn payloads and called from the marker loop",
        "target_call_sites": ["0x29c5cc", "0x29c5d8", "0x29c68c", "0x29c694", "0x29c69c"],
        "operation": "allocates and fills a saved-marker record, examines APP0 and APP14 metadata, and appends the record to the marker list",
        "evidence": [
            "The target jpeg_save_markers routine selects this callback when a COM or APPn payload is configured to be retained.",
            "The target body maintains the current saved-marker record across input-buffer refills, copies marker data into the record, examines APP0 and APP14 payloads, and links the completed record into the list.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28db3c",
        "target_ea": "0x29afac",
        "role": "get_interesting_appn",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "installed for APP0 and APP14 when the application is not saving the full marker payload",
        "target_call_sites": ["0x29c558", "0x29c65c"],
        "operation": "reads the interesting prefix of APP0 or APP14, examines JFIF or Adobe metadata, and skips the rest of the marker",
        "evidence": [
            "The target marker initializer installs this function in the APP0 and APP14 processor slots by default.",
            "The target body reads at most the metadata prefix, dispatches APP0 to the JFIF examiner and APP14 to the Adobe path, then skips any remaining bytes.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28dd9c",
        "target_ea": "0x29b20c",
        "role": "read_markers",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "installed as the marker-reader read_markers callback",
        "target_call_sites": ["0x29c4e4", "0x29c4ec"],
        "operation": "drives the JPEG marker state machine, dispatches SOF, DHT, DQT, DRI, APPn, COM, SOS, and EOI handling, and returns suspension or scan status",
        "evidence": [
            "The target marker initializer stores this function in the marker-reader read_markers slot.",
            "The target body scans for SOI and subsequent markers, dispatches SOF to get_sof and DHT to get_dht, handles marker-length and APPn paths, and returns the JPEG controller status values for suspension, SOS, and EOI.",
            "The source and target normalized metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x28eb20",
        "target_ea": "0x29bf90",
        "role": "read_restart_marker",
        "family": "libjpeg marker reader",
        "source_file": "jdmarker.c",
        "parent_source": "jinit_marker_reader at 0x28f028",
        "parent_target": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
        "target_context": "installed as the marker-reader restart callback",
        "target_call_sites": ["0x29c4f4"],
        "operation": "finds the next restart marker, validates the expected sequence, invokes resynchronization when needed, and advances the restart counter",
        "evidence": [
            "The target marker initializer stores this function in the marker-reader read_restart_marker slot.",
            "The target body scans for FF marker bytes, tracks discarded data, compares the marker against the expected restart number, calls the source resynchronization callback on mismatch, and advances the modulo-eight restart state.",
            "The source and target functions have identical complete feature metrics.",
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
            "match_kind": "manual-libjpeg-jdmarker-role-anchor",
            "family": spec["family"],
            "source_name": spec["role"],
            "source_role": spec["role"],
            "source_file": spec["source_file"],
            "source_component": spec["parent_source"],
            "target_component": spec["parent_target"],
            "source_basis": "libjpeg %s body and marker-reader callback context"
            % spec["role"],
            "source_parent": spec["parent_source"],
            "target_parent": spec["parent_target"],
            "target_context": spec["target_context"],
            "target_call_sites": spec["target_call_sites"],
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
        "artifact": "spectron_jpeg_marker_reader_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdmarker reader routines",
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
            "source_controller": "jinit_marker_reader at 0x28f028",
            "target_controller": "v18_jinit_marker_reader_jpeg_decompress_struct at 0x29c498",
            "source_source_file": "jdmarker.c",
            "target_source_file": "jdmarker.c",
            "role_resolution": "standard libjpeg jdmarker roles, target callback installation table, target marker-loop call sites, reviewed pseudocode, and normalized ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because the source and target functions both retained default names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdmarker.c",
            "inlining_note": "get_soi, get_sos, get_dqt, get_dri, next_marker, and first_marker logic is visible in the target read_markers or read_restart_marker bodies rather than as separate IDA function starts",
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
            "marker_reader_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The marker-reader initializer provides direct slots for reset_marker_reader, read_markers, read_restart_marker, skip_variable, and get_interesting_appn. The saved-marker callback is selected by jpeg_save_markers, while get_sof, get_dht, and examine_app0 are confirmed by their marker-loop call sites and bodies.",
            "Several other jdmarker source helpers are compiler-inlined into read_markers or read_restart_marker in both builds, so they do not receive separate labels in this pass.",
            "The source and target bodies have identical normalized metrics; eight rows are complete metric matches and one differs only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
