#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg source and sink callbacks.

These are standard libjpeg I/O callbacks. The target installation sites and
the bodies are recorded alongside the source and target feature metrics so
that the labels do not rely on address order alone.
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
        "source_ea": "0x28b9f4",
        "target_ea": "0x298e64",
        "role": "init_destination",
        "family": "libjpeg destination callbacks",
        "source_file": "jdatadst.c",
        "parent_source": "jpeg_stdio_dest at 0x28bb5c",
        "parent_target": "v18_jpeg_stdio_dest at 0x298fcc",
        "target_call_site": "0x298fdc",
        "operation": "allocates or resets the 4096-byte output buffer and initializes next_output_byte and free_in_buffer",
        "evidence": [
            "The target v18_jpeg_stdio_dest routine stores the callback at 0x298fdc.",
            "The target body obtains the destination buffer through the file object, stores its start in the destination state, and sets the free count to 4096.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28ba30",
        "target_ea": "0x298ea0",
        "role": "empty_output_buffer",
        "family": "libjpeg destination callbacks",
        "source_file": "jdatadst.c",
        "parent_source": "jpeg_stdio_dest at 0x28bb5c",
        "parent_target": "v18_jpeg_stdio_dest at 0x298fcc",
        "target_call_site": "0x298fe8",
        "operation": "writes a full 4096-byte output buffer and restores the destination cursor",
        "evidence": [
            "The target v18_jpeg_stdio_dest routine stores the callback at 0x298fe8.",
            "The target body calls the JFWRITE callback for exactly 4096 bytes, reports JPEG error 37 on a short write, and resets the buffer state.",
            "The source and target normalized metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x28baa4",
        "target_ea": "0x298f14",
        "role": "term_destination",
        "family": "libjpeg destination callbacks",
        "source_file": "jdatadst.c",
        "parent_source": "jpeg_stdio_dest at 0x28bb5c",
        "parent_target": "v18_jpeg_stdio_dest at 0x298fcc",
        "target_call_site": "0x298ff4",
        "operation": "flushes the final partial output buffer and checks the destination error callback",
        "evidence": [
            "The target v18_jpeg_stdio_dest routine stores the callback at 0x298ff4.",
            "The target body writes the remaining bytes, calls JFFLUSH, checks JFERROR, and reports JPEG error 37 through the error manager when needed.",
            "The source and target normalized metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x28bbbc",
        "target_ea": "0x29902c",
        "role": "init_source",
        "family": "libjpeg source callbacks",
        "source_file": "jdatasrc.c",
        "parent_source": "jpeg_stdio_src at 0x28bd9c",
        "parent_target": "v18_jpeg_stdio_src at 0x29920c",
        "target_call_site": "0x299220",
        "operation": "marks the source as being at the beginning of the input file",
        "evidence": [
            "The target v18_jpeg_stdio_src routine stores the callback at 0x299220.",
            "The target body sets the source start_of_file flag at offset 64, which is the standard libjpeg init_source operation.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28bbcc",
        "target_ea": "0x29903c",
        "role": "fill_input_buffer",
        "family": "libjpeg source callbacks",
        "source_file": "jdatasrc.c",
        "parent_source": "jpeg_stdio_src at 0x28bd9c",
        "parent_target": "v18_jpeg_stdio_src at 0x29920c",
        "target_call_site": "0x29922c",
        "operation": "reads up to 4096 bytes, invokes the JPEG error path at EOF, and supplies an EOI marker",
        "evidence": [
            "The target v18_jpeg_stdio_src routine stores the callback at 0x29922c.",
            "The target body calls JFREAD for 4096 bytes, reports the end-of-file warning when appropriate, and installs the two-byte JPEG EOI marker FF D9 when no bytes are read.",
            "The source and target normalized metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x28bc88",
        "target_ea": "0x2990f8",
        "role": "skip_input_data",
        "family": "libjpeg source callbacks",
        "source_file": "jdatasrc.c",
        "parent_source": "jpeg_stdio_src at 0x28bd9c",
        "parent_target": "v18_jpeg_stdio_src at 0x29920c",
        "target_call_site": "0x299238",
        "operation": "skips requested input bytes by consuming the current buffer and refilling it through JFREAD",
        "evidence": [
            "The target v18_jpeg_stdio_src routine stores the callback at 0x299238.",
            "The target body consumes complete 4096-byte source buffers, refills them through JFREAD, handles EOF with the same error path, and advances next_input_byte and bytes_in_buffer.",
            "The source and target normalized metrics match; only register allocation detail differs.",
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
            raise ValueError("unexpected metric differences for %s: %s" % (spec["role"], differences))
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
            "match_kind": "manual-libjpeg-io-role-anchor",
            "family": spec["family"],
            "source_name": spec["role"],
            "source_role": spec["role"],
            "source_file": spec["source_file"],
            "source_component": spec["parent_source"],
            "target_component": spec["parent_target"],
            "source_basis": "libjpeg %s body and callback installation" % spec["role"],
            "source_parent": spec["parent_source"],
            "target_parent": spec["parent_target"],
            "target_call_site": spec["target_call_site"],
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
        "artifact": "spectron_jpeg_io_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg source and destination callbacks",
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
            "destination_parent": "v18_jpeg_stdio_dest at 0x298fcc",
            "source_parent": "v18_jpeg_stdio_src at 0x29920c",
            "destination_source_file": "jdatadst.c",
            "source_source_file": "jdatasrc.c",
            "role_resolution": "standard libjpeg callback bodies, installation slots, caller context, and source-target feature metrics",
            "name_policy": "v18-prefixed semantic role because the source and target functions both retained default IDA names",
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
            "destination_callback_count": 3,
            "source_callback_count": 3,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The destination callbacks are identified by the JFWRITE, JFFLUSH, and JFERROR operations installed by jpeg_stdio_dest.",
            "The source callbacks are identified by the JFREAD, start_of_file, EOI-marker, and buffer-advance operations installed by jpeg_stdio_src.",
            "The source and target bodies have identical normalized metrics; four rows differ only in register allocation detail and two rows are complete metric matches.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
