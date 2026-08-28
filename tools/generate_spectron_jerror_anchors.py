#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg error handlers."""

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
        "source_ea": "0x292aac",
        "target_ea": "0x29ff1c",
        "role": "emit_message",
        "target_context": "installed as the standard emit_message handler by jpeg_std_error",
        "target_install_sites": ["0x2a010c", "0x2a0114"],
        "operation": "emits a warning or trace message according to the message level, warning count, and configured trace level",
        "evidence": [
            "The target jpeg_std_error initializer stores this routine in the emit_message callback field.",
            "The target body forwards the message to output_message for the first warning or an enabled trace level, and increments the warning count for warning messages.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x292b24",
        "target_ea": "0x29ff94",
        "role": "reset_error_mgr",
        "target_context": "installed as the standard reset_error_mgr handler by jpeg_std_error",
        "target_install_sites": ["0x2a013c", "0x2a0144"],
        "operation": "resets the JPEG warning count and current message code while leaving the application trace level unchanged",
        "evidence": [
            "The target jpeg_std_error initializer stores this routine in the reset_error_mgr callback field.",
            "The target body clears the warning counter and message code at the standard error-manager offsets.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x292b34",
        "target_ea": "0x29ffa4",
        "role": "format_message",
        "target_context": "installed as the standard format_message handler by jpeg_std_error",
        "target_install_sites": ["0x2a012c", "0x2a0134"],
        "operation": "looks up the active JPEG message, detects a string parameter, and formats either the string or integer arguments into the caller's buffer",
        "evidence": [
            "The target jpeg_std_error initializer stores this routine in the format_message callback field.",
            "The target body selects the built-in or add-on message table, falls back for an invalid code, scans for %s, and formats the saved string or integer parameters.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x292c1c",
        "target_ea": "0x2a008c",
        "role": "output_message",
        "target_context": "installed as the standard output_message handler by jpeg_std_error",
        "target_install_sites": ["0x2a011c", "0x2a0124"],
        "operation": "formats the current JPEG message into a local buffer and writes it with a trailing newline to stderr",
        "evidence": [
            "The target jpeg_std_error initializer stores this routine in the output_message callback field.",
            "The target body calls format_message into a 200-byte local buffer and passes the result to fprintf on stderr with a newline.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x292c64",
        "target_ea": "0x2a00d4",
        "role": "error_exit",
        "target_context": "installed as the standard error_exit handler by jpeg_std_error",
        "target_install_sites": ["0x2a00fc", "0x2a0104"],
        "operation": "prints the current message, destroys the JPEG object, and terminates the process with exit status one",
        "evidence": [
            "The target jpeg_std_error initializer stores this routine in the error_exit callback field.",
            "The target body invokes output_message, calls jpeg_destroy for temporary-resource cleanup, and exits with status one without returning.",
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
                "match_kind": "manual-libjpeg-jerror-role-anchor",
                "family": "libjpeg error handling and message formatting",
                "source_name": spec["role"],
                "source_role": spec["role"],
                "source_file": "jerror.c",
                "source_component": "jpeg_std_error at 0x292c8c",
                "target_component": "v18_jpeg_std_error at 0x2a00fc",
                "source_basis": "libjpeg %s body and jpeg_std_error callback installation"
                % spec["role"],
                "source_parent": "jpeg_std_error at 0x292c8c",
                "target_parent": "v18_jpeg_std_error at 0x2a00fc",
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
        "artifact": "spectron_jpeg_error_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jerror routines",
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
            "source_controller": "jpeg_std_error at 0x292c8c",
            "target_controller": "v18_jpeg_std_error at 0x2a00fc",
            "source_source_file": "jerror.c",
            "target_source_file": "jerror.c",
            "role_resolution": "standard libjpeg jerror callback contract, target jpeg_std_error callback assignments, reviewed pseudocode, and normalized ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because both source and target functions retained default names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jerror.c",
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
            "error_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The target jpeg_std_error initializer preserves the standard callback order for error exit, message emission, output, formatting, and reset handling.",
            "Four rows match the complete recorded ARM64 feature set; output_message differs only in register allocation detail while retaining identical normalized shape.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
