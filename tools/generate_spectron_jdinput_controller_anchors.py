#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg input controller.

The four functions in this artifact are the callback slots installed by
``jinit_input_controller``. Their names are recovered from the standard
libjpeg controller contract, the target installation table, and matching
1.8-to-Spectron function features.
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
        "source_ea": "0x28be44",
        "target_ea": "0x2992b4",
        "role": "finish_input_pass",
        "controller_slot": "finish_input_pass",
        "family": "libjpeg input controller",
        "source_file": "jdinput.c",
        "parent_source": "jinit_input_controller at 0x28cb48",
        "parent_target": "v18_jinit_input_controller_jpeg_decompress_struct at 0x299fb8",
        "target_install_site": "0x29a008",
        "operation": "switches consume_input back to consume_markers after a scan finishes",
        "evidence": [
            "The target initializer stores this function in the input-controller finish_input_pass slot at 0x29a008.",
            "The target body writes the target consume_markers callback into the controller consume_input field and returns that callback.",
            "The source and target normalized metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x28be58",
        "target_ea": "0x2992c8",
        "role": "reset_input_controller",
        "controller_slot": "reset_input_controller",
        "family": "libjpeg input controller",
        "source_file": "jdinput.c",
        "parent_source": "jinit_input_controller at 0x28cb48",
        "parent_target": "v18_jinit_input_controller_jpeg_decompress_struct at 0x299fb8",
        "target_install_site": "0x299fec",
        "operation": "resets controller state, restores consume_markers, resets marker and error state, and clears coefficient bits",
        "evidence": [
            "The target initializer stores this function in the input-controller reset_input_controller slot at 0x299fec.",
            "The target body clears scan and end-of-image state, restores the target consume_markers callback, calls the error and marker reset callbacks, and clears coef_bits.",
            "The source and target normalized metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x28beb0",
        "target_ea": "0x299320",
        "role": "start_input_pass",
        "controller_slot": "start_input_pass",
        "family": "libjpeg input controller",
        "source_file": "jdinput.c",
        "parent_source": "jinit_input_controller at 0x28cb48",
        "parent_target": "v18_jinit_input_controller_jpeg_decompress_struct at 0x299fb8",
        "target_install_site": "0x299ffc",
        "operation": "builds scan-level MCU state, materializes missing quantization tables, starts entropy and coefficient passes, and selects consume_data",
        "evidence": [
            "The target initializer stores this function in the input-controller start_input_pass slot at 0x299ffc.",
            "The target body computes MCU membership and dimensions, allocates missing quantization tables, invokes the entropy and coefficient start-pass callbacks, and assigns consume_data to the controller.",
            "The source and target functions have identical complete feature metrics.",
        ],
    },
    {
        "source_ea": "0x28c378",
        "target_ea": "0x2997e8",
        "role": "consume_markers",
        "controller_slot": "consume_input",
        "family": "libjpeg input controller",
        "source_file": "jdinput.c",
        "parent_source": "jinit_input_controller at 0x28cb48",
        "parent_target": "v18_jinit_input_controller_jpeg_decompress_struct at 0x299fb8",
        "target_install_site": "0x299fdc",
        "operation": "consumes JPEG markers, performs initial image and scan setup, handles suspension and EOI, and advances the controller state machine",
        "evidence": [
            "The target initializer stores this function in the input-controller consume_input slot at 0x299fdc and the reset path restores the same callback.",
            "The target body reads the marker-reader result, validates dimensions, precision, component sampling, and scan composition, builds component and MCU state, and returns the standard JPEG controller status values.",
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
            "match_kind": "manual-libjpeg-jdinput-controller-role-anchor",
            "family": spec["family"],
            "source_name": spec["role"],
            "source_role": spec["role"],
            "source_file": spec["source_file"],
            "source_component": spec["parent_source"],
            "target_component": spec["parent_target"],
            "source_basis": "libjpeg %s body and jinit_input_controller callback slot"
            % spec["role"],
            "source_parent": spec["parent_source"],
            "target_parent": spec["parent_target"],
            "controller_slot": spec["controller_slot"],
            "target_install_site": spec["target_install_site"],
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
        "artifact": "spectron_jpeg_input_controller_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdinput controller callbacks",
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
            "source_controller": "jinit_input_controller at 0x28cb48",
            "target_controller": "v18_jinit_input_controller_jpeg_decompress_struct at 0x299fb8",
            "source_source_file": "jdinput.c",
            "target_source_file": "jdinput.c",
            "role_resolution": "standard libjpeg jdinput callback contract, target installation slots, source-target pseudocode, and normalized ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because the source and target functions both retained default names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdinput.c",
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
            "controller_callback_count": 4,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The four functions occupy the consume_input, reset_input_controller, start_input_pass, and finish_input_pass slots initialized by jinit_input_controller.",
            "The target consume_markers body includes the initial image and scan setup work that the standard jdinput source performs while consuming the header state machine.",
            "The source and target bodies have identical normalized metrics; two rows are complete metric matches and two differ only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
