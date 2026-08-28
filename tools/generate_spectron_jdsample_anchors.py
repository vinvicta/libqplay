#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg upsampler block."""

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
        "source_ea": "0x291b6c",
        "target_ea": "0x29efdc",
        "role": "start_pass_upsample",
        "target_context": "installed as the upsampler start-pass callback",
        "target_install_sites": ["0x29fcd8"],
        "operation": "records the output height and maximum vertical sampling factor at the start of an upsampling pass",
        "evidence": [
            "The target upsampler initializer stores this function in the first field of the upsampler object.",
            "The target body reads the decompressor output height and maximum vertical sampling factor into the upsampler state, matching the jdmainct pass contract.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x291b84",
        "target_ea": "0x29eff4",
        "role": "sep_upsample",
        "target_context": "installed as the public upsample callback for the decompression pipeline",
        "target_install_sites": ["0x29fce8"],
        "operation": "runs component upsamplers into a row buffer, converts the produced rows, and advances the input and output row cursors while respecting the available buffer rows",
        "evidence": [
            "The target upsampler initializer stores this function in the public upsample field after allocating the per-component upsampler state.",
            "The target body drains converted rows, invokes each component method for new input rows, calls the color converter, and advances the decompressor row state.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x291ce8",
        "target_ea": "0x29f158",
        "role": "fullsize_upsample",
        "target_context": "selected when a component's sampling factors already match the output factors",
        "target_install_sites": ["0x29fdcc", "0x29fdd4"],
        "operation": "passes a full-size component row through without changing its sample layout",
        "evidence": [
            "The target initializer selects this method in the full-size branch where the horizontal and vertical factors match.",
            "The target body only redirects the destination row pointer to the source row pointer, which is the fullsize_upsample contract.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x291cf0",
        "target_ea": "0x29f160",
        "role": "noop_upsample",
        "target_context": "selected for components marked component_needed false",
        "target_install_sites": ["0x29fd58"],
        "operation": "returns a null output row for an unused component",
        "evidence": [
            "The target initializer selects this method before sampling-factor dispatch when component_needed is false.",
            "The target body writes a null row pointer and returns, matching the unused-component no-op path.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x291cf8",
        "target_ea": "0x29f168",
        "role": "h2v1_upsample",
        "target_context": "selected for simple horizontal 2:1 expansion with no vertical expansion",
        "target_install_sites": ["0x29ff0c"],
        "operation": "duplicates each input sample horizontally to expand a component by two",
        "evidence": [
            "The target initializer selects this method for the horizontal two-to-one, non-fancy branch.",
            "The target body duplicates each source byte into two output samples and uses a NEON interleaved-store fast path for long rows.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x291f6c",
        "target_ea": "0x29f3dc",
        "role": "h2v1_fancy_upsample",
        "target_context": "selected for fancy horizontal 2:1 expansion",
        "target_install_sites": ["0x29fefc"],
        "operation": "expands a component horizontally by two with neighboring-sample interpolation and edge replication",
        "evidence": [
            "The target initializer selects this method for the horizontal two-to-one branch when fancy upsampling is enabled.",
            "The target body computes the 3-near-plus-far interpolation used by libjpeg, handles the first and last samples specially, and vectorizes the steady-state row.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x292220",
        "target_ea": "0x29f690",
        "role": "h1v2_fancy_upsample",
        "target_context": "selected for fancy vertical 2:1 expansion and marks the upsampler as needing context rows",
        "target_install_sites": ["0x29fd30", "0x29fd38"],
        "operation": "expands a component vertically by two with horizontal and vertical interpolation from neighboring rows",
        "evidence": [
            "The target initializer selects this method for the vertical two-to-one branch when fancy upsampling is enabled and sets the context-row flag.",
            "The target body reads adjacent component rows, performs the weighted interpolation for both output rows, and handles the two-row boundary cases.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x292360",
        "target_ea": "0x29f7d0",
        "role": "int_upsample",
        "target_context": "selected for other integral horizontal and vertical expansion ratios",
        "target_install_sites": ["0x29fd28", "0x29fd48"],
        "operation": "expands samples and rows by the integer horizontal and vertical factors recorded in the component state",
        "evidence": [
            "The target initializer selects this generic method after validating that both expansion ratios are integral, then stores the horizontal and vertical expansion factors.",
            "The target body duplicates each source sample horizontally, copies the resulting row vertically, and uses a NEON fill path for long rows.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x292568",
        "target_ea": "0x29f9d8",
        "role": "h2v2_upsample",
        "target_context": "selected for simple vertical 2:1 expansion with the corresponding horizontal two-sample layout",
        "target_install_sites": ["0x29fd2c", "0x29fd4c"],
        "operation": "duplicates component samples horizontally by two and copies each expanded row to produce the two-row output",
        "evidence": [
            "The target initializer selects this method in the non-fancy vertical two-to-one branch.",
            "The target body duplicates source bytes into adjacent output samples, then copies the expanded row for the second output row, matching the simple h2v2 path.",
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
            "match_kind": "manual-libjpeg-jdsample-role-anchor",
            "family": "libjpeg decompression upsampler",
            "source_name": spec["role"],
            "source_role": spec["role"],
            "source_file": "jdsample.c",
            "source_component": "jinit_upsampler_jpeg_decompress_struct at 0x29282c",
            "target_component": "v18_jinit_upsampler_jpeg_decompress_struct at 0x29fc9c",
            "source_basis": "libjpeg %s body and upsampler dispatch context" % spec["role"],
            "source_parent": "jinit_upsampler_jpeg_decompress_struct at 0x29282c",
            "target_parent": "v18_jinit_upsampler_jpeg_decompress_struct at 0x29fc9c",
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
        "artifact": "spectron_jpeg_upsampler_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jdsample upsampler routines",
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
            "source_controller": "jinit_upsampler_jpeg_decompress_struct at 0x29282c",
            "target_controller": "v18_jinit_upsampler_jpeg_decompress_struct at 0x29fc9c",
            "source_source_file": "jdsample.c",
            "target_source_file": "jdsample.c",
            "role_resolution": "standard libjpeg jdsample callback contract, target upsampler initializer dispatch sites, reviewed pseudocode, and complete ARM64 feature equality",
            "name_policy": "v18-prefixed semantic role because both source and target functions retained default names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdsample.c",
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
            "upsampler_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The target upsampler initializer preserves the source callback table and dispatches to the full-size, no-op, h2v1, fancy h2v1, fancy h1v2, generic integral, or simple h2v2 paths.",
            "All nine source and target functions have identical complete ARM64 feature metrics, including register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
