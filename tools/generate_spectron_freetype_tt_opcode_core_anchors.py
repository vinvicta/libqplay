#!/usr/bin/env python3
"""Create reviewed anchors for the next Spectron TrueType opcode block."""

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
        "source_ea": "0x260660",
        "target_ea": "0x26dad0",
        "source_name": "Ins_MDRP",
        "proposed_name": "v18_Ins_MDRP",
        "role": "TrueType MDRP direct-relative-point opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns default opcode dispatch for MDRP range 0xc0-0xdf",
        "source_data": "the handler measures the original distance to rp0, applies the opcode-selected rounding and minimum-distance rules, moves the point in zp1, and updates rp1, rp2, and optionally rp0",
        "target_data": "the target default opcode path preserves the same distance, rounding, minimum-distance, point-move, and reference-point updates",
        "operation": "moves a point directly relative to reference point 0 using the active graphics-state round and minimum-distance settings",
    },
    {
        "source_ea": "0x2608e0",
        "target_ea": "0x26dd50",
        "source_name": "Ins_MIRP",
        "proposed_name": "v18_Ins_MIRP",
        "role": "TrueType MIRP indirect-relative-point opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns default opcode dispatch for MIRP range 0xe0-0xff",
        "source_data": "the handler reads a CVT entry, derives the original and current distances to rp0, applies control cut-in, rounding, minimum-distance, and twilight handling, then moves the point and updates the reference points",
        "target_data": "the target default opcode path preserves the same CVT lookup, distance interpolation, rounding, minimum-distance, point-move, and reference-point logic",
        "operation": "moves a point indirectly relative to reference point 0 using a control-value-table distance",
    },
    {
        "source_ea": "0x260bc4",
        "target_ea": "0x26e034",
        "source_name": "Normalize",
        "proposed_name": "v18_Normalize",
        "role": "TrueType unit-vector normalization helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TrueType vector-setup call path used by SPvFS, SFvFS, and line-vector instructions",
        "source_data": "the helper normalizes an input vector and writes its F2Dot14 unit-vector components to the output structure",
        "target_data": "the target helper preserves the zero-vector handling, length calculation, fixed-point scaling, and signed unit-vector output",
        "operation": "converts a coordinate vector into the normalized F2Dot14 unit vector used by the interpreter",
    },
    {
        "source_ea": "0x260d7c",
        "target_ea": "0x26e1ec",
        "source_name": "Ins_MINDEX",
        "proposed_name": "v18_Ins_MINDEX",
        "role": "TrueType MINDEX stack-reordering opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for MINDEX at opcode 0x26",
        "source_data": "the handler validates the requested stack index, removes that entry, shifts the intervening entries down, and places the selected value at the top",
        "target_data": "the target handler preserves the same stack bounds check, memmove-based shift, error result, and top-of-stack insertion",
        "operation": "moves an indexed stack element to the top of the TrueType interpreter stack",
    },
    {
        "source_ea": "0x260e00",
        "target_ea": "0x26e270",
        "source_name": "TT_Done_Context",
        "proposed_name": "v18_TT_Done_Context",
        "role": "TrueType execution-context destructor",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "FreeType execution-context teardown call site",
        "source_data": "the destructor releases the glyph loader context buffers, clears their sizes and pointers, frees the context object, and leaves the owning slot null",
        "target_data": "the target teardown helper preserves the same buffer cleanup order, pointer clearing, context free, and owner reset",
        "operation": "releases the TrueType execution context and its stack, call-stack, and glyph-instruction storage",
    },
    {
        "source_ea": "0x260e8c",
        "target_ea": "0x26e2fc",
        "source_name": "Ins_IP",
        "proposed_name": "v18_Ins_IP",
        "role": "TrueType IP interpolate-point opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for IP at opcode 0x39",
        "source_data": "the handler walks the selected points and contours, shifts or linearly interpolates untouched coordinates between the reference points, and handles twilight and phantom-point cases",
        "target_data": "the target handler preserves the same contour traversal, touched-point selection, fixed-point interpolation, and reference-range cleanup",
        "operation": "interpolates untouched points between the current reference points using original and current coordinate ranges",
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
    expected_differences = spec.get("expected_differences", [])
    unexpected_differences = [
        field for field in differences if field not in expected_differences
    ]
    if unexpected_differences:
        raise ValueError(
            "%s unexpectedly differs in %s"
            % (spec["source_name"], unexpected_differences)
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
        "match_kind": "manual-freetype-tt-opcode-core-role-anchor",
        "family": "FreeType TrueType opcode and execution-context helpers",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType TrueType interpreter module",
        "target_component": "stripped Spectron FreeType TrueType interpreter",
        "source_basis": "opcode dispatch or lifecycle topology, matching pseudocode, official FreeType source role, and exact or explicitly explained ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The original FreeType source identifies the helper or opcode contract.",
            "The target call graph reaches the corresponding parallel helper or dispatcher case.",
            "The official FreeType TrueType source defines the matching role and operation.",
            "The source and target ARM64 feature records match across the complete recorded metric set, or differ only in the accepted register-allocation detail.",
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
    anchors = []
    for spec in SPECS:
        original = original_by_ea[spec["source_ea"]]
        spectron = spectron_by_ea[spec["target_ea"]]
        if not original.get("is_default_name"):
            raise ValueError("source candidate is not a default name")
        if not spectron.get("is_default_name"):
            raise ValueError("target candidate is not a default name")
        anchors.append(build_anchor(original, spectron, spec))

    result = {
        "schema_version": 1,
        "artifact": "spectron_freetype_tt_opcode_core_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for FreeType TrueType opcode and execution-context helpers",
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
            "source_true_type_region": "source FreeType TrueType opcode and context-helper candidates at 0x260660, 0x2608e0, 0x260bc4, 0x260d7c, 0x260e00, and 0x260e8c",
            "target_true_type_region": "the parallel target candidates at the source address plus 0xd470",
            "role_resolution": "TT_RunIns dispatch topology, execution-context teardown topology, matching pseudocode, official FreeType source roles, and exact ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/f720f0dbcf012d6c984dbbefa0875ef9840458c6/src/truetype/ttinterp.c",
            ],
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({anchor["spectron_ea"] for anchor in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(
                anchor["spectron_default_name"] for anchor in anchors
            ),
            "source_default_name_count": sum(
                anchor["original_default_name"] for anchor in anchors
            ),
            "normalized_shape_exact_count": sum(
                anchor["normalized_shape_equal"] for anchor in anchors
            ),
            "full_metric_exact_count": sum(
                anchor["full_metric_equal"] for anchor in anchors
            ),
            "opcode_handler_anchor_count": 4,
            "helper_anchor_count": 2,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates had no surviving source names.",
            "The MDRP and MIRP anchors cover the default target dispatch paths for direct and CVT-controlled point movement.",
            "Normalize is the fixed-point vector helper used by the vector-setting instructions, and TT_Done_Context is the execution-context teardown helper.",
            "MINDEX and IP cover the stack-reordering and point-interpolation opcode paths.",
            "The exact metric matches, source-to-target displacement, and matching call topology support direct translation for this block.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
