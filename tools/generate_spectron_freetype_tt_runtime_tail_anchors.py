#!/usr/bin/env python3
"""Create reviewed anchors for the next Spectron TrueType runtime block."""

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
        "source_ea": "0x261624",
        "target_ea": "0x26ea94",
        "source_name": "Ins_ENDF",
        "proposed_name": "v18_Ins_ENDF",
        "role": "TrueType ENDF function-definition return opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for ENDF at opcode 0x2d",
        "source_data": "the handler decrements the call stack and current instruction count, restores the enclosing code range, and returns to the interpreter loop or reports an invalid definition state",
        "target_data": "the target handler preserves the same call-stack decrement, instruction-count update, code-range restoration, and interpreter-loop return paths",
        "operation": "returns from a TrueType function definition and restores the enclosing instruction stream",
    },
    {
        "source_ea": "0x2616e0",
        "target_ea": "0x26eb50",
        "source_name": "tt_size_done",
        "proposed_name": "v18_tt_size_done",
        "role": "TrueType size-object destructor",
        "source_file": "src/truetype/ttobjs.c",
        "topology": "TrueType size teardown callback from the face and size lifecycle",
        "source_data": "the destructor releases the size-owned storage, control-value table, function definitions, instruction definitions, and related interpreter allocations before clearing the object",
        "target_data": "the target destructor preserves the same size-owned buffer cleanup, definition-list release, pointer clearing, and object teardown order",
        "operation": "releases the bytecode and control-value state owned by one TrueType size object",
    },
    {
        "source_ea": "0x261818",
        "target_ea": "0x26ec88",
        "source_name": "Dual_Project",
        "proposed_name": "v18_Dual_Project",
        "role": "TrueType dual-vector projection callback",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "Compute_Funcs installs the callback at the dual-projection slot for a non-axis dual vector",
        "source_data": "the helper projects a coordinate difference against the interpreter's dual projection vector and returns the fixed-point scalar used by movement and distance instructions",
        "target_data": "the target helper reads the parallel dual-vector fields and preserves the same fixed-point projection arithmetic",
        "operation": "projects a coordinate difference onto the interpreter's dual projection vector",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x2618a4",
        "target_ea": "0x26ed14",
        "source_name": "Ins_FDEF",
        "proposed_name": "v18_Ins_FDEF",
        "role": "TrueType FDEF function-definition opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for FDEF at opcode 0x2c",
        "source_data": "the handler records a function definition, scans forward to its matching ENDF, skips the body during normal execution, and updates the definition table",
        "target_data": "the target handler preserves the function-definition registration, ENDF scan, definition-table growth, and instruction-pointer skip",
        "operation": "registers a TrueType function definition and skips its body during execution",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x2619d4",
        "target_ea": "0x26ee44",
        "source_name": "Ins_IDEF",
        "proposed_name": "v18_Ins_IDEF",
        "role": "TrueType IDEF instruction-definition opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for IDEF at opcode 0x89",
        "source_data": "the handler records an instruction definition, scans to the matching ENDF, and skips the definition body after updating the instruction-definition table",
        "target_data": "the target handler preserves the instruction-definition registration, ENDF scan, table update, and instruction-pointer skip",
        "operation": "registers a TrueType instruction definition and skips its body during execution",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x261d8c",
        "target_ea": "0x26f1fc",
        "source_name": "Ins_DELTAP",
        "proposed_name": "v18_Ins_DELTAP",
        "role": "TrueType DELTAP point-adjustment opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for DELTAP1, DELTAP2, and DELTAP3 at opcodes 0x5d, 0x71, and 0x72",
        "source_data": "the handler consumes point and delta pairs, derives the current ppem and delta base, applies the selected delta shift, and moves qualifying points",
        "target_data": "the target handler preserves the point and delta stack consumption, ppem threshold calculation, delta-base selection, and point movement",
        "operation": "applies TrueType variation deltas to selected glyph points",
    },
    {
        "source_ea": "0x261fc4",
        "target_ea": "0x26f434",
        "source_name": "Ins_DELTAC",
        "proposed_name": "v18_Ins_DELTAC",
        "role": "TrueType DELTAC control-value adjustment opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for DELTAC1, DELTAC2, and DELTAC3 at opcodes 0x73, 0x74, and 0x75",
        "source_data": "the handler consumes CVT and delta pairs, derives the ppem and delta base, applies the delta shift, and updates selected control-value entries",
        "target_data": "the target handler preserves the CVT index and delta consumption, ppem threshold calculation, delta-base selection, and scaled CVT update",
        "operation": "applies TrueType variation deltas to control-value-table entries",
    },
    {
        "source_ea": "0x2621f4",
        "target_ea": "0x26f664",
        "source_name": "TT_Load_Context",
        "proposed_name": "v18_TT_Load_Context",
        "role": "TrueType execution-context loader",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "context and size setup path before TT_RunIns execution",
        "source_data": "the helper copies size state into the execution context, grows the operand and call stacks and glyph instruction buffer, initializes glyph code ranges, and selects the active zones",
        "target_data": "the target helper preserves the size-state copy, stack and instruction-buffer growth, code-range setup, zone selection, and context-field initialization",
        "operation": "loads a TrueType size into the execution context used by the bytecode interpreter",
    },
    {
        "source_ea": "0x2625e8",
        "target_ea": "0x26fa58",
        "source_name": "Ins_SHC",
        "proposed_name": "v18_Ins_SHC",
        "role": "TrueType SHC contour-shift opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for SHC1 and SHC2 at opcodes 0x34 and 0x35",
        "source_data": "the handler projects the reference point, computes the movement distance, and shifts the selected contour in the chosen zone",
        "target_data": "the target handler preserves the reference projection, movement callback, contour selection, and point-by-point shift",
        "operation": "shifts one contour by the movement applied to the reference point",
    },
    {
        "source_ea": "0x262864",
        "target_ea": "0x26fcd4",
        "source_name": "Ins_SHP",
        "proposed_name": "v18_Ins_SHP",
        "role": "TrueType SHP point-shift opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for SHP1 and SHP2 at opcodes 0x32 and 0x33",
        "source_data": "the handler obtains the movement of the selected reference point and shifts points in the selected zone while preserving untouched-point state",
        "target_data": "the target handler preserves reference-point selection, movement projection, zone traversal, and point displacement",
        "operation": "shifts selected points by the movement of a reference point",
    },
    {
        "source_ea": "0x262a74",
        "target_ea": "0x26fee4",
        "source_name": "Ins_ISECT",
        "proposed_name": "v18_Ins_ISECT",
        "role": "TrueType ISECT intersection-point opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns opcode dispatch for ISECT at opcode 0x0f",
        "source_data": "the handler reads two line segments, computes their intersection with fixed-point cross products, and stores the result in the selected point",
        "target_data": "the target handler preserves the segment endpoints, cross-product calculation, parallel-line fallback, and selected-point update",
        "operation": "places a point at the intersection of two projected outline segments",
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
        "match_kind": "manual-freetype-tt-runtime-tail-role-anchor",
        "family": "FreeType TrueType interpreter, projection, and context helpers",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType TrueType interpreter module",
        "target_component": "stripped Spectron FreeType TrueType interpreter",
        "source_basis": "TT_RunIns dispatch or interpreter callback topology, matching pseudocode, official FreeType source role, and exact or explicitly explained ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "expected_metric_differences": expected_differences,
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
        "artifact": "spectron_freetype_tt_runtime_tail_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining FreeType TrueType runtime tail",
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
            "source_true_type_region": "source FreeType TrueType runtime-tail candidates from 0x261624 through 0x262db4",
            "target_true_type_region": "the parallel target candidates at the source address plus 0xd470",
            "role_resolution": "TT_RunIns dispatch or Compute_Funcs callback topology, matching pseudocode, official FreeType source roles, and exact or explicitly explained ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/f720f0dbcf012d6c984dbbefa0875ef9840458c6/src/truetype/ttinterp.c",
                "https://android.googlesource.com/platform/external/freetype/+/3053d1b9db55099918843889e4809ce97483ca9f/src/truetype/ttobjs.c",
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
            "opcode_handler_anchor_count": 8,
            "lifecycle_or_context_anchor_count": 2,
            "projection_anchor_count": 1,
            "register_detail_only_difference_count": sum(
                anchor["metric_differences"] == ["register_detail_hash"]
                for anchor in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates had no surviving source names.",
            "The ENDF, FDEF, IDEF, DELTAP, DELTAC, SHC, SHP, and ISECT rows are tied directly to TT_RunIns opcode cases.",
            "Dual_Project is identified by Compute_Funcs installing the source helper in the dual-projection callback slot; its small register-detail difference is compiler allocation only.",
            "tt_size_done and TT_Load_Context are identified from the size and execution-context lifecycle paths.",
            "The shared 0xd470 address displacement, matching pseudocode, and exact or register-detail-only metrics support direct translation for this block.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
