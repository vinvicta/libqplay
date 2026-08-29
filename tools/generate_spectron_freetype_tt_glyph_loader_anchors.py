#!/usr/bin/env python3
"""Create reviewed anchors for the next Spectron TrueType glyph block."""

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
        "source_ea": "0x262db4",
        "target_ea": "0x270224",
        "source_name": "load_truetype_glyph",
        "proposed_name": "v18_load_truetype_glyph",
        "role": "internal recursive TrueType glyph loader",
        "source_file": "src/truetype/ttgload.c",
        "topology": "TT_Load_Glyph invokes the helper for the main glyph-loading loop, and the helper recursively loads composite components",
        "source_data": "the helper checks the component recursion depth and glyph index, reads glyph metrics and the loca/glyf frame, dispatches simple or composite outline loading, and recursively loads component glyphs",
        "target_data": "the target preserves the recursion guard, glyph metrics callbacks, loca/glyf stream access, simple and composite paths, component recursion, and glyph-loader bookkeeping",
        "operation": "loads one TrueType glyph and its composite components into the active glyph loader",
    },
    {
        "source_ea": "0x263d1c",
        "target_ea": "0x27118c",
        "source_name": "TT_Load_Glyph",
        "proposed_name": "v18_TT_Load_Glyph",
        "role": "TrueType glyph-slot load implementation",
        "source_file": "src/truetype/ttgload.c",
        "topology": "the driver Load_Glyph callback passes the validated slot and size into this implementation, which initializes the loader and calls load_truetype_glyph",
        "source_data": "the function validates size and load flags, initializes the TrueType loader and execution context, loads the glyph, copies the outline or composite data into the slot, computes the metrics, and releases temporary state",
        "target_data": "the target preserves loader allocation and reset, execution-context setup, glyph loading, outline or composite-slot transfer, metric calculation, and cleanup/error paths",
        "operation": "loads and finalizes a TrueType glyph for a requested size and slot",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x264f78",
        "target_ea": "0x2723e8",
        "source_name": "tt_glyph_load",
        "proposed_name": "v18_tt_glyph_load",
        "role": "TrueType driver Load_Glyph callback",
        "source_file": "src/truetype/ttdriver.c",
        "topology": "the TrueType driver class exposes this callback; it validates the size, face, and glyph index, normalizes load flags, and calls TT_Load_Glyph",
        "source_data": "the callback checks the size and face handles, rejects an out-of-range glyph index, adds the required no-bitmap/no-scale/no-hinting flags, and forwards the request to TT_Load_Glyph",
        "target_data": "the target preserves the handle and glyph-index checks, load-flag normalization, and argument order used to call the larger TT_Load_Glyph implementation",
        "operation": "validates a driver glyph-load request and forwards it into the TrueType glyph loader",
    },
    {
        "source_ea": "0x264fcc",
        "target_ea": "0x27243c",
        "source_name": "Ins_SxVTL",
        "proposed_name": "v18_Ins_SxVTL",
        "role": "shared TrueType SPVTL/SFVTL vector-construction helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns calls the helper from opcode cases 0x06, 0x07, 0x08, and 0x09 for SPVTL and SFVTL",
        "source_data": "the helper reads two points from the selected zone, computes their vector, applies the clockwise or counter-clockwise opcode variant, normalizes it, and writes the resulting fixed-point vector",
        "target_data": "the target preserves the point-zone bounds checks, vector subtraction and rotation, fixed-point normalization, and error result used by both SPVTL and SFVTL handlers",
        "operation": "constructs and normalizes the projection or freedom vector defined by two outline points",
    },
    {
        "source_ea": "0x26521c",
        "target_ea": "0x27268c",
        "source_name": "Ins_CALL",
        "proposed_name": "v18_Ins_CALL",
        "role": "TrueType CALL opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns dispatches opcode 0x2b to the handler after popping the function index",
        "source_data": "the handler resolves the requested function definition, checks that it is active and that the call stack has room, records the return location, and enters the function code range",
        "target_data": "the target preserves function-definition lookup, active-definition validation, call-stack overflow handling, return-record setup, code-range transfer, and interpreter step-state update",
        "operation": "calls a previously defined TrueType function",
    },
    {
        "source_ea": "0x265370",
        "target_ea": "0x2727e0",
        "source_name": "Ins_LOOPCALL",
        "proposed_name": "v18_Ins_LOOPCALL",
        "role": "TrueType LOOPCALL opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns dispatches opcode 0x2a to the handler with the loop count and function index on the operand stack",
        "source_data": "the handler resolves the function definition, checks the active definition and call-stack capacity, records the requested iteration count and return location, and enters the function code range",
        "target_data": "the target preserves the loop-count and function-index handling, definition lookup, call-record initialization, stack checks, and code-range transfer",
        "operation": "calls a TrueType function repeatedly for a requested loop count",
    },
    {
        "source_ea": "0x2654d4",
        "target_ea": "0x272944",
        "source_name": "Ins_UNKNOWN",
        "proposed_name": "v18_Ins_UNKNOWN",
        "role": "TrueType undefined-opcode and IDEF dispatch handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "TT_RunIns reaches the helper from its undefined-opcode fallback after the normal opcode ranges and consults the IDEF table",
        "source_data": "the handler scans active instruction definitions for the current opcode, records a return frame, transfers control to the custom instruction body, or reports an invalid opcode",
        "target_data": "the target preserves the active-IDEF scan, call-stack overflow handling, return-record setup, code-range transfer, and invalid-opcode result",
        "operation": "dispatches an instruction redefined through TrueType IDEF or reports an unknown opcode",
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
            "%s differs unexpectedly in %s"
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
        "match_kind": "manual-freetype-tt-glyph-loader-role-anchor",
        "family": "FreeType TrueType glyph loading and interpreter helpers",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType TrueType glyph loader and interpreter",
        "target_component": "stripped Spectron FreeType TrueType glyph loader and interpreter",
        "source_basis": "matching source and target pseudocode, caller or callback topology, official FreeType source role, and exact ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in METRIC_FIELDS[:-1]
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "expected_metric_differences": expected_differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The source candidate is the matching FreeType role in the original build.",
            "The target candidate has the same displacement and matching caller or callback topology.",
            "The official FreeType TrueType source defines the matching role and operation.",
            "The complete recorded ARM64 feature metric set is identical between source and target, or differs only in the explicitly accepted register-allocation detail.",
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
        "artifact": "spectron_freetype_tt_glyph_loader_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TrueType glyph-loader and remaining interpreter helper block",
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
            "source_true_type_region": "source candidates from 0x262db4 through 0x2655e8",
            "target_true_type_region": "the parallel target candidates at the source address plus 0xd470",
            "role_resolution": "matching pseudocode, TT_Load_Glyph and tt_glyph_load call topology, TT_RunIns opcode or fallback topology, official FreeType source roles, and exact feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/truetype/ttgload.c",
                "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/truetype/ttdriver.c",
                "https://android.googlesource.com/platform/external/freetype/+/aeb407daf3711a10a27f3bc2223c5eb05158076e/src/truetype/ttinterp.c",
            ],
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({anchor["spectron_ea"] for anchor in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(anchor["spectron_default_name"] for anchor in anchors),
            "source_default_name_count": sum(anchor["original_default_name"] for anchor in anchors),
            "normalized_shape_exact_count": len(anchors),
            "full_metric_exact_count": sum(
                anchor["full_metric_equal"] for anchor in anchors
            ),
            "glyph_loader_anchor_count": 3,
            "interpreter_helper_anchor_count": 4,
            "register_detail_only_difference_count": sum(
                anchor["metric_differences"] == ["register_detail_hash"]
                for anchor in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates retained only IDA auto-generated names.",
            "The three glyph-loader rows are tied to the tt_glyph_load callback, TT_Load_Glyph implementation, and recursive load_truetype_glyph path.",
            "The four interpreter rows are tied to TT_RunIns opcode cases 0x06 through 0x09, 0x2a, and 0x2b, plus its undefined-opcode IDEF fallback.",
            "The shared 0xd470 address displacement, matching pseudocode, matching topology, and exact metrics support direct translation for this block.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
