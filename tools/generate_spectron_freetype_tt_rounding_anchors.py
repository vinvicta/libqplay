#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType TrueType rounding helpers."""

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
        "source_ea": "0x25fe38",
        "target_ea": "0x26d2a8",
        "source_name": "Round_To_Grid",
        "proposed_name": "v18_Round_To_Grid",
        "role": "TrueType grid-rounding callback",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Round for TT_Round_To_Grid",
        "source_data": "the callback rounds compensated positive and negative F26Dot6 distances to the pixel grid",
        "target_data": "the parallel target interpreter retains the same compensated grid-rounding callback",
        "operation": "rounds a compensated distance to the pixel grid while preserving the sign and clamping an invalid result",
    },
    {
        "source_ea": "0x25fe7c",
        "target_ea": "0x26d2ec",
        "source_name": "Round_To_Half_Grid",
        "proposed_name": "v18_Round_To_Half_Grid",
        "role": "TrueType half-grid rounding callback",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Round for TT_Round_To_Half_Grid",
        "source_data": "the callback floors compensated positive and negative F26Dot6 distances and offsets the result by half a pixel",
        "target_data": "the parallel target interpreter retains the same compensated half-grid callback",
        "operation": "rounds a compensated distance to the half-pixel grid with signed clamping",
    },
    {
        "source_ea": "0x25feb8",
        "target_ea": "0x26d328",
        "source_name": "Round_Down_To_Grid",
        "proposed_name": "v18_Round_Down_To_Grid",
        "role": "TrueType downward grid-rounding callback",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Round for TT_Round_Down_To_Grid",
        "source_data": "the callback floors the compensated distance to the pixel grid for both signs",
        "target_data": "the parallel target interpreter retains the same downward grid-rounding callback",
        "operation": "rounds a compensated distance down to the pixel grid and clamps an invalid signed result",
    },
    {
        "source_ea": "0x25fef4",
        "target_ea": "0x26d364",
        "source_name": "Round_Up_To_Grid",
        "proposed_name": "v18_Round_Up_To_Grid",
        "role": "TrueType upward grid-rounding callback",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Round for TT_Round_Up_To_Grid",
        "source_data": "the callback ceils the compensated distance to the pixel grid for both signs",
        "target_data": "the parallel target interpreter retains the same upward grid-rounding callback",
        "operation": "rounds a compensated distance up to the pixel grid and clamps an invalid signed result",
    },
    {
        "source_ea": "0x25ff38",
        "target_ea": "0x26d3a8",
        "source_name": "Round_To_Double_Grid",
        "proposed_name": "v18_Round_To_Double_Grid",
        "role": "TrueType double-grid rounding callback",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Round for TT_Round_To_Double_Grid",
        "source_data": "the callback rounds the compensated distance to the 32-unit double grid",
        "target_data": "the parallel target interpreter retains the same compensated double-grid callback",
        "operation": "rounds a compensated F26Dot6 distance to the double pixel grid",
    },
    {
        "source_ea": "0x25ff7c",
        "target_ea": "0x26d3ec",
        "source_name": "Round_Super",
        "proposed_name": "v18_Round_Super",
        "role": "TrueType super-rounding callback",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Round for TT_Round_Super",
        "source_data": "the callback uses the execution context phase, threshold, and period fields to round a compensated distance",
        "target_data": "the parallel target interpreter retains the same execution-context super-rounding callback",
        "operation": "super-rounds a compensated distance using the interpreter's configured phase, threshold, and period",
    },
    {
        "source_ea": "0x25ffe8",
        "target_ea": "0x26d458",
        "source_name": "Round_Super_45",
        "proposed_name": "v18_Round_Super_45",
        "role": "TrueType precise super-rounding callback",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Round for TT_Round_Super_45",
        "source_data": "the callback uses division and multiplication by the execution context period for the higher-precision super-round mode",
        "target_data": "the parallel target interpreter retains the same precise super-rounding callback",
        "operation": "super-rounds a compensated distance with period arithmetic for the 45-degree mode",
    },
    {
        "source_ea": "0x260050",
        "target_ea": "0x26d4c0",
        "source_name": "Compute_Funcs",
        "proposed_name": "v18_Compute_Funcs",
        "role": "TrueType interpreter callback selector",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "called when the graphics state changes the projection or freedom vectors",
        "source_data": "the helper installs projection, movement, and original-coordinate callbacks based on the current vectors and caches the scaling state",
        "target_data": "the target helper installs the already translated parallel callbacks, including v18_Direct_Move and v18_Project_x",
        "operation": "selects the interpreter's projection and movement function pointers for the active graphics-state vectors",
        "expected_differences": ["register_detail_hash"],
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
        "match_kind": "manual-freetype-tt-rounding-role-anchor",
        "family": "FreeType TrueType interpreter rounding and callback selection",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType TrueType interpreter module",
        "target_component": "stripped Spectron FreeType TrueType interpreter",
        "source_basis": "TrueType rounding or callback-selection topology, matching pseudocode, official FreeType source role, and exact or explicitly explained ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The original TrueType interpreter topology identifies the rounding callback or callback-selection role.",
            "The target code retains the corresponding parallel callback or execution-context setup at the translated location.",
            "The official FreeType TrueType source defines the matching helper name and operation.",
            "The source and target ARM64 feature records match completely, or differ only in the recorded register-allocation detail accepted for this anchor.",
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
        "artifact": "spectron_freetype_tt_rounding_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for FreeType TrueType rounding callbacks and callback selection",
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
            "source_true_type_region": "0x25fe38-0x260050 in the source FreeType TrueType interpreter region",
            "target_true_type_region": "the parallel target region at the source address plus 0xd470",
            "role_resolution": "Compute_Round callback selection, Compute_Funcs callback installation, matching pseudocode, official FreeType source roles, and exact or explicitly explained ARM64 feature metrics",
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
            "rounding_helper_anchor_count": 7,
            "interpreter_setup_anchor_count": 1,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates had no surviving source names.",
            "The first seven anchors cover the seven remaining TrueType rounding callbacks in the source's Round_* family; the already translated Round_None helper completes the eight standard modes.",
            "The final anchor is Compute_Funcs, which installs the projection and movement callbacks used by the interpreter.",
            "The exact or explicitly explained metric matches, the contiguous source-to-target displacement, and the matching callback topology support a direct translation for this FreeType block.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
