#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType TrueType state opcodes."""

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
        "source_ea": "0x2602a4",
        "target_ea": "0x26d714",
        "source_name": "Ins_SZP0",
        "proposed_name": "v18_Ins_SZP0",
        "role": "TrueType SZP0 zone-pointer opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for SZP0 at opcode 0x13",
        "source_data": "the handler selects the twilight or glyph zone for zp0 and stores the matching graphics-state zone selector",
        "target_data": "the target opcode dispatch preserves the same zp0 structure assignment and selector update",
        "operation": "sets zone pointer 0 to either the twilight or glyph zone and updates GEP0",
    },
    {
        "source_ea": "0x2602fc",
        "target_ea": "0x26d76c",
        "source_name": "Ins_SZP1",
        "proposed_name": "v18_Ins_SZP1",
        "role": "TrueType SZP1 zone-pointer opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for SZP1 at opcode 0x14",
        "source_data": "the handler selects the twilight or glyph zone for zp1 and stores the matching graphics-state zone selector",
        "target_data": "the target opcode dispatch preserves the same zp1 structure assignment and selector update",
        "operation": "sets zone pointer 1 to either the twilight or glyph zone and updates GEP1",
    },
    {
        "source_ea": "0x260354",
        "target_ea": "0x26d7c4",
        "source_name": "Ins_SZP2",
        "proposed_name": "v18_Ins_SZP2",
        "role": "TrueType SZP2 zone-pointer opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for SZP2 at opcode 0x15",
        "source_data": "the handler selects the twilight or glyph zone for zp2 and stores the matching graphics-state zone selector",
        "target_data": "the target opcode dispatch preserves the same zp2 structure assignment and selector update",
        "operation": "sets zone pointer 2 to either the twilight or glyph zone and updates GEP2",
    },
    {
        "source_ea": "0x2603ac",
        "target_ea": "0x26d81c",
        "source_name": "Ins_SZPS",
        "proposed_name": "v18_Ins_SZPS",
        "role": "TrueType SZPS zone-pointer opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for SZPS at opcode 0x16",
        "source_data": "the handler selects one zone, copies it into all three zone pointers, and stores the selector in all three graphics-state fields",
        "target_data": "the target opcode dispatch preserves the same all-zone structure copies and selector updates",
        "operation": "sets zp0, zp1, and zp2 to the selected twilight or glyph zone and updates GEP0, GEP1, and GEP2",
    },
    {
        "source_ea": "0x260468",
        "target_ea": "0x26d8d8",
        "source_name": "Ins_ALIGNRP",
        "proposed_name": "v18_Ins_ALIGNRP",
        "role": "TrueType AlignRP opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for AlignRP at opcode 0x3c",
        "source_data": "the handler loops over stack-supplied points, projects each point against rp0, and moves it in zp1 by the negative projected distance",
        "target_data": "the target handler retains the same loop, projection callback, zp1 movement callback, and error-state cleanup",
        "operation": "aligns each selected point in zp1 to the reference point rp0 using the active projection and movement callbacks",
    },
    {
        "source_ea": "0x260590",
        "target_ea": "0x26da00",
        "source_name": "Ins_UTP",
        "proposed_name": "v18_Ins_UTP",
        "role": "TrueType UTP opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for UTP at opcode 0x29",
        "source_data": "the handler clears the touch bits selected by the active freedom vector from a point in zp0",
        "target_data": "the target handler retains the same point-bound check, vector-dependent touch mask, and tag update",
        "operation": "untouches the selected point's x and y coordinates according to the active freedom vector",
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
        "match_kind": "manual-freetype-tt-opcode-state-role-anchor",
        "family": "FreeType TrueType zone-pointer and point-state opcode handlers",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType TrueType interpreter module",
        "target_component": "stripped Spectron FreeType TrueType interpreter",
        "source_basis": "opcode dispatch topology, matching pseudocode, official FreeType source role, and exact or explicitly explained ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The original TrueType opcode dispatch identifies the handler and its opcode contract.",
            "The target TT_RunIns dispatch reaches the corresponding parallel handler with the same state fields and callback calls.",
            "The official FreeType TrueType source defines the matching handler name and operation.",
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
        "artifact": "spectron_freetype_tt_opcode_state_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for FreeType TrueType zone-pointer and point-state opcode handlers",
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
            "source_true_type_region": "0x2602a4-0x260590 in the source FreeType TrueType interpreter opcode region",
            "target_true_type_region": "the parallel target region at the source address plus 0xd470",
            "role_resolution": "TT_RunIns dispatch topology, matching pseudocode, official FreeType source roles, and exact ARM64 feature metrics",
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
            "zone_pointer_anchor_count": 4,
            "point_state_anchor_count": 2,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates had no surviving source names.",
            "The first four anchors are the contiguous SZP0, SZP1, SZP2, and SZPS zone-pointer handlers.",
            "The final two anchors cover AlignRP point alignment and UTP touch-bit clearing.",
            "The exact metric matches, contiguous source-to-target displacement, and matching TT_RunIns dispatch topology support a direct translation for this FreeType block.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
