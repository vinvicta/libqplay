#!/usr/bin/env python3
"""Create the reviewed Spectron FreeType ``tt_size_reset`` anchor."""

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


SPEC = {
    "source_ea": "0x25eaf8",
    "target_ea": "0x26bf68",
    "source_name": "tt_size_reset",
    "proposed_name": "v18_tt_size_reset",
    "role": "TrueType size-metrics reset helper",
    "source_file": "src/truetype/ttobjs.c",
    "topology": (
        "the TrueType driver class stores this body in its size_reset slot; "
        "the helper requests current face metrics, copies the requested width "
        "and height, recomputes scaled ppem metrics, and marks the TrueType "
        "size metrics valid"
    ),
    "source_data": (
        "TrueType driver class size_reset slot at 0x36d3e0, "
        "the eighth qword in the class record beginning at 0x36d3a0"
    ),
    "target_data": (
        "TrueType driver class size_reset slot at 0x3801b0, "
        "the eighth qword in the class record beginning at 0x380170"
    ),
    "operation": (
        "resets TrueType size metrics after a size or resolution change, "
        "scaling the horizontal and vertical metrics and selecting the active "
        "ppem dimension"
    ),
    "reference": (
        "https://android.googlesource.com/platform/external/freetype/%2B/"
        "6da2e02232e1bcf31cfb78894d46c7902b90ee9f/src/truetype/ttobjs.c"
    ),
}


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


def build_anchor(original: dict, spectron: dict) -> dict:
    original_metrics = metrics(original)
    spectron_metrics = metrics(spectron)
    differences = [
        field
        for field in METRIC_FIELDS
        if original_metrics[field] != spectron_metrics[field]
    ]
    if not original.get("is_default_name"):
        raise ValueError("source candidate is not a default name")
    if not spectron.get("is_default_name"):
        raise ValueError("target candidate is not a default name")
    if differences:
        raise ValueError("unexpected metric differences: %s" % differences)

    return {
        "original_ea": SPEC["source_ea"],
        "original_name": original["name"],
        "original_current_name": original["name"],
        "original_default_name": True,
        "original_metrics": original_metrics,
        "original_function_end": original.get("end_ea"),
        "original_string_refs": original.get("string_refs", []),
        "original_direct_call_names": original.get("direct_call_names", []),
        "spectron_ea": SPEC["target_ea"],
        "spectron_current_name": spectron["name"],
        "spectron_default_name": True,
        "spectron_metrics": spectron_metrics,
        "spectron_function_end": spectron.get("end_ea"),
        "spectron_string_refs": spectron.get("string_refs", []),
        "spectron_direct_call_names": spectron.get("direct_call_names", []),
        "proposed_name": SPEC["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-freetype-tt-size-reset-anchor",
        "family": "FreeType TrueType size-management helpers",
        "source_name": SPEC["source_name"],
        "source_role": SPEC["role"],
        "source_file": SPEC["source_file"],
        "topology": SPEC["topology"],
        "source_data": SPEC["source_data"],
        "target_data": SPEC["target_data"],
        "source_component": "FreeType TrueType driver",
        "target_component": "stripped Spectron FreeType TrueType driver",
        "source_basis": (
            "matching pseudocode, corresponding TrueType driver class slot, "
            "official FreeType source role, and exact ARM64 feature metrics"
        ),
        "operation": SPEC["operation"],
        "reference_sources": [SPEC["reference"]],
        "normalized_shape_equal": True,
        "full_metric_equal": True,
        "metric_differences": [],
        "semantic_match_already_present": False,
        "evidence": [
            "The source and target TrueType driver class records point to the matching body in their size_reset slot.",
            "The target pointer table begins at 0x380170, and its size_reset pointer at 0x3801b0 is the source pointer at 0x36d3e0 plus the shared 0xd470 relocation.",
            "The source and target pseudocode perform the same FT_Request_Metrics, FT_DivFix, FT_MulFix, and FT_MulDiv scaling sequence and set the same valid flag.",
            "The official FreeType ttobjs.c source defines this body as tt_size_reset and gives the matching size-metrics reset contract.",
            "All recorded ARM64 feature metrics are exact, including instruction shape, call topology, and register-detail allocation.",
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
    anchor = build_anchor(
        original_by_ea[SPEC["source_ea"]],
        spectron_by_ea[SPEC["target_ea"]],
    )
    result = {
        "schema_version": 1,
        "artifact": "spectron_freetype_tt_size_reset_manual_translation_anchor_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the FreeType TrueType size reset helper",
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
            "source_region": "0x25eaf8 through 0x25ec84",
            "target_region": "0x26bf68 through 0x26c0f4",
            "address_displacement": "0xd470",
            "source_driver_class": "TrueType driver class record beginning at 0x36d3a0",
            "target_driver_class": "TrueType driver class record beginning at 0x380170",
            "source_size_reset_slot": "0x36d3e0",
            "target_size_reset_slot": "0x3801b0",
            "role_resolution": (
                "matching TrueType driver class slot, matching pseudocode, "
                "official FreeType source role, and exact ARM64 feature metrics"
            ),
            "name_policy": "v18-prefixed semantic role because the target candidate retained only an IDA auto-generated name",
            "reference_sources": [SPEC["reference"]],
        },
        "summary": {
            "anchor_count": 1,
            "unique_target_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": 1,
            "source_default_name_count": 1,
            "normalized_shape_exact_count": 1,
            "full_metric_exact_count": 1,
            "register_detail_only_count": 0,
            "tt_size_reset_count": 1,
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed FreeType role label, not a claim that the stripped target retained its original debug symbol.",
            "The driver-class pointer table is stronger than a displacement-only match because the source and target records select the same size_reset slot while the surrounding class fields relocate together.",
            "The target body is a complete feature-for-feature match for the source body, so v18_tt_size_reset is a high-confidence semantic translation.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
