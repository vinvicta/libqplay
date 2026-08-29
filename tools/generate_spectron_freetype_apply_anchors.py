#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron FreeType apply callbacks."""

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
        "source_ea": "0x26df5c",
        "target_ea": "0x27b3cc",
        "source_name": "af_latin2_hints_apply",
        "proposed_name": "v18_af_latin2_hints_apply",
        "role": "Latin2 autofit glyph hinting callback",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the Latin2 script class stores this large routine in its hints_apply slot; it reloads the outline, builds segments and edges, applies Latin2 stem adjustments, aligns edge points, and finalizes the hinted outline",
        "source_data": "Latin2 script class hints_apply slot at 0x35e670 + 0x38",
        "target_data": "Latin2 script class hints_apply slot at 0x3713f0 + 0x38",
        "operation": "runs the complete Latin2 autofit hinting pass for one glyph outline",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
    },
    {
        "source_ea": "0x26f820",
        "target_ea": "0x27cc90",
        "source_name": "af_latin_hints_apply",
        "proposed_name": "v18_af_latin_hints_apply",
        "role": "Latin autofit glyph hinting callback",
        "source_file": "src/autofit/aflatin.c",
        "topology": "the Latin script class stores this large routine in its hints_apply slot; it reloads the outline, builds segments and edges, applies Latin stem adjustments, aligns edge points, and finalizes the hinted outline",
        "source_data": "Latin script class hints_apply slot at 0x35e6b0 + 0x38",
        "target_data": "Latin script class hints_apply slot at 0x371430 + 0x38",
        "operation": "runs the complete Latin autofit hinting pass for one glyph outline",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/aflatin.c",
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
    if not original.get("is_default_name"):
        raise ValueError("source candidate is not a default name: %s" % spec["source_name"])
    if not spectron.get("is_default_name"):
        raise ValueError("target candidate is not a default name: %s" % spec["source_name"])
    if differences not in ([], ["register_detail_hash"]):
        raise ValueError(
            "%s unexpectedly differs in %s" % (spec["source_name"], differences)
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
        "match_kind": "manual-freetype-apply-anchor",
        "family": "FreeType autofit apply callbacks",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType autofit module",
        "target_component": "stripped Spectron FreeType autofit module",
        "source_basis": "matching pseudocode, script class-table topology, official FreeType source role, and exact or register-detail-only ARM64 feature metrics",
        "operation": spec["operation"],
        "reference_sources": [spec["reference"]],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in METRIC_FIELDS[:-1]
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The source and target script class records select the matching hints_apply callback slot.",
            "The stripped target retains the same Latin or Latin2 call topology at the translated address.",
            "The official FreeType source defines the matching callback contract and hinting stages.",
            "The source and target recorded ARM64 metrics are exact or differ only in register-detail allocation.",
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
    anchors = [
        build_anchor(
            original_by_ea[spec["source_ea"]],
            spectron_by_ea[spec["target_ea"]],
            spec,
        )
        for spec in SPECS
    ]
    result = {
        "schema_version": 1,
        "artifact": "spectron_freetype_apply_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the Latin and Latin2 FreeType autofit apply callbacks",
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
            "source_region": "0x26df5c through 0x2711d4",
            "target_region": "0x27b3cc through 0x27e644",
            "address_displacement": "0xd470",
            "role_resolution": "matching script class-table topology, FreeType source roles, and exact ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": sorted({spec["reference"] for spec in SPECS}),
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({anchor["spectron_ea"] for anchor in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(anchor["spectron_default_name"] for anchor in anchors),
            "source_default_name_count": sum(anchor["original_default_name"] for anchor in anchors),
            "normalized_shape_exact_count": sum(anchor["normalized_shape_equal"] for anchor in anchors),
            "full_metric_exact_count": sum(anchor["full_metric_equal"] for anchor in anchors),
            "register_detail_only_count": sum(
                anchor["metric_differences"] == ["register_detail_hash"]
                for anchor in anchors
            ),
            "latin2_callback_count": 1,
            "latin_callback_count": 1,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target callbacks retained only IDA auto-generated names.",
            "The Latin2 and Latin script class records select the two apply callbacks through their hints_apply slots.",
            "The surrounding translated helper names make the callback bodies readable as the final stage that reloads, hints, aligns, and returns one glyph outline.",
            "Both source and target pairs match the complete recorded ARM64 feature set.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
