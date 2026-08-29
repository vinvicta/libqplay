#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType autofit callbacks."""

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
        "source_ea": "0x267ecc",
        "target_ea": "0x27533c",
        "source_name": "tt_driver_init",
        "proposed_name": "v18_tt_driver_init",
        "role": "TrueType driver module initializer",
        "source_file": "src/truetype/ttobjs.c",
        "topology": "the TrueType module class stores this callback at 0x36d360; it creates the interpreter context and returns TT_Err_Could_Not_Find_Context when that fails",
        "source_data": "TrueType module class record at 0x36d330 + 0x30",
        "target_data": "corresponding stripped TrueType module class record at 0x380100 + 0x30",
        "operation": "creates the TrueType execution context used by the driver module",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/truetype/ttobjs.c",
    },
    {
        "source_ea": "0x267ef0",
        "target_ea": "0x275360",
        "source_name": "af_dummy_hints_init",
        "proposed_name": "v18_af_dummy_hints_init",
        "role": "dummy autofit hint-state initializer",
        "source_file": "src/autofit/afdummy.c",
        "topology": "the dummy script class stores this callback at 0x35e720; the callback installs the active metrics object and its scaler flags into the hint state",
        "source_data": "af_dummy_script_class at 0x35e6f0 + 0x30",
        "target_data": "corresponding stripped dummy script class at 0x3714a0 + 0x30",
        "operation": "initializes the glyph-hint state for the no-specialized-hinting fallback",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/f128616796ff176d99eb03c948fadf68161d5855/src/autofit/afdummy.c",
    },
    {
        "source_ea": "0x267f08",
        "target_ea": "0x275378",
        "source_name": "af_dummy_hints_apply",
        "proposed_name": "v18_af_dummy_hints_apply",
        "role": "dummy autofit outline application callback",
        "source_file": "src/autofit/afdummy.c",
        "topology": "the dummy script class stores this callback at 0x35e728; the old fallback implementation is a successful no-op",
        "source_data": "af_dummy_script_class at 0x35e6f0 + 0x38",
        "target_data": "corresponding stripped dummy script class at 0x3714a8 + 0x38",
        "operation": "accepts an outline without applying script-specific point adjustments",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/f128616796ff176d99eb03c948fadf68161d5855/src/autofit/afdummy.c",
    },
    {
        "source_ea": "0x267f10",
        "target_ea": "0x275380",
        "source_name": "af_latin_hints_init",
        "proposed_name": "v18_af_latin_hints_init",
        "role": "Latin autofit hint-state initializer",
        "source_file": "src/autofit/aflatin.c",
        "topology": "the Latin script class stores this callback at 0x35e6e0; it copies the active Latin metrics and render-mode-derived flags into the hint state",
        "source_data": "af_latin_script_class at 0x35e6b0 + 0x30",
        "target_data": "corresponding stripped Latin script class at 0x371460 + 0x30",
        "operation": "initializes Latin glyph hinting state from the scaled Latin metrics",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/aflatin.c",
    },
    {
        "source_ea": "0x267f90",
        "target_ea": "0x275400",
        "source_name": "af_latin2_hints_init",
        "proposed_name": "v18_af_latin2_hints_init",
        "role": "Latin2 autofit hint-state initializer",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the Latin2 script class stores this callback at 0x35e6a0; it copies the active Latin2 metrics and render-mode-derived flags into the hint state",
        "source_data": "af_latin2_script_class at 0x35e670 + 0x30",
        "target_data": "corresponding stripped Latin2 script class at 0x371420 + 0x30",
        "operation": "initializes Latin2 glyph hinting state from the scaled Latin2 metrics",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
    },
    {
        "source_ea": "0x268010",
        "target_ea": "0x275480",
        "source_name": "af_cjk_metrics_scale",
        "proposed_name": "v18_af_cjk_metrics_scale",
        "role": "CJK autofit metrics scaler",
        "source_file": "src/autofit/afcjk.c",
        "topology": "the CJK script class stores this callback at 0x35e650; the callback copies the scaler and updates both horizontal and vertical metric axes",
        "source_data": "af_cjk_script_class at 0x35e630 + 0x20",
        "target_data": "corresponding stripped CJK script class at 0x3713e0 + 0x20",
        "operation": "scales CJK autofit metrics for the requested face, render mode, and device size",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/afcjk.c",
    },
    {
        "source_ea": "0x268050",
        "target_ea": "0x2754c0",
        "source_name": "af_cjk_hints_init",
        "proposed_name": "v18_af_cjk_hints_init",
        "role": "CJK autofit hint-state initializer",
        "source_file": "src/autofit/afcjk.c",
        "topology": "the CJK script class stores this callback at 0x35e660; it installs the CJK scaler values and render-mode flags into the hint state",
        "source_data": "af_cjk_script_class at 0x35e630 + 0x30",
        "target_data": "corresponding stripped CJK script class at 0x3713f0 + 0x30",
        "operation": "initializes CJK glyph hinting state from the scaled CJK metrics",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/afcjk.c",
    },
    {
        "source_ea": "0x2680c0",
        "target_ea": "0x275530",
        "source_name": "af_latin2_hints_compute_segments",
        "proposed_name": "v18_af_latin2_hints_compute_segments",
        "role": "Latin2 outline segment extraction helper",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the helper is called once per dimension by af_latin2_metrics_init_widths at 0x26b198 and by af_latin2_hints_apply at 0x26df5c; it builds and sorts the 88-byte segment records",
        "source_data": "af_latin2_metrics_init_widths at 0x26b198 and af_latin2_hints_apply at 0x26df5c call the helper at 0x26b3a8, 0x26e2dc, and 0x26e7d8",
        "target_data": "corresponding calls from 0x278608 and 0x27b3cc reach the target at 0x278818, 0x27b74c, and 0x27bc48",
        "operation": "walks an outline, classifies directional runs, and creates the segment records used by Latin2 stem and edge analysis",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
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
    if differences:
        raise ValueError(
            "%s unexpectedly differs in %s" % (spec["source_name"], differences)
        )
    if not original.get("is_default_name"):
        raise ValueError("source candidate is not a default name: %s" % spec["source_name"])
    if not spectron.get("is_default_name"):
        raise ValueError("target candidate is not a default name: %s" % spec["source_name"])

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
        "match_kind": "manual-freetype-autofit-role-anchor",
        "family": "FreeType autofit callbacks and Latin2 segment analysis",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType autofit module",
        "target_component": "stripped Spectron FreeType autofit module",
        "source_basis": "callback-table or caller topology, matching pseudocode, official FreeType source role, and exact ARM64 feature metrics",
        "operation": spec["operation"],
        "reference_sources": [spec["reference"]],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in METRIC_FIELDS[:-1]
        ),
        "full_metric_equal": True,
        "metric_differences": [],
        "semantic_match_already_present": False,
        "evidence": [
            "The original callback table or caller graph identifies the exact FreeType role.",
            "The stripped target retains the same callback or caller topology at the translated address.",
            "The official FreeType source defines the matching callback or outline-analysis operation.",
            "All recorded ARM64 feature metrics match exactly between source and target.",
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
        anchors.append(
            build_anchor(
                original_by_ea[spec["source_ea"]],
                spectron_by_ea[spec["target_ea"]],
                spec,
            )
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_freetype_autofit_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for eight FreeType autofit callbacks and Latin2 segment-analysis helpers",
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
            "source_region": "0x267ecc through 0x268608",
            "target_region": "0x27533c through 0x275a78",
            "address_displacement": "0xd470",
            "role_resolution": "FreeType callback-table records, caller topology, matching pseudocode, official source roles, and exact ARM64 feature metrics",
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
            "callback_anchor_count": 7,
            "segment_analysis_anchor_count": 1,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target static helpers retained only IDA auto-generated names.",
            "The first seven rows are callback entries in the TrueType and autofit class records. Their table slots distinguish similar short bodies that would be ambiguous from pseudocode alone.",
            "The final row is the Latin2 segment builder. Its calls from both the Latin2 metrics-width probe and the full glyph hinting callback identify it as af_latin2_hints_compute_segments rather than the later edge builder.",
            "The source and target bodies match exactly in the recorded feature set, including register-detail hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
