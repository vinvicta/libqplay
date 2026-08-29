#!/usr/bin/env python3
"""Create reviewed anchors for the next Spectron FreeType autofit block."""

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
        "source_ea": "0x268608",
        "target_ea": "0x275a78",
        "source_name": "af_latin2_hints_link_segments",
        "proposed_name": "v18_af_latin2_hints_link_segments",
        "role": "Latin2 segment-linking helper",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the Latin2 hint-application path calls this helper after segment extraction; it scores compatible segments and records reciprocal links or serif relationships",
        "source_data": "called by the Latin2 hint-application routine at 0x26d1f8",
        "target_data": "corresponding calls from the stripped Latin2 hint-application routine at 0x27a668",
        "operation": "scores parallel outline segments and links compatible stem pairs",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
    },
    {
        "source_ea": "0x2688fc",
        "target_ea": "0x275d6c",
        "source_name": "af_latin2_hints_compute_edges",
        "proposed_name": "v18_af_latin2_hints_compute_edges",
        "role": "Latin2 edge-construction helper",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the Latin2 hint-application routine calls this helper after segment linking; it allocates edge records, groups segments, and sets edge direction and serif relationships",
        "source_data": "called by the Latin2 hint-application routine at 0x26d1f8",
        "target_data": "corresponding calls from the stripped Latin2 hint-application routine at 0x27a668",
        "operation": "converts linked outline segments into sorted edge records for Latin2 hinting",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
    },
    {
        "source_ea": "0x268e58",
        "target_ea": "0x2762c8",
        "source_name": "af_glyph_hints_done",
        "proposed_name": "v18_af_glyph_hints_done",
        "role": "autofit glyph-hint buffer destructor",
        "source_file": "src/autofit/afhints.c",
        "topology": "the autofitter load-glyph routine calls this cleanup helper after a glyph pass; it releases the dynamic hint buffers and clears the hint object",
        "source_data": "called from af_autofitter_load_glyph at 0x2711d4",
        "target_data": "corresponding calls from v18_af_autofitter_load_glyph at 0x27e644",
        "operation": "releases temporary points, contours, segments, and edges owned by the glyph-hint object",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/f720f0db/src/autofit/afhints.c",
    },
    {
        "source_ea": "0x268f44",
        "target_ea": "0x2763b4",
        "source_name": "af_loader_load_g",
        "proposed_name": "v18_af_loader_load_g",
        "role": "recursive autofit glyph loader",
        "source_file": "src/autofit/afloader.c",
        "topology": "the five-argument helper calls FT_Load_Glyph, handles transformed and composite outlines, and recursively loads component glyphs while preserving the loader state",
        "source_data": "recursive helper called by itself and by af_loader_load_glyph",
        "target_data": "corresponding recursive helper in the stripped autofit loader block",
        "operation": "loads, transforms, and assembles one glyph or its composite components",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/f128616796ff176d99eb03c948fadf68161d5855/src/autofit/afloader.c",
    },
    {
        "source_ea": "0x2696d4",
        "target_ea": "0x276b44",
        "source_name": "af_glyph_hints_reload",
        "proposed_name": "v18_af_glyph_hints_reload",
        "role": "autofit outline-to-hint reload helper",
        "source_file": "src/autofit/afhints.c",
        "topology": "the helper is shared by the Latin, Latin2, CJK, and generic hint-application paths; it rebuilds point, contour, and segment state from an FT_Outline",
        "source_data": "shared by source hint-application and metrics-width routines",
        "target_data": "corresponding shared helper in the stripped autofit block",
        "operation": "reloads an outline into the autofitter's point and contour representation",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/f720f0db/src/autofit/afhints.c",
    },
    {
        "source_ea": "0x269bf4",
        "target_ea": "0x277064",
        "source_name": "af_latin2_metrics_scale",
        "proposed_name": "v18_af_latin2_metrics_scale",
        "role": "Latin2 autofit metrics scaler",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the Latin2 script class stores this routine in its metrics_scale slot; it updates the scaler, width data, blue-zone values, and scaled axis records",
        "source_data": "af_latin2_script_class at 0x35e670 + 0x20",
        "target_data": "corresponding stripped Latin2 script class at 0x371420 + 0x20",
        "operation": "scales Latin2 style metrics for the active face and render size",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
    },
    {
        "source_ea": "0x269f1c",
        "target_ea": "0x27738c",
        "source_name": "af_latin_metrics_scale",
        "proposed_name": "v18_af_latin_metrics_scale",
        "role": "Latin autofit metrics scaler",
        "source_file": "src/autofit/aflatin.c",
        "topology": "the Latin script class stores this routine in its metrics_scale slot; it updates the scaler, width data, blue-zone values, and scaled axis records",
        "source_data": "af_latin_script_class at 0x35e6b0 + 0x20",
        "target_data": "corresponding stripped Latin script class at 0x371460 + 0x20",
        "operation": "scales Latin style metrics for the active face and render size",
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
        "match_kind": "manual-freetype-autofit-followup-anchor",
        "family": "FreeType autofit follow-up helpers",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType autofit module",
        "target_component": "stripped Spectron FreeType autofit module",
        "source_basis": "matching pseudocode, callback or caller topology, official FreeType source role, and exact or register-detail-only ARM64 feature metrics",
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
            "The original pseudocode and caller or callback topology identify the FreeType role.",
            "The stripped target retains the same role topology at the translated address.",
            "The official FreeType source defines the matching helper or callback contract.",
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
        "artifact": "spectron_freetype_autofit_followup_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the next FreeType autofit helper block",
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
            "source_region": "0x268608 through 0x269f1c",
            "target_region": "0x275a78 through 0x27738c",
            "address_displacement": "0xd470",
            "role_resolution": "matching pseudocode, FreeType callback and caller topology, official source roles, and exact or register-detail-only ARM64 feature metrics",
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
            "callback_anchor_count": 2,
            "loader_anchor_count": 2,
            "segment_analysis_anchor_count": 2,
            "cleanup_anchor_count": 1,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target static helpers retained only IDA auto-generated names.",
            "The Latin2 linker and edge builder are identified by their sequential hint-application calls and matching aflatin2.c roles.",
            "The recursive five-argument loader matches af_loader_load_g, while the outline reload and hint-buffer cleanup helpers match afhints.c.",
            "The Latin2 and Latin scaler rows are selected by the corresponding script class metrics_scale slots.",
            "The source and target bodies match exactly in the recorded feature set except for the approved register-detail difference on af_glyph_hints_done.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
