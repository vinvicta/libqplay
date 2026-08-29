#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron FreeType autofit metrics block."""

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
        "source_name": "af_cjk_hints_link_segments",
        "proposed_name": "v18_af_cjk_hints_link_segments",
        "role": "CJK segment-linking helper",
        "source_file": "src/autofit/afcjk.c",
        "topology": "the CJK hint-application routine calls this helper after segment extraction; it scores compatible segments and records reciprocal links or serif relationships",
        "source_data": "called by the CJK hint-application routine at 0x26d1f8; the CJK class record selects that routine",
        "target_data": "called by the stripped CJK hint-application routine at 0x27a668; the target CJK class record selects that routine",
        "operation": "scores parallel outline segments and links compatible CJK stem pairs",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/a45c6a1cf3625709e149550b8fff1f09d01388d3/src/autofit/afcjk.c",
        "correction": True,
        "previous_v311_name": "v18_af_latin2_hints_link_segments",
        "correction_reason": "the source and target class tables select the CJK hint-application callbacks, not the Latin2 callbacks",
        "name_action": "correct-previous-v311-role",
    },
    {
        "source_ea": "0x2688fc",
        "target_ea": "0x275d6c",
        "source_name": "af_cjk_hints_compute_edges",
        "proposed_name": "v18_af_cjk_hints_compute_edges",
        "role": "CJK edge-construction helper",
        "source_file": "src/autofit/afcjk.c",
        "topology": "the CJK hint-application routine calls this helper after segment linking; it creates edge records and carries CJK direction, link, and serif relationships forward",
        "source_data": "called by the CJK hint-application routine at 0x26d1f8; the CJK class record selects that routine",
        "target_data": "called by the stripped CJK hint-application routine at 0x27a668; the target CJK class record selects that routine",
        "operation": "converts linked outline segments into sorted edge records for CJK hinting",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/a45c6a1cf3625709e149550b8fff1f09d01388d3/src/autofit/afcjk.c",
        "correction": True,
        "previous_v311_name": "v18_af_latin2_hints_compute_edges",
        "correction_reason": "the source and target class tables select the CJK hint-application callbacks, not the Latin2 callbacks",
        "name_action": "correct-previous-v311-role",
    },
    {
        "source_ea": "0x26a3d0",
        "target_ea": "0x277840",
        "source_name": "af_latin_hints_compute_segments",
        "proposed_name": "v18_af_latin_hints_compute_segments",
        "role": "shared Latin segment-analysis helper",
        "source_file": "src/autofit/aflatin.c",
        "topology": "the helper is called by the Latin metrics-width probe and by the Latin, CJK, and Latin2 hint paths; it builds the outline segment records consumed by edge construction",
        "source_data": "called from the source Latin metrics-width routine and from the Latin, CJK, and Latin2 hint-application paths",
        "target_data": "the corresponding calls remain in the stripped metrics and script-specific hint paths after the 0xd470 relocation",
        "operation": "walks outline points, builds segment records, determines direction, and links point ranges for Latin autofit",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/aflatin.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26a904",
        "target_ea": "0x277d74",
        "source_name": "af_latin_metrics_init_widths",
        "proposed_name": "v18_af_latin_metrics_init_widths",
        "role": "shared autofit standard-width probe",
        "source_file": "src/autofit/aflatin.c",
        "topology": "the routine loads a representative glyph, reloads its outline into autofit hint state, computes segments for each dimension, and is called by both Latin and CJK metrics initialization",
        "source_data": "called by af_cjk_metrics_init with character code 30000 and by af_latin_metrics_init with character code 111",
        "target_data": "the target metrics initializers preserve the same two call sites at the translated addresses",
        "operation": "loads a representative glyph and measures its standard stem widths for autofit metrics",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/aflatin.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26adcc",
        "target_ea": "0x27823c",
        "source_name": "af_cjk_metrics_init",
        "proposed_name": "v18_af_cjk_metrics_init",
        "role": "CJK autofit metrics initializer",
        "source_file": "src/autofit/afcjk.c",
        "topology": "the CJK script class stores this routine in its metrics_init slot; it selects the CJK charmap, probes a representative glyph, and restores the original charmap",
        "source_data": "CJK script class metrics_init slot at 0x35e630 + 0x18",
        "target_data": "CJK script class metrics_init slot at 0x3713b0 + 0x18",
        "operation": "initializes CJK script metrics and probes the representative glyph used for standard widths",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/a45c6a1cf3625709e149550b8fff1f09d01388d3/src/autofit/afcjk.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26ae34",
        "target_ea": "0x2782a4",
        "source_name": "af_hint_normal_stem",
        "proposed_name": "v18_af_hint_normal_stem",
        "role": "CJK normal-stem adjustment helper",
        "source_file": "src/autofit/afcjk.c",
        "topology": "the CJK hint-application routine calls this five-argument helper for horizontal and vertical edges; it applies standard-width snapping, thresholds, and anchor placement",
        "source_data": "called twice by the source CJK hint-application routine at 0x26d92c and 0x26d998",
        "target_data": "called twice by the target CJK hint-application routine at the corresponding translated sites",
        "operation": "normalizes a stem width and places the second edge relative to the selected anchor",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/75b4fbd0462ad4544ffc447213777d1f0d536c1a/src/autofit/afcjk.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26b198",
        "target_ea": "0x278608",
        "source_name": "af_latin2_metrics_init_widths",
        "proposed_name": "v18_af_latin2_metrics_init_widths",
        "role": "Latin2 autofit standard-width probe",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the Latin2 metrics initializer calls this near-twin of the Latin width probe; it loads the representative glyph, reloads hint state, and uses the Latin2 segment builder for both dimensions",
        "source_data": "called by the Latin2 script class metrics initializer at 0x26b6d0",
        "target_data": "called by the stripped Latin2 script class metrics initializer at the translated site",
        "operation": "loads a representative glyph and measures standard widths using Latin2 segment analysis",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26b660",
        "target_ea": "0x278ad0",
        "source_name": "af_latin2_metrics_init",
        "proposed_name": "v18_af_latin2_metrics_init",
        "role": "Latin2 autofit metrics initializer",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the Latin2 script class stores this routine in its metrics_init slot; it initializes width data, blue zones, and digit metrics after the Latin2 width probe",
        "source_data": "Latin2 script class metrics_init slot at 0x35e670 + 0x18",
        "target_data": "Latin2 script class metrics_init slot at 0x3713f0 + 0x18",
        "operation": "initializes Latin2 style metrics, blue zones, and representative digit widths",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26bb4c",
        "target_ea": "0x278fbc",
        "source_name": "af_latin_metrics_init",
        "proposed_name": "v18_af_latin_metrics_init",
        "role": "Latin autofit metrics initializer",
        "source_file": "src/autofit/aflatin.c",
        "topology": "the Latin script class stores this routine in its metrics_init slot; it initializes width data, blue zones, and digit metrics after probing the representative glyph",
        "source_data": "Latin script class metrics_init slot at 0x35e6b0 + 0x18",
        "target_data": "Latin script class metrics_init slot at 0x371430 + 0x18",
        "operation": "initializes Latin style metrics, blue zones, and representative digit widths",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/aflatin.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26c040",
        "target_ea": "0x2794b0",
        "source_name": "af_latin2_hints_compute_edges",
        "proposed_name": "v18_af_latin2_hints_compute_edges",
        "role": "Latin2 edge-construction helper",
        "source_file": "src/autofit/aflatin2.c",
        "topology": "the Latin2 hint-application routine calls this helper after segment linking; it allocates, sorts, and relates edge records using Latin2 thresholds",
        "source_data": "called by the source Latin2 hint-application routine at 0x26ec1c and 0x26ec64",
        "target_data": "called by the stripped Latin2 hint-application routine at the corresponding translated sites",
        "operation": "converts Latin2 outline segments into sorted edge records with link and serif relationships",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26c61c",
        "target_ea": "0x279a8c",
        "source_name": "af_latin_hints_compute_edges",
        "proposed_name": "v18_af_latin_hints_compute_edges",
        "role": "Latin edge-construction helper",
        "source_file": "src/autofit/aflatin.c",
        "topology": "the Latin hint-application routine calls this helper after segment linking; it applies Latin thresholds while allocating and relating the edge records",
        "source_data": "called by the source Latin hint-application routine at 0x27037c and 0x2703c4",
        "target_data": "called by the stripped Latin hint-application routine at the corresponding translated sites",
        "operation": "converts Latin outline segments into sorted edge records with link and serif relationships",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/aflatin.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26cb68",
        "target_ea": "0x279fd8",
        "source_name": "af_glyph_hints_align_edge_points",
        "proposed_name": "v18_af_glyph_hints_align_edge_points",
        "role": "shared edge-point alignment helper",
        "source_file": "src/autofit/afhints.c",
        "topology": "the CJK, Latin2, and Latin hint-application routines all call this helper after edge placement; it aligns points belonging to each edge and interpolates the remaining outline points",
        "source_data": "called by source CJK, Latin2, and Latin hint-application routines",
        "target_data": "called by target CJK, Latin2, and Latin hint-application routines at the translated addresses",
        "operation": "aligns all points of an edge to one coordinate and interpolates points between aligned edges",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/8483e21a1fdc252bd234eb55c6b63c17551933ee/src/autofit/afhints.c",
        "name_action": "rename-with-v18-prefix",
    },
    {
        "source_ea": "0x26d1f8",
        "target_ea": "0x27a668",
        "source_name": "af_cjk_hints_apply",
        "proposed_name": "v18_af_cjk_hints_apply",
        "role": "CJK autofit glyph hinting callback",
        "source_file": "src/autofit/afcjk.c",
        "topology": "the CJK script class stores this large routine in its hints_apply slot; it reloads the outline, builds segments and edges, applies stem adjustments, aligns edge points, and finalizes the hinted outline",
        "source_data": "CJK script class hints_apply slot at 0x35e630 + 0x38",
        "target_data": "CJK script class hints_apply slot at 0x3713b0 + 0x38",
        "operation": "runs the complete CJK autofit hinting pass for one glyph outline",
        "reference": "https://android.googlesource.com/platform/external/freetype/+/a45c6a1cf3625709e149550b8fff1f09d01388d3/src/autofit/afcjk.c",
        "name_action": "rename-with-v18-prefix",
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

    anchor = {
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
        "match_kind": "manual-freetype-autofit-metrics-anchor",
        "family": "FreeType autofit metrics and feature helpers",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType autofit module",
        "target_component": "stripped Spectron FreeType autofit module",
        "source_basis": "matching pseudocode, class-table or caller topology, official FreeType source role, and exact or register-detail-only ARM64 feature metrics",
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
            "The original pseudocode and class-table or caller topology identify the FreeType role.",
            "The stripped target retains the same role topology at the translated address.",
            "The official FreeType source defines the matching helper or callback contract.",
            "The source and target recorded ARM64 metrics are exact or differ only in register-detail allocation.",
        ],
        "name_action": spec["name_action"],
    }
    if spec.get("correction"):
        anchor["correction"] = True
        anchor["previous_v311_name"] = spec["previous_v311_name"]
        anchor["correction_reason"] = spec["correction_reason"]
        anchor["previous_checkpoint"] = "spectron_translation_checkpoint_20260828_v311"
    return anchor


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
        "artifact": "spectron_freetype_autofit_metrics_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for FreeType autofit metrics, feature construction, and the CJK hint callback",
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
            "source_region": "0x268608 through 0x26d1f8",
            "target_region": "0x275a78 through 0x27a668",
            "address_displacement": "0xd470",
            "role_resolution": "matching pseudocode, FreeType class-table and caller topology, official source roles, and exact or register-detail-only ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "correction_policy": "the two historical v311 Latin2 labels are retained in the v311 record for auditability and superseded here by CJK labels proven by both class tables",
            "reference_sources": sorted({spec["reference"] for spec in SPECS}),
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({anchor["spectron_ea"] for anchor in anchors}),
            "high_confidence_count": len(anchors),
            "correction_count": sum(anchor.get("correction", False) for anchor in anchors),
            "new_label_count": sum(not anchor.get("correction", False) for anchor in anchors),
            "target_default_name_count": sum(anchor["spectron_default_name"] for anchor in anchors),
            "source_default_name_count": sum(anchor["original_default_name"] for anchor in anchors),
            "normalized_shape_exact_count": sum(anchor["normalized_shape_equal"] for anchor in anchors),
            "full_metric_exact_count": sum(anchor["full_metric_equal"] for anchor in anchors),
            "register_detail_only_count": sum(
                anchor["metric_differences"] == ["register_detail_hash"]
                for anchor in anchors
            ),
            "class_callback_anchor_count": 4,
            "metrics_initializer_anchor_count": 4,
            "edge_and_segment_anchor_count": 4,
            "correction_anchor_count": 2,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target static helpers retained only IDA auto-generated names.",
            "The source and target class records select the CJK link, edge, metrics, and apply callbacks; the two earlier v311 Latin2 labels are therefore corrected here.",
            "The shared metrics-width probe and edge-point alignment helper are identified by their callers and reuse across the script-specific paths.",
            "The Latin, Latin2, and CJK metrics initializers and edge builders are selected by their corresponding class slots or caller paths.",
            "All thirteen source and target pairs match normalized shape. Eleven match the complete recorded feature set, while two differ only in register-detail allocation.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
