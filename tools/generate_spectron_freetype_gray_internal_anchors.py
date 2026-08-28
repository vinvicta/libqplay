#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType gray-raster internals."""

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
        "source_ea": "0x25b660",
        "target_ea": "0x268ad0",
        "source_name": "gray_render_span",
        "proposed_name": "v18_gray_render_span",
        "role": "gray raster span callback",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "called by gray_raster_render for direct span output and bitmap-row writes",
        "source_data": "gray_raster_render at 0x35e518 + 0x20 reaches this bitmap or span helper",
        "target_data": "ft_grays_raster1 at 0x371298 + 0x20 reaches the corresponding target helper",
        "operation": "clips and writes a run of gray coverage values into the destination bitmap or forwards the span to the render callback",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x25bb64",
        "target_ea": "0x268fd4",
        "source_name": "gray_convert_glyph_inner",
        "proposed_name": "v18_gray_convert_glyph_inner",
        "role": "gray glyph conversion inner helper",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "called by gray_convert_glyph for each scan-conversion band",
        "source_data": "gray_convert_glyph at 0x25be44 calls this helper after preparing the worker band",
        "target_data": "the corresponding target band-conversion routine is called by the target gray_convert_glyph equivalent",
        "operation": "decomposes the outline under a setjmp guard, records raster cells, and finishes the active gray cell buffer",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x25bca8",
        "target_ea": "0x269118",
        "source_name": "gray_move_to",
        "proposed_name": "v18_gray_move_to",
        "role": "gray outline move callback",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "first callback in the gray outline decomposition table at 0x35e4e8",
        "source_data": "outline callback table 0x35e4e8 + 0x00",
        "target_data": "corresponding gray outline callback table in the stripped target",
        "operation": "starts a new contour by moving the gray worker to the supplied outline point",
        "expected_differences": [],
    },
    {
        "source_ea": "0x25be44",
        "target_ea": "0x2692b4",
        "source_name": "gray_convert_glyph",
        "proposed_name": "v18_gray_convert_glyph",
        "role": "gray glyph conversion helper",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "called by gray_raster_render and dispatches band-by-band conversion to gray_convert_glyph_inner",
        "source_data": "gray_raster_render at 0x25c878 calls this outline-to-cells band loop",
        "target_data": "target gray_raster_render equivalent at 0x269ce8 calls the parallel band loop",
        "operation": "splits a large outline into bounded bands and converts each band into gray raster cells",
        "expected_differences": [],
    },
    {
        "source_ea": "0x25cf78",
        "target_ea": "0x26a3e8",
        "source_name": "gray_render_scanline",
        "proposed_name": "v18_gray_render_scanline",
        "role": "gray scanline renderer",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "called by gray_render_line for each scanline crossing",
        "source_data": "gray_render_line at 0x25d4bc calls the scanline coverage and cell-update routine",
        "target_data": "corresponding scanline routine in the target gray raster block",
        "operation": "updates gray cells for one scanline segment using the worker's fixed-point coverage state",
        "expected_differences": [],
    },
    {
        "source_ea": "0x25d4bc",
        "target_ea": "0x26a92c",
        "source_name": "gray_render_line",
        "proposed_name": "v18_gray_render_line",
        "role": "gray line renderer",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "called by gray_render_conic, gray_render_cubic, and gray_line_to",
        "source_data": "outline callbacks at 0x25e2ec, 0x25e04c, and 0x25dcbc reach this line interpolator",
        "target_data": "parallel target outline callbacks reach the corresponding line interpolator",
        "operation": "walks a line across scanlines, emits scanline segments, and updates the gray raster cell state",
        "expected_differences": [],
    },
    {
        "source_ea": "0x25dcbc",
        "target_ea": "0x26b12c",
        "source_name": "gray_render_cubic",
        "proposed_name": "v18_gray_render_cubic",
        "role": "gray cubic Bézier renderer",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "outline callback table 0x35e4e8 + 0x18",
        "source_data": "outline callback table 0x35e4e8 + 0x18",
        "target_data": "corresponding cubic callback in the target gray outline table",
        "operation": "subdivides a cubic Bézier edge and sends its line segments through gray_render_line",
        "expected_differences": [],
    },
    {
        "source_ea": "0x25e04c",
        "target_ea": "0x26b4bc",
        "source_name": "gray_render_conic",
        "proposed_name": "v18_gray_render_conic",
        "role": "gray conic Bézier renderer",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "outline callback table 0x35e4e8 + 0x10",
        "source_data": "outline callback table 0x35e4e8 + 0x10",
        "target_data": "corresponding conic callback in the target gray outline table",
        "operation": "subdivides a conic Bézier edge and sends its line segments through gray_render_line",
        "expected_differences": [],
    },
    {
        "source_ea": "0x25e2ec",
        "target_ea": "0x26b75c",
        "source_name": "gray_line_to",
        "proposed_name": "v18_gray_line_to",
        "role": "gray outline line callback",
        "source_file": "src/smooth/ftgrays.c",
        "topology": "second callback in the gray outline decomposition table at 0x35e4e8",
        "source_data": "outline callback table 0x35e4e8 + 0x08",
        "target_data": "corresponding gray outline callback table in the stripped target",
        "operation": "passes a straight outline edge to gray_render_line",
        "expected_differences": [],
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
    if differences != spec["expected_differences"]:
        raise ValueError(
            "%s unexpectedly differs in %s (expected %s)"
            % (spec["source_name"], differences, spec["expected_differences"])
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
        "match_kind": "manual-freetype-gray-internal-role-anchor",
        "family": "FreeType gray raster internals",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType gray raster module",
        "target_component": "stripped Spectron FreeType gray raster module",
        "source_basis": "FreeType helper name, outline callback or worker-call topology, matching pseudocode, and matching normalized ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The original gray outline callback table and worker call graph identify the exact helper role.",
            "The target gray raster block retains the same callback or worker topology at the translated location.",
            "The official FreeType ftgrays.c source defines the matching helper and its raster operation.",
            "The source and target ARM64 feature records match across normalized metrics; any remaining difference is recorded explicitly.",
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
        "artifact": "spectron_freetype_gray_internal_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for nine FreeType gray-raster outline and scan-conversion helpers",
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
            "source_outline_callbacks": "callback table at 0x35e4e8: gray_move_to, gray_line_to, gray_render_conic, and gray_render_cubic",
            "source_raster_record": "ft_grays_raster at 0x35e518, with raster_render at +0x20",
            "target_raster_record": "ft_grays_raster1 at 0x371298, with raster_render at +0x20",
            "role_resolution": "outline callback table, gray worker call topology, official FreeType source roles, matching pseudocode, and normalized ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/smooth/ftgrays.c",
                "https://android.googlesource.com/platform/external/freetype/+/8483e21a1fdc252bd234eb55c6b63c17551933ee/include/freetype/ftimage.h",
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
            "outline_callback_anchor_count": 4,
            "conversion_helper_anchor_count": 2,
            "scan_conversion_anchor_count": 3,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates had no surviving source names.",
            "The four outline callbacks are resolved from the original callback table and the matching target decomposition topology.",
            "gray_convert_glyph and gray_convert_glyph_inner form the banded outline-to-cell conversion path used by the raster render callback.",
            "gray_render_scanline and gray_render_line implement the fixed-point cell and scanline coverage path, while the conic and cubic helpers reduce curves to line segments.",
            "All source and target records in this batch match across normalized feature metrics; the span writer and inner conversion helper differ only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
