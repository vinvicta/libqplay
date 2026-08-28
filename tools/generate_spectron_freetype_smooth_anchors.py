#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType smooth renderer code."""

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
        "source_ea": "0x25b5f4",
        "target_ea": "0x268a64",
        "source_name": "ft_smooth_init",
        "proposed_name": "v18_ft_smooth_init",
        "role": "smooth renderer module initializer",
        "source_file": "src/smooth/ftsmooth.c",
        "data_slot": "ft_smooth_lcdv_renderer_class.module_init; shared by all three smooth renderer classes",
        "source_data": "ft_smooth_lcdv_renderer_class at 0x36d1c8 + 0x30, also the corresponding slots at 0x36d240 and 0x36d2b8",
        "target_data": "ft_smooth_lcdv_renderer_class1 at 0x37ff98 + 0x30, also the corresponding slots at 0x380010 and 0x380088",
        "operation": "initializes the smooth renderer by resetting its gray raster with the library render pool",
    },
    {
        "source_ea": "0x25b62c",
        "target_ea": "0x268a9c",
        "source_name": "ft_smooth_set_mode",
        "proposed_name": "v18_ft_smooth_set_mode",
        "role": "smooth renderer mode callback",
        "source_file": "src/smooth/ftsmooth.c",
        "data_slot": "ft_smooth_lcdv_renderer_class.set_mode; shared by all three smooth renderer classes",
        "source_data": "ft_smooth_lcdv_renderer_class at 0x36d1c8 + 0x68, also the corresponding slots at 0x36d240 and 0x36d2b8",
        "target_data": "ft_smooth_lcdv_renderer_class1 at 0x37ff98 + 0x68, also the corresponding slots at 0x380010 and 0x380088",
        "operation": "forwards a renderer mode request to the active gray raster",
    },
    {
        "source_ea": "0x25b654",
        "target_ea": "0x268ac4",
        "source_name": "gray_raster_done",
        "proposed_name": "v18_gray_raster_done",
        "role": "gray raster destructor",
        "source_file": "src/smooth/ftgrays.c",
        "data_slot": "ft_grays_raster.raster_done",
        "source_data": "ft_grays_raster at 0x35e518 + 0x28",
        "target_data": "ft_grays_raster1 at 0x371298 + 0x28",
        "operation": "releases the gray raster object through the FreeType memory allocator",
    },
    {
        "source_ea": "0x25b76c",
        "target_ea": "0x268bdc",
        "source_name": "gray_raster_new",
        "proposed_name": "v18_gray_raster_new",
        "role": "gray raster constructor",
        "source_file": "src/smooth/ftgrays.c",
        "data_slot": "ft_grays_raster.raster_new",
        "source_data": "ft_grays_raster at 0x35e518 + 0x08",
        "target_data": "ft_grays_raster1 at 0x371298 + 0x08",
        "operation": "allocates and returns the gray raster state used by the smooth renderers",
    },
    {
        "source_ea": "0x25b7b4",
        "target_ea": "0x268c24",
        "source_name": "ft_smooth_get_cbox",
        "proposed_name": "v18_ft_smooth_get_cbox",
        "role": "smooth renderer control-box callback",
        "source_file": "src/smooth/ftsmooth.c",
        "data_slot": "ft_smooth_lcdv_renderer_class.get_glyph_cbox; shared by all three smooth renderer classes",
        "source_data": "ft_smooth_lcdv_renderer_class at 0x36d1c8 + 0x60, also the corresponding slots at 0x36d240 and 0x36d2b8",
        "target_data": "ft_smooth_lcdv_renderer_class1 at 0x37ff98 + 0x60, also the corresponding slots at 0x380010 and 0x380088",
        "operation": "clears and computes the outline control box when the glyph format is outline",
    },
    {
        "source_ea": "0x25b7dc",
        "target_ea": "0x268c4c",
        "source_name": "ft_smooth_render_lcd_v",
        "proposed_name": "v18_ft_smooth_render_lcd_v",
        "role": "vertical LCD smooth renderer callback",
        "source_file": "src/smooth/ftsmooth.c",
        "data_slot": "ft_smooth_lcdv_renderer_class.render_glyph",
        "source_data": "ft_smooth_lcdv_renderer_class at 0x36d1c8 + 0x50",
        "target_data": "ft_smooth_lcdv_renderer_class1 at 0x37ff98 + 0x50",
        "operation": "renders a glyph through the generic smooth path in vertical LCD mode and marks the bitmap as LCD_V",
    },
    {
        "source_ea": "0x25ba90",
        "target_ea": "0x268f00",
        "source_name": "gray_raster_reset",
        "proposed_name": "v18_gray_raster_reset",
        "role": "gray raster pool reset callback",
        "source_file": "src/smooth/ftgrays.c",
        "data_slot": "ft_grays_raster.raster_reset",
        "source_data": "ft_grays_raster at 0x35e518 + 0x10",
        "target_data": "ft_grays_raster1 at 0x371298 + 0x10",
        "operation": "reinitializes the raster worker and cell buffer from the supplied render pool",
    },
    {
        "source_ea": "0x25baec",
        "target_ea": "0x268f5c",
        "source_name": "ft_smooth_transform",
        "proposed_name": "v18_ft_smooth_transform",
        "role": "smooth renderer transform callback",
        "source_file": "src/smooth/ftsmooth.c",
        "data_slot": "ft_smooth_lcdv_renderer_class.transform_glyph; shared by all three smooth renderer classes",
        "source_data": "ft_smooth_lcdv_renderer_class at 0x36d1c8 + 0x58, also the corresponding slots at 0x36d240 and 0x36d2b8",
        "target_data": "ft_smooth_lcdv_renderer_class1 at 0x37ff98 + 0x58, also the corresponding slots at 0x380010 and 0x380088",
        "operation": "validates the outline glyph format and applies an optional matrix and translation",
    },
    {
        "source_ea": "0x25c878",
        "target_ea": "0x269ce8",
        "source_name": "gray_raster_render",
        "proposed_name": "v18_gray_raster_render",
        "role": "gray raster render callback",
        "source_file": "src/smooth/ftgrays.c",
        "data_slot": "ft_grays_raster.raster_render",
        "source_data": "ft_grays_raster at 0x35e518 + 0x20",
        "target_data": "ft_grays_raster1 at 0x371298 + 0x20",
        "operation": "scan-converts an outline into a gray bitmap or direct span stream",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x25ca78",
        "target_ea": "0x269ee8",
        "source_name": "ft_smooth_render",
        "proposed_name": "v18_ft_smooth_render",
        "role": "normal smooth renderer callback",
        "source_file": "src/smooth/ftsmooth.c",
        "data_slot": "ft_smooth_renderer_class.render_glyph",
        "source_data": "ft_smooth_renderer_class at 0x36d2b8 + 0x50",
        "target_data": "ft_smooth_renderer_class1 at 0x380088 + 0x50",
        "operation": "renders a glyph through the generic smooth path in normal grayscale mode",
    },
    {
        "source_ea": "0x25ccb8",
        "target_ea": "0x26a128",
        "source_name": "ft_smooth_render_lcd",
        "proposed_name": "v18_ft_smooth_render_lcd",
        "role": "horizontal LCD smooth renderer callback",
        "source_file": "src/smooth/ftsmooth.c",
        "data_slot": "ft_smooth_lcd_renderer_class.render_glyph",
        "source_data": "ft_smooth_lcd_renderer_class at 0x36d240 + 0x50",
        "target_data": "ft_smooth_lcd_renderer_class1 at 0x380010 + 0x50",
        "operation": "renders a glyph through the generic smooth path in horizontal LCD mode and marks the bitmap as LCD",
    },
    {
        "source_ea": "0x2573b8",
        "target_ea": "0x264828",
        "source_name": "tt_face_build_cmaps",
        "proposed_name": "v18_tt_face_build_cmaps",
        "role": "TrueType cmap builder",
        "source_file": "src/sfnt/ttcmap.c",
        "data_slot": "called by sfnt_load_face after the cmap table has been loaded",
        "source_data": "called from tt_face_load_cmap and sfnt_load_face in the original SFNT module",
        "target_data": "called from the stripped sfnt_load_face equivalent in the Spectron SFNT module",
        "operation": "walks cmap subtables, selects supported cmap classes, and creates the face cmap objects",
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
    if differences != expected_differences:
        raise ValueError(
            "%s unexpectedly differs in %s (expected %s)"
            % (spec["source_name"], differences, expected_differences)
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
        "match_kind": "manual-freetype-smooth-table-role-anchor",
        "family": "FreeType smooth renderer and gray raster",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "data_slot": spec["data_slot"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType smooth renderer and gray raster modules",
        "target_component": "stripped Spectron FreeType smooth renderer and gray raster modules",
        "source_basis": "FreeType helper name, callback-table slot, matching function body, and matching normalized ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The original callback tables identify the exact renderer or raster slot for this helper.",
            "The corresponding Spectron tables retain the same callback topology and point to the target candidate.",
            "The official FreeType smooth and gray-raster sources define the matching helper role and operation.",
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
        "artifact": "spectron_freetype_smooth_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for FreeType smooth renderer, gray raster, and cmap-builder helpers",
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
            "source_renderer_records": "ft_smooth_lcdv_renderer_class at 0x36d1c8, ft_smooth_lcd_renderer_class at 0x36d240, and ft_smooth_renderer_class at 0x36d2b8",
            "target_renderer_records": "ft_smooth_lcdv_renderer_class1 at 0x37ff98, ft_smooth_lcd_renderer_class1 at 0x380010, and ft_smooth_renderer_class1 at 0x380088",
            "source_raster_record": "ft_grays_raster at 0x35e518",
            "target_raster_record": "ft_grays_raster1 at 0x371298",
            "role_resolution": "callback-table slots, official FreeType source roles, matching pseudocode, and exact ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/smooth/ftsmooth.c",
                "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/smooth/ftgrays.c",
                "https://android.googlesource.com/platform/external/freetype/+/f720f0db/src/sfnt/ttcmap.c",
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
            "callback_table_anchor_count": len(anchors) - 1,
            "cmap_builder_anchor_count": 1,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates had no surviving source names.",
            "The three renderer classes share initialization, transform, control-box, and mode callbacks, while their render slots select normal, horizontal LCD, or vertical LCD behavior.",
            "The gray raster record independently identifies the raster constructor, reset, render, and destructor callbacks.",
            "tt_face_build_cmaps is the adjacent SFNT cmap-construction helper called while the face is being loaded.",
            "All source and target records in this batch match across normalized feature metrics; gray_raster_render and tt_face_build_cmaps differ only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
