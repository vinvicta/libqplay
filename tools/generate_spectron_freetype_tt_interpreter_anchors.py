#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType TrueType internals."""

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
        "source_ea": "0x25e320",
        "target_ea": "0x26b790",
        "source_name": "tt_get_kerning",
        "proposed_name": "v18_tt_get_kerning",
        "role": "TrueType kerning driver wrapper",
        "source_file": "src/truetype/ttdriver.c",
        "topology": "TrueType driver-class get_kerning callback",
        "source_data": "tt_driver_class at 0x36d330 + 0x98 points to this wrapper",
        "target_data": "the corresponding stripped TrueType driver record points to the parallel target wrapper",
        "operation": "checks the face format and forwards a glyph-pair kerning request to the active SFNT face service",
    },
    {
        "source_ea": "0x25e35c",
        "target_ea": "0x26b7cc",
        "source_name": "tt_face_get_location",
        "proposed_name": "v18_tt_face_get_location",
        "role": "TrueType loca-table glyph location helper",
        "source_file": "src/truetype/ttpload.c",
        "topology": "called by the TrueType glyph loader while resolving a glyph's loca-table offset and length",
        "source_data": "the glyph loader reaches this helper after loading the face loca table and Index_To_Loc_Format field",
        "target_data": "the corresponding target glyph loader retains the same loca-table access pattern",
        "operation": "returns a glyph data offset from the loca table and writes the byte length for the requested glyph",
    },
    {
        "source_ea": "0x25e4e4",
        "target_ea": "0x26b954",
        "source_name": "tt_size_init",
        "proposed_name": "v18_tt_size_init",
        "role": "TrueType size object initializer",
        "source_file": "src/truetype/ttobjs.c",
        "topology": "TrueType driver-class init_size callback",
        "source_data": "tt_driver_class at 0x36d330 + 0x70 points to the size initializer",
        "target_data": "the corresponding stripped TrueType driver record points to the parallel target initializer",
        "operation": "resets the size object's bytecode, width, and strike-selection state before a new size is used",
    },
    {
        "source_ea": "0x25e504",
        "target_ea": "0x26b974",
        "source_name": "TT_MulFix14",
        "proposed_name": "v18_TT_MulFix14",
        "role": "14-bit fixed-point multiplication helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "called by the TrueType interpreter's projection, freedom-vector, and rounding calculations",
        "source_data": "multiple interpreter helpers and opcode handlers call this signed fixed-point arithmetic routine",
        "target_data": "the parallel target interpreter helpers call the corresponding fixed-point routine",
        "operation": "multiplies two signed values and returns a rounded result scaled from the interpreter's 14-bit fixed-point format",
    },
    {
        "source_ea": "0x25e580",
        "target_ea": "0x26b9f0",
        "source_name": "Direct_Move_X",
        "proposed_name": "v18_Direct_Move_X",
        "role": "current-coordinate x movement helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected as the x-axis direct-movement function in the interpreter execution context",
        "source_data": "Compute_Funcs installs this helper when the freedom vector resolves to the x axis",
        "target_data": "the target interpreter keeps the same axis-specialized function selection",
        "operation": "adds a distance to a point's current x coordinate and marks the x coordinate touched",
    },
    {
        "source_ea": "0x25e5b0",
        "target_ea": "0x26ba20",
        "source_name": "Direct_Move_Y",
        "proposed_name": "v18_Direct_Move_Y",
        "role": "current-coordinate y movement helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected as the y-axis direct-movement function in the interpreter execution context",
        "source_data": "Compute_Funcs installs this helper when the freedom vector resolves to the y axis",
        "target_data": "the target interpreter keeps the same axis-specialized function selection",
        "operation": "adds a distance to a point's current y coordinate and marks the y coordinate touched",
    },
    {
        "source_ea": "0x25e5e4",
        "target_ea": "0x26ba54",
        "source_name": "Direct_Move_Orig_X",
        "proposed_name": "v18_Direct_Move_Orig_X",
        "role": "original-coordinate x movement helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected as the x-axis original-coordinate movement function in the interpreter execution context",
        "source_data": "Compute_Funcs installs this helper for original-coordinate movement along x",
        "target_data": "the target interpreter keeps the same original-coordinate axis specialization",
        "operation": "adds a distance to a point's original x coordinate",
    },
    {
        "source_ea": "0x25e5fc",
        "target_ea": "0x26ba6c",
        "source_name": "Direct_Move_Orig_Y",
        "proposed_name": "v18_Direct_Move_Orig_Y",
        "role": "original-coordinate y movement helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected as the y-axis original-coordinate movement function in the interpreter execution context",
        "source_data": "Compute_Funcs installs this helper for original-coordinate movement along y",
        "target_data": "the target interpreter keeps the same original-coordinate axis specialization",
        "operation": "adds a distance to a point's original y coordinate",
    },
    {
        "source_ea": "0x25e618",
        "target_ea": "0x26ba88",
        "source_name": "Round_None",
        "proposed_name": "v18_Round_None",
        "role": "no-op TrueType rounding mode",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "installed in the execution context when the graphics state selects round mode none",
        "source_data": "the rounding-mode setup selects this helper as the round_func callback",
        "target_data": "the target interpreter retains the same round_func selection path",
        "operation": "applies the compensation term without quantizing the value to a grid period",
    },
    {
        "source_ea": "0x25e640",
        "target_ea": "0x26bab0",
        "source_name": "TT_DotFix14",
        "proposed_name": "v18_TT_DotFix14",
        "role": "14-bit fixed-point vector dot product",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "used by projection and freedom-vector setup in the TrueType interpreter",
        "source_data": "interpreter vector helpers call this routine with the execution context's projected vector fields",
        "target_data": "the target vector setup retains the same projected-vector calculation",
        "operation": "computes and rounds the dot product of two interpreter vectors in 14-bit fixed-point form",
    },
    {
        "source_ea": "0x25e6cc",
        "target_ea": "0x26bb3c",
        "source_name": "Project_x",
        "proposed_name": "v18_Project_x",
        "role": "x-axis projection helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "installed as the projection callback when the projection vector is the x axis",
        "source_data": "Compute_Funcs assigns this helper to the projection function table for x-axis projection",
        "target_data": "the target interpreter preserves the same projection callback assignment",
        "operation": "returns the x component of the supplied point vector",
    },
    {
        "source_ea": "0x25e6d4",
        "target_ea": "0x26bb44",
        "source_name": "Project_y",
        "proposed_name": "v18_Project_y",
        "role": "y-axis projection helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "installed as the projection callback when the projection vector is the y axis",
        "source_data": "Compute_Funcs assigns this helper to the projection function table for y-axis projection",
        "target_data": "the target interpreter preserves the same projection callback assignment",
        "operation": "returns the y component of the supplied point vector",
    },
    {
        "source_ea": "0x25e6dc",
        "target_ea": "0x26bb4c",
        "source_name": "Ins_NPUSHW",
        "proposed_name": "v18_Ins_NPUSHW",
        "role": "TrueType NPUSHW opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for NPUSHW",
        "source_data": "the interpreter opcode table reaches this handler for the variable-count word-push instruction",
        "target_data": "the target opcode table retains the same NPUSHW dispatch entry",
        "operation": "reads a count and signed 16-bit words from the instruction stream and pushes them onto the interpreter stack",
    },
    {
        "source_ea": "0x25e770",
        "target_ea": "0x26bbe0",
        "source_name": "Ins_PUSHW",
        "proposed_name": "v18_Ins_PUSHW",
        "role": "TrueType PUSHW opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for the PUSHW instruction range",
        "source_data": "the interpreter opcode table reaches this handler for the compact word-push instructions",
        "target_data": "the target opcode table retains the same PUSHW dispatch entry",
        "operation": "decodes the opcode-selected number of signed 16-bit words and pushes them onto the interpreter stack",
    },
    {
        "source_ea": "0x25e7f8",
        "target_ea": "0x26bc68",
        "source_name": "Ins_GC",
        "proposed_name": "v18_Ins_GC",
        "role": "TrueType GC opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for GC[0] and GC[1]",
        "source_data": "the interpreter dispatch cases for the two GC variants reach this point-validation and projection handler",
        "target_data": "the target opcode table retains the same GC variant dispatch structure",
        "operation": "validates a point index, selects the current or original projected coordinate, and pushes it onto the stack",
    },
    {
        "source_ea": "0x25e890",
        "target_ea": "0x26bd00",
        "source_name": "Ins_SCFS",
        "proposed_name": "v18_Ins_SCFS",
        "role": "TrueType SCFS opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for SCFS",
        "source_data": "the interpreter dispatch case for SCFS reaches this point-validation and coordinate-update handler",
        "target_data": "the target opcode table retains the same SCFS dispatch structure",
        "operation": "validates a point index, projects the requested coordinate, and moves the point by the stack-supplied delta",
    },
    {
        "source_ea": "0x25e950",
        "target_ea": "0x26bdc0",
        "source_name": "Ins_GETINFO",
        "proposed_name": "v18_Ins_GETINFO",
        "role": "TrueType GETINFO opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for GETINFO",
        "source_data": "the interpreter dispatch case for GETINFO reaches this graphics-state feature query",
        "target_data": "the target opcode table retains the same GETINFO dispatch structure",
        "operation": "maps the instruction's request mask to interpreter version, engine, and subpixel feature flags",
    },
    {
        "source_ea": "0x25e9a8",
        "target_ea": "0x26be18",
        "source_name": "Ins_MD",
        "proposed_name": "v18_Ins_MD",
        "role": "TrueType MD opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for MD[0] and MD[1]",
        "source_data": "the interpreter dispatch cases for the two MD variants reach this distance-measurement handler",
        "target_data": "the target opcode table retains the same MD variant dispatch structure",
        "operation": "validates two point indices, projects their current or original coordinates, and pushes the signed distance",
    },
    {
        "source_ea": "0x25edd0",
        "target_ea": "0x26c240",
        "source_name": "Ins_IUP",
        "proposed_name": "v18_Ins_IUP",
        "role": "TrueType IUP opcode handler",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "opcode dispatch entry for IUP",
        "source_data": "the interpreter dispatch case for IUP reaches this untouched-point interpolation routine",
        "target_data": "the target opcode table retains the same IUP dispatch structure",
        "operation": "interpolates untouched points between touched points in the selected coordinate dimension",
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
        "match_kind": "manual-freetype-tt-interpreter-role-anchor",
        "family": "FreeType TrueType driver, glyph loading, and interpreter",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType TrueType driver, glyph loading, and interpreter modules",
        "target_component": "stripped Spectron FreeType TrueType modules",
        "source_basis": "FreeType helper name, driver or opcode topology, matching pseudocode, and exact ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": True,
        "metric_differences": [],
        "semantic_match_already_present": False,
        "evidence": [
            "The original TrueType driver, glyph-loader, or opcode topology identifies the helper role.",
            "The target code retains the corresponding call or dispatch topology at the translated location.",
            "The official FreeType TrueType source defines the matching helper name and operation.",
            "The source and target ARM64 feature records match across the complete recorded metric set.",
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
        "artifact": "spectron_freetype_tt_interpreter_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for FreeType TrueType driver, glyph-loading, and interpreter helpers",
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
            "source_driver_record": "tt_driver_class at 0x36d330, including the get_kerning and init_size callbacks",
            "source_interpreter_dispatch": "TrueType opcode dispatch and Compute_Funcs setup in the 0x25e3xx-0x25fxxx interpreter region",
            "target_region": "parallel stripped Spectron TrueType driver and interpreter region at the source address plus 0xd470",
            "role_resolution": "driver callback slots, opcode dispatch topology, matching pseudocode, official FreeType source roles, and exact ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9f/src/truetype/ttdriver.c",
                "https://android.googlesource.com/platform/external/freetype/+/75b4fbd0462ad4544ffc447213777d1f0d536c1a/src/truetype/ttpload.c",
                "https://android.googlesource.com/platform/external/freetype/+/3053d1b9db55099918843889e4809ce97483ca9f/src/truetype/ttobjs.c",
                "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/truetype/ttinterp.c",
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
            "driver_and_loader_anchor_count": 3,
            "interpreter_helper_anchor_count": 16,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates had no surviving source names.",
            "The first three anchors cover the TrueType driver's kerning wrapper, loca-table lookup, and size initializer.",
            "The remaining anchors cover fixed-point helpers, axis-specialized movement and projection callbacks, and a contiguous group of TrueType opcode handlers.",
            "The exact metric match across every anchor supports a direct source-to-target translation for this compiler-preserved FreeType block.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
