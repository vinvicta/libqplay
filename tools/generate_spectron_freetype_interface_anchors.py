#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's remaining FreeType SFNT helpers."""

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
        "source_ea": "0x2565e8",
        "target_ea": "0x263a58",
        "source_name": "tt_face_goto_table",
        "proposed_name": "v18_tt_face_goto_table",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.goto_table",
        "interface_offset": "0x00",
        "source_data": "sfnt_interface at 0x36cda0 + 0x00",
        "target_data": "sfnt_interface at 0x37fb70 + 0x00",
        "operation": "finds an SFNT table directory entry and seeks the font stream to it",
        "expected_differences": [],
    },
    {
        "source_ea": "0x257704",
        "target_ea": "0x264b74",
        "source_name": "sfnt_init_face",
        "proposed_name": "v18_sfnt_init_face",
        "source_file": "src/sfnt/sfobjs.c",
        "interface_slot": "sfnt_interface.init_face",
        "interface_offset": "0x08",
        "source_data": "sfnt_interface at 0x36cda0 + 0x08",
        "target_data": "sfnt_interface at 0x37fb70 + 0x08",
        "operation": "connects a face to the SFNT module, opens the font container, and loads its directory",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x25a8e0",
        "target_ea": "0x267d50",
        "source_name": "sfnt_load_face",
        "proposed_name": "v18_sfnt_load_face",
        "source_file": "src/sfnt/sfobjs.c",
        "interface_slot": "sfnt_interface.load_face",
        "interface_offset": "0x10",
        "source_data": "sfnt_interface at 0x36cda0 + 0x10",
        "target_data": "sfnt_interface at 0x37fb70 + 0x10",
        "operation": "loads the required SFNT tables, selects names and charmaps, and populates the face object",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x257254",
        "target_ea": "0x2646c4",
        "source_name": "sfnt_done_face",
        "proposed_name": "v18_sfnt_done_face",
        "source_file": "src/sfnt/sfobjs.c",
        "interface_slot": "sfnt_interface.done_face",
        "interface_offset": "0x18",
        "source_data": "sfnt_interface at 0x36cda0 + 0x18",
        "target_data": "sfnt_interface at 0x37fb70 + 0x18",
        "operation": "releases the SFNT face tables, metrics, charmaps, names, and stream-owned resources",
        "expected_differences": [],
    },
    {
        "source_ea": "0x258204",
        "target_ea": "0x265674",
        "source_name": "tt_face_load_head",
        "proposed_name": "v18_tt_face_load_head",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_head",
        "interface_offset": "0x30",
        "source_data": "sfnt_interface at 0x36cda0 + 0x30",
        "target_data": "sfnt_interface at 0x37fb70 + 0x30",
        "operation": "loads the TrueType head table into the face header",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x256d24",
        "target_ea": "0x264194",
        "source_name": "tt_face_load_hhea",
        "proposed_name": "v18_tt_face_load_hhea",
        "source_file": "src/sfnt/ttmtx.c",
        "interface_slot": "sfnt_interface.load_hhea",
        "interface_offset": "0x38",
        "source_data": "sfnt_interface at 0x36cda0 + 0x38",
        "target_data": "sfnt_interface at 0x37fb70 + 0x38",
        "operation": "loads the horizontal or vertical metrics header and clears its metric pointers",
        "expected_differences": [],
    },
    {
        "source_ea": "0x258198",
        "target_ea": "0x265608",
        "source_name": "tt_face_load_cmap",
        "proposed_name": "v18_tt_face_load_cmap",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_cmap",
        "interface_offset": "0x40",
        "source_data": "sfnt_interface at 0x36cda0 + 0x40",
        "target_data": "sfnt_interface at 0x37fb70 + 0x40",
        "operation": "loads and retains the cmap table frame for later cmap construction",
        "expected_differences": [],
    },
    {
        "source_ea": "0x257f64",
        "target_ea": "0x2653d4",
        "source_name": "tt_face_load_maxp",
        "proposed_name": "v18_tt_face_load_maxp",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_maxp",
        "interface_offset": "0x48",
        "source_data": "sfnt_interface at 0x36cda0 + 0x48",
        "target_data": "sfnt_interface at 0x37fb70 + 0x48",
        "operation": "loads the maximum-profile table and records the glyph and execution limits",
        "expected_differences": [],
    },
    {
        "source_ea": "0x256b7c",
        "target_ea": "0x263fec",
        "source_name": "tt_face_load_os2",
        "proposed_name": "v18_tt_face_load_os2",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_os2",
        "interface_offset": "0x50",
        "source_data": "sfnt_interface at 0x36cda0 + 0x50",
        "target_data": "sfnt_interface at 0x37fb70 + 0x50",
        "operation": "loads the OS/2 metrics and character-set fields from the font table",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x256b14",
        "target_ea": "0x263f84",
        "source_name": "tt_face_load_post",
        "proposed_name": "v18_tt_face_load_post",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_post",
        "interface_offset": "0x58",
        "source_data": "sfnt_interface at 0x36cda0 + 0x58",
        "target_data": "sfnt_interface at 0x37fb70 + 0x58",
        "operation": "loads the TrueType post table and records its format and fixed-pitch fields",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x256960",
        "target_ea": "0x263dd0",
        "source_name": "tt_face_load_name",
        "proposed_name": "v18_tt_face_load_name",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_name",
        "interface_offset": "0x60",
        "source_data": "sfnt_interface at 0x36cda0 + 0x60",
        "target_data": "sfnt_interface at 0x37fb70 + 0x60",
        "operation": "loads, validates, and indexes the font name records",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x255fc0",
        "target_ea": "0x263430",
        "source_name": "tt_face_free_name",
        "proposed_name": "v18_tt_face_free_name",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.free_name",
        "interface_offset": "0x68",
        "source_data": "sfnt_interface at 0x36cda0 + 0x68",
        "target_data": "sfnt_interface at 0x37fb70 + 0x68",
        "operation": "frees cached name strings and the name-record array",
        "expected_differences": [],
    },
    {
        "source_ea": "0x257030",
        "target_ea": "0x2644a0",
        "source_name": "tt_face_load_kern",
        "proposed_name": "v18_tt_face_load_kern",
        "source_file": "src/sfnt/ttkern.c",
        "interface_slot": "sfnt_interface.load_kern",
        "interface_offset": "0x70",
        "source_data": "sfnt_interface at 0x36cda0 + 0x70",
        "target_data": "sfnt_interface at 0x37fb70 + 0x70",
        "operation": "loads the optional kern table and records available and ordered subtables",
        "expected_differences": [],
    },
    {
        "source_ea": "0x256ef4",
        "target_ea": "0x264364",
        "source_name": "tt_face_load_gasp",
        "proposed_name": "v18_tt_face_load_gasp",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_gasp",
        "interface_offset": "0x78",
        "source_data": "sfnt_interface at 0x36cda0 + 0x78",
        "target_data": "sfnt_interface at 0x37fb70 + 0x78",
        "operation": "loads and validates the gasp grid-fitting range records",
        "expected_differences": [],
    },
    {
        "source_ea": "0x2568fc",
        "target_ea": "0x263d6c",
        "source_name": "tt_face_load_pclt",
        "proposed_name": "v18_tt_face_load_pclt",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_pclt",
        "interface_offset": "0x80",
        "source_data": "sfnt_interface at 0x36cda0 + 0x80",
        "target_data": "sfnt_interface at 0x37fb70 + 0x80",
        "operation": "loads the optional PCLT table when the font contains it",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x254bb8",
        "target_ea": "0x262028",
        "source_name": "tt_face_get_kerning",
        "proposed_name": "v18_tt_face_get_kerning",
        "source_file": "src/sfnt/ttkern.c",
        "interface_slot": "sfnt_interface.get_kerning",
        "interface_offset": "0xa8",
        "source_data": "sfnt_interface at 0x36cda0 + 0xa8",
        "target_data": "sfnt_interface at 0x37fb70 + 0xa8",
        "operation": "looks up a glyph pair in the loaded kern subtables and returns its horizontal adjustment",
        "expected_differences": [],
    },
    {
        "source_ea": "0x257c28",
        "target_ea": "0x265098",
        "source_name": "tt_face_load_font_dir",
        "proposed_name": "v18_tt_face_load_font_dir",
        "source_file": "src/sfnt/ttload.c",
        "interface_slot": "sfnt_interface.load_font_dir",
        "interface_offset": "0xb0",
        "source_data": "sfnt_interface at 0x36cda0 + 0xb0",
        "target_data": "sfnt_interface at 0x37fb70 + 0xb0",
        "operation": "reads and validates the SFNT offset table and table directory",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x25687c",
        "target_ea": "0x263cec",
        "source_name": "tt_face_load_hmtx",
        "proposed_name": "v18_tt_face_load_hmtx",
        "source_file": "src/sfnt/ttmtx.c",
        "interface_slot": "sfnt_interface.load_hmtx",
        "interface_offset": "0xb8",
        "source_data": "sfnt_interface at 0x36cda0 + 0xb8",
        "target_data": "sfnt_interface at 0x37fb70 + 0xb8",
        "operation": "loads horizontal or vertical metrics and records the long and short metric arrays",
        "expected_differences": [],
    },
    {
        "source_ea": "0x2566d8",
        "target_ea": "0x263b48",
        "source_name": "tt_face_get_metrics",
        "proposed_name": "v18_tt_face_get_metrics",
        "source_file": "src/sfnt/ttmtx.c",
        "interface_slot": "sfnt_interface.get_metrics",
        "interface_offset": "0xe0",
        "source_data": "sfnt_interface at 0x36cda0 + 0xe0",
        "target_data": "sfnt_interface at 0x37fb70 + 0xe0",
        "operation": "returns the bearing and advance for a horizontal or vertical glyph metric record",
        "expected_differences": [],
    },
    {
        "source_ea": "0x256060",
        "target_ea": "0x2634d0",
        "source_name": "tt_name_entry_ascii_from_other",
        "proposed_name": "v18_tt_name_entry_ascii_from_other",
        "source_file": "src/sfnt/sfobjs.c",
        "interface_slot": "sfnt_load_face name conversion helper",
        "interface_offset": None,
        "source_data": "called by sfnt_load_face while selecting an Apple name record",
        "target_data": "called by the stripped sfnt_load_face equivalent",
        "operation": "copies an Apple Roman or symbol name entry to ASCII and replaces non-printable bytes",
        "expected_differences": [],
    },
    {
        "source_ea": "0x2563d0",
        "target_ea": "0x263840",
        "source_name": "tt_name_entry_ascii_from_utf16",
        "proposed_name": "v18_tt_name_entry_ascii_from_utf16",
        "source_file": "src/sfnt/sfobjs.c",
        "interface_slot": "sfnt_load_face name conversion helper",
        "interface_offset": None,
        "source_data": "called by sfnt_load_face while selecting a Unicode name record",
        "target_data": "called by the stripped sfnt_load_face equivalent",
        "operation": "converts a UTF-16BE name entry to printable ASCII",
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
        "match_kind": "manual-freetype-sfnt-interface-role-anchor",
        "family": "FreeType SFNT interface and name helpers",
        "source_name": spec["source_name"],
        "source_role": spec["operation"],
        "source_file": spec["source_file"],
        "interface_slot": spec["interface_slot"],
        "interface_offset": spec["interface_offset"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType SFNT interface and object-management layer",
        "target_component": "stripped Spectron FreeType SFNT layer",
        "source_basis": "SFNT interface slot or direct name-helper caller, official source role, and matching function body",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The original and target sfnt_interface records point to the paired functions in the same logical slots.",
            "The two name conversion helpers are reached from the corresponding sfnt_load_face name-selection logic.",
            "The official FreeType SFNT source files define the recovered names and operations.",
            "All normalized ARM64 feature metrics match; recorded differences are limited to register allocation detail.",
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
        "artifact": "spectron_freetype_sfnt_interface_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for nineteen SFNT interface callbacks and two internal name conversion helpers",
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
            "source_interface": "sfnt_interface at 0x36cda0",
            "target_interface": "sfnt_interface at 0x37fb70",
            "target_interface_note": "The load_any slot at +0x28 was translated in the preceding SFNT service checkpoint and is not repeated here.",
            "role_resolution": "same interface slot or corresponding name-helper caller, official FreeType source role, matching pseudocode, and ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/75b4fbd0462ad4544ffc447213777d1f0d536c1a/include/freetype/internal/sfnt.h",
                "https://android.googlesource.com/platform/external/freetype/+/75b4fbd0462ad4544ffc447213777d1f0d536c1a/src/sfnt/sfdriver.c",
                "https://android.googlesource.com/platform/external/freetype/+/3053d1b9db55099918843889e4809ce97483ca9f/src/sfnt/ttload.c",
                "https://android.googlesource.com/platform/external/freetype/+/41371e1e39c8528eb0c4bc40683c736e6683e60c/src/sfnt/sfobjs.c",
                "https://android.googlesource.com/platform/external/freetype/+/75b4fbd0462ad4544ffc447213777d1f0d536c1a/src/sfnt/ttkern.c",
                "https://android.googlesource.com/platform/external/freetype/+/75b4fbd0462ad4544ffc447213777d1f0d536c1a/src/sfnt/ttmtx.c",
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
            "interface_slot_count": sum(
                anchor["interface_offset"] is not None for anchor in anchors
            ),
            "name_helper_count": sum(
                anchor["interface_offset"] is None for anchor in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target functions had no surviving source names.",
            "Nineteen functions are recovered from the parallel sfnt_interface records; the two remaining functions are the name converters called by sfnt_load_face.",
            "The prior SFNT service checkpoint already translated the load_any callback, so this artifact does not duplicate that target.",
            "The source and target bodies have identical normalized feature metrics in this batch; several pairs differ only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
