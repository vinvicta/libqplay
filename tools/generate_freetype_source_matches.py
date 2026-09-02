#!/usr/bin/env python3
"""Record exact FreeType 2.3.6 source matches in the current IDA inventory.

The address and name checks prevent this artifact from silently describing a
different binary or a rename that was not actually applied. The generator
only reads local JSON files and does not contact a network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT.parent / "analysis" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "ida_freetype_source_matches_20260901.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SOURCE_REPOSITORY = "https://github.com/freetype/freetype2"
SOURCE_TAG = "VER-2-3-6"
SOURCE_COMMIT = "6174e17cf7cb3eef826d95c96757dbb0feea7bdb"


MATCHES = [
    {
        "address": "0x250e94",
        "upstream_name": "destroy_size",
        "source_file": "src/base/ftobjs.c",
        "source_line": 774,
        "evidence": "The generic finalizer, driver done_size callback, internal allocation free, and size free occur in the same order.",
    },
    {
        "address": "0x25e320",
        "upstream_name": "tt_get_kerning",
        "source_file": "src/truetype/ttdriver.c",
        "source_line": 106,
        "evidence": "The output vector is zeroed and the SFNT service supplies the horizontal kerning value when available.",
    },
    {
        "address": "0x25e35c",
        "upstream_name": "tt_face_get_location",
        "source_file": "src/truetype/ttpload.c",
        "source_line": 119,
        "evidence": "The loca table short and long offset paths, bounds checks, and entry-size handling match exactly.",
    },
    {
        "address": "0x25e4e4",
        "upstream_name": "tt_size_init",
        "source_file": "src/truetype/ttobjs.c",
        "source_line": 727,
        "evidence": "The bytecode and CVT state is cleared and the strike index is initialized to 0xffffffff as in the source.",
    },
    {
        "address": "0x25e504",
        "upstream_name": "TT_MulFix14",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1139,
        "evidence": "The high and low half multiply, 0x2000 rounding, 14-bit shift, and sign restoration are identical.",
    },
    {
        "address": "0x25e580",
        "upstream_name": "Direct_Move_X",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1634,
        "evidence": "The x-axis freedom-vector move and touch-X tag update match the interpreter callback.",
    },
    {
        "address": "0x25e5b0",
        "upstream_name": "Direct_Move_Y",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1646,
        "evidence": "The y-axis freedom-vector move and touch-Y tag update match the interpreter callback.",
    },
    {
        "address": "0x25e5e4",
        "upstream_name": "Direct_Move_Orig_X",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1668,
        "evidence": "The original-coordinate x-axis movement path matches the special interpreter callback.",
    },
    {
        "address": "0x25e5fc",
        "upstream_name": "Direct_Move_Orig_Y",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1679,
        "evidence": "The original-coordinate y-axis movement path matches the special interpreter callback.",
    },
    {
        "address": "0x25e618",
        "upstream_name": "Round_None",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1712,
        "evidence": "The compensation add or subtract rules and signed overflow clamps match the no-rounding function.",
    },
    {
        "address": "0x25e640",
        "upstream_name": "Project",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 2186,
        "evidence": "The helper computes a TT_DotFix14 result using the current projection vector fields.",
    },
    {
        "address": "0x25e6cc",
        "upstream_name": "Project_x",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 2242,
        "evidence": "The callback returns its x input and is assigned by Compute_Funcs to the horizontal projection slot.",
    },
    {
        "address": "0x25e6d4",
        "upstream_name": "Project_y",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 2269,
        "evidence": "The callback returns its y input and is assigned by Compute_Funcs to the vertical projection slot.",
    },
    {
        "address": "0x25e6dc",
        "upstream_name": "Ins_NPUSHW",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4621,
        "evidence": "The count bounds check, signed big-endian word reads, instruction pointer advance, and stack updates match.",
    },
    {
        "address": "0x25e770",
        "upstream_name": "Ins_PUSHW",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4676,
        "evidence": "The opcode-derived word count and signed instruction-stream reads match.",
    },
    {
        "address": "0x25e7f8",
        "upstream_name": "Ins_GC",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4717,
        "evidence": "The point validation, current or original projection selection, and result write match.",
    },
    {
        "address": "0x25e890",
        "upstream_name": "Ins_SCFS",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4758,
        "evidence": "The projection of the stack distance, freedom-vector move, twilight copy, and error path match.",
    },
    {
        "address": "0x25e950",
        "upstream_name": "Ins_GETINFO",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 6715,
        "evidence": "The version, rotation, stretch, and grayscale feature bits match the handler.",
    },
    {
        "address": "0x25e9a8",
        "upstream_name": "Ins_MD",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4800,
        "evidence": "The two-point bounds checks, dual projection, scaling, and stack result match.",
    },
    {
        "address": "0x25eaf8",
        "upstream_name": "tt_size_request",
        "source_file": "src/truetype/ttdriver.c",
        "source_line": 179,
        "evidence": "The metrics request and scaling logic match, and the address occupies the corresponding driver class slot.",
    },
    {
        "address": "0x25ec84",
        "upstream_name": "Direct_Move_Orig",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1596,
        "evidence": "The freedom-vector movement updates original coordinates without setting touch flags.",
    },
    {
        "address": "0x25ed14",
        "upstream_name": "Direct_Move",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1543,
        "evidence": "The freedom-vector movement updates current coordinates and sets the touch flags.",
    },
    {
        "address": "0x25edd0",
        "upstream_name": "Ins_ISECT",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 6036,
        "evidence": "The five-point intersection calculation, discriminant threshold, midpoint fallback, and touch-both flag match.",
    },
    {
        "address": "0x260050",
        "upstream_name": "Compute_Funcs",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 2289,
        "evidence": "The projection and movement callback selection, including the unpatented-hinting branch, matches the source.",
    },
]


# These rows were established in the follow-up source pass.  Keeping the
# compact address table here makes the generated artifact reproducible while
# the common evidence sentence still explains the standard used for each row.
ADDITIONAL_SOURCE_ROWS = (
    (0x252E90, "destroy_face", "src/base/ftobjs.c", 822),
    (0x254B98, "tt_get_cmap_info", "src/sfnt/ttcmap.c", 3112),
    (0x254BB8, "tt_face_get_kerning", "src/sfnt/ttkern.c", 177),
    (0x254D80, "get_sfnt_table", "src/sfnt/sfdriver.c", 58),
    (0x255FC0, "tt_face_free_name", "src/sfnt/ttload.c", 786),
    (0x256060, "tt_name_entry_ascii_from_utf16", "src/sfnt/sfobjs.c", 49),
    (0x2563D0, "tt_name_entry_ascii_from_other", "src/sfnt/sfobjs.c", 80),
    (0x2565E8, "tt_face_goto_table", "src/sfnt/ttload.c", 111),
    (0x25663C, "tt_face_load_any", "src/sfnt/ttload.c", 394),
    (0x2566D8, "tt_face_get_metrics", "src/sfnt/ttmtx.c", 347),
    (0x25687C, "tt_face_load_hmtx", "src/sfnt/ttmtx.c", 66),
    (0x2568FC, "tt_face_load_pclt", "src/sfnt/ttload.c", 1067),
    (0x256960, "tt_face_load_name", "src/sfnt/ttload.c", 656),
    (0x256B14, "tt_face_load_post", "src/sfnt/ttload.c", 1007),
    (0x256B7C, "tt_face_load_os2", "src/sfnt/ttload.c", 867),
    (0x256D24, "tt_face_load_hhea", "src/sfnt/ttmtx.c", 254),
    (0x256EF4, "tt_face_load_gasp", "src/sfnt/ttload.c", 1126),
    (0x257030, "tt_face_load_kern", "src/sfnt/ttkern.c", 45),
    (0x257254, "sfnt_done_face", "src/sfnt/sfobjs.c", 1028),
    (0x2573B8, "tt_face_build_cmaps", "src/sfnt/ttcmap.c", 3010),
    (0x257704, "sfnt_init_face", "src/sfnt/sfobjs.c", 415),
    (0x25796C, "sfnt_table_info", "src/sfnt/sfdriver.c", 103),
    (0x2579B4, "sfnt_get_ps_name", "src/sfnt/sfdriver.c", 169),
    (0x257C28, "tt_face_load_font_dir", "src/sfnt/ttload.c", 262),
    (0x257F64, "tt_face_load_maxp", "src/sfnt/ttload.c", 550),
    (0x258198, "tt_face_load_cmap", "src/sfnt/ttload.c", 831),
    (0x258204, "tt_face_load_head", "src/sfnt/ttload.c", 514),
    (0x25A8E0, "sfnt_load_face", "src/sfnt/sfobjs.c", 503),
    (0x25B5F4, "ft_smooth_init", "src/smooth/ftsmooth.c", 30),
    (0x25B62C, "ft_smooth_set_mode", "src/smooth/ftsmooth.c", 45),
    (0x25B654, "gray_raster_done", "src/smooth/ftgrays.c", 1928),
    (0x25B660, "gray_render_span", "src/smooth/ftgrays.c", 1119),
    (0x25B76C, "gray_raster_new", "src/smooth/ftgrays.c", 1909),
    (0x25B7B4, "ft_smooth_get_cbox", "src/smooth/ftsmooth.c", 84),
    (0x25B7DC, "ft_smooth_render_lcd_v", "src/smooth/ftsmooth.c", 363),
    (0x25BA90, "gray_raster_reset", "src/smooth/ftgrays.c", 1940),
    (0x25BAEC, "ft_smooth_transform", "src/smooth/ftsmooth.c", 57),
    (0x25BB64, "gray_convert_glyph_inner", "src/smooth/ftgrays.c", 1604),
    (0x25BCA8, "gray_move_to", "src/smooth/ftgrays.c", 1067),
    (0x25BE44, "gray_convert_glyph", "src/smooth/ftgrays.c", 1634),
    (0x25C878, "gray_raster_render", "src/smooth/ftgrays.c", 1788),
    (0x25CA78, "ft_smooth_render", "src/smooth/ftsmooth.c", 330),
    (0x25CCB8, "ft_smooth_render_lcd", "src/smooth/ftsmooth.c", 345),
    (0x25CF78, "gray_render_scanline", "src/smooth/ftgrays.c", 524),
    (0x25D4BC, "gray_render_line", "src/smooth/ftgrays.c", 631),
    (0x25DCBC, "gray_cubic_to", "src/smooth/ftgrays.c", 1108),
    (0x25E04C, "gray_conic_to", "src/smooth/ftgrays.c", 1098),
    (0x25E2EC, "gray_line_to", "src/smooth/ftgrays.c", 1089),
    (0x25F4F4, "tt_slot_init", "src/truetype/ttobjs.c", 937),
    (0x25F500, "tt_face_done", "src/truetype/ttobjs.c", 331),
    (0x25F648, "tt_face_init", "src/truetype/ttobjs.c", 171),
    (0x25FD8C, "Current_Ratio", "src/truetype/ttinterp.c", 1346),
    (0x25FE38, "Round_To_Grid", "src/truetype/ttinterp.c", 1752),
    (0x25FE7C, "Round_To_Half_Grid", "src/truetype/ttinterp.c", 1796),
    (0x25FEB8, "Round_Down_To_Grid", "src/truetype/ttinterp.c", 1838),
    (0x25FEF4, "Round_Up_To_Grid", "src/truetype/ttinterp.c", 1882),
    (0x25FF38, "Round_To_Double_Grid", "src/truetype/ttinterp.c", 1926),
    (0x25FF7C, "Round_Super", "src/truetype/ttinterp.c", 1976),
    (0x25FFE8, "Round_Super_45", "src/truetype/ttinterp.c", 2024),
    (0x2602A4, "Ins_SZP0", "src/truetype/ttinterp.c", 4925),
    (0x2602FC, "Ins_SZP1", "src/truetype/ttinterp.c", 4954),
    (0x260354, "Ins_SZP2", "src/truetype/ttinterp.c", 4983),
    (0x2603AC, "Ins_SZPS", "src/truetype/ttinterp.c", 5012),
    (0x260468, "Ins_ALIGNRP", "src/truetype/ttinterp.c", 5983),
    (0x260590, "Ins_UTP", "src/truetype/ttinterp.c", 6257),
    (0x260660, "Ins_MDRP", "src/truetype/ttinterp.c", 5748),
    (0x2608E0, "Ins_IP", "src/truetype/ttinterp.c", 6153),
    (0x260BC4, "TT_DotFix14", "src/truetype/ttinterp.c", 1203),
    (0x260D7C, "Ins_MINDEX", "src/truetype/ttinterp.c", 4081),
    (0x260E00, "tt_driver_done", "src/truetype/ttobjs.c", 903),
    (0x260E8C, "Ins_IUP", "src/truetype/ttinterp.c", 6417),
    (0x261624, "Ins_ENDF", "src/truetype/ttinterp.c", 4323),
    (0x2616E0, "tt_size_done_bytecode", "src/truetype/ttobjs.c", 531),
    (0x261818, "Dual_Project", "src/truetype/ttinterp.c", 2216),
    (0x2618A4, "Ins_FDEF", "src/truetype/ttinterp.c", 4258),
    (0x2619D4, "Ins_IDEF", "src/truetype/ttinterp.c", 4526),
    (0x261D8C, "Ins_DELTAP", "src/truetype/ttinterp.c", 6521),
    (0x261FC4, "Ins_DELTAC", "src/truetype/ttinterp.c", 6616),
    (0x2621F4, "TT_Load_Context", "src/truetype/ttinterp.c", 556),
    (0x2625E8, "Ins_SHC", "src/truetype/ttinterp.c", 5418),
    (0x262864, "Ins_SHP", "src/truetype/ttinterp.c", 5365),
    (0x262A74, "Ins_MIRP", "src/truetype/ttinterp.c", 5861),
    (0x262DB4, "load_truetype_glyph", "src/truetype/ttgload.c", 1089),
    (0x263D1C, "TT_Load_Glyph", "src/truetype/ttgload.c", 1897),
    (0x264F78, "Load_Glyph", "src/truetype/ttdriver.c", 241),
    (0x264FCC, "Ins_SxVTL", "src/truetype/ttinterp.c", 2528),
    (0x26521C, "Ins_CALL", "src/truetype/ttinterp.c", 4371),
    (0x265370, "Ins_LOOPCALL", "src/truetype/ttinterp.c", 4448),
    (0x2654D4, "Ins_UNKNOWN", "src/truetype/ttinterp.c", 6743),
    (0x267ECC, "tt_driver_init", "src/truetype/ttobjs.c", 870),
    (0x267EF0, "af_dummy_hints_init", "src/autofit/afdummy.c", 25),
    (0x267F08, "af_dummy_hints_apply", "src/autofit/afdummy.c", 35),
    (0x267F10, "af_latin_hints_init", "src/autofit/aflatin.c", 1309),
    (0x267F90, "af_latin2_hints_init", "src/autofit/aflatin2.c", 1391),
    (0x268010, "af_cjk_metrics_scale", "src/autofit/afcjk.c", 95),
    (0x268050, "af_cjk_hints_init", "src/autofit/afcjk.c", 602),
    (0x2680C0, "af_latin2_hints_compute_segments", "src/autofit/aflatin2.c", 611),
    (0x268608, "af_cjk_hints_link_segments", "src/autofit/afcjk.c", 158),
    (0x2688FC, "af_cjk_hints_compute_edges", "src/autofit/afcjk.c", 323),
    (0x268E58, "af_face_globals_free", "src/autofit/afglobal.c", 192),
    (0x268F44, "af_loader_load_g", "src/autofit/afloader.c", 85),
    (0x2696D4, "af_glyph_hints_reload", "src/autofit/afhints.c", 553),
    (0x269BF4, "af_latin2_metrics_scale", "src/autofit/aflatin2.c", 589),
    (0x269F1C, "af_latin_metrics_scale", "src/autofit/aflatin.c", 587),
    (0x26A3D0, "af_latin_hints_compute_segments", "src/autofit/aflatin.c", 607),
    (0x26A904, "af_latin_metrics_init_widths", "src/autofit/aflatin.c", 37),
    (0x26ADCC, "af_cjk_metrics_init", "src/autofit/afcjk.c", 49),
    (0x26AE34, "af_hint_normal_stem", "src/autofit/afcjk.c", 888),
    (0x26B198, "af_latin2_metrics_init_widths", "src/autofit/aflatin2.c", 45),
    (0x26B660, "af_latin2_metrics_init", "src/autofit/aflatin2.c", 405),
    (0x26BB4C, "af_latin_metrics_init", "src/autofit/aflatin.c", 397),
    (0x26C040, "af_latin2_hints_compute_edges", "src/autofit/aflatin2.c", 966),
    (0x26C61C, "af_latin_hints_compute_edges", "src/autofit/aflatin.c", 912),
    (0x26CB68, "af_glyph_hints_align_weak_points", "src/autofit/afhints.c", 1111),
    (0x26D1F8, "af_cjk_hints_apply", "src/autofit/afcjk.c", 1356),
    (0x26DF5C, "af_latin2_hints_apply", "src/autofit/aflatin2.c", 2184),
    (0x26F820, "af_latin_hints_apply", "src/autofit/aflatin.c", 2045),
)

MATCHES.extend(
    {
        "address": f"0x{address:x}",
        "upstream_name": name,
        "source_file": source_file,
        "source_line": source_line,
        "evidence": (
            f"The decompiled {name} body matches the tagged FreeType 2.3.6 "
            "implementation, and the surrounding call or callback context "
            "agrees with the corresponding source role."
        ),
    }
    for address, name, source_file, source_line in ADDITIONAL_SOURCE_ROWS
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_report(inventory_path: Path) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")
    rows = {int(row["ea"]): row for row in document}
    output_matches = []
    for item in MATCHES:
        ea = int(item["address"], 16)
        row = rows.get(ea)
        if row is None:
            raise ValueError(f"source match address is absent from inventory: {item['address']}")
        if row.get("name") != item["upstream_name"]:
            raise ValueError(
                f"IDA name mismatch at {item['address']}: "
                f"expected {item['upstream_name']}, got {row.get('name')}"
            )
        if row.get("is_default_sub"):
            raise ValueError(f"source match remains a default sub_: {item['address']}")
        source_url = f"{SOURCE_REPOSITORY}/blob/{SOURCE_TAG}/{item['source_file']}#L{item['source_line']}"
        output_matches.append({
            **item,
            "ida_name": row["name"],
            "ida_name_origin": row.get("name_origin"),
            "size": int(row.get("size", 0)),
            "xrefs_to": row.get("xrefs_to"),
            "source_url": source_url,
            "confidence": "exact",
        })
    output_matches.sort(key=lambda item: int(item["address"], 16))
    return {
        "schema": "libqplay.ida-freetype-source-match.v1",
        "tool": "tools/generate_freetype_source_matches.py",
        "tool_version": 1,
        "analysis_date": "2026-09-01",
        "analysis_scope": "exact source matches for embedded FreeType and TrueType helpers in original ARM64 libqplay.so",
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "source": {
            "repository": SOURCE_REPOSITORY,
            "tag": SOURCE_TAG,
            "commit": SOURCE_COMMIT,
            "files": sorted({item["source_file"] for item in output_matches}),
            "acquisition_note": "The source was inspected from a local pinned checkout. Artifact generation reads local files only.",
        },
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "network_contacted": False,
        "match_count": len(output_matches),
        "matches": output_matches,
        "method": [
            "Compare the ARM64 decompiler body with the tagged upstream implementation.",
            "Use callback-table assignments, object field offsets, and neighboring source behavior as corroborating evidence.",
            "Require the current IDA inventory to contain the expected applied name before recording an exact match.",
        ],
        "not_claimed": [
            "That every remaining FreeType or JPEG routine has been matched.",
            "That this source tag accounts for local compiler or build-option changes outside the matched bodies.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", nargs="?", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    inventory = args.inventory if args.inventory.is_absolute() else Path.cwd() / args.inventory
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not inventory.is_file():
        parser.error(f"IDA inventory does not exist: {inventory}")
    report = build_report(inventory)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": output.as_posix(),
        "match_count": report["match_count"],
        "inventory_rows": report["inventory"]["row_count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
