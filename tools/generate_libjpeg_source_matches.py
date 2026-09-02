#!/usr/bin/env python3
"""Record exact IJG libjpeg 6b source matches in the ARM64 IDA inventory.

The APK contains the Independent JPEG Group implementation and retains the
public libjpeg entry points, while the static callback and worker routines
were created by IDA as address-only functions.  This report records only the
residual routines whose decompiled bodies and callback assignments were
matched against the official IJG 6b source tree.  Static aliases use a file
prefix because names such as ``start_pass`` occur in several source files.

The generator reads a local IDA inventory and never contacts a network.  It
can be run before the aliases are applied to create a staging report, then
again with ``--require-applied`` after the IDA database has been renamed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT.parent / "analysis" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "ida_libjpeg_source_matches_20260902.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SOURCE_ARCHIVE_URL = "https://www.ijg.org/files/jpegsrc.v6b.tar.gz"
SOURCE_ARCHIVE_SHA256 = "75c3ec241e9996504fe02a9ed4d12f16b74ade713972f3db9e65ce95cd27e35d"
SOURCE_VERSION = "6b  27-Mar-1998"


def row(address: int, source_file: str, upstream_name: str, source_line: int) -> dict:
    return {
        "address": f"0x{address:x}",
        "source_file": source_file,
        "upstream_name": upstream_name,
        "source_line": source_line,
    }


# Each entry below is a source-level role match.  The ARM64 compiler inlined
# several smaller IJG helpers into their callers, so the table intentionally
# does not claim that every source function has a separate machine function.
MATCHES = [
    row(0x28B9F4, "jdatadst.c", "init_destination", 43),
    row(0x28BA30, "jdatadst.c", "empty_output_buffer", 81),
    row(0x28BAA4, "jdatadst.c", "term_destination", 106),
    row(0x28BBBC, "jdatasrc.c", "init_source", 44),
    row(0x28BBCC, "jdatasrc.c", "fill_input_buffer", 90),
    row(0x28BC88, "jdatasrc.c", "skip_input_data", 128),
    row(0x28BC84, "jdatasrc.c", "term_source", 169),
    row(0x28BE44, "jdinput.c", "finish_input_pass", 271),
    row(0x28BE58, "jdinput.c", "reset_input_controller", 339),
    row(0x28BEB0, "jdinput.c", "start_input_pass", 254),
    row(0x28C378, "jdinput.c", "consume_markers", 288),
    row(0x28CBB8, "jdmarker.c", "get_sof", 237),
    row(0x28CFFC, "jdmarker.c", "examine_app0", 584),
    row(0x28D2EC, "jdmarker.c", "skip_variable", 845),
    row(0x28D400, "jdmarker.c", "reset_marker_reader", 1242),
    row(0x28D424, "jdmarker.c", "get_interesting_appn", 691),
    row(0x28D804, "jdmarker.c", "save_marker", 739),
    row(0x28DB3C, "jdmarker.c", "next_marker", 874),
    row(0x28DD9C, "jdmarker.c", "read_markers", 952),
    row(0x28EB20, "jdmarker.c", "read_restart_marker", 1113),
    row(0x0E0454, "jdmarker.c", "examine_app14", 660),
    row(0x28F2B0, "jdmaster.c", "prepare_for_output_pass", 438),
    row(0x28F478, "jdmaster.c", "finish_output_pass", 498),
    row(0x28FEE0, "jdmerge.c", "start_pass_merged_upsample", 126),
    row(0x28FEF4, "jdmerge.c", "merged_1v_upsample", 193),
    row(0x28FF44, "jdmerge.c", "h2v1_merged_upsample", 226),
    row(0x290094, "jdmerge.c", "h2v2_merged_upsample", 288),
    row(0x290294, "jdmerge.c", "merged_2v_upsample", 144),
    row(0x290538, "jdphuff.c", "start_pass_phuff_decoder", 92),
    row(0x29095C, "jdphuff.c", "decode_mcu_DC_first", 286),
    row(0x290E3C, "jdphuff.c", "decode_mcu_AC_first", 357),
    row(0x291154, "jdphuff.c", "decode_mcu_DC_refine", 442),
    row(0x2912F8, "jdphuff.c", "decode_mcu_AC_refine", 491),
    row(0x2916F8, "jdpostct.c", "start_pass_dpost", 73),
    row(0x291810, "jdpostct.c", "post_process_1pass", 126),
    row(0x2918A0, "jdpostct.c", "post_process_prepass", 158),
    row(0x2919A0, "jdpostct.c", "post_process_2pass", 202),
    row(0x291B6C, "jdsample.c", "start_pass_upsample", 69),
    row(0x291B84, "jdsample.c", "sep_upsample", 89),
    row(0x291CE8, "jdsample.c", "fullsize_upsample", 157),
    row(0x291CF0, "jdsample.c", "noop_upsample", 170),
    row(0x291CF8, "jdsample.c", "int_upsample", 189),
    row(0x291F6C, "jdsample.c", "h2v1_upsample", 233),
    row(0x292220, "jdsample.c", "h2v2_upsample", 261),
    row(0x292360, "jdsample.c", "h2v1_fancy_upsample", 304),
    row(0x292568, "jdsample.c", "h2v2_fancy_upsample", 345),
    row(0x292AAC, "jerror.c", "emit_message", 128),
    row(0x292B24, "jerror.c", "reset_error_mgr", 212),
    row(0x292B34, "jerror.c", "format_message", 157),
    row(0x292C1C, "jerror.c", "output_message", 98),
    row(0x292C64, "jerror.c", "error_exit", 70),
    row(0x292CF8, "jmemmgr.c", "alloc_small", 257),
    row(0x292EF8, "jmemmgr.c", "alloc_large", 342),
    row(0x293058, "jmemmgr.c", "alloc_sarray", 395),
    row(0x293168, "jmemmgr.c", "alloc_barray", 443),
    row(0x293500, "jmemmgr.c", "request_virt_sarray", 523),
    row(0x2938B0, "jmemmgr.c", "request_virt_barray", 553),
    row(0x293ACC, "jmemmgr.c", "realize_virt_arrays", 583),
    row(0x293CE8, "jmemmgr.c", "access_virt_sarray", 756),
    row(0x293E50, "jmemmgr.c", "access_virt_barray", 841),
    row(0x2941D0, "jmemmgr.c", "free_pool", 930),
    row(0x294534, "jmemmgr.c", "self_destruct", 1002),
    row(0x294F44, "jquant1.c", "color_quantize", 459),
    row(0x294FD0, "jquant1.c", "color_quantize3", 487),
    row(0x295050, "jquant1.c", "quantize3_ord_dither", 565),
    row(0x295138, "jquant1.c", "finish_pass_1_quant", 798),
    row(0x29513C, "jquant1.c", "new_color_map_1_quant", 810),
    row(0x295164, "jquant1.c", "quantize_fs_dither", 610),
    row(0x295344, "jquant1.c", "quantize_ord_dither", 515),
    row(0x29545C, "jquant1.c", "start_pass_1_quant", 741),
    row(0x296270, "jquant2.c", "prescan_quantize", 224),
    row(0x2962F4, "jquant2.c", "finish_pass2", 1156),
    row(0x2962F8, "jquant2.c", "new_color_map_2_quant", 1230),
    row(0x296308, "jquant2.c", "start_pass_2_quant", 1167),
    row(0x296620, "jquant2.c", "find_nearby_colors", 646),
    row(0x296A64, "jquant2.c", "fill_inverse_cmap", 855),
    row(0x296EE0, "jquant2.c", "pass2_no_dither", 915),
    row(0x296FE4, "jquant2.c", "pass2_fs_dither", 949),
    row(0x297388, "jquant2.c", "finish_pass1", 1143),
    row(0x2986C0, "jcmarker.c", "write_marker_byte", 450),
    row(0x29872C, "jcmarker.c", "write_file_trailer", 602),
    row(0x2987F0, "jcmarker.c", "write_marker_header", 438),
    row(0x2989A0, "jcmarker.c", "emit_dqt", 144),
    row(0x298E90, "jcmarker.c", "write_file_header", 469),
    row(0x299AC8, "jcmarker.c", "emit_dht", 184),
    row(0x299E54, "jcmarker.c", "write_frame_header", 494),
    row(0x29A2D8, "jcmarker.c", "write_scan_header", 551),
    row(0x29AA48, "jcmarker.c", "write_tables_only", 616),
    row(0x29C6BC, "jdcoefct.c", "dummy_consume_data", 228),
    row(0x29C6C4, "jdcoefct.c", "consume_data", 244),
    row(0x29C9C8, "jdcoefct.c", "start_output_pass", 119),
    row(0x29CB80, "jdcoefct.c", "decompress_smooth_data", 461),
    row(0x29D2F8, "jdcoefct.c", "decompress_data", 315),
    row(0x29D510, "jdcoefct.c", "start_input_pass", 107),
    row(0x29D570, "jdcoefct.c", "decompress_onepass", 147),
    row(0x29DA68, "jdcolor.c", "ycc_rgb_convert", 120),
    row(0x29DB28, "jdcolor.c", "null_convert", 169),
    row(0x29DBA4, "jdcolor.c", "gray_rgb_convert", 217),
    row(0x29DEE8, "jdcolor.c", "ycck_cmyk_convert", 245),
    row(0x29DFCC, "jdcolor.c", "grayscale_convert", 201),
    row(0x29DFC8, "jdcolor.c", "start_pass_dcolor", 293),
    row(0x29E40C, "jddctmgr.c", "start_pass", 89),
    row(0x29F2D0, "jdhuff.c", "start_pass_huff_decoder", 86),
    row(0x29F734, "jdhuff.c", "decode_mcu", 517),
    row(0x29FC98, "jdmainct.c", "process_data_simple_main", 345),
    row(0x29FD40, "jdmainct.c", "process_data_context_main", 385),
    row(0x2A00C0, "jdmainct.c", "process_data_crank_post", 459),
    row(0x2A00F8, "jdmainct.c", "start_pass_main", 307),
    row(0x2A1B50, "jccoefct.c", "start_iMCU_row", 72),
    row(0x2A1BB4, "jccoefct.c", "compress_data", 143),
    row(0x2A1E40, "jccoefct.c", "compress_first_pass", 245),
    row(0x2A2394, "jccoefct.c", "start_pass_coef", 100),
    row(0x2A24CC, "jccoefct.c", "compress_output", 341),
    row(0x2A2B0C, "jccolor.c", "rgb_ycc_start", 86),
    row(0x2A2BD0, "jccolor.c", "rgb_ycc_convert", 130),
    row(0x2A2CA4, "jccolor.c", "rgb_gray_convert", 186),
    row(0x2A2D1C, "jccolor.c", "cmyk_ycck_convert", 225),
    row(0x2A2E20, "jccolor.c", "grayscale_convert", 280),
    row(0x2A2E6C, "jccolor.c", "null_convert", 309),
    row(0x2A2EE0, "jccolor.c", "null_method", 341),
    row(0x2A31F0, "jcdctmgr.c", "start_pass_fdctmgr", 54),
    row(0x2A3638, "jcdctmgr.c", "forward_DCT", 180),
    row(0x2A37A0, "jcdctmgr.c", "forward_DCT_float", 270),
    row(0x2A3CF0, "jchuff.c", "encode_mcu_gather", 645),
    row(0x2A3F30, "jchuff.c", "finish_pass_huff", 533),
    row(0x2A40B0, "jchuff.c", "encode_mcu_huff", 476),
    row(0x2A4EC8, "jchuff.c", "start_pass_huff", 106),
    row(0x2A54A4, "jchuff.c", "finish_pass_gather", 846),
    row(0x2A563C, "jcmainct.c", "process_data_simple_main", 113),
    row(0x2A575C, "jcmainct.c", "start_pass_main", 69),
    row(0x2A5898, "jcmaster.c", "validate_script", 130),
    row(0x2A6234, "jcmaster.c", "pass_startup", 489),
    row(0x2A6270, "jcmaster.c", "finish_pass_master", 503),
    row(0x2A6324, "jcmaster.c", "prepare_for_pass", 401),
    row(0x2A73FC, "jcphuff.c", "start_pass_phuff", 106),
    row(0x2A75DC, "jcphuff.c", "emit_eobrun", 316),
    row(0x2A7C80, "jcphuff.c", "encode_mcu_AC_refine", 618),
    row(0x2A88EC, "jcphuff.c", "finish_pass_phuff", 746),
    row(0x2A8AA4, "jcphuff.c", "finish_pass_gather_phuff", 767),
    row(0x2A8DA4, "jcphuff.c", "encode_mcu_DC_refine", 571),
    row(0x2A922C, "jcphuff.c", "encode_mcu_DC_first", 377),
    row(0x2A9AE0, "jcphuff.c", "encode_mcu_AC_first", 464),
    row(0x2AA4B8, "jcprepct.c", "start_pass_prep", 78),
    row(0x2AA510, "jcprepct.c", "pre_process_context", 195),
    row(0x2AA7A4, "jcprepct.c", "pre_process_data", 128),
    row(0x2AAE3C, "jcsample.c", "start_pass_downsample", 75),
    row(0x2AAE40, "jcsample.c", "sep_downsample", 114),
    row(0x2AAEE4, "jcsample.c", "int_downsample", 140),
    row(0x2AB2F4, "jcsample.c", "h2v1_downsample", 212),
    row(0x2AB4A4, "jcsample.c", "h2v2_downsample", 249),
    row(0x2AB670, "jcsample.c", "h2v2_smooth_downsample", 292),
    row(0x2ABA28, "jcsample.c", "fullsize_smooth_downsample", 392),
    row(0x2ABCD0, "jcsample.c", "fullsize_downsample", 187),
]


def alias_for(item: dict) -> str:
    return f"libjpeg_{Path(item['source_file']).stem}_{item['upstream_name']}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_report(inventory_path: Path, require_applied: bool = False) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")
    rows = {int(item["ea"]): item for item in document}
    seen_addresses = set()
    seen_names = set()
    matches = []
    for item in MATCHES:
        ea = int(item["address"], 16)
        alias = alias_for(item)
        if ea in seen_addresses:
            raise ValueError(f"duplicate source-match address: {item['address']}")
        if alias in seen_names:
            raise ValueError(f"duplicate source-match alias: {alias}")
        seen_addresses.add(ea)
        seen_names.add(alias)
        current = rows.get(ea)
        if current is None:
            raise ValueError(f"source match address is absent from inventory: {item['address']}")
        current_name = current.get("name")
        is_alias = current_name == alias
        is_default = bool(current.get("is_default_sub")) or str(current_name).startswith(
            ("sub_", "nullsub_")
        )
        is_previous_source_alias = str(current_name).startswith(("libjpeg_", "zlib_"))
        if require_applied and not is_alias:
            raise ValueError(
                f"source match is not applied at {item['address']}: "
                f"expected {alias}, got {current_name}"
            )
        if not is_alias and not is_default and not is_previous_source_alias:
            raise ValueError(
                f"unexpected pre-existing name at {item['address']}: {current_name}"
            )
        source_url = f"{SOURCE_ARCHIVE_URL}#{item['source_file']}:{item['source_line']}"
        matches.append(
            {
                **item,
                "confidence": "exact",
                "current_ida_name": current_name,
                "ida_name": alias,
                "ida_name_origin": current.get("name_origin") if is_alias else None,
                "original_profile_category": "jpeg_static_internal",
                "role": (
                    f"IJG libjpeg 6b {item['upstream_name']} role from "
                    f"{item['source_file']}"
                ),
                "size": int(current.get("size", 0)),
                "source_url": source_url,
                "xrefs_to": current.get("xrefs_to"),
            }
        )
    matches.sort(key=lambda item: int(item["address"], 16))
    applied_count = sum(item["current_ida_name"] == item["ida_name"] for item in matches)
    return {
        "artifact": "ida_libjpeg_source_matches_20260902",
        "schema": "libqplay.ida-libjpeg-source-match.v1",
        "tool": "tools/generate_libjpeg_source_matches.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": (
            "exact source-role matches for residual static IJG libjpeg 6b "
            "routines in the original ARM64 libqplay.so"
        ),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "source": {
            "project": "Independent JPEG Group",
            "version": SOURCE_VERSION,
            "version_file": "jversion.h",
            "version_string": "6b  27-Mar-1998",
            "copyright_string": "Copyright (C) 1998, Thomas G. Lane",
            "archive_url": SOURCE_ARCHIVE_URL,
            "archive_sha256": SOURCE_ARCHIVE_SHA256,
            "source_files": sorted({item["source_file"] for item in matches}),
            "acquisition_note": (
                "The official v6b archive was downloaded once into a local "
                "pinned checkout for comparison. This report reads only the "
                "local IDA inventory."
            ),
        },
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "network_contacted": False,
        "match_count": len(matches),
        "applied_name_count": applied_count,
        "name_policy": (
            "Static routines receive libjpeg_<source-file>_<source-name> "
            "aliases so repeated upstream callback names remain unique in IDA."
        ),
        "matches": matches,
        "method": [
            "Confirm the embedded IJG version from the binary copyright and version strings.",
            "Compare decompiled control flow, data structure offsets, and callback-table assignments with the tagged v6b source.",
            "Check the address, function size, xref count, and current IDA name against the inventory before recording a row.",
        ],
        "not_claimed": [
            "That every source-level IJG helper has a standalone machine function.",
            "That compiler inlining or local build options are absent from the APK.",
            "That the source archive alone proves the runtime image accepts every malformed JPEG input safely.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", nargs="?", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--require-applied",
        action="store_true",
        help="require every current IDA name to equal its generated source alias",
    )
    args = parser.parse_args()
    inventory = args.inventory if args.inventory.is_absolute() else Path.cwd() / args.inventory
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not inventory.is_file():
        parser.error(f"IDA inventory does not exist: {inventory}")
    report = build_report(inventory, require_applied=args.require_applied)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": output.as_posix(),
                "match_count": report["match_count"],
                "applied_name_count": report["applied_name_count"],
                "inventory_rows": report["inventory"]["row_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
