#!/usr/bin/env python3
"""Build the final residual report for the persisted IDA translation copy.

The public unresolved-function profile describes the 488 default functions in
the pre-persistence inventory. The role-candidate pass names 28 application or
engine entries, the first CyaSSL pass names 11 static TLS and crypto roles, and
the next static-library pass names 30 zlib, bzip2, minizip, GPC, CyaSSL,
LibTomCrypt, and YAJL roles. IDA reclassifies one compiler branch veneer as a
thunk when the saved copy is reopened. A later source comparison also names
141 embedded FreeType and TrueType routines from the pinned FreeType 2.3.6
source. This helper subtracts those known changes and emits the exact residual
count in the latest persisted database. It only reads JSON files and performs
no network operation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


DEFAULT_PROFILE = "artifacts/unresolved_function_profile.json"
DEFAULT_ROLES = "artifacts/unresolved_function_candidates.json"
DEFAULT_STATIC_ROLES = [
    "artifacts/cyassl_static_role_audit_20260826.json",
    "artifacts/static_library_role_audit_20260901.json",
]
DEFAULT_OUTPUT = "artifacts/ida_residual_profile.json"

CURRENT_DATABASE = {
    "path": "analysis/libqplay_translated_from_active_v11.i64",
    "sha256": "26471ffbe194a721e4fde7e894a451c7c8dccbe61c32eafc8305190b37ee6917",
    "bytes": 61286570,
    "format": "packed IDA 9.3 database",
    "close_reopen_verified": False,
    "function_count": 11297,
}

REANALYZED_FUNCTIONS = {
    0x0E01A0: {
        "new_name": "gpc_abort_malloc_failure_tristrip_node",
        "reason": (
            "IDA function at 0xe01a0 was identified as the GPC tristrip "
            "allocation-failure abort from its fixed diagnostic and exit path."
        ),
    },
    0x152200: {
        "new_name": "gpc_free_sbtree",
        "reason": (
            "The helper recursively frees the scanbeam tree passed through "
            "gpc_build_lmt and matches the upstream GPC free_sbtree role."
        ),
    },
    0x152898: {
        "new_name": "gpc_build_sbt",
        "reason": (
            "The helper flattens the scanbeam tree into the sorted scanbeam "
            "array and matches the upstream GPC build_sbt role."
        ),
    },
    0x1F94FC: {
        "new_name": "j_TCachedStream_get_minfilecachesize",
        "reason": (
            "IDA reclassified the four-byte unconditional branch veneer as a "
            "named thunk to TCachedStream_get_minfilecachesize when the "
            "persisted translation copy was rebuilt."
        ),
    },
    0x250E94: {
        "new_name": "destroy_size",
        "reason": (
            "The cleanup body matches FreeType 2.3.6 destroy_size: it runs "
            "the generic and driver finalizers, frees size->internal, and "
            "then frees the size object."
        ),
    },
    0x25E320: {
        "new_name": "tt_get_kerning",
        "reason": (
            "The helper initializes the kerning vector and delegates the x "
            "coordinate to the TrueType SFNT service, matching the pinned "
            "FreeType 2.3.6 tt_get_kerning implementation."
        ),
    },
    0x25E35C: {
        "new_name": "tt_face_get_location",
        "reason": (
            "The loca-table offset and short/long format handling match the "
            "pinned FreeType 2.3.6 tt_face_get_location implementation."
        ),
    },
    0x25E4E4: {
        "new_name": "tt_size_init",
        "reason": (
            "The size initialization fields and reset values match the "
            "pinned FreeType 2.3.6 tt_size_init implementation."
        ),
    },
    0x25E504: {
        "new_name": "TT_MulFix14",
        "reason": (
            "The split multiply, 0x2000 rounding, 14-bit shift, and sign "
            "restore match the pinned FreeType 2.3.6 TT_MulFix14 helper."
        ),
    },
    0x25E580: {
        "new_name": "Direct_Move_X",
        "reason": (
            "The x-axis point movement and touch flag behavior match the "
            "pinned FreeType 2.3.6 Direct_Move_X interpreter callback."
        ),
    },
    0x25E5B0: {
        "new_name": "Direct_Move_Y",
        "reason": (
            "The y-axis point movement and touch flag behavior match the "
            "pinned FreeType 2.3.6 Direct_Move_Y interpreter callback."
        ),
    },
    0x25E5E4: {
        "new_name": "Direct_Move_Orig_X",
        "reason": (
            "The original-coordinate x movement behavior matches the pinned "
            "FreeType 2.3.6 Direct_Move_Orig_X callback."
        ),
    },
    0x25E5FC: {
        "new_name": "Direct_Move_Orig_Y",
        "reason": (
            "The original-coordinate y movement behavior matches the pinned "
            "FreeType 2.3.6 Direct_Move_Orig_Y callback."
        ),
    },
    0x25E618: {
        "new_name": "Round_None",
        "reason": (
            "The signed compensation and overflow clamps match the pinned "
            "FreeType 2.3.6 Round_None implementation."
        ),
    },
    0x25E640: {
        "new_name": "Project",
        "reason": (
            "The projection-vector fixed-point dot product matches the pinned "
            "FreeType 2.3.6 Project interpreter callback."
        ),
    },
    0x25E6CC: {
        "new_name": "Project_x",
        "reason": (
            "The callback returns its x input and occupies the projection "
            "slot selected by Compute_Funcs, matching FreeType 2.3.6."
        ),
    },
    0x25E6D4: {
        "new_name": "Project_y",
        "reason": (
            "The callback returns its y input and occupies the projection "
            "slot selected by Compute_Funcs, matching FreeType 2.3.6."
        ),
    },
    0x25E6DC: {
        "new_name": "Ins_NPUSHW",
        "reason": (
            "The count check, signed big-endian word reads, and instruction "
            "state updates match the pinned FreeType 2.3.6 Ins_NPUSHW."
        ),
    },
    0x25E770: {
        "new_name": "Ins_PUSHW",
        "reason": (
            "The opcode-derived word count and signed stream reads match the "
            "pinned FreeType 2.3.6 Ins_PUSHW implementation."
        ),
    },
    0x25E7F8: {
        "new_name": "Ins_GC",
        "reason": (
            "The point validation, projection choice, and current-coordinate "
            "write match the pinned FreeType 2.3.6 Ins_GC handler."
        ),
    },
    0x25E890: {
        "new_name": "Ins_SCFS",
        "reason": (
            "The projection, freedom-vector move, and twilight copy behavior "
            "match the pinned FreeType 2.3.6 Ins_SCFS handler."
        ),
    },
    0x25E950: {
        "new_name": "Ins_GETINFO",
        "reason": (
            "The version and graphics-state feature bits match the pinned "
            "FreeType 2.3.6 Ins_GETINFO handler."
        ),
    },
    0x25E9A8: {
        "new_name": "Ins_MD",
        "reason": (
            "The two-point validation, dual projection, scaling, and stack "
            "result match the pinned FreeType 2.3.6 Ins_MD handler."
        ),
    },
    0x25EAF8: {
        "new_name": "tt_size_request",
        "reason": (
            "The metrics request and scaling path match the pinned FreeType "
            "2.3.6 tt_size_request driver callback and its class-table slot."
        ),
    },
    0x25EC84: {
        "new_name": "Direct_Move_Orig",
        "reason": (
            "The freedom-vector movement of original coordinates without touch "
            "flags matches the pinned FreeType 2.3.6 Direct_Move_Orig."
        ),
    },
    0x25ED14: {
        "new_name": "Direct_Move",
        "reason": (
            "The freedom-vector movement of current coordinates with touch flags "
            "matches the pinned FreeType 2.3.6 Direct_Move."
        ),
    },
    0x25EDD0: {
        "new_name": "Ins_ISECT",
        "reason": (
            "The five-point intersection math, discriminant fallback, and touch "
            "flags match the pinned FreeType 2.3.6 Ins_ISECT handler."
        ),
    },
    0x260050: {
        "new_name": "Compute_Funcs",
        "reason": (
            "The projection and movement callback selection, including the "
            "unpatented-hinting branch, matches the pinned FreeType 2.3.6 "
            "Compute_Funcs implementation."
        ),
    },
}


# The current IDA copy carries exact names for these additional FreeType
# routines. The source-line and body evidence lives in the dedicated
# source-match artifact; this table supplies the residual arithmetic.
ADDITIONAL_FREETYPE_REANALYZED = {
    0x252E90: "destroy_face",
    0x254B98: "tt_get_cmap_info",
    0x254BB8: "tt_face_get_kerning",
    0x254D80: "get_sfnt_table",
    0x255FC0: "tt_face_free_name",
    0x256060: "tt_name_entry_ascii_from_utf16",
    0x2563D0: "tt_name_entry_ascii_from_other",
    0x2565E8: "tt_face_goto_table",
    0x25663C: "tt_face_load_any",
    0x2566D8: "tt_face_get_metrics",
    0x25687C: "tt_face_load_hmtx",
    0x2568FC: "tt_face_load_pclt",
    0x256960: "tt_face_load_name",
    0x256B14: "tt_face_load_post",
    0x256B7C: "tt_face_load_os2",
    0x256D24: "tt_face_load_hhea",
    0x256EF4: "tt_face_load_gasp",
    0x257030: "tt_face_load_kern",
    0x257254: "sfnt_done_face",
    0x2573B8: "tt_face_build_cmaps",
    0x257704: "sfnt_init_face",
    0x25796C: "sfnt_table_info",
    0x2579B4: "sfnt_get_ps_name",
    0x257C28: "tt_face_load_font_dir",
    0x257F64: "tt_face_load_maxp",
    0x258198: "tt_face_load_cmap",
    0x258204: "tt_face_load_head",
    0x25A8E0: "sfnt_load_face",
    0x25B5F4: "ft_smooth_init",
    0x25B62C: "ft_smooth_set_mode",
    0x25B654: "gray_raster_done",
    0x25B660: "gray_render_span",
    0x25B76C: "gray_raster_new",
    0x25B7B4: "ft_smooth_get_cbox",
    0x25B7DC: "ft_smooth_render_lcd_v",
    0x25BA90: "gray_raster_reset",
    0x25BAEC: "ft_smooth_transform",
    0x25BB64: "gray_convert_glyph_inner",
    0x25BCA8: "gray_move_to",
    0x25BE44: "gray_convert_glyph",
    0x25C878: "gray_raster_render",
    0x25CA78: "ft_smooth_render",
    0x25CCB8: "ft_smooth_render_lcd",
    0x25CF78: "gray_render_scanline",
    0x25D4BC: "gray_render_line",
    0x25DCBC: "gray_cubic_to",
    0x25E04C: "gray_conic_to",
    0x25E2EC: "gray_line_to",
    0x25F4F4: "tt_slot_init",
    0x25F500: "tt_face_done",
    0x25F648: "tt_face_init",
    0x25FD8C: "Current_Ratio",
    0x25FE38: "Round_To_Grid",
    0x25FE7C: "Round_To_Half_Grid",
    0x25FEB8: "Round_Down_To_Grid",
    0x25FEF4: "Round_Up_To_Grid",
    0x25FF38: "Round_To_Double_Grid",
    0x25FF7C: "Round_Super",
    0x25FFE8: "Round_Super_45",
    0x2602A4: "Ins_SZP0",
    0x2602FC: "Ins_SZP1",
    0x260354: "Ins_SZP2",
    0x2603AC: "Ins_SZPS",
    0x260468: "Ins_ALIGNRP",
    0x260590: "Ins_UTP",
    0x260660: "Ins_MDRP",
    0x2608E0: "Ins_IP",
    0x260BC4: "TT_DotFix14",
    0x260D7C: "Ins_MINDEX",
    0x260E00: "tt_driver_done",
    0x260E8C: "Ins_IUP",
    0x261624: "Ins_ENDF",
    0x2616E0: "tt_size_done_bytecode",
    0x261818: "Dual_Project",
    0x2618A4: "Ins_FDEF",
    0x2619D4: "Ins_IDEF",
    0x261D8C: "Ins_DELTAP",
    0x261FC4: "Ins_DELTAC",
    0x2621F4: "TT_Load_Context",
    0x2625E8: "Ins_SHC",
    0x262864: "Ins_SHP",
    0x262A74: "Ins_MIRP",
    0x262DB4: "load_truetype_glyph",
    0x263D1C: "TT_Load_Glyph",
    0x264F78: "Load_Glyph",
    0x264FCC: "Ins_SxVTL",
    0x26521C: "Ins_CALL",
    0x265370: "Ins_LOOPCALL",
    0x2654D4: "Ins_UNKNOWN",
    0x267ECC: "tt_driver_init",
    0x267EF0: "af_dummy_hints_init",
    0x267F08: "af_dummy_hints_apply",
    0x267F10: "af_latin_hints_init",
    0x267F90: "af_latin2_hints_init",
    0x268010: "af_cjk_metrics_scale",
    0x268050: "af_cjk_hints_init",
    0x2680C0: "af_latin2_hints_compute_segments",
    0x268608: "af_cjk_hints_link_segments",
    0x2688FC: "af_cjk_hints_compute_edges",
    0x268E58: "af_face_globals_free",
    0x268F44: "af_loader_load_g",
    0x2696D4: "af_glyph_hints_reload",
    0x269BF4: "af_latin2_metrics_scale",
    0x269F1C: "af_latin_metrics_scale",
    0x26A3D0: "af_latin_hints_compute_segments",
    0x26A904: "af_latin_metrics_init_widths",
    0x26ADCC: "af_cjk_metrics_init",
    0x26AE34: "af_hint_normal_stem",
    0x26B198: "af_latin2_metrics_init_widths",
    0x26B660: "af_latin2_metrics_init",
    0x26BB4C: "af_latin_metrics_init",
    0x26C040: "af_latin2_hints_compute_edges",
    0x26C61C: "af_latin_hints_compute_edges",
    0x26CB68: "af_glyph_hints_align_weak_points",
    0x26D1F8: "af_cjk_hints_apply",
    0x26DF5C: "af_latin2_hints_apply",
    0x26F820: "af_latin_hints_apply",
}

for _ea, _name in ADDITIONAL_FREETYPE_REANALYZED.items():
    REANALYZED_FUNCTIONS.setdefault(
        _ea,
        {
            "new_name": _name,
            "reason": (
                "The current IDA name is backed by an exact comparison with "
                "the pinned FreeType 2.3.6 implementation."
            ),
        },
    )


def address(value: int | str) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def generate(
    profile: dict,
    roles: dict,
    static_roles: list[dict] | dict | None = None,
) -> dict:
    role_by_ea = {address(item["va"]): item for item in roles["candidates"]}
    if static_roles is None:
        static_documents = []
    elif isinstance(static_roles, dict):
        static_documents = [static_roles]
    else:
        static_documents = list(static_roles)
    static_by_ea = {}
    static_sources = []
    for document in static_documents:
        static_sources.append(document["artifact"])
        for item in document.get("aliases", []):
            ea = address(item["va"])
            if ea in static_by_ea:
                raise ValueError(f"duplicate static role address: 0x{ea:x}")
            static_by_ea[ea] = item
    profile_entries = [
        entry
        for group in profile["categories"]
        for entry in group["entries"]
    ]
    profile_by_ea = {address(item["ea"]): item for item in profile_entries}

    missing_roles = sorted(set(role_by_ea) - set(profile_by_ea))
    if missing_roles:
        raise ValueError(
            "role candidates missing from profile: "
            + ", ".join(f"0x{ea:x}" for ea in missing_roles)
        )
    missing_static_roles = sorted(set(static_by_ea) - set(profile_by_ea))
    if missing_static_roles:
        raise ValueError(
            "static CyaSSL aliases missing from profile: "
            + ", ".join(f"0x{ea:x}" for ea in missing_static_roles)
        )

    residual = []
    removed_roles = []
    removed_static_roles = []
    removed_reanalyzed = []
    for group in profile["categories"]:
        category = group["category"]
        for original in group["entries"]:
            ea = address(original["ea"])
            if ea in role_by_ea:
                candidate = role_by_ea[ea]
                removed_roles.append(
                    {
                        "ea": f"0x{ea:x}",
                        "proposed_name": candidate["proposed_name"],
                        "confidence": candidate["confidence"],
                    }
                )
                continue
            if ea in static_by_ea:
                alias = static_by_ea[ea]
                removed_static_roles.append(
                    {
                        "ea": f"0x{ea:x}",
                        "proposed_name": alias["proposed_name"],
                        "confidence": alias["confidence"],
                        "source_match": alias["source_match"],
                    }
                )
                continue
            if ea in REANALYZED_FUNCTIONS:
                item = REANALYZED_FUNCTIONS[ea]
                removed_reanalyzed.append(
                    {
                        "ea": f"0x{ea:x}",
                        "new_name": item["new_name"],
                        "reason": item["reason"],
                    }
                )
                continue
            residual.append(
                {
                    "ea": f"0x{ea:x}",
                    "category": category,
                    "current_ida_name": original["current_ida_name"],
                    "segment": original["segment"],
                    "size": original["size"],
                }
            )

    residual.sort(key=lambda item: address(item["ea"]))
    if len(removed_roles) != roles["candidate_count"]:
        raise ValueError("role removal count does not match candidate artifact")
    expected_static_count = sum(
        document["alias_count"] for document in static_documents
    )
    if len(removed_static_roles) != expected_static_count:
        raise ValueError("static role removal count does not match audit artifacts")
    expected = profile["unresolved_default_sub_function_count"] - len(
        removed_roles
    ) - len(removed_static_roles) - len(removed_reanalyzed)
    if len(residual) != expected:
        raise ValueError(
            f"residual count mismatch: expected {expected}, got {len(residual)}"
        )

    groups = {}
    for item in residual:
        group = groups.setdefault(
            item["category"],
            {"category": item["category"], "count": 0, "total_bytes": 0, "entries": []},
        )
        group["count"] += 1
        group["total_bytes"] += item["size"]
        group["entries"].append(item)

    evidence_by_category = {
        item["category"]: item["evidence"]
        for item in profile["category_summary"]
    }
    category_summary = []
    for category in sorted(groups):
        group = groups[category]
        entries = group["entries"]
        category_summary.append(
            {
                "category": category,
                "count": group["count"],
                "total_bytes": group["total_bytes"],
                "first_ea": entries[0]["ea"],
                "last_ea": entries[-1]["ea"],
                "evidence": evidence_by_category[category],
            }
        )

    database = {
        **CURRENT_DATABASE,
        "default_sub_function_count": len(residual),
    }

    result = {
        "schema_version": 1,
        "artifact": "ida_persisted_residual_profile",
        "purpose": (
            "Account for every default sub_ function left in the persisted "
            "IDA translation copy without inventing source names."
        ),
        "binary": profile["binary"],
        "binary_sha256": profile["binary_sha256"],
        "database": database,
        "pre_persistence_snapshot": {
            "profile": "artifacts/unresolved_function_profile.json",
            "default_sub_function_count": profile["default_sub_function_count"],
            "unresolved_default_sub_function_count": profile[
                "unresolved_default_sub_function_count"
            ],
        },
        "applied_role_aliases": {
            "source": "artifacts/unresolved_function_candidates.json",
            "count": len(removed_roles),
            "entries": sorted(removed_roles, key=lambda item: address(item["ea"])),
        },
        "applied_static_role_aliases": {
            "sources": [
                f"artifacts/{artifact}.json" for artifact in static_sources
            ],
            "count": len(removed_static_roles),
            "entries": sorted(
                removed_static_roles, key=lambda item: address(item["ea"])
            ),
        },
        "ida_reclassified_functions": removed_reanalyzed,
        "remaining_default_sub_function_count": len(residual),
        "category_summary": category_summary,
        "categories": [groups[key] for key in sorted(groups)],
        "residual_default_sub_functions": residual,
        "translation_limit": (
            "These entries are IDA-created functions with no surviving source "
            "name in the APK. Library-family evidence is recorded where "
            "available, but family membership is not converted into a guessed "
            "source symbol."
        ),
        "source_artifacts": {
            "profile": "artifacts/unresolved_function_profile.json",
            "role_candidates": "artifacts/unresolved_function_candidates.json",
            "static_role_aliases": [
                f"artifacts/{artifact}.json" for artifact in static_sources
            ],
            "freetype_source_matches": "artifacts/ida_freetype_source_matches_20260901.json",
            "validation": "artifacts/ida_translation_validation.json",
        },
        "network_contacted": False,
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--roles", default=DEFAULT_ROLES)
    parser.add_argument(
        "--static-roles",
        action="append",
        default=None,
        help="static role audit JSON; may be supplied more than once",
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    static_paths = args.static_roles or DEFAULT_STATIC_ROLES
    result = generate(
        load(args.profile),
        load(args.roles),
        [load(path) for path in static_paths],
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "remaining_default_sub_function_count": result[
                    "remaining_default_sub_function_count"
                ],
                "categories": [
                    {"category": item["category"], "count": item["count"]}
                    for item in result["category_summary"]
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
