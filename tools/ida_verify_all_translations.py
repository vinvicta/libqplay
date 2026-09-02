#!/usr/bin/env python3
"""Verify the complete prepared translation set in the current IDA database.

This is a read-only check for IDALIB or the IDA Python console. It verifies
the 277 native role candidates, every exact script-table callback label that
has a proposed name, 28 application or engine role aliases, 11 CyaSSL role
aliases, 27 bundled library role aliases, four older persisted function
reclassifications, and 24 exact FreeType source matches at their expected
addresses. The expected database totals are also checked after the boundary
pass.
"""

from __future__ import annotations

import json
from pathlib import Path

import ida_auto
import ida_funcs
import ida_idaapi
import ida_name
import idautils


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
NATIVE_GROUPS = (
    "callbacks",
    "static_initializers",
    "sound_wrappers",
    "sound_table_followup",
    "server_player_properties",
    "server_player_functions",
    "server_npc_properties",
    "server_npc_functions",
    "server_level_properties",
    "server_level_functions",
    "server_weapon_properties",
    "server_bomb_properties",
    "explosion_properties",
    "server_chest_properties",
    "server_extra_properties",
    "server_flying_properties",
    "server_sign_properties",
    "projectile_properties",
    "server_level_link_properties",
    "tiles_layer_properties",
    "tiles_layer_functions",
)

RECLASSIFIED_NAMES = (
    (0x1F94FC, "j_TCachedStream_get_minfilecachesize"),
    (0x0E01A0, "gpc_abort_malloc_failure_tristrip_node"),
    (0x152200, "gpc_free_sbtree"),
    (0x152898, "gpc_build_sbt"),
)

FREETYPE_SOURCE_MATCH_NAMES = (
    (0x250E94, "destroy_size"),
    (0x25E320, "tt_get_kerning"),
    (0x25E35C, "tt_face_get_location"),
    (0x25E4E4, "tt_size_init"),
    (0x25E504, "TT_MulFix14"),
    (0x25E580, "Direct_Move_X"),
    (0x25E5B0, "Direct_Move_Y"),
    (0x25E5E4, "Direct_Move_Orig_X"),
    (0x25E5FC, "Direct_Move_Orig_Y"),
    (0x25E618, "Round_None"),
    (0x25E640, "Project"),
    (0x25E6CC, "Project_x"),
    (0x25E6D4, "Project_y"),
    (0x25E6DC, "Ins_NPUSHW"),
    (0x25E770, "Ins_PUSHW"),
    (0x25E7F8, "Ins_GC"),
    (0x25E890, "Ins_SCFS"),
    (0x25E950, "Ins_GETINFO"),
    (0x25E9A8, "Ins_MD"),
    (0x25EAF8, "tt_size_request"),
    (0x25EC84, "Direct_Move_Orig"),
    (0x25ED14, "Direct_Move"),
    (0x25EDD0, "Ins_ISECT"),
    (0x260050, "Compute_Funcs"),
)


def load(relative_path: str) -> dict:
    return json.loads((REPO / relative_path).read_text(encoding="utf-8"))


def expected_names() -> list[dict]:
    native = load("artifacts/native_callback_candidates.json")
    script = load("artifacts/script_table_inventory.json")
    roles = load("artifacts/unresolved_function_candidates.json")
    cyassl = load("artifacts/cyassl_static_role_audit_20260826.json")
    static_libraries = load("artifacts/static_library_role_audit_20260826.json")
    rows = []
    for group in NATIVE_GROUPS:
        for item in native.get(group, []):
            rows.append(
                {
                    "source": "native_callback_candidates",
                    "va": int(item["va"], 16),
                    "expected_name": item["proposed_name"],
                }
            )
    for item in script["unique_callbacks"]:
        if item.get("proposed_name"):
            rows.append(
                {
                    "source": "script_table_inventory",
                    "va": int(item["va"], 16),
                    "expected_name": item["proposed_name"],
                    "needs_boundary": item["status"] == "no_function_boundary",
                }
            )
    for item in roles["candidates"]:
        rows.append(
            {
                "source": "unresolved_function_candidates",
                "va": int(item["va"], 16),
                "expected_name": item["proposed_name"],
            }
        )
    for item in cyassl["aliases"]:
        rows.append(
            {
                "source": "cyassl_static_role_audit",
                "va": int(item["va"], 16),
                "expected_name": item["proposed_name"],
            }
        )
    for item in static_libraries["aliases"]:
        rows.append(
            {
                "source": "static_library_role_audit",
                "va": int(item["va"], 16),
                "expected_name": item["proposed_name"],
            }
        )
    for va, name in RECLASSIFIED_NAMES:
        rows.append(
            {
                "source": "ida_residual_profile",
                "va": va,
                "expected_name": name,
            }
        )
    for va, name in FREETYPE_SOURCE_MATCH_NAMES:
        rows.append(
            {
                "source": "ida_freetype_source_matches",
                "va": va,
                "expected_name": name,
            }
        )
    return rows


def main() -> None:
    ida_auto.auto_wait()
    rows = expected_names()
    failures = []
    for row in rows:
        actual_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, row["expected_name"])
        if actual_ea != row["va"]:
            failures.append(
                {
                    **row,
                    "actual_ea": None if actual_ea == ida_idaapi.BADADDR else hex(actual_ea),
                }
            )
            continue
        function = ida_funcs.get_func(row["va"])
        if function is None:
            failures.append({**row, "error": "expected name is not a function"})
        elif row.get("needs_boundary") and function.start_ea != row["va"]:
            failures.append({**row, "error": "function start does not match expected VA"})

    function_count = sum(1 for _ in idautils.Functions())
    default_sub_count = sum(
        1
        for ea in idautils.Functions()
        if (ida_funcs.get_func_name(ea) or "").startswith("sub_")
    )
    result = {
        "expected_name_count": len(rows),
        "verified_name_count": len(rows) - len(failures),
        "failure_count": len(failures),
        "function_count": function_count,
        "default_sub_count": default_sub_count,
        "expected_function_count": 11297,
        "expected_default_sub_count": 394,
        "failures": failures,
        "status": "ok"
        if not failures and function_count == 11297 and default_sub_count == 394
        else "failed",
    }
    print(json.dumps(result, sort_keys=True))
    if result["status"] != "ok":
        raise RuntimeError("translation verification failed")


if __name__ == "__main__":
    main()
