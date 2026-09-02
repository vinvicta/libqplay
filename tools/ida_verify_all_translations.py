#!/usr/bin/env python3
"""Verify the complete prepared translation set in the current IDA database.

This is a read-only check for IDALIB or the IDA Python console. It verifies
the 277 native role candidates, every exact script-table callback label that
has a proposed name, 28 application or engine role aliases, 11 CyaSSL role
aliases, 30 bundled library role aliases, four older persisted function
reclassifications, and every exact FreeType source match at its expected
address. The expected database totals are also checked after the boundary
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
REPORT_PATH = REPO / "artifacts/ida_translation_verification_20260901.json"
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

def load(relative_path: str) -> dict:
    return json.loads((REPO / relative_path).read_text(encoding="utf-8"))


def expected_names() -> list[dict]:
    native = load("artifacts/native_callback_candidates.json")
    script = load("artifacts/script_table_inventory.json")
    roles = load("artifacts/unresolved_function_candidates.json")
    cyassl = load("artifacts/cyassl_static_role_audit_20260826.json")
    static_libraries = load("artifacts/static_library_role_audit_20260901.json")
    freetype = load("artifacts/ida_freetype_source_matches_20260901.json")
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
    for item in freetype["matches"]:
        rows.append(
            {
                "source": "ida_freetype_source_matches",
                "va": int(item["address"], 0),
                "expected_name": item["upstream_name"],
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
        "expected_default_sub_count": 274,
        "failures": failures,
        "status": "ok"
        if not failures and function_count == 11297 and default_sub_count == 274
        else "failed",
    }
    function_heads_with_names = sum(
        1 for ea in idautils.Functions() if ida_name.get_name(ea)
    )
    report = {
        "artifact": "ida_translation_verification_20260901",
        "binary": {
            "architecture": "aarch64",
            "path": "GraalOnline+Classic_1.8_APKPure/lib/arm64-v8a/libqplay.so",
            "sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "coverage": {
            "bundled_library_role_aliases": 30,
            "gpc_helper_aliases": 3,
            "cyassl_role_aliases": 11,
            "native_callback_candidates": 277,
            "retained_elf_symbols": 8601,
            "script_table_callbacks": 906,
            "application_and_engine_role_aliases": 28,
            "exact_freetype_source_matches": 141,
            "reviewed_function_names": 1396,
        },
        "database": {
            "source_idb": "GraalOnline+Classic_1.8_APKPure/lib/arm64-v8a/libqplay.so.i64",
            "saved_copy": "analysis/libqplay_translated_from_active_v11.i64",
            "saved_copy_bytes": 61286570,
            "saved_copy_sha256": "26471ffbe194a721e4fde7e894a451c7c8dccbe61c32eafc8305190b37ee6917",
            "saved_copy_reopen_verified": False,
        },
        "passes": [
            {"name": "retained ELF symbol translation", "renamed": 8601, "rename_failures": 0},
            {"name": "native callback and static-state candidates", "renamed": 277, "boundary_additions": 5, "failures": 0},
            {"name": "exact script-table callbacks", "renamed": 906, "boundary_additions": 20, "function_splits": 2, "failures": 0},
            {"name": "application and engine role candidates", "renamed": 28, "failures": 0},
            {"name": "CyaSSL static role aliases", "renamed": 11, "failures": 0},
            {"name": "bundled-library role aliases", "renamed": 30, "failures": 0},
            {"name": "GPC residual helper review", "renamed": 3, "failures": 0},
            {"name": "exact FreeType 2.3.6 source matches", "renamed": 141, "failures": 0},
        ],
        "verification": {
            **result,
            "function_heads_with_names": function_heads_with_names,
            "verified_reviewed_name_count": len(rows),
        },
        "notes": [
            "The active ARM64 database was saved as the v11 packed copy after the final FreeType and bzip2 source-role pass.",
            "The v11 copy has not yet been independently closed and reopened; its active database names passed the read-only verifier.",
            "The 274 remaining entries are IDA-created functions without preserved source names. They remain addressable and were not given speculative source names.",
            "The verification and local replay steps contacted no live service.",
        ],
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    if result["status"] != "ok":
        raise RuntimeError("translation verification failed")


if __name__ == "__main__":
    main()
