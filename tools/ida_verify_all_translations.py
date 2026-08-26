#!/usr/bin/env python3
"""Verify the complete prepared translation set in the current IDA database.

This is a read-only check for IDALIB or the IDA Python console. It verifies
the 277 native role candidates, 906 exact script-table callbacks, and 28
unresolved application or engine role aliases at their expected addresses.
The expected database totals are also checked after the boundary pass.
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


def load(relative_path: str) -> dict:
    return json.loads((REPO / relative_path).read_text(encoding="utf-8"))


def expected_names() -> list[dict]:
    native = load("artifacts/native_callback_candidates.json")
    script = load("artifacts/script_table_inventory.json")
    roles = load("artifacts/unresolved_function_candidates.json")
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
        "expected_default_sub_count": 459,
        "failures": failures,
        "status": "ok"
        if not failures and function_count == 11297 and default_sub_count == 459
        else "failed",
    }
    print(json.dumps(result, sort_keys=True))
    if result["status"] != "ok":
        raise RuntimeError("translation verification failed")


if __name__ == "__main__":
    main()
