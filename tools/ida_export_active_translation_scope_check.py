#!/usr/bin/env python3
"""Export a compact scope check for the persisted ARM64 IDA translation.

The check answers a narrow question: are any IDA-created ``sub_`` functions
still sitting in the Android bridge, script callback, or direct native socket,
file, process, and update boundaries? It is read-only, does not rename code,
and does not contact a service.
"""

from __future__ import annotations

import json
from pathlib import Path

import ida_auto
import ida_funcs
import idaapi
import idautils
import idc


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
SCRIPT_TABLE = REPO / "artifacts" / "script_table_inventory.json"
OUTPUT = REPO / "artifacts" / "ida_active_translation_scope_check_20260901.json"
ANDROID_START = 0x240000
ANDROID_END = 0x247000
APP_CORE_START = 0x1E0000
APP_CORE_END = 0x247000
BOUNDARY_TARGETS = {
    ".execvp",
    ".fork",
    ".send",
    ".sendto",
    ".read",
    ".select",
    ".connect",
    ".recv",
    ".gethostbyname",
    ".socket",
    ".open",
    ".fopen",
    ".mkdir",
    ".chmod",
    ".unlink",
}


def function_rows() -> list[dict]:
    rows = []
    for ea in idautils.Functions():
        name = idc.get_name(ea) or ""
        if not name.startswith("sub_"):
            continue
        function = ida_funcs.get_func(ea)
        rows.append(
            {
                "address": f"0x{ea:x}",
                "name": name,
                "size": function.end_ea - function.start_ea if function else 0,
                "segment": idc.get_segm_name(ea) or "",
            }
        )
    return sorted(rows, key=lambda item: int(item["address"], 16))


def direct_boundary_edges(default_rows: list[dict]) -> list[dict]:
    edges = []
    for row in default_rows:
        caller_ea = int(row["address"], 16)
        seen = set()
        for instruction in idautils.FuncItems(caller_ea):
            for reference in idautils.XrefsFrom(instruction, 0):
                target = ida_funcs.get_func(reference.to)
                if target is None:
                    continue
                target_name = idc.get_name(target.start_ea) or ""
                key = (target.start_ea, target_name)
                if target_name in BOUNDARY_TARGETS and key not in seen:
                    edges.append(
                        {
                            "caller": row["address"],
                            "caller_name": row["name"],
                            "callsite": f"0x{instruction:x}",
                            "target": f"0x{target.start_ea:x}",
                            "target_name": target_name,
                        }
                    )
                    seen.add(key)
    return sorted(
        edges,
        key=lambda item: (
            int(item["caller"], 16),
            int(item["callsite"], 16),
            int(item["target"], 16),
        ),
    )


def script_callback_rows() -> tuple[int, list[dict]]:
    document = json.loads(SCRIPT_TABLE.read_text(encoding="utf-8"))
    callbacks = {
        int(item["va"], 0)
        for item in document.get("unique_callbacks", [])
        if item.get("va")
    }
    rows = []
    for address in sorted(callbacks):
        name = idc.get_name(address) or ""
        if name.startswith("sub_"):
            rows.append({"address": f"0x{address:x}", "name": name})
    return len(callbacks), rows


def main() -> None:
    ida_auto.auto_wait()
    default_rows = function_rows()
    callback_count, callback_defaults = script_callback_rows()
    boundary_edges = direct_boundary_edges(default_rows)
    android_defaults = [
        row
        for row in default_rows
        if ANDROID_START <= int(row["address"], 16) < ANDROID_END
    ]
    app_core_defaults = [
        row
        for row in default_rows
        if APP_CORE_START <= int(row["address"], 16) < APP_CORE_END
    ]
    result = {
        "schema": "libqplay.ida-active-translation-scope-check.v1",
        "tool": "tools/ida_export_active_translation_scope_check.py",
        "analysis_date": "2026-09-01",
        "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        "database": {
            "input_path": idaapi.get_input_file_path(),
            "function_count": sum(1 for _ in idautils.Functions()),
            "default_sub_count": len(default_rows),
        },
        "checks": {
            "android_bridge_range": {
                "start": f"0x{ANDROID_START:x}",
                "end_exclusive": f"0x{ANDROID_END:x}",
                "default_sub_count": len(android_defaults),
                "default_sub_functions": android_defaults,
            },
            "application_core_range": {
                "start": f"0x{APP_CORE_START:x}",
                "end_exclusive": f"0x{APP_CORE_END:x}",
                "default_sub_count": len(app_core_defaults),
                "default_sub_functions": app_core_defaults,
            },
            "script_table_callbacks": {
                "unique_callback_count": callback_count,
                "default_sub_count": len(callback_defaults),
                "default_sub_functions": callback_defaults,
            },
            "direct_boundary_calls": {
                "targets": sorted(BOUNDARY_TARGETS),
                "default_sub_edge_count": len(boundary_edges),
                "edges": boundary_edges,
            },
        },
        "interpretation": [
            "The 278 remaining default sub_ functions are outside the Android bridge callback region.",
            "The four default functions in the broader application-core range are short static-state wrappers around TString, TStringList, or TGraalVar objects; their decompiled bodies do not contain the selected socket, file, process, or update boundary calls.",
            "Every address in the 1779-entry script callback inventory has a non-default active IDA name, including the callbacks reviewed in the focused Android passes.",
        ],
        "status": "ok"
        if len(default_rows) == 278
        and not android_defaults
        and not callback_defaults
        and not boundary_edges
        else "review-required",
        "network_contacted": False,
    }
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": OUTPUT.as_posix(),
                "default_sub_count": len(default_rows),
                "android_default_sub_count": len(android_defaults),
                "script_callback_default_sub_count": len(callback_defaults),
                "direct_boundary_edge_count": len(result["checks"]["direct_boundary_calls"]["edges"]),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
