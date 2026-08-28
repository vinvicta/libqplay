#!/usr/bin/env python3
"""Dump read-only qword context and cross-references for selected addresses."""

from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import idautils


def addresses() -> list[int]:
    text = os.environ.get("LIBQPLAY_CONTEXT_EAS", "")
    if not text.strip():
        raise ValueError("LIBQPLAY_CONTEXT_EAS is required")
    return [int(item.strip(), 0) for item in text.split(",") if item.strip()]


def xrefs(ea: int) -> list[dict]:
    result = []
    for ref in idautils.XrefsTo(ea):
        function = ida_funcs.get_func(ref.frm)
        result.append(
            {
                "from": "0x%x" % ref.frm,
                "type": int(ref.type),
                "caller_ea": None if function is None else "0x%x" % function.start_ea,
                "caller_name": None if function is None else ida_funcs.get_func_name(function.start_ea),
            }
        )
    return result


def qword_rows(ea: int, radius: int) -> list[dict]:
    start = ea - radius
    end = ea + radius
    rows = []
    for address in range(start & ~7, end, 8):
        value = ida_bytes.get_qword(address)
        rows.append(
            {
                "ea": "0x%x" % address,
                "value": "0x%x" % value,
                "name": ida_name.get_name(value),
                "points_to_function": ida_funcs.get_func(value) is not None,
            }
        )
    return rows


def main() -> None:
    ida_auto.auto_wait()
    radius = int(os.environ.get("LIBQPLAY_CONTEXT_RADIUS", "0x60"), 0)
    rows = []
    for ea in addresses():
        rows.append(
            {
                "ea": "0x%x" % ea,
                "name": ida_name.get_name(ea),
                "segment": None
                if ida_bytes.get_bytes(ea, 1) is None
                else str(ida_bytes.get_bytes(ea, 1)),
                "xrefs_to": xrefs(ea),
                "qwords": qword_rows(ea, radius),
            }
        )
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
