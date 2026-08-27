#!/usr/bin/env python3
"""Dump qwords and nearby names from an IDA data range.

This is a read-only helper for inspecting registration records, vtables, and
other pointer tables in the ARM64 databases. Set ``LIBQPLAY_DATA_START`` and
``LIBQPLAY_DATA_END`` to hexadecimal addresses. The end address is excluded.
"""

from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import idautils


def parse_address(name: str) -> int:
    value = os.environ.get(name)
    if not value:
        raise ValueError("missing %s" % name)
    return int(value, 0)


def string_value(ea: int) -> str | None:
    if not ida_bytes.is_strlit(ida_bytes.get_flags(ea)):
        return None
    value = ida_bytes.get_strlit_contents(ea, -1, 0)
    return None if not value else value.decode("utf-8", errors="replace")


def main() -> None:
    ida_auto.auto_wait()
    start = parse_address("LIBQPLAY_DATA_START")
    end = parse_address("LIBQPLAY_DATA_END")
    step = int(os.environ.get("LIBQPLAY_DATA_STEP", "8"), 0)
    rows = []
    for ea in range(start, end, step):
        value = ida_bytes.get_qword(ea)
        row = {
            "ea": "0x%x" % ea,
            "value": "0x%x" % value,
            "name": ida_name.get_name(value),
            "string": string_value(value),
            "xrefs_to": [
                {
                    "from": "0x%x" % ref.frm,
                    "caller_ea": None
                    if ida_funcs.get_func(ref.frm) is None
                    else "0x%x" % ida_funcs.get_func(ref.frm).start_ea,
                    "caller_name": None
                    if ida_funcs.get_func(ref.frm) is None
                    else ida_funcs.get_func_name(ida_funcs.get_func(ref.frm).start_ea),
                }
                for ref in idautils.XrefsTo(ea)
            ],
        }
        if value == ida_idaapi.BADADDR:
            row["value"] = None
        rows.append(row)
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
