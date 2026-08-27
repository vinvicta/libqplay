#!/usr/bin/env python3
"""Dump data references made by selected IDA functions.

Set ``LIBQPLAY_FUNCTION_DATA_REFS`` to a comma-separated list of function
addresses. The helper is read-only and is useful for separating static global
state groups when stripped builds contain several similar cleanup callbacks.
"""

from __future__ import annotations

import json
import os

import ida_auto
import ida_funcs
import ida_name
import idautils


def addresses() -> list[int]:
    text = os.environ.get("LIBQPLAY_FUNCTION_DATA_REFS", "")
    if text.strip():
        return [int(item.strip(), 0) for item in text.split(",") if item.strip()]
    start = os.environ.get("LIBQPLAY_FUNCTION_DATA_REFS_START")
    end = os.environ.get("LIBQPLAY_FUNCTION_DATA_REFS_END")
    if start is None or end is None:
        raise ValueError(
            "LIBQPLAY_FUNCTION_DATA_REFS or its START and END range is required"
        )
    return list(idautils.Functions(int(start, 0), int(end, 0)))


def data_ref_ranges() -> list[tuple[int, int]]:
    text = os.environ.get("LIBQPLAY_DATA_REF_RANGES", "")
    ranges = []
    for item in text.split(","):
        if not item.strip():
            continue
        start, end = item.split("-", 1)
        ranges.append((int(start, 0), int(end, 0)))
    return ranges


def main() -> None:
    ida_auto.auto_wait()
    ranges = data_ref_ranges()
    rows = []
    for ea in addresses():
        function = ida_funcs.get_func(ea)
        row = {
            "ea": "0x%x" % ea,
            "name": ida_name.get_name(ea),
            "function_start": None,
            "function_end": None,
            "data_refs": [],
        }
        if function is None or function.start_ea != ea:
            rows.append(row)
            continue
        row["function_start"] = "0x%x" % function.start_ea
        row["function_end"] = "0x%x" % function.end_ea
        refs = []
        seen = set()
        for item in idautils.FuncItems(function.start_ea):
            for data_ea in idautils.DataRefsFrom(item):
                if ranges and not any(start <= data_ea < end for start, end in ranges):
                    continue
                key = (item, data_ea)
                if key in seen:
                    continue
                seen.add(key)
                refs.append(
                    {
                        "from": "0x%x" % item,
                        "data_ea": "0x%x" % data_ea,
                        "data_name": ida_name.get_name(data_ea),
                    }
                )
        row["data_refs"] = refs
        rows.append(row)
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
