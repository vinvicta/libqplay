#!/usr/bin/env python3
"""Find functions that reference one or more data-address ranges.

Set ``LIBQPLAY_FIND_DATA_REF_RANGES`` to a comma-separated list of ranges in
the form ``start-end``. The helper is read-only and prints only functions
with at least one matching data reference, which keeps large stripped IDBs
manageable during global-state correlation.
"""

from __future__ import annotations

import json
import os

import ida_auto
import ida_funcs
import ida_name
import idautils


def ranges() -> list[tuple[int, int]]:
    text = os.environ.get("LIBQPLAY_FIND_DATA_REF_RANGES", "")
    result = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        start, end = item.split("-", 1)
        result.append((int(start, 0), int(end, 0)))
    if not result:
        raise ValueError("LIBQPLAY_FIND_DATA_REF_RANGES is required")
    return result


def main() -> None:
    ida_auto.auto_wait()
    wanted = ranges()
    rows = []
    for start in idautils.Functions():
        function = ida_funcs.get_func(start)
        if function is None:
            continue
        refs = []
        seen = set()
        for item in idautils.FuncItems(function.start_ea):
            for data_ea in idautils.DataRefsFrom(item):
                if not any(lo <= data_ea < hi for lo, hi in wanted):
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
        if refs:
            rows.append(
                {
                    "function_start": "0x%x" % function.start_ea,
                    "function_end": "0x%x" % function.end_ea,
                    "name": ida_name.get_name(function.start_ea),
                    "data_refs": refs,
                }
            )
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
