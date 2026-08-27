#!/usr/bin/env python3
"""Materialize reviewed Spectron code ranges that clean IDA left unnamed.

This script only adds function boundaries in the currently open IDA database.
The caller controls whether the database is saved. The ranges are kept
explicit so a saved copy cannot silently absorb unrelated code.
"""

from __future__ import annotations

import os

import ida_auto
import ida_funcs


def ranges() -> list[tuple[int, int]]:
    text = os.environ.get("SPECTRON_HIDDEN_FUNCTIONS", "0x1a9bb0:0x1a9c2c")
    result = []
    for item in text.split(","):
        start_text, end_text = item.split(":", 1)
        result.append((int(start_text, 16), int(end_text, 16)))
    return result


def main() -> None:
    ida_auto.auto_wait()
    rows = []
    for start, end in ranges():
        function = ida_funcs.get_func(start)
        if function is not None:
            rows.append(
                {
                    "start": "0x%x" % start,
                    "end": "0x%x" % end,
                    "existing_start": "0x%x" % function.start_ea,
                    "existing_end": "0x%x" % function.end_ea,
                    "added": False,
                }
            )
            continue
        added = ida_funcs.add_func(start, end)
        function = ida_funcs.get_func(start)
        rows.append(
            {
                "start": "0x%x" % start,
                "end": "0x%x" % end,
                "existing_start": None if function is None else "0x%x" % function.start_ea,
                "existing_end": None if function is None else "0x%x" % function.end_ea,
                "added": bool(added),
            }
        )
    print(rows)


if __name__ == "__main__":
    main()
