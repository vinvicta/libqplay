#!/usr/bin/env python3
"""Dump a read-only qword window from the current IDA database."""

from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_name


def main() -> None:
    ida_auto.auto_wait()
    base = int(os.environ["LIBQPLAY_DATA_BASE"], 0)
    count = int(os.environ.get("LIBQPLAY_DATA_COUNT", "32"), 0)
    rows = []
    for index in range(count):
        ea = base + index * 8
        value = ida_bytes.get_qword(ea)
        rows.append(
            {
                "ea": "0x%x" % ea,
                "index": index,
                "value": "0x%x" % value,
                "name": ida_name.get_name(value) if value != 0 else "",
            }
        )
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
