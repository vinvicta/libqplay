#!/usr/bin/env python3
"""Dump read-only IDA metadata for a data window and its incoming references."""

from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_idaapi
import ida_name
import ida_segment
import idautils


def parse_addresses() -> list[int]:
    text = os.environ.get("LIBQPLAY_DATA_ADDRESSES", "")
    if not text.strip():
        base = int(os.environ["LIBQPLAY_DATA_BASE"], 0)
        count = int(os.environ.get("LIBQPLAY_DATA_COUNT", "32"), 0)
        return [base + index * 8 for index in range(count)]
    return [int(part.strip(), 0) for part in text.split(",") if part.strip()]


def main() -> None:
    ida_auto.auto_wait()
    addresses = parse_addresses()
    rows = []
    for ea in addresses:
        segment = ida_segment.getseg(ea)
        refs = []
        for xref in idautils.XrefsTo(ea):
            refs.append(
                {
                    "from": "0x%x" % xref.frm,
                    "type": int(xref.type),
                    "name": ida_name.get_name(xref.frm),
                }
            )
        rows.append(
            {
                "ea": "0x%x" % ea,
                "name": ida_name.get_name(ea),
                "item_size": ida_bytes.get_item_size(ea),
                "flags": "0x%x" % ida_bytes.get_flags(ea),
                "qword": "0x%x" % ida_bytes.get_qword(ea),
                "qword_name": ida_name.get_name(ida_bytes.get_qword(ea)),
                "comment": ida_bytes.get_cmt(ea, False),
                "segment": None
                if segment is None
                else {
                    "name": ida_segment.get_segm_name(segment),
                    "start": "0x%x" % segment.start_ea,
                    "end": "0x%x" % segment.end_ea,
                },
                "xrefs_to": refs,
            }
        )
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
