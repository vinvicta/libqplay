#!/usr/bin/env python3
"""Dump read-only byte and pointer evidence around selected IDA addresses."""

from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import idautils


def addresses() -> list[int]:
    text = os.environ.get("LIBQPLAY_DATA_EVIDENCE", "")
    return [int(item.strip(), 16) for item in text.split(",") if item.strip()]


def xrefs_to(ea: int) -> list[dict]:
    rows = []
    for xref in idautils.XrefsTo(ea):
        function = ida_funcs.get_func(xref.frm)
        rows.append(
            {
                "from": "0x%x" % xref.frm,
                "type": int(xref.type),
                "function_start": None if function is None else "0x%x" % function.start_ea,
                "function_name": None if function is None else ida_funcs.get_func_name(function.start_ea),
            }
        )
    return rows


def row(ea: int, size: int) -> dict:
    raw = ida_bytes.get_bytes(ea, size) or b""
    pointers = []
    for offset in range(0, max(0, len(raw) - 7), 8):
        value = ida_bytes.get_qword(ea + offset)
        pointers.append(
            {
                "ea": "0x%x" % (ea + offset),
                "value": "0x%x" % value,
                "name": ida_name.get_name(value) if value else None,
                "item_size": ida_bytes.get_item_size(ea + offset),
            }
        )
    segment = ida_segment.getseg(ea)
    return {
        "ea": "0x%x" % ea,
        "size": len(raw),
        "bytes_hex": raw.hex(),
        "segment": None if segment is None else ida_segment.get_segm_name(segment),
        "item_name": ida_name.get_name(ea),
        "item_size": ida_bytes.get_item_size(ea),
        "xrefs_to": xrefs_to(ea),
        "pointers": pointers,
    }


def main() -> None:
    ida_auto.auto_wait()
    size = int(os.environ.get("LIBQPLAY_DATA_EVIDENCE_SIZE", "256"), 0)
    document = {
        "artifact": "ida_data_window_evidence",
        "network_contacted": False,
        "rows": [row(ea, size) for ea in addresses()],
    }
    output_path = os.environ.get("LIBQPLAY_DATA_EVIDENCE_OUT")
    rendered = json.dumps(document, indent=2, sort_keys=True)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
        print("data evidence written to %s" % output_path)
    else:
        print(rendered)


if __name__ == "__main__":
    main()
