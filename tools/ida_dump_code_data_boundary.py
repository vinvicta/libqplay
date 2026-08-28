#!/usr/bin/env python3
"""Inspect IDA's code/data interpretation around selected addresses.

This helper is read-only. It records segment permissions, item flags, the
containing function, raw bytes, and decoded ARM64 instructions so a suspected
literal-pool or code boundary can be checked without changing the database.
Set ``LIBQPLAY_BOUNDARY_EAS`` to a comma-separated list of hexadecimal
addresses and optionally ``LIBQPLAY_BOUNDARY_RADIUS`` to a byte radius.
"""

from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_lines
import ida_name
import ida_segment
import ida_ua
import idautils


def parse_addresses() -> list[int]:
    value = os.environ.get("LIBQPLAY_BOUNDARY_EAS", "")
    if not value.strip():
        raise ValueError("LIBQPLAY_BOUNDARY_EAS is required")
    return [int(item.strip(), 0) for item in value.split(",") if item.strip()]


def flags(ea: int) -> dict:
    value = ida_bytes.get_flags(ea)
    return {
        "value": "0x%x" % value,
        "is_code": bool(ida_bytes.is_code(value)),
        "is_data": bool(ida_bytes.is_data(value)),
        "is_unknown": bool(ida_bytes.is_unknown(value)),
        "is_tail": bool(ida_bytes.is_tail(value)),
        "item_head": "0x%x" % ida_bytes.get_item_head(ea),
        "item_size": int(ida_bytes.get_item_size(ea)),
    }


def segment(ea: int) -> dict | None:
    seg = ida_segment.getseg(ea)
    if seg is None:
        return None
    return {
        "name": ida_segment.get_segm_name(seg),
        "start": "0x%x" % seg.start_ea,
        "end": "0x%x" % seg.end_ea,
        "perm": "0x%x" % seg.perm,
    }


def function(ea: int) -> dict | None:
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    return {
        "start": "0x%x" % func.start_ea,
        "end": "0x%x" % func.end_ea,
        "name": ida_funcs.get_func_name(func.start_ea),
        "flags": "0x%x" % int(func.flags),
    }


def xrefs_to(ea: int) -> list[dict]:
    rows = []
    for ref in idautils.XrefsTo(ea):
        caller = ida_funcs.get_func(ref.frm)
        rows.append(
            {
                "from": "0x%x" % ref.frm,
                "type": int(ref.type),
                "caller": None
                if caller is None
                else {
                    "start": "0x%x" % caller.start_ea,
                    "name": ida_funcs.get_func_name(caller.start_ea),
                },
            }
        )
    return rows


def instruction_window(ea: int, radius: int) -> list[dict]:
    start = max(0, (ea - radius) & ~3)
    end = ea + radius
    rows = []
    for address in range(start, end, 4):
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, address)
        line = ida_lines.generate_disasm_line(address, 0) or ""
        rows.append(
            {
                "ea": "0x%x" % address,
                "decoded_size": int(size),
                "mnemonic": ida_ua.print_insn_mnem(address),
                "text": ida_lines.tag_remove(line),
                "flags": flags(address),
                "bytes": (ida_bytes.get_bytes(address, 4) or b"").hex(),
            }
        )
    return rows


def main() -> None:
    ida_auto.auto_wait()
    radius = int(os.environ.get("LIBQPLAY_BOUNDARY_RADIUS", "0x30"), 0)
    rows = []
    for ea in parse_addresses():
        rows.append(
            {
                "ea": "0x%x" % ea,
                "name": ida_name.get_name(ea),
                "flags": flags(ea),
                "segment": segment(ea),
                "function": function(ea),
                "xrefs_to": xrefs_to(ea),
                "raw_at_ea": (ida_bytes.get_bytes(ea, 64) or b"").hex(),
                "instruction_window": instruction_window(ea, radius),
            }
        )
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
