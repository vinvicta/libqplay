#!/usr/bin/env python3
"""Dump read-only IDA evidence for selected functions.

Use ``LIBQPLAY_FUNCTION_EVIDENCE`` as a comma-separated list of hexadecimal
addresses. The script records the current name, function range, incoming
references, disassembly text, comments, and Hex-Rays pseudocode. It is useful
for reviewing unresolved role candidates without changing the IDB.
"""

from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_lines
import ida_name
import ida_ua
import idautils


DEFAULT_TARGETS = (0x20AC18,)


def target_addresses() -> list[int]:
    text = os.environ.get("LIBQPLAY_FUNCTION_EVIDENCE", "")
    if not text.strip():
        return list(DEFAULT_TARGETS)
    addresses = []
    for item in (part.strip() for part in text.split(",")):
        if not item:
            continue
        if item.lower().startswith("0x"):
            addresses.append(int(item, 16))
            continue
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, item)
        if ea == ida_idaapi.BADADDR:
            raise ValueError("could not resolve function name: %s" % item)
        addresses.append(ea)
    return addresses


def xrefs_to(ea: int) -> list[dict]:
    result = []
    for xref in idautils.XrefsTo(ea):
        caller = ida_funcs.get_func(xref.frm)
        result.append(
            {
                "from": "0x%x" % xref.frm,
                "type": int(xref.type),
                "caller_ea": None if caller is None else "0x%x" % caller.start_ea,
                "caller_name": None
                if caller is None
                else ida_funcs.get_func_name(caller.start_ea),
            }
        )
    return result


def disassembly(function: ida_funcs.func_t) -> list[dict]:
    result = []
    for ea in idautils.FuncItems(function.start_ea):
        line = ida_lines.generate_disasm_line(ea, 0) or ""
        result.append(
            {
                "ea": "0x%x" % ea,
                "mnemonic": ida_ua.print_insn_mnem(ea),
                "text": ida_lines.tag_remove(line),
            }
        )
    return result


def pseudocode(ea: int) -> str | None:
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as error:
        return "decompile error: %r" % (error,)
    return None if cfunc is None else str(cfunc)


def main() -> None:
    ida_auto.auto_wait()
    rows = []
    for ea in target_addresses():
        function = ida_funcs.get_func(ea)
        row = {
            "ea": "0x%x" % ea,
            "name": ida_name.get_name(ea),
            "function_start": None,
            "function_end": None,
            "comment": None,
            "xrefs_to": xrefs_to(ea),
            "disassembly": [],
            "pseudocode": None,
        }
        if function is not None:
            row["function_start"] = "0x%x" % function.start_ea
            row["function_end"] = "0x%x" % function.end_ea
            row["comment"] = ida_bytes.get_cmt(ea, False)
            row["disassembly"] = disassembly(function)
            row["pseudocode"] = pseudocode(ea)
        rows.append(row)

    print(json.dumps({"targets": rows}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
