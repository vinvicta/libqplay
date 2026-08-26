#!/usr/bin/env python3
"""Dump read-only IDA evidence for selected functions and string references.

Use ``LIBQPLAY_FUNCTION_EVIDENCE`` as a comma-separated list of hexadecimal
addresses. The script records the current name, function range, incoming
references, disassembly text, comments, and Hex-Rays pseudocode. It is useful
for reviewing unresolved role candidates without changing the IDB.

Use ``LIBQPLAY_STRING_XREFS`` as a comma-separated list of hexadecimal string
addresses to list the functions that reference those literals. This is useful
for tracing native loaders and hook installers without changing the IDB.

Set ``LIBQPLAY_EVIDENCE_COMPACT=1`` to omit instruction-by-instruction
disassembly while retaining function names, ranges, comments, incoming
references, and pseudocode.

Use ``LIBQPLAY_RAW_EVIDENCE`` as a comma-separated list of hexadecimal
instruction addresses to decode a short raw instruction window. This also
works for code that IDA has not assigned to a function.
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


def string_addresses() -> list[int]:
    text = os.environ.get("LIBQPLAY_STRING_XREFS", "")
    if not text.strip():
        return []
    addresses = []
    for item in (part.strip() for part in text.split(",")):
        if not item:
            continue
        if item.lower().startswith("0x"):
            addresses.append(int(item, 16))
            continue
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, item)
        if ea == ida_idaapi.BADADDR:
            raise ValueError("could not resolve string address: %s" % item)
        addresses.append(ea)
    return addresses


def raw_addresses() -> list[int]:
    text = os.environ.get("LIBQPLAY_RAW_EVIDENCE", "")
    if not text.strip():
        return []
    return [int(part.strip(), 16) for part in text.split(",") if part.strip()]


def raw_disassembly(ea: int, limit: int = 256) -> list[dict]:
    result = []
    for _ in range(limit):
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            break
        line = ida_lines.generate_disasm_line(ea, 0) or ""
        result.append(
            {
                "ea": "0x%x" % ea,
                "mnemonic": ida_ua.print_insn_mnem(ea),
                "text": ida_lines.tag_remove(line),
            }
        )
        ea += size
        if result[-1]["mnemonic"].upper() in {"RET", "BRK", "UDF"}:
            break
    return result


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
    compact = os.environ.get("LIBQPLAY_EVIDENCE_COMPACT", "") == "1"
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
            row["disassembly"] = [] if compact else disassembly(function)
            row["pseudocode"] = pseudocode(ea)
        rows.append(row)

    string_rows = []
    for ea in string_addresses():
        refs = []
        for xref in idautils.XrefsTo(ea):
            caller = ida_funcs.get_func(xref.frm)
            refs.append(
                {
                    "from": "0x%x" % xref.frm,
                    "type": int(xref.type),
                    "caller_ea": None
                    if caller is None
                    else "0x%x" % caller.start_ea,
                    "caller_name": None
                    if caller is None
                    else ida_funcs.get_func_name(caller.start_ea),
                }
            )
        string_rows.append(
            {
                "ea": "0x%x" % ea,
                "name": ida_name.get_name(ea),
                "value": ida_bytes.get_strlit_contents(ea, -1, 0).decode(
                    "utf-8", errors="replace"
                )
                if ida_bytes.is_strlit(ida_bytes.get_flags(ea))
                else None,
                "xrefs_to": refs,
            }
        )

    raw_rows = [
        {"ea": "0x%x" % ea, "disassembly": raw_disassembly(ea)}
        for ea in raw_addresses()
    ]

    print(
        json.dumps(
            {"raw": raw_rows, "strings": string_rows, "targets": rows},
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
