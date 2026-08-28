#!/usr/bin/env python3
"""Dump normalized instruction tokens for selected IDA functions."""

from __future__ import annotations

import json
import os

import ida_auto
import ida_funcs
import ida_idaapi
import ida_lines
import ida_ua
import ida_name


BRANCH_MNEMONICS = {
    "B",
    "BL",
    "BC.cond",
    "CBNZ",
    "CBZ",
    "TBNZ",
    "TBZ",
    "BR",
    "BLR",
    "RET",
}


def addresses() -> list[int]:
    text = os.environ.get("LIBQPLAY_FUNCTION_EVIDENCE", "")
    if not text.strip():
        raise ValueError("LIBQPLAY_FUNCTION_EVIDENCE is required")
    result = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        if item.lower().startswith("0x"):
            result.append(int(item, 16))
        else:
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, item)
            if ea == ida_idaapi.BADADDR:
                raise ValueError("could not resolve function name: %s" % item)
            result.append(ea)
    return result


def operand_shape(op: ida_ua.op_t, mnemonic: str) -> str:
    if op.type == ida_ua.o_void:
        return ""
    if op.type == ida_ua.o_reg:
        return "reg"
    if op.type == ida_ua.o_imm:
        value = int(op.value)
        if value in {0, 1, 2, 3, 4, 8, 16, 32, 64, 255, 256, 1024}:
            return "imm:%d" % value
        if -16 <= value <= 16:
            return "imm:%d" % value
        return "imm:other"
    if op.type in {ida_ua.o_near, ida_ua.o_far}:
        return "target"
    if op.type == ida_ua.o_mem:
        return "memory"
    if op.type == ida_ua.o_displ:
        displacement = int(op.addr)
        if displacement == 0:
            return "displ:0"
        if -32 <= displacement <= 32:
            return "displ:%d" % displacement
        return "displ:other"
    if op.type == ida_ua.o_phrase:
        return "phrase"
    if op.type == getattr(ida_ua, "o_fphrase", -1):
        return "fphrase"
    return "type:%d" % op.type


def dump(ea: int) -> dict:
    function = ida_funcs.get_func(ea)
    if function is None:
        return {"ea": "0x%x" % ea, "error": "not a function"}
    rows = []
    for item_ea in range(function.start_ea, function.end_ea, 4):
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, item_ea)
        if size <= 0:
            continue
        mnemonic = ida_ua.print_insn_mnem(item_ea).upper()
        operands = []
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            operands.append(operand_shape(op, mnemonic))
        rows.append(
            {
                "ea": "0x%x" % item_ea,
                "mnemonic": mnemonic,
                "text": ida_lines.tag_remove(ida_lines.generate_disasm_line(item_ea, 0) or ""),
                "shape": mnemonic + ":" + ",".join(operands),
                "itype": int(insn.itype),
            }
        )
    return {
        "ea": "0x%x" % function.start_ea,
        "name": ida_name.get_name(function.start_ea),
        "end_ea": "0x%x" % function.end_ea,
        "instructions": rows,
    }


def main() -> None:
    ida_auto.auto_wait()
    print(json.dumps({"functions": [dump(ea) for ea in addresses()]}, indent=2))


if __name__ == "__main__":
    main()
