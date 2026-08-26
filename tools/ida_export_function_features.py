#!/usr/bin/env python3
"""Export compact, offline function features from the current IDA database.

This helper is intended for cross-build comparison.  It records function
ranges, instruction and control-flow shape, direct-call context, and short
string references without exporting a full disassembly.  Addresses and
PC-relative targets are deliberately normalized, so a later build can be
compared without assuming that its layout matches the original library.

The script is read-only.  Run it through IDALIB with ``LIBQPLAY_FEATURES_OUT``
set to the JSON output path.  It does not load native code or contact a
network.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter

import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_idaapi
import ida_lines
import ida_name
import ida_nalt
import ida_ua
import idautils


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


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def clean_name(name: str | None) -> str | None:
    if not name:
        return None
    return name.split("@", 1)[0]


def name_is_default(name: str | None, ea: int) -> bool:
    if not name:
        return True
    return name in {f"sub_{ea:X}", f"loc_{ea:X}"}


def operand_shape(op: ida_ua.op_t, mnemonic: str) -> str:
    operand_type = op.type
    if operand_type == ida_ua.o_void:
        return ""
    if operand_type == ida_ua.o_reg:
        return "reg"
    if operand_type == ida_ua.o_imm:
        # Keep a coarse constant bucket.  Exact immediates are useful for
        # matching small protocol constants, while large addresses are not.
        value = int(op.value)
        if value in {0, 1, 2, 3, 4, 8, 16, 32, 64, 255, 256, 1024}:
            return f"imm:{value}"
        if -16 <= value <= 16:
            return f"imm:{value}"
        return "imm:other"
    if operand_type in {ida_ua.o_near, ida_ua.o_far}:
        return "target"
    if operand_type == ida_ua.o_mem:
        return "memory"
    if operand_type == ida_ua.o_displ:
        displacement = int(op.addr)
        if displacement == 0:
            return "displ:0"
        if -32 <= displacement <= 32:
            return f"displ:{displacement}"
        return "displ:other"
    if operand_type == ida_ua.o_phrase:
        return "phrase"
    if operand_type == getattr(ida_ua, "o_fphrase", -1):
        return "fphrase"
    return f"type:{operand_type}"


def operand_detail(op: ida_ua.op_t, mnemonic: str) -> str:
    """Return a register-aware operand token with relocations normalized."""
    operand_type = op.type
    if operand_type == ida_ua.o_void:
        return ""
    if operand_type == ida_ua.o_reg:
        return f"reg:{op.reg}"
    if operand_type == ida_ua.o_imm:
        value = int(op.value)
        if mnemonic in BRANCH_MNEMONICS or mnemonic in {"ADR", "ADRP"}:
            return "imm:relocated"
        return f"imm:{value}"
    if operand_type in {ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem}:
        return "target"
    if operand_type == ida_ua.o_displ:
        return f"displ:{op.reg}:{int(op.addr)}"
    if operand_type == ida_ua.o_phrase:
        return f"phrase:{op.reg}"
    if operand_type == getattr(ida_ua, "o_fphrase", -1):
        return f"fphrase:{op.reg}"
    return f"type:{operand_type}:{op.reg}:{int(op.value)}:{int(op.addr)}"


def operand_register_shape(op: ida_ua.op_t, mnemonic: str) -> str:
    """Preserve register allocation while discarding relocation addresses."""
    operand_type = op.type
    if operand_type == ida_ua.o_void:
        return ""
    if operand_type == ida_ua.o_reg:
        return f"reg:{op.reg}"
    if operand_type == ida_ua.o_imm:
        value = int(op.value)
        if mnemonic in BRANCH_MNEMONICS or mnemonic in {"ADR", "ADRP"}:
            return "imm:relocated"
        if -32 <= value <= 32:
            return f"imm:{value}"
        return "imm:other"
    if operand_type in {ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem}:
        return "target"
    if operand_type == ida_ua.o_displ:
        return f"displ:reg:{op.reg}"
    if operand_type == ida_ua.o_phrase:
        return f"phrase:{op.reg}"
    if operand_type == getattr(ida_ua, "o_fphrase", -1):
        return f"fphrase:{op.reg}"
    return f"type:{operand_type}:reg:{op.reg}"


def string_at(ea: int) -> str | None:
    flags = ida_bytes.get_flags(ea)
    if not ida_bytes.is_strlit(flags):
        return None
    value = ida_bytes.get_strlit_contents(ea, -1, 0)
    if not value:
        return None
    text = value.decode("utf-8", errors="replace")
    if len(text) > 128:
        return None
    return text


def function_strings(items: list[int]) -> list[str]:
    values = set()
    for ea in items:
        for ref in idautils.DataRefsFrom(ea):
            value = string_at(ref)
            if value is not None:
                values.add(value)
    return sorted(values)


def direct_call_names(items: list[int]) -> list[str]:
    names = []
    for ea in items:
        mnemonic = ida_ua.print_insn_mnem(ea).upper()
        if mnemonic not in {"BL", "BLR"}:
            continue
        for ref in idautils.CodeRefsFrom(ea, False):
            target_name = clean_name(ida_name.get_name(ref))
            if target_name:
                names.append(target_name)
    return sorted(set(names))


def basic_block_shape(function: ida_funcs.func_t) -> tuple[int, list[int]]:
    try:
        blocks = list(ida_gdl.FlowChart(function))
    except Exception:
        return 0, []
    sizes = sorted(max(0, block.end_ea - block.start_ea) for block in blocks)
    return len(blocks), sizes


def function_row(function: ida_funcs.func_t) -> dict:
    items = list(idautils.FuncItems(function.start_ea))
    mnemonic_tokens = []
    shape_tokens = []
    opcode_tokens = []
    detail_tokens = []
    register_shape_tokens = []
    mnemonic_counts = Counter()
    call_count = 0
    branch_count = 0
    return_count = 0
    for ea in items:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            continue
        mnemonic = ida_ua.print_insn_mnem(ea).upper()
        mnemonic_counts[mnemonic] += 1
        mnemonic_tokens.append(mnemonic)
        if mnemonic in {"BL", "BLR"}:
            call_count += 1
        if mnemonic in BRANCH_MNEMONICS:
            branch_count += 1
        if mnemonic == "RET":
            return_count += 1
        operands = []
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            operands.append(operand_shape(op, mnemonic))
        shape_tokens.append(mnemonic + ":" + ",".join(operands))
        opcode_tokens.append(str(insn.itype) + ":" + ",".join(operands))
        details = []
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            details.append(operand_detail(op, mnemonic))
        detail_tokens.append(mnemonic + ":" + ",".join(details))
        register_shapes = []
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            register_shapes.append(operand_register_shape(op, mnemonic))
        register_shape_tokens.append(mnemonic + ":" + ",".join(register_shapes))

    block_count, block_sizes = basic_block_shape(function)
    name = clean_name(ida_name.get_name(function.start_ea))
    strings = function_strings(items)
    calls = direct_call_names(items)
    string_digest = digest("\x1f".join(strings)) if strings else None
    row = {
        "ea": "0x%x" % function.start_ea,
        "end_ea": "0x%x" % function.end_ea,
        "size": function.end_ea - function.start_ea,
        "name": name,
        "is_default_name": name_is_default(name, function.start_ea),
        "instruction_count": len(mnemonic_tokens),
        "basic_block_count": block_count,
        "basic_block_sizes": block_sizes,
        "call_count": call_count,
        "branch_count": branch_count,
        "return_count": return_count,
        "mnemonic_histogram": dict(sorted(mnemonic_counts.items())),
        "mnemonic_hash": digest(" ".join(mnemonic_tokens)),
        "shape_hash": digest(" ".join(shape_tokens)),
        "opcode_shape_hash": digest(" ".join(opcode_tokens)),
        "register_detail_hash": digest(" ".join(detail_tokens)),
        "register_shape_hash": digest(" ".join(register_shape_tokens)),
        "string_refs": strings,
        "string_refs_hash": string_digest,
        "direct_call_names": calls,
    }
    return row


def main() -> None:
    output = os.environ.get("LIBQPLAY_FEATURES_OUT")
    if not output:
        raise ValueError("LIBQPLAY_FEATURES_OUT is required")
    ida_auto.auto_wait()
    functions = []
    for index in range(ida_funcs.get_func_qty()):
        function = ida_funcs.getn_func(index)
        if function is None or function.start_ea == ida_idaapi.BADADDR:
            continue
        functions.append(function_row(function))
    result = {
        "artifact": "ida_function_features",
        "scope": "offline IDA feature export for cross-build comparison",
        "database_input": ida_nalt.get_input_file_path(),
        "network_contacted": False,
        "function_count": len(functions),
        "functions": functions,
    }
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"output": output, "function_count": len(functions)}))


if __name__ == "__main__":
    main()
