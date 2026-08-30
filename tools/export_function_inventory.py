"""Export a complete function inventory from the active IDA database.

The symbol translation pass covers names that survive in the ELF. IDA also
creates functions while it analyzes code, and those entries do not have an
original symbol to translate. This script records both groups so the address
coverage is explicit without assigning guessed names to compiler-generated
functions.

Run it from the IDA Pro MCP bridge with ``py_exec_file``. The output directory
is intentionally outside the public repository first, so the generated files
can be reviewed before they are copied into ``symbols/``.
"""

import csv
import json
import os
import re

import ida_auto
import ida_funcs
import ida_idaapi
import ida_name
import ida_nalt
import ida_segment
import ida_xref
import idautils


SYMBOL_JSON = "/home/v/Desktop/graal-decomp/libqplay/symbols/libqplay.symbols.json"
OUTPUT_DIR = os.environ.get(
    "LIBQPLAY_INVENTORY_OUTPUT_DIR",
    "/home/v/Desktop/graal-decomp/analysis",
)
DEFAULT_SUB_RE = re.compile(r"^sub_[0-9A-Fa-f]+$")


def load_symbol_rows():
    with open(SYMBOL_JSON, "r", encoding="utf-8") as handle:
        rows = json.load(handle)
    return {int(row["ea"]): row for row in rows}, rows


def input_sha256():
    """Return the IDA-reported input hash when the installed SDK exposes it."""

    for name in ("retrieve_input_file_sha256", "get_input_file_sha256"):
        getter = getattr(ida_nalt, name, None)
        if getter is None:
            continue
        try:
            value = getter()
        except Exception:
            continue
        if isinstance(value, bytes):
            return value.hex()
        if value:
            return str(value)
    return None


def function_flags(func):
    flags = int(getattr(func, "flags", 0))
    thunk_flag = int(getattr(ida_funcs, "FUNC_THUNK", 0))
    library_flag = int(getattr(ida_funcs, "FUNC_LIB", 0))
    return flags, bool(flags & thunk_flag), bool(flags & library_flag)


def count_xrefs_to(ea):
    try:
        # xrefblk_t walks the database's native sorted xref list directly.
        # This is substantially cheaper than constructing an idautils
        # iterator for every one of the 11,000-plus functions.
        block = ida_xref.xrefblk_t()
        count = 0
        if block.first_to(ea, 0):
            count = 1
            while block.next_to():
                count += 1
        return count
    except Exception:
        return None


def collect_inventory():
    ida_auto.auto_wait()
    symbols_by_ea, symbol_rows = load_symbol_rows()
    inventory = []

    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func is None:
            continue

        name = ida_name.get_name(ea) or ""
        source = symbols_by_ea.get(ea)
        default_sub = bool(DEFAULT_SUB_RE.match(name))
        if source is not None:
            origin = "elf_symbol"
        elif default_sub:
            origin = "ida_default_sub"
        else:
            origin = "ida_named_non_elf"

        flags, is_thunk, is_library = function_flags(func)
        segment = ida_segment.getseg(ea)
        segment_name = ida_segment.get_segm_name(segment) if segment else None

        inventory.append(
            {
                "ea": int(ea),
                "name": name,
                "name_origin": origin,
                "source_kind": source.get("kind") if source else None,
                "original_symbol": source.get("original") if source else None,
                "demangled_symbol": source.get("demangled") if source else None,
                "translated_alias": source.get("alias") if source else None,
                "segment": segment_name,
                "size": int(func.end_ea - func.start_ea),
                "xrefs_to": count_xrefs_to(ea),
                "flags": flags,
                "is_thunk": is_thunk,
                "is_library": is_library,
                "is_default_sub": default_sub,
            }
        )

    inventory.sort(key=lambda row: row["ea"])
    return inventory, symbol_rows


def write_outputs(inventory, symbol_rows):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    json_path = os.path.join(OUTPUT_DIR, "libqplay.function_inventory.json")
    csv_path = os.path.join(OUTPUT_DIR, "libqplay.function_inventory.csv")
    summary_path = os.path.join(OUTPUT_DIR, "libqplay.function_inventory.summary.json")

    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(inventory, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    fields = [
        "ea",
        "name",
        "name_origin",
        "source_kind",
        "original_symbol",
        "demangled_symbol",
        "translated_alias",
        "segment",
        "size",
        "xrefs_to",
        "flags",
        "is_thunk",
        "is_library",
        "is_default_sub",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(inventory)

    source_functions = sum(row.get("kind") != "data" for row in symbol_rows)
    source_data = sum(row.get("kind") == "data" for row in symbol_rows)
    summary = {
        "input": ida_nalt.get_input_file_path(),
        "input_sha256": input_sha256(),
        "symbol_export_rows": len(symbol_rows),
        "symbol_export_function_rows": source_functions,
        "symbol_export_data_rows": source_data,
        "total_functions": len(inventory),
        "functions_backed_by_elf_symbols": sum(row["name_origin"] == "elf_symbol" for row in inventory),
        "ida_default_sub_functions": sum(row["name_origin"] == "ida_default_sub" for row in inventory),
        "ida_named_non_elf_functions": sum(row["name_origin"] == "ida_named_non_elf" for row in inventory),
        "thunk_functions": sum(row["is_thunk"] for row in inventory),
        "library_functions": sum(row["is_library"] for row in inventory),
        "segments": sorted({row["segment"] for row in inventory if row["segment"]}),
    }
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    return json_path, csv_path, summary_path, summary


inventory, symbol_rows = collect_inventory()
paths = write_outputs(inventory, symbol_rows)
print(json.dumps({"paths": paths[:3], "summary": paths[3]}, ensure_ascii=False))
