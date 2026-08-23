"""Export and optionally apply readable aliases for C++ names in the active IDA DB.

Run from the IDA Pro MCP bridge with py_exec_file.  The first pass is intentionally
non-mutating; set APPLY_RENAMES = True only after reviewing the generated map.
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
import idautils


APPLY_RENAMES = False
OUTPUT_DIR = "/home/v/Desktop/graal-decomp/analysis"


def is_mangled(name):
    if not name:
        return False
    candidate = name
    if candidate.startswith("j_."):
        candidate = candidate[3:]
    elif candidate.startswith("."):
        candidate = candidate[1:]
    return candidate.startswith("_Z")


def demangle(name):
    candidates = [name]
    if name.startswith("j_."):
        candidates.append(name[3:])
    if name.startswith("."):
        candidates.append(name[1:])
    for candidate in candidates:
        try:
            value = ida_name.demangle_name(candidate, ida_name.MNG_SHORT_FORM)
        except Exception:
            value = None
        if value:
            return value
    return None


def symbol_kind(name, ea):
    if ida_funcs.get_func(ea):
        if name.startswith("j_."):
            return "jump_thunk"
        if name.startswith("."):
            return "plt_thunk"
        return "function"
    return "data"


def readable_alias(demangled, original, kind):
    value = demangled
    value = value.replace("operator<<", "operator_lshift")
    value = value.replace("operator>>", "operator_rshift")
    value = value.replace("operator=", "operator_assign")
    value = value.replace("operator()", "operator_call")
    value = value.replace("operator[]", "operator_index")
    value = value.replace("operator*", "operator_deref")
    value = value.replace("operator&", "operator_address")
    value = value.replace("operator+", "operator_add")
    value = value.replace("operator-", "operator_sub")
    value = value.replace("operator==", "operator_eq")
    value = value.replace("operator!=", "operator_ne")
    value = value.replace("operator<", "operator_lt")
    value = value.replace("operator>", "operator_gt")
    value = value.replace("operator new", "operator_new")
    value = value.replace("operator delete", "operator_delete")
    value = value.replace("::", "__")
    value = re.sub(r"\bconst\b", "const", value)
    value = re.sub(r"\bvolatile\b", "volatile", value)
    value = re.sub(r"\s+", "_", value)
    value = re.sub(r"[^0-9A-Za-z_]", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    if not value:
        return None
    if value[0].isdigit():
        value = "_" + value

    if kind == "plt_thunk":
        value = "plt_" + value
    elif kind == "jump_thunk":
        value = "jump_" + value
    elif kind == "data":
        value = "data_" + value

    # Keep names comfortably below IDA's practical identifier limit.
    if len(value) > 180:
        value = value[:180].rstrip("_")
    return value


def collect_rows():
    ida_auto.auto_wait()
    rows = []
    seen = set()
    for ea, name in idautils.Names():
        if ea in seen or not is_mangled(name):
            continue
        seen.add(ea)
        value = demangle(name)
        if not value:
            continue
        kind = symbol_kind(name, ea)
        rows.append(
            {
                "ea": ea,
                "original": name,
                "demangled": value,
                "kind": kind,
            }
        )
    rows.sort(key=lambda row: (row["ea"], row["original"]))

    used = {}
    for row in rows:
        base = readable_alias(row["demangled"], row["original"], row["kind"])
        if not base:
            continue
        alias = base
        suffix = 2
        while alias in used and used[alias] != row["ea"]:
            alias = "%s__%d" % (base, suffix)
            suffix += 1
        used[alias] = row["ea"]
        row["alias"] = alias

    return [row for row in rows if row.get("alias")]


def apply_aliases(rows):
    changed = 0
    failed = []
    for row in rows:
        try:
            if ida_name.set_name(row["ea"], row["alias"], ida_name.SN_NOCHECK):
                changed += 1
            else:
                failed.append({"ea": row["ea"], "alias": row["alias"]})
        except Exception as exc:
            failed.append({"ea": row["ea"], "alias": row["alias"], "error": repr(exc)})
    return changed, failed


def write_outputs(rows, changed, failed):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    json_path = os.path.join(OUTPUT_DIR, "libqplay.symbols.json")
    csv_path = os.path.join(OUTPUT_DIR, "libqplay.symbols.csv")
    summary_path = os.path.join(OUTPUT_DIR, "libqplay.symbols.summary.json")

    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ea", "kind", "original", "demangled", "alias"])
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "input": ida_nalt.get_input_file_path(),
        "apply_renames": APPLY_RENAMES,
        "translated_symbols": len(rows),
        "functions": sum(row["kind"] == "function" for row in rows),
        "plt_thunks": sum(row["kind"] == "plt_thunk" for row in rows),
        "jump_thunks": sum(row["kind"] == "jump_thunk" for row in rows),
        "data": sum(row["kind"] == "data" for row in rows),
        "renamed": changed,
        "rename_failures": failed,
    }
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    return json_path, csv_path, summary_path, summary


rows = collect_rows()
changed = 0
failed = []
if APPLY_RENAMES:
    changed, failed = apply_aliases(rows)
json_path, csv_path, summary_path, summary = write_outputs(rows, changed, failed)
print(json.dumps({"paths": [json_path, csv_path, summary_path], "summary": summary}, ensure_ascii=False))
