#!/usr/bin/env python3
"""Audit every retained named dynamic symbol against an IDA database.

Function-boundary coverage is only one part of the target's surviving
metadata.  This read-only pass also records objects, absolute symbols, and
undefined imports so they are not mistaken for missing code labels.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import ida_nalt
import ida_segment
import idc
import idautils


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
SYMBOL_AUDIT = Path(
    os.environ.get(
        "SPECTRON_SYMBOL_AUDIT",
        str(REPO / "artifacts/spectron_symbol_table_audit_20260827.json"),
    )
)
OUTPUT_PATH = Path(
    os.environ.get(
        "SPECTRON_DYNAMIC_SYMBOL_COVERAGE_OUTPUT",
        "/tmp/spectron_dynamic_symbol_coverage.json",
    )
)
EXPECTED_BINARY_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
)


def input_sha256() -> str | None:
    for method_name in ("retrieve_input_file_sha256", "get_input_file_sha256"):
        method = getattr(ida_nalt, method_name, None)
        if method is None:
            continue
        try:
            value = method()
        except Exception:
            continue
        if isinstance(value, bytes):
            return value.hex()
        if value:
            return str(value)
    return None


def symbol_item(ea: int) -> dict:
    segment = ida_segment.getseg(ea)
    function = ida_funcs.get_func(ea)
    item_head = idc.get_item_head(ea)
    flags = ida_bytes.get_flags(ea)
    if function is not None:
        location_kind = "ida_function_exact" if function.start_ea == ea else "ida_function_containing"
    elif segment is None:
        location_kind = "no_ida_segment"
    elif ida_bytes.is_code(flags):
        location_kind = "ida_code_item_without_function"
    elif ida_bytes.is_data(flags):
        location_kind = "ida_data_item"
    else:
        location_kind = "ida_noncode_item"
    return {
        "ida_name_at_value": ida_name.get_name(ea) if segment is not None else None,
        "ida_item_head": None if item_head == ida_idaapi.BADADDR else hex(item_head),
        "ida_item_name": (
            None
            if item_head == ida_idaapi.BADADDR
            else ida_name.get_name(item_head)
        ),
        "ida_function_start": (
            hex(function.start_ea) if function is not None else None
        ),
        "ida_function_end": hex(function.end_ea) if function is not None else None,
        "segment_name": ida_segment.get_segm_name(segment) if segment else None,
        "location_kind": location_kind,
    }


def dynamic_symbol_status(row: dict) -> str:
    if row["location_kind"] == "undefined_or_zero_value":
        if row["ida_plt_stubs"]:
            return "undefined_import_with_plt_stub"
        return "undefined_no_target_address"
    if row["ida_name_matches_dynamic_name"]:
        return "exact_retained_dynamic_name"
    ida_name_at_value = row["ida_name_at_value"] or ""
    if ida_name_at_value.startswith("v18_"):
        return "source_backed_v18_alias"
    if ida_name_at_value.startswith("spectron_"):
        return "target_only_descriptive"
    if (
        ida_name_at_value.startswith("_Z")
        or ida_name_at_value.startswith("CyaSSL")
        or ida_name_at_value.startswith("Java_")
    ):
        return "other_retained_target_name"
    if row["type"] == "NOTYPE":
        return "linker_boundary_alias_mismatch"
    return "ida_name_different_or_alias"


def main() -> None:
    ida_auto.auto_wait()
    document = json.loads(SYMBOL_AUDIT.read_text(encoding="utf-8"))
    target = document["spectron"]
    if target["input"]["sha256"] != EXPECTED_BINARY_SHA256:
        raise RuntimeError("dynamic-symbol audit hash does not match target library")
    defined_indices = {row["index"] for row in target["defined_named_symbols"]}
    rows = []
    location_counts = Counter()
    name_match_counts = Counter()
    status_counts = Counter()
    function_name_eas = {}
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if name:
            function_name_eas.setdefault(name, []).append(ea)
    for symbol in target["named_symbols"]:
        row = {
            "dynamic_index": symbol["index"],
            "dynamic_name": symbol["name"],
            "binding": symbol["binding_name"],
            "type": symbol["type_name"],
            "section_index": symbol["section_index"],
            "value": hex(symbol["value"]),
            "size": symbol["size"],
            "is_defined": symbol["index"] in defined_indices,
        }
        if row["is_defined"] and symbol["value"] != 0:
            row.update(symbol_item(symbol["value"]))
            row["ida_plt_stubs"] = []
            exact_name = row["ida_name_at_value"] == symbol["name"]
            item_name_match = row["ida_item_name"] == symbol["name"]
        else:
            plt_stubs = []
            for stub_name, stub_kind in (
                ("." + symbol["name"], "dot"),
                ("j_." + symbol["name"], "jump"),
            ):
                for stub_ea in function_name_eas.get(stub_name, []):
                    plt_stubs.append(
                        {
                            "name": stub_name,
                            "kind": stub_kind,
                            "ea": hex(stub_ea),
                        }
                    )
            row.update(
                {
                    "ida_name_at_value": None,
                    "ida_item_head": None,
                    "ida_item_name": None,
                    "ida_function_start": None,
                    "ida_function_end": None,
                    "segment_name": None,
                    "location_kind": "undefined_or_zero_value",
                    "ida_plt_stubs": plt_stubs,
                }
            )
            exact_name = False
            item_name_match = False
        row["ida_name_matches_dynamic_name"] = exact_name
        row["ida_item_name_matches_dynamic_name"] = item_name_match
        row["dynamic_symbol_status"] = dynamic_symbol_status(row)
        location_counts[row["location_kind"]] += 1
        name_match_counts["value_name_match" if exact_name else "value_name_mismatch"] += 1
        name_match_counts[
            "item_name_match" if item_name_match else "item_name_mismatch"
        ] += 1
        status_counts[row["dynamic_symbol_status"]] += 1
        rows.append(row)

    rows.sort(key=lambda row: (int(row["value"], 16), row["dynamic_index"]))
    result = {
        "schema_version": 1,
        "artifact": "spectron_dynamic_symbol_coverage_audit_20260828",
        "network_contacted": False,
        "input": ida_nalt.get_input_file_path(),
        "input_sha256": input_sha256(),
        "symbol_audit": str(SYMBOL_AUDIT),
        "summary": {
            "named_dynamic_symbol_count": len(rows),
            "defined_named_symbol_count": sum(row["is_defined"] for row in rows),
            "location_counts": dict(sorted(location_counts.items())),
            "name_match_counts": dict(sorted(name_match_counts.items())),
            "status_counts": dict(sorted(status_counts.items())),
        },
        "interpretation": [
            "Undefined imports have no target address in the library and are recorded without an IDA name expectation.",
            "An exact function or data-item name match means IDA already exposes the retained dynamic name at that address.",
            "A location without an exact name is a coverage candidate only after checking aliases and the symbol's type.",
            "A source-backed v18 alias is intentionally preferred over an obfuscated dynamic alias when the translated IDA database has reviewed cross-build evidence.",
            "A linker-boundary alias mismatch records multiple ELF boundary names at an IDA data item without replacing the useful existing item name.",
            "An undefined import with a PLT stub is represented by the target dynamic name plus the exact IDA veneer name and address; the import itself still has no address in the library.",
            "This audit does not promote data, absolute symbols, or undefined imports to functions.",
        ],
        "rows": rows,
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
