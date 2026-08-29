#!/usr/bin/env python3
"""Materialize reviewed ELF dynamic-function boundaries in a fresh IDA copy.

The target dynamic table records a positive size for twelve code symbols that
the translated v319 database did not turn into IDA functions.  This helper is
review-only by default.  Set ``SPECTRON_DYNAMIC_FUNCTION_APPLY=1`` and provide
``SPECTRON_DYNAMIC_FUNCTION_SAVE_PATH`` to create a new packed database.  The
script refuses to overwrite an existing database and does not invent names:
it applies the exact retained dynamic symbol name at each reviewed address.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
BOUNDARY_AUDIT = Path(
    os.environ.get(
        "SPECTRON_BOUNDARY_AUDIT",
        "/tmp/spectron_dynamic_symbol_boundaries_v319_fresh.json",
    )
)
EXPECTED_BINARY_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
)
EXPECTED_MISSING = {
    "0x1b0140": {
        "size": 1184,
        "name": "_ZN10_YTgFa6HPk10bdqDgaFFMBERK10eY2wgaf6pw",
    },
    "0x1b281c": {
        "size": 788,
        "name": "_ZN10EqV_Ka3Vx910KHqDgay4MBERK10i7FHgaP2lF",
    },
    "0x1b2b34": {
        "size": 1104,
        "name": "_ZN10EqV_Ka3Vx910ZCBDgaugWBERK10eY2wgaf6pw",
    },
    "0x1c6c94": {
        "size": 844,
        "name": "_ZN10_k_Bgam3zA10sqrSLaYGpTERK10i7FHgaP2lF",
    },
    "0x1c6fe4": {
        "size": 2304,
        "name": "_ZN10_k_Bgam3zA10KHqDgay4MBERK10i7FHgaP2lF",
    },
    "0x1caeb4": {
        "size": 400,
        "name": "_ZN10Q8n_Fa6V5W10ZCBDgaugWBERK10eY2wgaf6pw",
    },
    "0x1cd73c": {
        "size": 964,
        "name": "_ZN10_thLgaWjoI10KHqDgay4MBERK10i7FHgaP2lF",
    },
    "0x1cdb04": {
        "size": 1436,
        "name": "_ZN10_thLgaWjoI10ZCBDgaugWBERK10eY2wgaf6pw",
    },
    "0x1dac5c": {
        "size": 432,
        "name": "_ZN10s_YwgafWlw10PbVb4aCJD8ERK10eY2wgaf6pwS2_S2_",
    },
    "0x1df0bc": {
        "size": 844,
        "name": "_ZN10awDo2aJRkD10KHqDgay4MBERK10i7FHgaP2lF",
    },
    "0x1dfffc": {
        "size": 1052,
        "name": "_ZN10EYKlVaL7UR10ZCBDgaugWBERK10eY2wgaf6pw",
    },
    "0x2bcf44": {
        "size": 72,
        "name": "_Z17yajl_buf_truncateP10yajl_buf_tm",
    },
}
APPLY = os.environ.get("SPECTRON_DYNAMIC_FUNCTION_APPLY") == "1"
SAVE_PATH = os.environ.get("SPECTRON_DYNAMIC_FUNCTION_SAVE_PATH")
REPORT_PATH = Path(
    os.environ.get(
        "SPECTRON_DYNAMIC_FUNCTION_REPORT",
        "/tmp/spectron_dynamic_function_application.json",
    )
)


def append_comment(ea: int, name: str, size: int) -> bool:
    comment = (
        "Reviewed retained Spectron ELF dynamic function: "
        + name
        + "; exact dynamic-symbol size=0x"
        + format(size, "x")
        + "; boundary materialized from the offline ELF audit"
    )
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    ida_bytes.set_cmt(ea, comment if not existing else existing + " | " + comment, False)
    return True


def load_rows() -> list[dict]:
    document = json.loads(BOUNDARY_AUDIT.read_text(encoding="utf-8"))
    if document.get("artifact") != "spectron_dynamic_symbol_boundary_audit":
        raise RuntimeError("unexpected dynamic-symbol boundary audit artifact")
    if document.get("input_sha256") != EXPECTED_BINARY_SHA256:
        raise RuntimeError("boundary audit input hash does not match target library")
    missing = [row for row in document.get("rows", []) if not row["ida_exact_start"]]
    by_ea = {row["value"]: row for row in missing}
    if set(by_ea) != set(EXPECTED_MISSING):
        raise RuntimeError("boundary audit missing-function set changed")
    for value, expected in EXPECTED_MISSING.items():
        row = by_ea[value]
        if row["size"] != expected["size"] or row["dynamic_name"] != expected["name"]:
            raise RuntimeError("boundary audit row changed for " + value)
        if row["ida_containing_start"] is not None:
            raise RuntimeError("missing row unexpectedly has a containing function")
    return sorted(missing, key=lambda row: int(row["value"], 16))


def main() -> None:
    ida_auto.auto_wait()
    rows = load_rows()
    failures = []
    plan = []
    comments_added = 0
    renamed = 0
    materialized = 0

    for row in rows:
        ea = int(row["value"], 16)
        end_ea = ea + int(row["size"])
        name = row["dynamic_name"]
        function_at_start = ida_funcs.get_func(ea)
        function_at_end = ida_funcs.get_func(end_ea - 1)
        existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        item = {
            "target_ea": row["value"],
            "function_end_expected": hex(end_ea),
            "dynamic_name": name,
            "current_name": ida_name.get_name(ea),
            "existing_name_ea": (
                hex(existing_ea) if existing_ea != ida_idaapi.BADADDR else None
            ),
            "function_at_start": (
                hex(function_at_start.start_ea) if function_at_start else None
            ),
            "function_at_end": (
                hex(function_at_end.start_ea) if function_at_end else None
            ),
        }
        if function_at_start is not None:
            item["error"] = "address already belongs to an IDA function"
            failures.append(item)
            plan.append(item)
            continue
        if function_at_end is not None:
            item["error"] = "requested end overlaps an IDA function"
            failures.append(item)
            plan.append(item)
            continue
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            item["error"] = "retained dynamic name is already used elsewhere"
            failures.append(item)
            plan.append(item)
            continue

        if APPLY:
            if not ida_funcs.add_func(ea, end_ea):
                item["error"] = "IDA rejected the reviewed function boundary"
                failures.append(item)
                plan.append(item)
                continue
            function_after = ida_funcs.get_func(ea)
            if (
                function_after is None
                or function_after.start_ea != ea
                or function_after.end_ea != end_ea
            ):
                item["actual_function_start"] = (
                    hex(function_after.start_ea) if function_after else None
                )
                item["actual_function_end"] = (
                    hex(function_after.end_ea) if function_after else None
                )
                item["error"] = "IDA did not preserve the requested boundary"
                failures.append(item)
                plan.append(item)
                continue
            materialized += 1
            if ida_name.get_name(ea) != name:
                if not ida_name.set_name(ea, name, ida_name.SN_NOCHECK):
                    item["error"] = "IDA rejected the retained dynamic name"
                    failures.append(item)
                    plan.append(item)
                    continue
                renamed += 1
            if append_comment(ea, name, row["size"]):
                comments_added += 1
            item["actual_name"] = ida_name.get_name(ea)
            item["actual_function_end"] = hex(ida_funcs.get_func(ea).end_ea)
        plan.append(item)

    result = {
        "artifact": "spectron_dynamic_function_application",
        "network_contacted": False,
        "boundary_audit": str(BOUNDARY_AUDIT),
        "expected_binary_sha256": EXPECTED_BINARY_SHA256,
        "apply": APPLY,
        "save_path": SAVE_PATH,
        "row_count": len(rows),
        "materialized_count": materialized,
        "renamed_count": renamed,
        "comments_added": comments_added,
        "failure_count": len(failures),
        "failures": failures,
        "plan": plan,
    }
    if failures:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise RuntimeError("dynamic function application had failures")

    if APPLY and SAVE_PATH:
        output = Path(SAVE_PATH).expanduser().resolve()
        if output.exists():
            raise RuntimeError("refusing to overwrite an existing Spectron IDA copy")
        if output.suffix != ".i64":
            raise RuntimeError("SPECTRON_DYNAMIC_FUNCTION_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the dynamic-function copy")
        result["saved"] = True
    else:
        result["saved"] = False

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "apply",
                    "row_count",
                    "materialized_count",
                    "renamed_count",
                    "failure_count",
                    "saved",
                )
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
