#!/usr/bin/env python3
"""Repair IDA phantom functions created over forward-DCT literal pools.

The old libjpeg ARM64 build keeps four 16-byte NEON constants in executable
``.text`` immediately before ``jpeg_fdct_ifast``. IDA can mistake those
constants for a function because the floating-point DCT reaches them with
``ADR``. This script checks the exact bytes and neighboring function starts,
then optionally removes only the two phantom boundaries and defines the pools
as four 16-byte data items each.

Review mode is the default. Set ``FDCT_POOL_APPLY=1`` and provide
``FDCT_POOL_SAVE_PATH`` to save a new packed database. Existing files are
never overwritten.
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
import ida_ua
import idautils


POOLS = (
    {
        "start": 0x2B9870,
        "end": 0x2B98B0,
        "next_function": 0x2B98B0,
        "next_name": "v18_jpeg_fdct_ifast_int",
        "expected_name": "sub_2B9870",
        "vectors": (
            "f304353f" * 4,
            "d48b0a3f" * 4,
            "15efc33e" * 4,
            "753da73f" * 4,
        ),
    },
)

APPLY = os.environ.get("FDCT_POOL_APPLY") == "1"
EXPECT_REPAIRED = os.environ.get("FDCT_POOL_EXPECT_REPAIRED") == "1"
SAVE_PATH = os.environ.get("FDCT_POOL_SAVE_PATH")
REPORT_PATH = Path(
    os.environ.get(
        "FDCT_POOL_REPORT",
        "/tmp/spectron_fdct_literal_pool_repair.json",
    )
)


def pool_rows() -> list[dict]:
    rows = []
    for spec in POOLS:
        start = spec["start"]
        end = spec["end"]
        function = ida_funcs.get_func(start)
        next_function = ida_funcs.get_func(spec["next_function"])
        raw = ida_bytes.get_bytes(start, end - start) or b""
        expected = b"".join(bytes.fromhex(item) for item in spec["vectors"])
        refs = []
        for address in range(start, end, 16):
            for ref in idautils.XrefsTo(address):
                refs.append(
                    {
                        "from": "0x%x" % ref.frm,
                        "to": "0x%x" % address,
                        "type": int(ref.type),
                        "mnemonic": ida_ua.print_insn_mnem(ref.frm),
                    }
                )
        rows.append(
            {
                "start": "0x%x" % start,
                "end": "0x%x" % end,
                "raw_hex": raw.hex(),
                "raw_matches_expected": raw == expected,
                "function_before": None
                if function is None
                else {
                    "start": "0x%x" % function.start_ea,
                    "end": "0x%x" % function.end_ea,
                    "name": ida_funcs.get_func_name(function.start_ea),
                },
                "next_function": None
                if next_function is None
                else {
                    "start": "0x%x" % next_function.start_ea,
                    "end": "0x%x" % next_function.end_ea,
                    "name": ida_funcs.get_func_name(next_function.start_ea),
                },
                "references": refs,
                "data_items": [
                    {
                        "ea": "0x%x" % address,
                        "is_data": bool(ida_bytes.is_data(ida_bytes.get_flags(address))),
                        "item_head": "0x%x" % ida_bytes.get_item_head(address),
                        "item_size": int(ida_bytes.get_item_size(address)),
                        "name": ida_name.get_name(address),
                    }
                    for address in range(start, end, 16)
                ],
            }
        )
    return rows


def preconditions(rows: list[dict]) -> list[str]:
    failures = []
    for row, spec in zip(rows, POOLS):
        function = row["function_before"]
        if function is None:
            failures.append("missing phantom function at %s" % row["start"])
        elif function["start"] != row["start"] or function["end"] != row["end"]:
            failures.append("unexpected phantom boundary at %s" % row["start"])
        elif function["name"] != spec["expected_name"]:
            failures.append("unexpected phantom name at %s" % row["start"])
        next_function = row["next_function"]
        if next_function is None or next_function["start"] != "0x%x" % spec["next_function"]:
            failures.append("missing real neighbor at %s" % row["start"])
        elif next_function["name"] != spec["next_name"]:
            failures.append("unexpected real neighbor name at %s" % row["start"])
        if not row["raw_matches_expected"]:
            failures.append("literal bytes differ at %s" % row["start"])
        for ref in row["references"]:
            if (ref["mnemonic"] or "").upper() in {"BL", "BLR"}:
                failures.append("call reference enters pool at %s" % row["start"])
    return failures


def apply_pool(spec: dict) -> None:
    start = spec["start"]
    end = spec["end"]
    if not ida_funcs.del_func(start):
        raise RuntimeError("IDA rejected function deletion at 0x%x" % start)
    ida_bytes.del_items(start, ida_bytes.DELIT_EXPAND, end - start)
    for index, address in enumerate(range(start, end, 16)):
        if not ida_bytes.create_data(address, ida_bytes.FF_OWORD, 16, ida_idaapi.BADADDR):
            raise RuntimeError("IDA rejected data definition at 0x%x" % address)
        label = "xmmword_%X" % address
        if not ida_name.set_name(address, label, ida_name.SN_NOCHECK):
            raise RuntimeError("IDA rejected data label at 0x%x" % address)


def main() -> None:
    ida_auto.auto_wait()
    before = pool_rows()
    precondition_failures = preconditions(before)
    failures = [] if EXPECT_REPAIRED else list(precondition_failures)
    changed = False
    if APPLY:
        if precondition_failures:
            raise RuntimeError("precondition failure: %s" % "; ".join(precondition_failures))
        for spec in POOLS:
            apply_pool(spec)
        changed = True
    after = pool_rows()
    if APPLY or EXPECT_REPAIRED:
        for row, spec in zip(after, POOLS):
            if row["function_before"] is not None:
                failures.append("phantom function remains at %s" % row["start"])
            if not all(item["is_data"] for item in row["data_items"]):
                failures.append("pool is not represented as data at %s" % row["start"])
            if row["next_function"] is None or row["next_function"]["start"] != "0x%x" % spec["next_function"]:
                failures.append("real neighbor changed at %s" % row["start"])
    result = {
        "artifact": "spectron_fdct_literal_pool_boundary_repair",
        "apply": APPLY,
        "save_path": SAVE_PATH,
        "pool_count": len(POOLS),
        "changed": changed,
        "precondition_failure_count": len(precondition_failures),
        "failure_count": len(failures),
        "failures": failures,
        "before": before,
        "after": after,
        "verified": not failures,
    }
    if APPLY and SAVE_PATH:
        output = Path(SAVE_PATH).expanduser().resolve()
        if output.exists():
            raise RuntimeError("refusing to overwrite an existing IDA copy")
        if output.suffix != ".i64":
            raise RuntimeError("FDCT_POOL_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the repaired database")
        result["saved"] = True
    else:
        result["saved"] = False
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("apply", "pool_count", "changed", "failure_count", "saved", "verified")}, sort_keys=True))
    if failures:
        raise RuntimeError("FDCT literal-pool repair verification failed")


if __name__ == "__main__":
    main()
