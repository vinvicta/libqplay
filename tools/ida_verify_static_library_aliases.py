#!/usr/bin/env python3
"""Verify the reviewed static-library aliases in a saved IDA database."""

from __future__ import annotations

import json
from pathlib import Path

import ida_auto
import ida_funcs
import ida_idaapi
import ida_name
import idautils


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
AUDIT_PATH = REPO / "artifacts/static_library_role_audit_20260826.json"
REPORT_PATH = Path("/tmp/static_library_alias_verification_20260826.json")


def main() -> None:
    ida_auto.auto_wait()
    document = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    failures = []
    for alias in document["aliases"]:
        ea = int(alias["va"], 16)
        actual_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, alias["proposed_name"])
        if actual_ea != ea:
            failures.append(
                {
                    "va": alias["va"],
                    "expected_name": alias["proposed_name"],
                    "actual_ea": None if actual_ea == ida_idaapi.BADADDR else hex(actual_ea),
                }
            )
            continue
        function = ida_funcs.get_func(ea)
        if function is None or function.start_ea != ea:
            failures.append(
                {
                    "va": alias["va"],
                    "expected_name": alias["proposed_name"],
                    "error": "expected name is not the function start",
                }
            )

    function_count = sum(1 for _ in idautils.Functions())
    default_sub_count = sum(
        1
        for ea in idautils.Functions()
        if (ida_funcs.get_func_name(ea) or "").startswith("sub_")
    )
    result = {
        "alias_count": len(document["aliases"]),
        "verified_name_count": len(document["aliases"]) - len(failures),
        "failure_count": len(failures),
        "function_count": function_count,
        "default_sub_count": default_sub_count,
        "expected_function_count": document["database"]["function_count"],
        "expected_default_sub_count": document["database"]["default_sub_function_count_after"],
        "failures": failures,
        "status": "ok"
        if not failures
        and function_count == document["database"]["function_count"]
        and default_sub_count == document["database"]["default_sub_function_count_after"]
        else "failed",
    }
    REPORT_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, sort_keys=True))
    if result["status"] != "ok":
        raise RuntimeError("static-library alias verification failed")


if __name__ == "__main__":
    main()
