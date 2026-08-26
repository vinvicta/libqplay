#!/usr/bin/env python3
"""Verify a persisted Spectron IDA translation copy after reopening it."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re

import ida_auto
import ida_funcs
import ida_idaapi
import ida_name


MAP_PATH = Path(
    os.environ.get(
        "SPECTRON_TRANSLATION_MAP",
        "/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_semantic_function_translation_20260826.json",
    )
)
REPORT_PATH = Path(
    os.environ.get(
        "SPECTRON_TRANSLATION_VERIFY_REPORT",
        "/tmp/spectron_translation_verify_20260826.json",
    )
)
DEFAULT_SUB = re.compile(r"^sub_[0-9A-Fa-f]+$")


def main() -> None:
    ida_auto.auto_wait()
    document = json.loads(MAP_PATH.read_text(encoding="utf-8"))
    matches = [item for item in document["matches"] if item["confidence"] == "high"]
    failures = []
    for match in matches:
        ea = int(match["spectron_ea"], 16)
        function = ida_funcs.get_func(ea)
        actual_name = ida_name.get_name(ea)
        if function is None or function.start_ea != ea:
            failures.append({"ea": match["spectron_ea"], "error": "missing function start"})
        elif actual_name != match["alias_name"]:
            failures.append(
                {
                    "ea": match["spectron_ea"],
                    "expected": match["alias_name"],
                    "actual": actual_name,
                    "error": "alias mismatch",
                }
            )
    default_count = 0
    for index in range(ida_funcs.get_func_qty()):
        function = ida_funcs.getn_func(index)
        if function is None:
            continue
        if DEFAULT_SUB.match(ida_name.get_name(function.start_ea) or ""):
            default_count += 1
    result = {
        "artifact": "spectron_translation_reopen_verification",
        "map_path": str(MAP_PATH),
        "high_confidence_match_count": len(matches),
        "function_count": ida_funcs.get_func_qty(),
        "default_sub_function_count": default_count,
        "failure_count": len(failures),
        "failures": failures,
        "verified": not failures,
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
