#!/usr/bin/env python3
"""Verify reviewed manual Spectron anchors after reopening an IDA copy."""

from __future__ import annotations

import json
import os
from pathlib import Path

import ida_auto
import ida_funcs
import ida_idaapi
import ida_name


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
ANCHOR_OVERRIDE = os.environ.get("SPECTRON_MANUAL_ANCHORS")
ANCHOR_PATH = Path(
    ANCHOR_OVERRIDE
    or os.environ.get(
        "SPECTRON_MANUAL_ANCHOR_PATH",
        str(REPO / "artifacts/spectron_manual_translation_anchors_20260826.json"),
    )
)
EXPECTED_ARTIFACT = os.environ.get("SPECTRON_MANUAL_EXPECTED_ARTIFACT")
if EXPECTED_ARTIFACT is None and not ANCHOR_OVERRIDE:
    EXPECTED_ARTIFACT = "spectron_manual_translation_anchors_20260826"
REPORT_PATH = Path(
    os.environ.get(
        "SPECTRON_MANUAL_VERIFY_REPORT",
        "/tmp/spectron_manual_anchor_verification_20260826.json",
    )
)


def main() -> None:
    ida_auto.auto_wait()
    document = json.loads(ANCHOR_PATH.read_text(encoding="utf-8"))
    if EXPECTED_ARTIFACT and document.get("artifact") != EXPECTED_ARTIFACT:
        raise RuntimeError("unexpected Spectron manual-anchor artifact")
    anchors = document["anchors"]
    failures = []
    verified_name_count = 0
    for anchor in anchors:
        ea = int(anchor["spectron_ea"], 16)
        expected_name = anchor["proposed_name"]
        actual_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, expected_name)
        function = ida_funcs.get_func(ea)
        actual_name = ida_name.get_name(ea)
        if function is None or function.start_ea != ea:
            failures.append(
                {
                    "spectron_ea": anchor["spectron_ea"],
                    "error": "expected function start is missing",
                }
            )
            continue
        if anchor.get("spectron_function_end"):
            expected_end = int(anchor["spectron_function_end"], 16)
            if function.end_ea != expected_end:
                failures.append(
                    {
                        "spectron_ea": anchor["spectron_ea"],
                        "expected_function_end": anchor["spectron_function_end"],
                        "actual_function_end": "0x%x" % function.end_ea,
                        "error": "function boundary mismatch",
                    }
                )
                continue
        if actual_name != expected_name or actual_ea != ea:
            failures.append(
                {
                    "spectron_ea": anchor["spectron_ea"],
                    "expected_name": expected_name,
                    "actual_name": actual_name,
                    "actual_name_ea": None
                    if actual_ea == ida_idaapi.BADADDR
                    else hex(actual_ea),
                    "error": "anchor name mismatch",
                }
            )
        else:
            verified_name_count += 1

    result = {
        "artifact": "spectron_manual_anchor_reopen_verification",
        "anchor_path": str(ANCHOR_PATH),
        "expected_artifact": EXPECTED_ARTIFACT,
        "anchor_count": len(anchors),
        "verified_name_count": verified_name_count,
        "function_count": ida_funcs.get_func_qty(),
        "failure_count": len(failures),
        "failures": failures,
        "verified": not failures,
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    if failures:
        raise RuntimeError("Spectron manual-anchor verification failed")


if __name__ == "__main__":
    main()
