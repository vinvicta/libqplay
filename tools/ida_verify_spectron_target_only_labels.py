#!/usr/bin/env python3
"""Verify target-only Spectron labels after reopening an IDA copy."""

from __future__ import annotations

import json
import os
from pathlib import Path

import ida_auto
import ida_funcs
import ida_idaapi
import ida_name


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
LABEL_PATH = Path(
    os.environ.get(
        "SPECTRON_TARGET_LABEL_PATH",
        str(REPO / "artifacts/spectron_target_only_callback_labels_20260828.json"),
    )
)
EXPECTED_ARTIFACT = os.environ.get(
    "SPECTRON_TARGET_LABEL_EXPECTED_ARTIFACT",
    "spectron_target_only_callback_labels_20260828",
)
REPORT_PATH = Path(
    os.environ.get(
        "SPECTRON_TARGET_LABEL_VERIFY_REPORT",
        "/tmp/spectron_target_only_label_verification_20260828.json",
    )
)


def main() -> None:
    ida_auto.auto_wait()
    document = json.loads(LABEL_PATH.read_text(encoding="utf-8"))
    if document.get("artifact") != EXPECTED_ARTIFACT:
        raise RuntimeError("unexpected Spectron target-only label artifact")
    failures = []
    for label in document.get("labels", []):
        ea = int(label["target_ea"], 16)
        expected_name = label["proposed_name"]
        actual_name = ida_name.get_name(ea)
        actual_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, expected_name)
        function = ida_funcs.get_func(ea)
        if function is None or function.start_ea != ea:
            failures.append(
                {
                    "target_ea": label["target_ea"],
                    "error": "expected target function start is missing",
                }
            )
            continue
        expected_end = int(label["function_end"], 16)
        if function.end_ea != expected_end:
            failures.append(
                {
                    "target_ea": label["target_ea"],
                    "expected_function_end": label["function_end"],
                    "actual_function_end": "0x%x" % function.end_ea,
                    "error": "target function boundary mismatch",
                }
            )
            continue
        if actual_name != expected_name or actual_ea != ea:
            failures.append(
                {
                    "target_ea": label["target_ea"],
                    "expected_name": expected_name,
                    "actual_name": actual_name,
                    "actual_name_ea": None
                    if actual_ea == ida_idaapi.BADADDR
                    else hex(actual_ea),
                    "error": "target-only label mismatch",
                }
            )

    result = {
        "artifact": "spectron_target_only_label_reopen_verification",
        "label_path": str(LABEL_PATH),
        "expected_artifact": EXPECTED_ARTIFACT,
        "label_count": len(document.get("labels", [])),
        "verified_name_count": len(document.get("labels", [])) - len(failures),
        "failure_count": len(failures),
        "failures": failures,
        "verified": not failures,
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, sort_keys=True))
    if failures:
        raise RuntimeError("Spectron target-only label verification failed")


if __name__ == "__main__":
    main()
