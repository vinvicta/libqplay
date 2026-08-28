#!/usr/bin/env python3
"""Apply reviewed target-name corrections to a disposable Spectron IDA copy."""

from __future__ import annotations

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_idaapi
import ida_loader
import ida_name


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
CORRECTION_PATH = Path(
    os.environ.get(
        "SPECTRON_CORRECTION_PATH",
        str(REPO / "artifacts/spectron_tclient_handler_manual_translation_anchors_20260828.json"),
    )
)
EXPECTED_ARTIFACT = os.environ.get(
    "SPECTRON_CORRECTION_EXPECTED_ARTIFACT",
    "spectron_tclient_handler_manual_translation_anchors_20260828",
)
APPLY = os.environ.get("SPECTRON_CORRECTION_APPLY") == "1"
SAVE_PATH = os.environ.get("SPECTRON_CORRECTION_SAVE_PATH")
REPORT_PATH = Path(
    os.environ.get(
        "SPECTRON_CORRECTION_REPORT",
        "/tmp/spectron_name_correction_application_20260828.json",
    )
)


def append_comment(ea: int, correction: dict) -> bool:
    comment = (
        "Reviewed target-name correction: restore "
        + correction["restored_name"]
        + "; reason="
        + correction["reason"]
    )
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    ida_bytes.set_cmt(ea, comment if not existing else existing + " | " + comment, False)
    return True


def main() -> None:
    ida_auto.auto_wait()
    document = json.loads(CORRECTION_PATH.read_text(encoding="utf-8"))
    if document.get("artifact") != EXPECTED_ARTIFACT:
        raise RuntimeError("unexpected Spectron correction artifact")

    failures = []
    renamed = 0
    comments = 0
    plan = []
    for correction in document.get("corrections", []):
        ea = int(correction["target_ea"], 16)
        current = ida_name.get_name(ea)
        item = {
            "target_ea": correction["target_ea"],
            "current_name_expected": correction["current_name"],
            "restored_name": correction["restored_name"],
            "actual_name_before": current,
        }
        if current not in {correction["current_name"], correction["restored_name"]}:
            item["error"] = "the target name is neither the expected alias nor the restored symbol"
            failures.append(item)
            plan.append(item)
            continue

        existing_ea = ida_name.get_name_ea(
            ida_idaapi.BADADDR, correction["restored_name"]
        )
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            item["error"] = "the retained target symbol is already used elsewhere"
            failures.append(item)
            plan.append(item)
            continue

        if APPLY and current != correction["restored_name"]:
            if not ida_name.set_name(
                ea, correction["restored_name"], ida_name.SN_NOCHECK
            ):
                item["error"] = "IDA rejected the restored target symbol"
                failures.append(item)
                plan.append(item)
                continue
            renamed += 1
        if APPLY and append_comment(ea, correction):
            comments += 1
        item["actual_name_after"] = ida_name.get_name(ea)
        plan.append(item)

    result = {
        "artifact": "spectron_name_correction_application",
        "correction_path": str(CORRECTION_PATH),
        "expected_artifact": EXPECTED_ARTIFACT,
        "apply": APPLY,
        "save_path": SAVE_PATH,
        "correction_count": len(document.get("corrections", [])),
        "resolved_count": len(document.get("corrections", [])) - len(failures),
        "renamed_count": renamed,
        "comments_added": comments,
        "failure_count": len(failures),
        "failures": failures,
        "plan": plan,
    }
    if APPLY and SAVE_PATH:
        output = Path(SAVE_PATH).expanduser().resolve()
        if output.exists():
            raise RuntimeError("refusing to overwrite an existing Spectron IDA copy")
        if output.suffix != ".i64":
            raise RuntimeError("SPECTRON_CORRECTION_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the name-correction copy")
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
                    "correction_count",
                    "resolved_count",
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
