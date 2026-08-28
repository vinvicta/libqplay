#!/usr/bin/env python3
"""Apply reviewed target-only descriptive labels to a disposable IDA copy.

The default mode is review-only. Set ``SPECTRON_TARGET_LABEL_APPLY=1`` and
provide ``SPECTRON_TARGET_LABEL_SAVE_PATH`` to save a new packed database.
Existing files are never overwritten.
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
APPLY = os.environ.get("SPECTRON_TARGET_LABEL_APPLY") == "1"
SAVE_PATH = os.environ.get("SPECTRON_TARGET_LABEL_SAVE_PATH")
REPORT_PATH = Path(
    os.environ.get(
        "SPECTRON_TARGET_LABEL_REPORT",
        "/tmp/spectron_target_only_label_application_20260828.json",
    )
)


def append_comment(ea: int, label: dict) -> bool:
    comment = (
        "Reviewed Spectron-only label: "
        + label["proposed_name"]
        + "; property="
        + label["script_name"]
        + "; no demonstrated 1.8 source counterpart"
    )
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    ida_bytes.set_cmt(ea, comment if not existing else existing + " | " + comment, False)
    return True


def main() -> None:
    ida_auto.auto_wait()
    document = json.loads(LABEL_PATH.read_text(encoding="utf-8"))
    if document.get("artifact") != EXPECTED_ARTIFACT:
        raise RuntimeError("unexpected Spectron target-only label artifact")

    failures = []
    renamed = 0
    comments = 0
    plan = []
    labels = document.get("labels", [])
    for label in labels:
        ea = int(label["target_ea"], 16)
        function = ida_funcs.get_func(ea)
        actual_before = ida_name.get_name(ea)
        item = {
            "target_ea": label["target_ea"],
            "current_name_expected": label["current_name"],
            "proposed_name": label["proposed_name"],
            "actual_name_before": actual_before,
            "function_end_expected": label["function_end"],
        }
        if function is None or function.start_ea != ea:
            item["error"] = "address is not the expected target function start"
            failures.append(item)
            plan.append(item)
            continue
        if function.end_ea != int(label["function_end"], 16):
            item["actual_function_end"] = "0x%x" % function.end_ea
            item["error"] = "target function boundary mismatch"
            failures.append(item)
            plan.append(item)
            continue
        if actual_before not in {label["current_name"], label["proposed_name"]}:
            item["error"] = "target name is neither the expected default nor the reviewed label"
            failures.append(item)
            plan.append(item)
            continue

        proposed_name = label["proposed_name"]
        existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, proposed_name)
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            item["error"] = "proposed target-only name is already used elsewhere"
            failures.append(item)
            plan.append(item)
            continue

        if APPLY and actual_before != proposed_name:
            if not ida_name.set_name(ea, proposed_name, ida_name.SN_NOCHECK):
                item["error"] = "IDA rejected the target-only label"
                failures.append(item)
                plan.append(item)
                continue
            renamed += 1
        if APPLY and append_comment(ea, label):
            comments += 1
        item["actual_name_after"] = ida_name.get_name(ea)
        item["name_action"] = label.get("name_action", "rename-with-spectron-prefix")
        plan.append(item)

    result = {
        "artifact": "spectron_target_only_label_application",
        "label_path": str(LABEL_PATH),
        "expected_artifact": EXPECTED_ARTIFACT,
        "apply": APPLY,
        "save_path": SAVE_PATH,
        "label_count": len(labels),
        "resolved_count": len(labels) - len(failures),
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
            raise RuntimeError("SPECTRON_TARGET_LABEL_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the target-only label copy")
        result["saved"] = True
    else:
        result["saved"] = False

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "apply",
                    "label_count",
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
