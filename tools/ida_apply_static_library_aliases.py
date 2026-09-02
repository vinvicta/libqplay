#!/usr/bin/env python3
"""Apply reviewed static-library aliases to a disposable IDA copy.

The default mode is review-only. Set ``STATIC_LIBRARY_APPLY_RENAMES=1`` and
provide ``STATIC_LIBRARY_SAVE_PATH`` to save a new packed database. The input
database is never replaced.
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


REPO = Path(__file__).resolve().parents[1]
AUDIT_PATH = REPO / "artifacts/static_library_role_audit_20260901.json"
APPLY_RENAMES = os.environ.get("STATIC_LIBRARY_APPLY_RENAMES") == "1"
SAVE_PATH = os.environ.get("STATIC_LIBRARY_SAVE_PATH")
REPORT_PATH = os.environ.get(
    "STATIC_LIBRARY_REPORT_PATH",
    "/tmp/static_library_alias_application_20260901.json",
)


def load_aliases() -> list[dict]:
    document = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    if document.get("artifact") != "static_library_role_audit_20260901":
        raise RuntimeError("unexpected static-library role audit artifact")
    return document["aliases"]


def append_comment(ea: int, alias: dict) -> bool:
    comment = (
        "Static library role alias ("
        + alias["family"]
        + "): "
        + alias["role"]
        + " Evidence: "
        + "; ".join(alias["evidence"])
    )
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    ida_bytes.set_cmt(ea, comment if not existing else existing + " | " + comment, False)
    return True


def apply_aliases(aliases: list[dict]) -> dict:
    ida_auto.auto_wait()
    failures = []
    renamed = 0
    comments = 0
    plan = []
    for alias in aliases:
        ea = int(alias["va"], 16)
        function = ida_funcs.get_func(ea)
        item = {
            "va": alias["va"],
            "current_ida_name": alias["current_ida_name"],
            "proposed_name": alias["proposed_name"],
            "actual_name_before": ida_name.get_name(ea),
        }
        if function is None or function.start_ea != ea:
            item["error"] = "address is not the expected function start"
            failures.append(item)
            plan.append(item)
            continue
        existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, alias["proposed_name"])
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            item["error"] = "proposed name is already used at 0x%x" % existing_ea
            failures.append(item)
            plan.append(item)
            continue
        if APPLY_RENAMES:
            if not ida_name.set_name(ea, alias["proposed_name"], ida_name.SN_NOCHECK):
                item["error"] = "IDA rejected the proposed name"
                failures.append(item)
                plan.append(item)
                continue
            renamed += 1
            if append_comment(ea, alias):
                comments += 1
        item["actual_name_after"] = ida_name.get_name(ea)
        plan.append(item)

    result = {
        "apply_renames": APPLY_RENAMES,
        "save_path": SAVE_PATH,
        "alias_count": len(aliases),
        "resolved_count": len(aliases) - len(failures),
        "renamed_count": renamed,
        "comments_added": comments,
        "failure_count": len(failures),
        "failures": failures,
        "plan": plan,
    }
    if APPLY_RENAMES and SAVE_PATH:
        output = Path(SAVE_PATH).expanduser().resolve()
        if output.exists():
            raise RuntimeError("refusing to overwrite an existing IDA output")
        if output.suffix != ".i64":
            raise RuntimeError("STATIC_LIBRARY_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the packed static-library alias copy")
        result["saved"] = True
    else:
        result["saved"] = False

    report = Path(REPORT_PATH).expanduser().resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


result = apply_aliases(load_aliases())
print(
    json.dumps(
        {
            key: result[key]
            for key in (
                "apply_renames",
                "alias_count",
                "resolved_count",
                "renamed_count",
                "failure_count",
                "saved",
            )
        },
        sort_keys=True,
    )
)
