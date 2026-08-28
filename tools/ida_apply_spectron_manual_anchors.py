#!/usr/bin/env python3
"""Apply a reviewed semantic-anchor artifact to a new Spectron IDA copy.

The original context-anchor interface remains supported.  The newer
``SPECTRON_MANUAL_ANCHORS`` variable is a short alias for the anchor path and
is useful for the successive FreeType evidence batches.
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
APPLY = os.environ.get("SPECTRON_MANUAL_APPLY") == "1"
SAVE_PATH = os.environ.get("SPECTRON_MANUAL_SAVE_PATH")
REPORT_PATH = Path(
    os.environ.get(
        "SPECTRON_MANUAL_REPORT",
        "/tmp/spectron_manual_anchor_application_20260826.json",
    )
)


def append_comment(ea: int, anchor: dict) -> bool:
    if "source_name" in anchor:
        comment = (
            "Manual cross-build FreeType anchor from original 1.8: "
            + anchor["source_name"]
            + "; role="
            + anchor["source_role"]
            + "; source="
            + anchor["source_file"]
            + "; exact ARM64 feature metrics"
        )
    else:
        comment = (
            "Reviewed 1.8-to-Spectron anchor: "
            + anchor["original_name"]
            + " at "
            + anchor["original_ea"]
            + "; basis="
            + anchor["source_basis"]
            + "; confidence="
            + anchor["confidence"]
        )
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    ida_bytes.set_cmt(ea, comment if not existing else existing + " | " + comment, False)
    return True


def main() -> None:
    ida_auto.auto_wait()
    document = json.loads(ANCHOR_PATH.read_text(encoding="utf-8"))
    if EXPECTED_ARTIFACT and document.get("artifact") != EXPECTED_ARTIFACT:
        raise RuntimeError("unexpected Spectron manual-anchor artifact")
    anchors = document["anchors"]
    failures = []
    renamed = 0
    comments = 0
    plan = []

    for anchor in anchors:
        ea = int(anchor["spectron_ea"], 16)
        proposed_name = anchor["proposed_name"]
        function = ida_funcs.get_func(ea)
        actual_before = ida_name.get_name(ea)
        item = {
            "spectron_ea": anchor["spectron_ea"],
            "original_ea": anchor["original_ea"],
            "original_name": anchor.get("original_name", anchor.get("source_name")),
            "proposed_name": proposed_name,
            "actual_name_before": actual_before,
            "confidence": anchor.get("confidence"),
        }
        boundary_added = False
        if function is None and anchor.get("spectron_function_end"):
            if not APPLY:
                item["error"] = "the reviewed function boundary is ready but apply mode is disabled"
                failures.append(item)
                plan.append(item)
                continue
            end_ea = int(anchor["spectron_function_end"], 16)
            if end_ea <= ea or not ida_funcs.add_func(ea, end_ea):
                item["error"] = "IDA rejected the reviewed function boundary"
                failures.append(item)
                plan.append(item)
                continue
            function = ida_funcs.get_func(ea)
            boundary_added = function is not None and function.start_ea == ea
            item["spectron_function_end"] = anchor["spectron_function_end"]
            item["boundary_added"] = boundary_added
        if function is None or function.start_ea != ea:
            item["error"] = "address is not the expected Spectron function start"
            failures.append(item)
            plan.append(item)
            continue

        existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, proposed_name)
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            item["error"] = "proposed name is already used at 0x%x" % existing_ea
            failures.append(item)
            plan.append(item)
            continue

        if APPLY:
            if actual_before != proposed_name:
                if not ida_name.set_name(ea, proposed_name, ida_name.SN_NOCHECK):
                    item["error"] = "IDA rejected the proposed anchor name"
                    failures.append(item)
                    plan.append(item)
                    continue
                renamed += 1
            if append_comment(ea, anchor):
                comments += 1
        item["actual_name_after"] = ida_name.get_name(ea)
        item["name_action"] = anchor.get("name_action", "rename-with-v18-prefix")
        plan.append(item)

    result = {
        "artifact": "spectron_manual_anchor_application",
        "anchor_path": str(ANCHOR_PATH),
        "expected_artifact": EXPECTED_ARTIFACT,
        "apply": APPLY,
        "save_path": SAVE_PATH,
        "anchor_count": len(document["anchors"]),
        "resolved_count": len(document["anchors"]) - len(failures),
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
            raise RuntimeError("SPECTRON_MANUAL_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the manual-anchor copy")
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
                    "anchor_count",
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
