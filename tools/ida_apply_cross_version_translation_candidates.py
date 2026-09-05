#!/usr/bin/env python3
"""Review or apply exact-name 1.8 to 2.2 IDA translation candidates.

The default mode is review-only. Set ``CROSS_VERSION_APPLY_RENAMES=1`` and
provide ``CROSS_VERSION_SAVE_PATH`` to write a new packed IDA database. The
input database is never replaced. The optional
``CROSS_VERSION_ADD_FUNCTIONS=1`` setting permits creation of a function only
when the candidate address is not already covered by an existing function.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import idaapi


REPO = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = REPO / "artifacts/cross_version_translation_candidates_20260902.json"
APPLY_RENAMES = os.environ.get("CROSS_VERSION_APPLY_RENAMES") == "1"
ADD_FUNCTIONS = os.environ.get("CROSS_VERSION_ADD_FUNCTIONS") == "1"
SAVE_PATH = os.environ.get("CROSS_VERSION_SAVE_PATH")
REPORT_PATH = Path(
    os.environ.get(
        "CROSS_VERSION_REPORT_PATH",
        "/tmp/cross_version_translation_application_20260904.json",
    )
)
EXPECTED_TWO_TWO_SHA256 = "45a7f97df9b40cdac6fbd42dc715bbabf3bbdb9b33876990e232133a8818941e"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_candidates() -> tuple[dict, list[dict]]:
    document = json.loads(CANDIDATE_PATH.read_text(encoding="utf-8"))
    if document.get("artifact") != "cross_version_translation_candidates_20260902":
        raise RuntimeError("unexpected cross-version candidate artifact")
    mappings = document.get("results", {}).get("mappings")
    if not isinstance(mappings, list):
        raise RuntimeError("candidate artifact has no mapping list")
    return document, mappings


def target_input_record() -> dict:
    input_path = Path(idaapi.get_input_file_path())
    record = {"path": input_path.name, "expected_sha256": EXPECTED_TWO_TWO_SHA256}
    if input_path.is_file():
        record["observed_sha256"] = sha256_file(input_path)
        record["sha256_match"] = record["observed_sha256"] == EXPECTED_TWO_TWO_SHA256
    else:
        record["sha256_match"] = None
    return record


def resolve_address(value: str) -> int:
    address = idaapi.str2ea(value)
    if address == ida_idaapi.BADADDR:
        raise RuntimeError("could not resolve address %s" % value)
    return address


def append_comment(ea: int, mapping: dict) -> bool:
    comment = (
        "1.8 to 2.2 exact-name candidate: "
        + mapping["name"]
        + "; 1.8 size "
        + str(mapping["1.8_size"])
        + "; 2.2 size "
        + str(mapping["2.2_size"])
        + "; raw bytes equal="
        + str(mapping["raw_bytes_equal"])
        + ". Verify callers and data references before patching."
    )
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    ida_bytes.set_cmt(ea, comment if not existing else existing + " | " + comment, False)
    return True


def apply_candidates(document: dict, mappings: list[dict]) -> dict:
    ida_auto.auto_wait()
    input_record = target_input_record()
    if input_record.get("sha256_match") is False:
        raise RuntimeError(
            "target input hash does not match the unverified 2.2 candidate source: "
            + str(input_record.get("observed_sha256"))
        )

    failures = []
    renamed = 0
    added_functions = 0
    comments = 0
    plan = []
    for mapping in mappings:
        item = {
            "name": mapping["name"],
            "2.2_address": mapping["2.2_address"],
            "2.2_size": mapping["2.2_size"],
            "size_equal_across_versions": mapping["size_equal"],
            "raw_bytes_equal": mapping["raw_bytes_equal"],
        }
        try:
            ea = resolve_address(mapping["2.2_address"])
        except RuntimeError as exc:
            item["error"] = str(exc)
            failures.append(item)
            plan.append(item)
            continue

        function = ida_funcs.get_func(ea)
        if function is None and APPLY_RENAMES and ADD_FUNCTIONS:
            end_ea = ea + int(mapping["2.2_size"])
            if ida_funcs.add_func(ea, end_ea):
                function = ida_funcs.get_func(ea)
                added_functions += 1
        if function is None or function.start_ea != ea:
            item["error"] = "address is not an existing function start"
            failures.append(item)
            plan.append(item)
            continue

        actual_size = function.end_ea - function.start_ea
        item["actual_name_before"] = ida_name.get_name(ea)
        item["actual_size"] = actual_size
        item["boundary_size_match"] = actual_size == int(mapping["2.2_size"])
        if actual_size != int(mapping["2.2_size"]):
            item["error"] = "IDA function boundary does not match candidate symbol size"
            failures.append(item)
            plan.append(item)
            continue

        existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, mapping["name"])
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            item["error"] = "candidate name is already used at 0x%x" % existing_ea
            failures.append(item)
            plan.append(item)
            continue

        if APPLY_RENAMES:
            if not ida_name.set_name(ea, mapping["name"], ida_name.SN_NOCHECK):
                item["error"] = "IDA rejected candidate name"
                failures.append(item)
                plan.append(item)
                continue
            renamed += 1
            if append_comment(ea, mapping):
                comments += 1
        item["actual_name_after"] = ida_name.get_name(ea)
        plan.append(item)

    result = {
        "apply_renames": APPLY_RENAMES,
        "add_functions": ADD_FUNCTIONS,
        "candidate_count": len(mappings),
        "resolved_count": len(mappings) - len(failures),
        "renamed_count": renamed,
        "added_function_count": added_functions,
        "comments_added": comments,
        "failure_count": len(failures),
        "failures": failures,
        "target_input": input_record,
        "source_artifact": document["artifact"],
        "saved": False,
        "save_path": SAVE_PATH,
        "plan": plan,
    }
    if APPLY_RENAMES and SAVE_PATH:
        output = Path(SAVE_PATH).expanduser().resolve()
        if output.exists():
            raise RuntimeError("refusing to overwrite an existing IDA output")
        if output.suffix != ".i64":
            raise RuntimeError("CROSS_VERSION_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the packed translation copy")
        result["saved"] = True

    report = REPORT_PATH.expanduser().resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


document, mappings = load_candidates()
result = apply_candidates(document, mappings)
print(
    json.dumps(
        {
            key: result[key]
            for key in (
                "apply_renames",
                "add_functions",
                "candidate_count",
                "resolved_count",
                "renamed_count",
                "added_function_count",
                "failure_count",
                "saved",
            )
        },
        sort_keys=True,
    )
)
