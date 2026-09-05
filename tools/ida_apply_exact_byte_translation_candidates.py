#!/usr/bin/env python3
"""Review or apply unique 1.8 to 2.2 exact-byte translation candidates.

The default mode is review-only. Set ``EXACT_BYTE_APPLY_RENAMES=1`` and
provide ``EXACT_BYTE_SAVE_PATH`` to write a new packed IDA database. The input
database is never replaced. Set ``EXACT_BYTE_ADD_FUNCTIONS=1`` only when a
reviewer has confirmed that a missing function boundary should be created.
Repeated byte sequences are intentionally absent from the CSV and cannot be
renamed by this script.
"""

from __future__ import annotations

import csv
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
CANDIDATE_PATH = REPO / "symbols/libqplay_2.2_exact_byte_unique_matches.csv"
EXPECTED_TWO_TWO_SHA256 = "45a7f97df9b40cdac6fbd42dc715bbabf3bbdb9b33876990e232133a8818941e"
APPLY_RENAMES = os.environ.get("EXACT_BYTE_APPLY_RENAMES") == "1"
ADD_FUNCTIONS = os.environ.get("EXACT_BYTE_ADD_FUNCTIONS") == "1"
SAVE_PATH = os.environ.get("EXACT_BYTE_SAVE_PATH")
REPORT_PATH = Path(
    os.environ.get(
        "EXACT_BYTE_REPORT_PATH",
        "/tmp/libqplay_2.2_exact_byte_translation_review_20260904.json",
    )
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_candidates() -> list[dict[str, str]]:
    with CANDIDATE_PATH.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {
        "2.2_name",
        "2.2_address",
        "size",
        "byte_sha256",
        "1.8_ida_name",
        "1.8_address",
        "family",
    }
    if not rows or not required.issubset(rows[0]):
        raise RuntimeError("exact-byte candidate CSV has an unexpected header")
    return rows


def target_input_record() -> dict[str, object]:
    input_path = Path(idaapi.get_input_file_path())
    record: dict[str, object] = {
        "path": str(input_path),
        "expected_sha256": EXPECTED_TWO_TWO_SHA256,
    }
    if input_path.is_file():
        observed = sha256_file(input_path)
        record["observed_sha256"] = observed
        record["sha256_match"] = observed == EXPECTED_TWO_TWO_SHA256
    else:
        record["sha256_match"] = None
    return record


def resolve_address(value: str) -> int:
    address = idaapi.str2ea(value)
    if address == ida_idaapi.BADADDR:
        raise RuntimeError("could not resolve address %s" % value)
    return address


def append_comment(ea: int, row: dict[str, str], existing_name: str) -> bool:
    comment = (
        "Unique 1.8 to 2.2 exact-byte candidate: 2.2 exported name "
        + row["2.2_name"]
        + "; 1.8 name "
        + row["1.8_ida_name"]
        + "; 1.8 address "
        + row["1.8_address"]
        + "; size "
        + row["size"]
        + "; byte SHA-256 "
        + row["byte_sha256"]
        + ". Original 2.2 name before this pass: "
        + (existing_name or "<unnamed>")
        + ". Verify callers and data references before treating the alias as semantic proof."
    )
    current = ida_bytes.get_cmt(ea, False) or ""
    if comment in current:
        return False
    ida_bytes.set_cmt(ea, comment if not current else current + " | " + comment, False)
    return True


def review_candidates(rows: list[dict[str, str]]) -> dict[str, object]:
    ida_auto.auto_wait()
    input_record = target_input_record()
    if input_record.get("sha256_match") is False:
        raise RuntimeError(
            "target input hash does not match the unverified 2.2 candidate source: "
            + str(input_record.get("observed_sha256"))
        )

    failures: list[dict[str, object]] = []
    plan: list[dict[str, object]] = []
    renamed = 0
    added_functions = 0
    comments = 0

    for row in rows:
        item: dict[str, object] = {
            "2.2_name": row["2.2_name"],
            "2.2_address": row["2.2_address"],
            "1.8_ida_name": row["1.8_ida_name"],
            "1.8_address": row["1.8_address"],
            "size": int(row["size"]),
            "family": row["family"],
            "expected_byte_sha256": row["byte_sha256"],
        }
        try:
            ea = resolve_address(row["2.2_address"])
        except RuntimeError as exc:
            item["error"] = str(exc)
            failures.append(item)
            plan.append(item)
            continue

        function = ida_funcs.get_func(ea)
        if function is None and APPLY_RENAMES and ADD_FUNCTIONS:
            end_ea = ea + int(row["size"])
            if ida_funcs.add_func(ea, end_ea):
                function = ida_funcs.get_func(ea)
                added_functions += 1
        if function is None or function.start_ea != ea:
            item["error"] = "address is not an existing function start"
            failures.append(item)
            plan.append(item)
            continue

        actual_size = function.end_ea - function.start_ea
        item["actual_size"] = actual_size
        item["boundary_size_match"] = actual_size == int(row["size"])
        if actual_size != int(row["size"]):
            item["error"] = "IDA function boundary does not match candidate size"
            failures.append(item)
            plan.append(item)
            continue

        actual_bytes = ida_bytes.get_bytes(ea, actual_size)
        actual_hash = sha256_bytes(actual_bytes) if actual_bytes is not None else None
        item["actual_byte_sha256"] = actual_hash
        item["byte_hash_match"] = actual_hash == row["byte_sha256"]
        if actual_hash != row["byte_sha256"]:
            item["error"] = "IDA bytes do not match the candidate byte hash"
            failures.append(item)
            plan.append(item)
            continue

        existing_name = ida_name.get_name(ea) or ""
        item["actual_name_before"] = existing_name
        candidate_name = row["1.8_ida_name"]
        existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate_name)
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            item["error"] = "candidate name is already used at 0x%x" % existing_ea
            failures.append(item)
            plan.append(item)
            continue

        if APPLY_RENAMES:
            if not ida_name.set_name(ea, candidate_name, ida_name.SN_NOCHECK):
                item["error"] = "IDA rejected candidate name"
                failures.append(item)
                plan.append(item)
                continue
            renamed += 1
            if append_comment(ea, row, existing_name):
                comments += 1
        item["actual_name_after"] = ida_name.get_name(ea)
        plan.append(item)

    result: dict[str, object] = {
        "apply_renames": APPLY_RENAMES,
        "add_functions": ADD_FUNCTIONS,
        "candidate_csv": str(CANDIDATE_PATH),
        "candidate_csv_sha256": sha256_file(CANDIDATE_PATH),
        "candidate_count": len(rows),
        "resolved_count": len(rows) - len(failures),
        "renamed_count": renamed,
        "added_function_count": added_functions,
        "comments_added": comments,
        "failure_count": len(failures),
        "failures": failures,
        "target_input": input_record,
        "saved": False,
        "save_path": SAVE_PATH,
        "plan": plan,
    }
    if APPLY_RENAMES and SAVE_PATH:
        output = Path(SAVE_PATH).expanduser().resolve()
        if output.exists():
            raise RuntimeError("refusing to overwrite an existing IDA output")
        if output.suffix != ".i64":
            raise RuntimeError("EXACT_BYTE_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the packed translation copy")
        result["saved"] = True

    report = REPORT_PATH.expanduser().resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


result = review_candidates(load_candidates())
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
