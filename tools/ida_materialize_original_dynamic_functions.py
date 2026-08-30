#!/usr/bin/env python3
"""Materialize original 1.8 ELF function symbols that IDA left as data.

The original ARM64 library has eleven positive-size dynamic FUNC symbols that
were present in the ELF table but absent from the original IDA function list.
This helper is review-only by default. Set ``ORIGINAL_DYNAMIC_FUNCTION_APPLY=1``
and provide ``ORIGINAL_DYNAMIC_FUNCTION_SAVE_PATH`` to save a new packed IDA
copy. It applies only the exact ELF symbol ranges and names recorded in the
offline symbol audit.
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
import ida_nalt


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
SYMBOL_AUDIT = Path(
    os.environ.get(
        "ORIGINAL_DYNAMIC_SYMBOL_AUDIT",
        str(REPO / "artifacts/elf_symbol_table_audit_20260826.json"),
    )
)
SYMBOL_LIST = Path(
    os.environ.get(
        "ORIGINAL_SYMBOL_LIST",
        str(REPO / "symbols/libqplay.symbols.json"),
    )
)
EXPECTED_BINARY_SHA256 = (
    "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
)
EXPECTED_MISSING = {
    "0x1abf80": {
        "size": 1184,
        "name": "_ZN19GuiBitmapButtonCtrl8onRenderERK6TPoint",
    },
    "0x1ae65c": {
        "size": 796,
        "name": "_ZN13GuiButtonCtrl13drawWithStyleERK10TRectangle",
    },
    "0x1ae97c": {
        "size": 1104,
        "name": "_ZN13GuiButtonCtrl15drawWithProfileERK6TPoint",
    },
    "0x1c21b8": {
        "size": 844,
        "name": "_ZN13GuiScrollCtrl14drawBackgroundERK10TRectangle",
    },
    "0x1c2508": {
        "size": 2304,
        "name": "_ZN13GuiScrollCtrl13drawWithStyleERK10TRectangle",
    },
    "0x1c63a8": {
        "size": 400,
        "name": "_ZN11GuiTextCtrl15drawWithProfileERK6TPoint",
    },
    "0x1c8bb8": {
        "size": 964,
        "name": "_ZN15GuiTextEditCtrl13drawWithStyleERK10TRectangle",
    },
    "0x1c8f80": {
        "size": 1436,
        "name": "_ZN15GuiTextEditCtrl15drawWithProfileERK6TPoint",
    },
    "0x1d5fcc": {
        "size": 432,
        "name": "_ZN12GuiArrayCtrl21onRenderColumnHeadersERK6TPointS2_S2_",
    },
    "0x1da320": {
        "size": 844,
        "name": "_ZN16GuiPopUpMenuCtrl13drawWithStyleERK10TRectangle",
    },
    "0x1dc260": {
        "size": 1052,
        "name": "_ZN15GuiProgressCtrl15drawWithProfileERK6TPoint",
    },
}
APPLY = os.environ.get("ORIGINAL_DYNAMIC_FUNCTION_APPLY") == "1"
SAVE_PATH = os.environ.get("ORIGINAL_DYNAMIC_FUNCTION_SAVE_PATH")
REPORT_PATH = Path(
    os.environ.get(
        "ORIGINAL_DYNAMIC_FUNCTION_REPORT",
        "/tmp/original_dynamic_function_application.json",
    )
)


def input_sha256() -> str | None:
    for method_name in ("retrieve_input_file_sha256", "get_input_file_sha256"):
        method = getattr(ida_nalt, method_name, None)
        if method is None:
            continue
        try:
            value = method()
        except Exception:
            continue
        if isinstance(value, bytes):
            return value.hex()
        if value:
            return str(value)
    return None


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_rows() -> list[dict]:
    document = json.loads(SYMBOL_AUDIT.read_text(encoding="utf-8"))
    symbol_list = json.loads(SYMBOL_LIST.read_text(encoding="utf-8"))
    aliases = {row["ea"]: row for row in symbol_list}
    original = document["original"]
    defined_indices = {row["index"] for row in original["defined_named_symbols"]}
    rows = [
        row
        for row in original["named_symbols"]
        if row["type_name"] == "FUNC"
        and row["index"] in defined_indices
        and row["value"] > 0
        and row["size"] > 0
        and hex(row["value"]) in EXPECTED_MISSING
    ]
    rows.sort(key=lambda row: row["value"])
    if {hex(row["value"]) for row in rows} != set(EXPECTED_MISSING):
        raise RuntimeError("original dynamic-function symbol set changed")
    for row in rows:
        expected = EXPECTED_MISSING[hex(row["value"])]
        if row["size"] != expected["size"] or row["name"] != expected["name"]:
            raise RuntimeError("original dynamic-function row changed")
        source_symbol = aliases.get(row["value"])
        if source_symbol is None or source_symbol.get("kind") != "data":
            raise RuntimeError("missing original source alias record")
        alias = source_symbol.get("alias", "")
        if not alias.startswith("data_"):
            raise RuntimeError("unexpected original source alias prefix")
        row["source_alias"] = alias[len("data_") :]
    return rows


def append_comment(ea: int, name: str, size: int) -> bool:
    comment = (
        "Reviewed original 1.8 ELF dynamic function: "
        + name
        + "; exact dynamic-symbol size=0x"
        + format(size, "x")
        + "; boundary materialized from the offline ELF audit"
    )
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    ida_bytes.set_cmt(ea, comment if not existing else existing + " | " + comment, False)
    return True


def main() -> None:
    ida_auto.auto_wait()
    if input_sha256() not in (None, EXPECTED_BINARY_SHA256):
        raise RuntimeError("IDA input hash does not match the original 1.8 library")
    rows = load_rows()
    failures = []
    plan = []
    comments_added = 0
    renamed = 0
    materialized = 0

    for row in rows:
        ea = int(row["value"])
        end_ea = ea + int(row["size"])
        name = row["name"]
        source_alias = row["source_alias"]
        function_at_start = ida_funcs.get_func(ea)
        function_at_end = ida_funcs.get_func(end_ea - 1)
        existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, source_alias)
        item = {
            "original_ea": row["value"],
            "function_end_expected": hex(end_ea),
            "dynamic_name": name,
            "source_alias": source_alias,
            "current_name": ida_name.get_name(ea),
            "existing_name_ea": (
                hex(existing_ea) if existing_ea != ida_idaapi.BADADDR else None
            ),
            "function_at_start": (
                hex(function_at_start.start_ea) if function_at_start else None
            ),
            "function_at_end": (
                hex(function_at_end.start_ea) if function_at_end else None
            ),
        }
        if function_at_start is not None:
            item["error"] = "address already belongs to an IDA function"
            failures.append(item)
            plan.append(item)
            continue
        if function_at_end is not None:
            item["error"] = "requested end overlaps an IDA function"
            failures.append(item)
            plan.append(item)
            continue
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            item["error"] = "original source alias is already used elsewhere"
            failures.append(item)
            plan.append(item)
            continue

        if APPLY:
            if not ida_funcs.add_func(ea, end_ea):
                item["error"] = "IDA rejected the reviewed function boundary"
                failures.append(item)
                plan.append(item)
                continue
            function_after = ida_funcs.get_func(ea)
            if (
                function_after is None
                or function_after.start_ea != ea
                or function_after.end_ea != end_ea
            ):
                item["actual_function_start"] = (
                    hex(function_after.start_ea) if function_after else None
                )
                item["actual_function_end"] = (
                    hex(function_after.end_ea) if function_after else None
                )
                item["error"] = "IDA did not preserve the requested boundary"
                failures.append(item)
                plan.append(item)
                continue
            materialized += 1
            if ida_name.get_name(ea) != source_alias:
                if not ida_name.set_name(ea, source_alias, ida_name.SN_NOCHECK):
                    item["error"] = "IDA rejected the original source alias"
                    failures.append(item)
                    plan.append(item)
                    continue
                renamed += 1
            if append_comment(ea, name, row["size"]):
                comments_added += 1
            item["actual_name"] = ida_name.get_name(ea)
            item["actual_function_end"] = hex(ida_funcs.get_func(ea).end_ea)
        plan.append(item)

    result = {
        "artifact": "original_dynamic_function_application",
        "network_contacted": False,
        "symbol_audit": str(SYMBOL_AUDIT),
        "symbol_audit_sha256": file_sha256(SYMBOL_AUDIT),
        "symbol_list": str(SYMBOL_LIST),
        "symbol_list_sha256": file_sha256(SYMBOL_LIST),
        "expected_binary_sha256": EXPECTED_BINARY_SHA256,
        "input": ida_nalt.get_input_file_path(),
        "input_sha256": input_sha256(),
        "apply": APPLY,
        "save_path": SAVE_PATH,
        "row_count": len(rows),
        "materialized_count": materialized,
        "renamed_count": renamed,
        "comments_added": comments_added,
        "failure_count": len(failures),
        "failures": failures,
        "plan": plan,
    }
    if failures:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise RuntimeError("original dynamic-function application had failures")

    if APPLY and SAVE_PATH:
        output = Path(SAVE_PATH).expanduser().resolve()
        if output.exists():
            raise RuntimeError("refusing to overwrite an existing original IDA copy")
        if output.suffix != ".i64":
            raise RuntimeError("ORIGINAL_DYNAMIC_FUNCTION_SAVE_PATH must end in .i64")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not ida_loader.save_database(str(output), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the original dynamic-function copy")
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
                    "row_count",
                    "materialized_count",
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
