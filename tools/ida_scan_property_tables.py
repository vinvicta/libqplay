#!/usr/bin/env python3
"""Find encoded native property-table runs in an IDA database.

The client stores many script property tables as 0x30-byte records. This
read-only scanner looks for adjacent records whose first qword points to an
encoded script name and whose getter or setter pointers resolve into IDA
functions. It is intended to produce candidates for manual review, not to
assign aliases automatically.

The output is JSON on standard output. Use ``LIBQPLAY_PROPERTY_MIN_RUN`` to
change the minimum number of adjacent decoded records, which defaults to 3.
"""

from __future__ import annotations

import json
import os
import re

import ida_auto
import ida_bytes
import ida_funcs
import ida_segment


RECORD_SIZE = 0x30
MAX_NAME_BYTES = 96


def decode_script_name(raw: bytes) -> str | None:
    if not raw or len(raw) > MAX_NAME_BYTES:
        return None
    decoded = []
    length = len(raw)
    for index, encoded in enumerate(raw):
        signed_encoded = encoded if encoded < 0x80 else encoded - 0x100
        value = -11 - signed_encoded - length
        sentinel_test = ((value >> 2) & 0x3F) | ((value & 3) << 6)
        if sentinel_test == index:
            signed_encoded = 0
        value = -11 - signed_encoded - length
        decoded.append(((value << 6) - index + ((value >> 2) & 0x3F)) & 0xFF)
    try:
        text = bytes(decoded).decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text or any(ord(char) < 0x20 or ord(char) > 0x7E for char in text):
        return None
    return text


def encoded_name(pointer: int) -> str | None:
    segment = ida_segment.getseg(pointer)
    if segment is None or segment.perm & ida_segment.SEGPERM_EXEC:
        return None
    raw = ida_bytes.get_bytes(pointer, MAX_NAME_BYTES) or b""
    end = raw.find(b"\0")
    if end < 0:
        return None
    name = decode_script_name(raw[:end])
    if name is None or not re.fullmatch(r"[A-Za-z0-9_$:.]+", name):
        return None
    return name


def function_value(value: int) -> bool:
    return value == 0 or ida_funcs.get_func(value) is not None


def record(ea: int) -> dict | None:
    name_pointer = ida_bytes.get_qword(ea)
    name = encoded_name(name_pointer)
    getter = ida_bytes.get_qword(ea + 0x10)
    setter = ida_bytes.get_qword(ea + 0x18)
    if name is None or not function_value(getter) or not function_value(setter):
        return None
    return {
        "record_ea": "0x%x" % ea,
        "name_pointer": "0x%x" % name_pointer,
        "name_decoded": name,
        "getter_ea": "0x%x" % getter,
        "getter_name": ida_funcs.get_func_name(getter) if getter else None,
        "setter_ea": "0x%x" % setter,
        "setter_name": ida_funcs.get_func_name(setter) if setter else None,
    }


def scan_segment(start: int, end: int, minimum_run: int) -> list[dict]:
    candidates = []
    for ea in range((start + 7) & ~7, end - RECORD_SIZE + 1, 8):
        first = record(ea)
        if first is None:
            continue
        if ea >= start + RECORD_SIZE and record(ea - RECORD_SIZE) is not None:
            continue
        run = [first]
        next_ea = ea + RECORD_SIZE
        while next_ea + RECORD_SIZE <= end:
            row = record(next_ea)
            if row is None:
                break
            run.append(row)
            next_ea += RECORD_SIZE
        if len(run) >= minimum_run:
            candidates.append(run)
    return candidates


def main() -> None:
    ida_auto.auto_wait()
    minimum_run = int(os.environ.get("LIBQPLAY_PROPERTY_MIN_RUN", "3"), 0)
    tables = []
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if segment is None:
            continue
        for run in scan_segment(segment.start_ea, segment.end_ea, minimum_run):
            tables.append(
                {
                    "segment": segment.name,
                    "base": run[0]["record_ea"],
                    "record_count": len(run),
                    "default_callback_count": sum(
                        name.startswith("sub_")
                        for row in run
                        for name in (row["getter_name"], row["setter_name"])
                        if name is not None
                    ),
                    "properties": run,
                }
            )
    tables.sort(key=lambda item: int(item["base"], 16))
    print(json.dumps(tables, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
