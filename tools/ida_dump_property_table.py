#!/usr/bin/env python3
"""Dump encoded native property records from an IDA database.

The Graal native registration tables use 0x30-byte records. The first field
is an encoded script property name, the getter and setter callbacks are at
offsets 0x10 and 0x18, and the remaining fields carry shared type metadata.
This helper is read-only and prints both the IDA view and the raw bytes so a
table can be compared across builds even when IDA does not recognize the
encoded labels as strings.

Set ``LIBQPLAY_PROPERTY_TABLE_BASE`` and ``LIBQPLAY_PROPERTY_COUNT`` to select
the table. ``LIBQPLAY_PROPERTY_RECORD_SIZE`` defaults to 0x30.
"""

from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name


def address(name: str, default: int | None = None) -> int:
    text = os.environ.get(name)
    if not text:
        if default is None:
            raise ValueError("missing %s" % name)
        return default
    return int(text, 0)


def encoded_bytes(ea: int, limit: int = 128) -> bytes:
    data = ida_bytes.get_bytes(ea, limit) or b""
    end = data.find(b"\0")
    return data if end < 0 else data[:end]


def decode_script_name(raw: bytes) -> str | None:
    if not raw:
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
        return bytes(decoded).decode("ascii")
    except UnicodeDecodeError:
        return None


def pointer_row(ea: int) -> dict:
    value = ida_bytes.get_qword(ea)
    function = ida_funcs.get_func(value)
    return {
        "ea": "0x%x" % ea,
        "value": "0x%x" % value,
        "name": ida_name.get_name(value),
        "function_start": None if function is None else "0x%x" % function.start_ea,
        "function_end": None if function is None else "0x%x" % function.end_ea,
    }


def main() -> None:
    ida_auto.auto_wait()
    base = address("LIBQPLAY_PROPERTY_TABLE_BASE")
    count = address("LIBQPLAY_PROPERTY_COUNT")
    record_size = address("LIBQPLAY_PROPERTY_RECORD_SIZE", 0x30)
    raw_limit = address("LIBQPLAY_PROPERTY_RAW_LIMIT", 128)
    compact = os.environ.get("LIBQPLAY_PROPERTY_COMPACT") == "1"
    rows = []
    for index in range(count):
        record = base + index * record_size
        name_pointer = ida_bytes.get_qword(record)
        raw = encoded_bytes(name_pointer, raw_limit)
        getter = pointer_row(record + 0x10)
        setter = pointer_row(record + 0x18)
        if compact:
            rows.append(
                {
                    "index": index,
                    "record_ea": "0x%x" % record,
                    "name_decoded": decode_script_name(raw),
                    "getter_ea": getter["value"],
                    "getter_name": getter["name"],
                    "setter_ea": setter["value"],
                    "setter_name": setter["name"],
                }
            )
            continue
        rows.append(
            {
                "index": index,
                "record_ea": "0x%x" % record,
                "name_pointer": "0x%x" % name_pointer,
                "name_ida": ida_name.get_name(name_pointer),
                "name_raw_hex": raw.hex(),
                "name_decoded": decode_script_name(raw),
                "flags": "0x%x" % ida_bytes.get_qword(record + 0x8),
                "getter": getter,
                "setter": setter,
                "common": pointer_row(record + 0x20),
                "trailing": "0x%x" % ida_bytes.get_qword(record + 0x28),
            }
        )
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
