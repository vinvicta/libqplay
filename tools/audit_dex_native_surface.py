#!/usr/bin/env python3
"""Inventory the original APK's Natives class and direct DEX callsites.

This is a small offline DEX parser used to connect the Java method table with
the native JNI exports. It records access flags, code offsets, and direct
invoke-* references to the native methods in
com.quattroplay.GraalClassic.Natives. It does not execute bytecode, install
the APK, inspect live objects, or contact a network service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEX = ROOT.parent / "GraalOnline+Classic_1.8_APKPure" / "classes.dex"
DEFAULT_OUTPUT = ROOT / "artifacts" / "original_dex_native_surface_review_20260830.json"
NATIVES_DESCRIPTOR = "Lcom/quattroplay/GraalClassic/Natives;"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Dex:
    def __init__(self, data: bytes):
        if len(data) < 0x70 or not data.startswith(b"dex\n"):
            raise ValueError("input is not a DEX file")
        self.data = data
        self.string_count = self.u32(0x38)
        self.string_off = self.u32(0x3C)
        self.type_count = self.u32(0x40)
        self.type_off = self.u32(0x44)
        self.method_count = self.u32(0x58)
        self.method_off = self.u32(0x5C)
        self.class_count = self.u32(0x60)
        self.class_off = self.u32(0x64)
        self._strings: dict[int, str] = {}

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def uleb(self, offset: int) -> tuple[int, int]:
        value = 0
        shift = 0
        while offset < len(self.data):
            byte = self.data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, offset
            shift += 7
            if shift > 35:
                break
        raise ValueError("malformed ULEB128 value")

    def string(self, index: int) -> str:
        if index not in self._strings:
            if index < 0 or index >= self.string_count:
                raise ValueError("DEX string index out of range")
            string_offset = self.u32(self.string_off + index * 4)
            _utf16_length, position = self.uleb(string_offset)
            end = self.data.find(b"\0", position)
            if end < 0:
                raise ValueError("unterminated DEX string")
            self._strings[index] = self.data[position:end].decode("utf-8", "replace")
        return self._strings[index]

    def type(self, index: int) -> str:
        if index < 0 or index >= self.type_count:
            raise ValueError("DEX type index out of range")
        return self.string(self.u32(self.type_off + index * 4))

    def method_ids(self) -> list[dict]:
        methods = []
        for index in range(self.method_count):
            class_index, proto_index, name_index = struct.unpack_from(
                "<HHI", self.data, self.method_off + index * 8
            )
            methods.append(
                {
                    "index": index,
                    "class_index": class_index,
                    "class_descriptor": self.type(class_index),
                    "proto_index": proto_index,
                    "name": self.string(name_index),
                }
            )
        return methods

    def class_defs(self) -> list[dict]:
        result = []
        for index in range(self.class_count):
            fields = struct.unpack_from("<IIIIIIII", self.data, self.class_off + index * 32)
            class_index, access_flags, _super_index, _interfaces, _source, _annotations, class_data, _static = fields
            result.append(
                {
                    "index": index,
                    "class_index": class_index,
                    "descriptor": self.type(class_index),
                    "access_flags": access_flags,
                    "class_data_off": class_data,
                }
            )
        return result

    def class_methods(self, class_data_off: int) -> list[dict]:
        if not class_data_off:
            return []
        position = class_data_off
        counts = []
        for _ in range(4):
            value, position = self.uleb(position)
            counts.append(value)

        for field_count in counts[:2]:
            field_index = 0
            for _ in range(field_count):
                difference, position = self.uleb(position)
                _access_flags, position = self.uleb(position)
                field_index += difference

        methods = []
        for kind, method_count in zip(("direct", "virtual"), counts[2:]):
            method_index = 0
            for _ in range(method_count):
                difference, position = self.uleb(position)
                access_flags, position = self.uleb(position)
                code_off, position = self.uleb(position)
                method_index += difference
                methods.append(
                    {
                        "method_index": method_index,
                        "access_flags": access_flags,
                        "code_off": code_off,
                        "kind": kind,
                    }
                )
        return methods

    def code_units(self, code_off: int) -> tuple[int, ...]:
        if not code_off:
            return ()
        if code_off + 16 > len(self.data):
            return ()
        insns_size = self.u32(code_off + 12)
        start = code_off + 16
        end = start + insns_size * 2
        if end > len(self.data):
            return ()
        return struct.unpack_from("<%dH" % insns_size, self.data, start)


ACCESS_FLAGS = [
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0020, "synchronized"),
    (0x0040, "bridge"),
    (0x0080, "varargs"),
    (0x0100, "native"),
    (0x0200, "interface"),
    (0x0400, "abstract"),
    (0x0800, "strict"),
    (0x1000, "synthetic"),
    (0x10000, "constructor"),
    (0x20000, "declared-synchronized"),
]


def access_names(flags: int) -> list[str]:
    return [name for bit, name in ACCESS_FLAGS if flags & bit]


def instruction_width(opcode: int) -> int:
    """Return the width of ordinary Dalvik instructions in code units."""

    if opcode in {0x13, 0x14, 0x15, 0x16, 0x17, 0x19, 0x1C, 0x1F, 0x20, 0x22, 0x23}:
        return 2
    if opcode in {0x18, 0x1B, 0x24, 0x25, 0x26, 0x2B, 0x2C}:
        return 3
    if 0x2D <= opcode <= 0x3D:
        return 2
    if 0x44 <= opcode <= 0x72:
        return 3 if 0x6E <= opcode <= 0x72 else 2
    if 0x74 <= opcode <= 0x78:
        return 3
    if 0x90 <= opcode <= 0xAF:
        return 2
    if 0xD0 <= opcode <= 0xE2:
        return 2
    return 1


def direct_invokes(dex: Dex, units: tuple[int, ...], wanted: set[int], code_off: int) -> list[dict]:
    calls = []
    position = 0
    while position < len(units):
        first = units[position]
        opcode = first & 0xFF
        if 0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78:
            if position + 1 < len(units):
                method_index = units[position + 1]
                if method_index in wanted:
                    calls.append(
                        {
                            "method_index": method_index,
                            "opcode": "0x%02x" % opcode,
                            "code_unit": position,
                            "code_offset": "0x%x" % (code_off + 16 + position * 2),
                        }
                    )
        width = instruction_width(opcode)
        position += max(1, width)
    return calls


def readable_method(method: dict) -> dict:
    return {
        "index": method["index"],
        "name": method["name"],
        "class_descriptor": method["class_descriptor"],
        "proto_index": method["proto_index"],
    }


def audit(dex_path: Path) -> dict:
    data = dex_path.read_bytes()
    dex = Dex(data)
    all_methods = dex.method_ids()
    method_by_index = {method["index"]: method for method in all_methods}
    classes = dex.class_defs()
    native_class = next(
        item for item in classes if item["descriptor"] == NATIVES_DESCRIPTOR
    )
    class_methods = dex.class_methods(native_class["class_data_off"])
    native_methods = []
    native_method_indices = set()
    method_records = {}
    for entry in class_methods:
        method = method_by_index[entry["method_index"]]
        record = {
            "index": method["index"],
            "name": method["name"],
            "proto_index": method["proto_index"],
            "access_flags": "0x%x" % entry["access_flags"],
            "access": access_names(entry["access_flags"]),
            "code_off": "0x%x" % entry["code_off"],
            "kind": entry["kind"],
            "direct_calls": [],
        }
        method_records[entry["method_index"]] = record
        if entry["access_flags"] & 0x0100:
            native_method_indices.add(entry["method_index"])
            native_methods.append(record)

    for class_item in classes:
        for entry in dex.class_methods(class_item["class_data_off"]):
            if not entry["code_off"]:
                continue
            caller = method_by_index[entry["method_index"]]
            calls = direct_invokes(
                dex,
                dex.code_units(entry["code_off"]),
                native_method_indices,
                entry["code_off"],
            )
            for call in calls:
                target = method_records[call["method_index"]]
                target["direct_calls"].append(
                    {
                        "caller_class": caller["class_descriptor"],
                        "caller_method": caller["name"],
                        "caller_method_index": caller["index"],
                        "opcode": call["opcode"],
                        "code_offset": call["code_offset"],
                    }
                )

    for record in native_methods:
        record["direct_calls"].sort(
            key=lambda item: (item["caller_class"], item["caller_method"], item["code_offset"])
        )

    native_methods.sort(key=lambda item: item["index"])
    direct_call_count = sum(len(item["direct_calls"]) for item in native_methods)
    return {
        "artifact": "original_dex_native_surface_review_20260830",
        "input": {
            "path": str(dex_path),
            "bytes": len(data),
            "sha256": sha256_file(dex_path),
            "magic": data[:8].decode("ascii", "replace"),
        },
        "class": {
            "descriptor": NATIVES_DESCRIPTOR,
            "access_flags": "0x%x" % native_class["access_flags"],
            "access": access_names(native_class["access_flags"]),
            "method_count": len(class_methods),
            "native_method_count": len(native_methods),
        },
        "native_methods": native_methods,
        "summary": {
            "native_method_count": len(native_methods),
            "native_methods_with_direct_dex_callers": sum(
                bool(item["direct_calls"]) for item in native_methods
            ),
            "direct_dex_call_count": direct_call_count,
            "native_methods_without_direct_dex_callers": [
                item["name"] for item in native_methods if not item["direct_calls"]
            ],
        },
        "interpretation": [
            "This inventory follows direct invoke-* method references in DEX code items. Reflection, JNI function pointers, and calls from native code into Java are outside the scan.",
            "The Natives methods marked 0x109 are public static native methods in the original class. Their Java caller list is therefore an in-process callsite inventory, not an exported Android component list.",
            "A native method with no direct DEX caller may still be reachable through reflection or a callback path that is not represented by a direct invoke instruction.",
        ],
        "network_contacted": False,
        "schema": "libqplay.original-dex-native-surface-review.v1",
        "scope": "offline DEX method and direct-call inventory for the original 1.8 APK",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dex", nargs="?", type=Path, default=DEFAULT_DEX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    dex_path = args.dex if args.dex.is_absolute() else Path.cwd() / args.dex
    output_path = args.output if args.output.is_absolute() else ROOT / args.output
    if not dex_path.is_file():
        parser.error("DEX does not exist: %s" % dex_path)
    report = audit(dex_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output_path), **report["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
