#!/usr/bin/env python3
"""Find exact function-byte matches between the two local ARM64 builds.

The original 1.8 library has many IDA-created ``sub_`` functions in bundled
third-party code. The supplied Spectron library is a different build, so its
addresses are not reusable. It can still provide a source name when a
Spectron dynamic symbol has the same function size and exact bytes as an
original default function. This tool records only byte-identical, unambiguous
matches. It never loads either library or contacts a network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct


ELF64_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_SECTION = struct.Struct("<IIQQQQIIQQ")
ELF64_SYMBOL = struct.Struct("<IBBHQQ")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_c_string(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")


def parse_elf(path: Path) -> tuple[bytes, list[dict], list[dict]]:
    data = path.read_bytes()
    header = ELF64_HEADER.unpack_from(data, 0)
    if header[0][:4] != b"\x7fELF" or header[0][4] != 2:
        raise ValueError(f"expected an ELF64 file: {path}")
    shoff, shentsize, shnum, shstrndx = header[6], header[11], header[12], header[13]
    raw_sections = [
        ELF64_SECTION.unpack_from(data, shoff + index * shentsize)
        for index in range(shnum)
    ]
    shstr = raw_sections[shstrndx]
    shstr_blob = data[shstr[4] : shstr[4] + shstr[5]]
    sections = []
    for index, item in enumerate(raw_sections):
        sections.append(
            {
                "index": index,
                "name": read_c_string(shstr_blob, item[0]),
                "type": item[1],
                "address": item[3],
                "offset": item[4],
                "size": item[5],
                "link": item[6],
                "entry_size": item[9],
            }
        )

    by_name = {section["name"]: section for section in sections}
    dynsym = by_name.get(".dynsym")
    dynstr = by_name.get(".dynstr")
    if dynsym is None or dynstr is None:
        raise ValueError(f"missing dynamic symbol sections: {path}")
    dynstr_blob = data[dynstr["offset"] : dynstr["offset"] + dynstr["size"]]
    entry_size = dynsym["entry_size"] or ELF64_SYMBOL.size
    symbols = []
    for index in range(dynsym["size"] // entry_size):
        fields = ELF64_SYMBOL.unpack_from(data, dynsym["offset"] + index * entry_size)
        symbols.append(
            {
                "index": index,
                "name": read_c_string(dynstr_blob, fields[0]),
                "value": fields[4],
                "size": fields[5],
                "type": fields[1] & 0x0F,
                "section_index": fields[3],
            }
        )
    return data, sections, symbols


def va_to_file_offset(sections: list[dict], value: int) -> int | None:
    for section in sections:
        start = section["address"]
        end = start + section["size"]
        if start <= value < end:
            return section["offset"] + value - start
    return None


def function_bytes(data: bytes, sections: list[dict], value: int, size: int) -> bytes | None:
    offset = va_to_file_offset(sections, value)
    if offset is None or size <= 0 or offset + size > len(data):
        return None
    return data[offset : offset + size]


def spectron_named_functions(data: bytes, sections: list[dict], symbols: list[dict]) -> list[dict]:
    text_index = next(
        (section["index"] for section in sections if section["name"] == ".text"),
        None,
    )
    if text_index is None:
        raise ValueError("missing .text section")
    result = []
    for symbol in symbols:
        if symbol["type"] != 2 or symbol["section_index"] != text_index:
            continue
        if not symbol["name"] or symbol["size"] == 0:
            continue
        body = function_bytes(data, sections, symbol["value"], symbol["size"])
        if body is None:
            continue
        result.append(
            {
                "name": symbol["name"],
                "va": "0x%x" % symbol["value"],
                "size": symbol["size"],
                "sha256": sha256(body),
            }
        )
    return result


def original_default_functions(inventory_path: Path) -> list[dict]:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    result = []
    for item in inventory:
        if not item.get("is_default_sub") or item.get("segment") != ".text":
            continue
        result.append(
            {
                "current_ida_name": item["name"],
                "va": "0x%x" % item["ea"],
                "ea": item["ea"],
                "size": item["size"],
            }
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--spectron", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--min-size",
        type=int,
        default=12,
        help="ignore shorter functions because tiny byte sequences are rarely unique",
    )
    args = parser.parse_args()

    original_data, original_sections, _ = parse_elf(args.original)
    spectron_data, spectron_sections, spectron_symbols = parse_elf(args.spectron)
    spectron_functions = spectron_named_functions(
        spectron_data, spectron_sections, spectron_symbols
    )
    by_signature: dict[tuple[int, str], list[dict]] = {}
    for function in spectron_functions:
        by_signature.setdefault((function["size"], function["sha256"]), []).append(function)

    candidates = []
    considered = 0
    for original in original_default_functions(args.inventory):
        if original["size"] < args.min_size:
            continue
        body = function_bytes(
            original_data,
            original_sections,
            original["ea"],
            original["size"],
        )
        if body is None:
            continue
        considered += 1
        matches = by_signature.get((original["size"], sha256(body)), [])
        if len(matches) != 1:
            continue
        match = matches[0]
        candidates.append(
            {
                "current_ida_name": original["current_ida_name"],
                "original_va": original["va"],
                "size": original["size"],
                "spectron_name": match["name"],
                "spectron_va": match["va"],
                "sha256": match["sha256"],
            }
        )

    result = {
        "artifact": "spectron_exact_function_signature_matches",
        "scope": "offline exact byte comparison of local ARM64 ELF files",
        "network_contacted": False,
        "inputs": {
            "original": str(args.original),
            "original_sha256": sha256(original_data),
            "spectron": str(args.spectron),
            "spectron_sha256": sha256(spectron_data),
            "inventory": str(args.inventory),
            "minimum_function_size": args.min_size,
        },
        "summary": {
            "original_default_text_functions_considered": considered,
            "spectron_named_text_functions": len(spectron_functions),
            "unique_exact_matches": len(candidates),
        },
        "matches": candidates,
        "interpretation": [
            "The Spectron address is not a patch address for the original build.",
            "A match is useful as a source-name hint only when the exact bytes and size are unique in the Spectron dynamic symbol table.",
            "No match is treated as proof that the two builds share a complete source tree or ABI.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **result["summary"]}))


if __name__ == "__main__":
    main()
