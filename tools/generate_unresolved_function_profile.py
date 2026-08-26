#!/usr/bin/env python3
"""Profile IDA-created default functions that have no source symbol.

The symbol import already covers every surviving ELF record. This helper
explains the remaining default ``sub_`` entries without inventing names. It
uses the saved IDA inventory, the translation overlay, the ELF init/fini
arrays, and address ranges bracketed by recognizable third-party symbols.
It never loads or executes the library and performs no network operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


DEFAULT_BINARY = "/home/v/Desktop/graal-decomp/GraalOnline+Classic_1.8_APKPure/lib/arm64-v8a/libqplay.so"
DEFAULT_INVENTORY = "symbols/libqplay.function_inventory.json"
DEFAULT_OVERLAY = "artifacts/symbol_translation_overlay.json"
DEFAULT_SYMBOLS = "symbols/libqplay.symbols.json"
DEFAULT_OUTPUT = "artifacts/unresolved_function_profile.json"

ELF64_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_SECTION = struct.Struct("<IIQQQQIIQQ")


def value(value: int | str) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def read_sections(blob: bytes) -> dict[str, dict[str, int]]:
    header = ELF64_HEADER.unpack_from(blob, 0)
    if header[0][:4] != b"\x7fELF" or header[0][4] != 2:
        raise ValueError("expected an ELF64 input")

    raw = [
        ELF64_SECTION.unpack_from(blob, header[6] + index * header[11])
        for index in range(header[12])
    ]
    string_section = raw[header[13]]
    strings = blob[
        string_section[4] : string_section[4] + string_section[5]
    ]

    def section_name(offset: int) -> str:
        end = strings.find(b"\0", offset)
        if end < 0:
            end = len(strings)
        return strings[offset:end].decode("utf-8", "replace")

    sections = {}
    for item in raw:
        sections[section_name(item[0])] = {
            "address": item[3],
            "offset": item[4],
            "size": item[5],
        }
    return sections


def array_entries(blob: bytes, sections: dict[str, dict[str, int]], name: str) -> list[int]:
    section = sections.get(name)
    if section is None or section["size"] % 8:
        raise ValueError(f"missing or malformed {name} section")
    return [
        struct.unpack_from("<Q", blob, section["offset"] + offset)[0]
        for offset in range(0, section["size"], 8)
    ]


def region_definitions() -> list[dict[str, object]]:
    """Return static-library gaps bracketed by known symbol families.

    These are deliberately broad address regions, not guessed function names.
    Each region describes why its entries are treated as likely vendor code.
    """

    return [
        {
            "category": "gpc_static_internal",
            "start": 0x152200,
            "end": 0x153470,
            "family": "General Polygon Clipper",
            "evidence": "The gap ends at gpc_free_polygon and follows TBitmap::readTGA.",
        },
        {
            "category": "freetype_static_internal",
            "start": 0x250E94,
            "end": 0x274204,
            "family": "FreeType",
            "evidence": "The region is bracketed by the archive I/O helpers and the FreeType to bzip2 transition.",
        },
        {
            "category": "bzip2_static_internal",
            "start": 0x2751C0,
            "end": 0x27FD34,
            "family": "bzip2",
            "evidence": "The entries sit between exported BZ2 routines and the zlib CRC transition.",
        },
        {
            "category": "zlib_static_internal",
            "start": 0x27FD34,
            "end": 0x28A218,
            "family": "zlib",
            "evidence": "The region is bracketed by crc32_combine64 and adler32_combine64.",
        },
        {
            "category": "jpeg_static_internal",
            "start": 0x28A2F4,
            "end": 0x2AF170,
            "family": "libjpeg",
            "evidence": "The entries occupy the static gaps in the contiguous JPEG implementation region.",
        },
        {
            "category": "gif_static_internal",
            "start": 0x2AF788,
            "end": 0x2AF7A4,
            "family": "GIF support",
            "evidence": "The entries sit between FreeLastSavedImage and the YAJL buffer code.",
        },
        {
            "category": "yajl_static_internal",
            "start": 0x2B3BE8,
            "end": 0x2B4380,
            "family": "YAJL",
            "evidence": "The entries are in the final YAJL string-validation gap before CyaSSL RSA code.",
        },
        {
            "category": "cyassl_static_internal",
            "start": 0x2B6384,
            "end": 0x2CB030,
            "family": "CyaSSL and bundled crypto",
            "evidence": "The entries are inside the CyaSSL certificate, crypto, and TLS implementation region.",
        },
    ]


def classify(ea: int, init_fini: set[int]) -> tuple[str, str]:
    if ea == 0xD2170:
        return "plt0_resolver", "The first 20-byte .plt entry is the AArch64 resolver slot, not an imported function."
    if ea in init_fini:
        return "init_or_fini_array_entry", "The address is referenced by the ELF .init_array or .fini_array."
    for region in region_definitions():
        if int(region["start"]) <= ea < int(region["end"]):
            return str(region["category"]), str(region["evidence"])
    return "app_or_engine_unknown", "No source name or safe library-region classification was recovered."


def generate(args: argparse.Namespace) -> dict[str, object]:
    blob = Path(args.binary).read_bytes()
    sections = read_sections(blob)
    init_entries = array_entries(blob, sections, ".init_array")
    fini_entries = array_entries(blob, sections, ".fini_array")
    init_fini = set(init_entries + fini_entries)

    inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    overlay = json.loads(Path(args.overlay).read_text(encoding="utf-8"))
    symbols = json.loads(Path(args.symbols).read_text(encoding="utf-8"))
    unresolved = [
        dict(item, ea=value(item["ea"]))
        for item in overlay["unresolved_default_sub_functions"]
    ]

    groups: dict[str, dict[str, object]] = {}
    for item in unresolved:
        category, evidence = classify(item["ea"], init_fini)
        group = groups.setdefault(
            category,
            {
                "category": category,
                "evidence": evidence,
                "count": 0,
                "total_bytes": 0,
                "entries": [],
            },
        )
        group["count"] = int(group["count"]) + 1
        group["total_bytes"] = int(group["total_bytes"]) + int(item["size"])
        group["entries"].append(
            {
                "ea": f"0x{item['ea']:x}",
                "current_ida_name": item["current_ida_name"],
                "segment": item["segment"],
                "size": item["size"],
            }
        )

    for group in groups.values():
        group["entries"].sort(key=lambda item: value(item["ea"]))

    regions = []
    for region in region_definitions():
        regions.append(
            {
                "category": region["category"],
                "family": region["family"],
                "start": f"0x{int(region['start']):x}",
                "end_exclusive": f"0x{int(region['end']):x}",
                "evidence": region["evidence"],
            }
        )

    result = {
        "purpose": "Classify unresolved IDA default sub_ entries without assigning speculative names.",
        "binary": "private original ARM64 libqplay.so",
        "binary_sha256": sha256(blob),
        "inventory_function_count": len(inventory),
        "translated_elf_symbol_records": sum(
            item.get("name_origin") == "elf_symbol" for item in inventory
        ),
        "default_sub_function_count": len(overlay["default_sub_functions"]),
        "unresolved_default_sub_function_count": len(unresolved),
        "init_array_entries": [f"0x{ea:x}" for ea in init_entries],
        "fini_array_entries": [f"0x{ea:x}" for ea in fini_entries],
        "regions": regions,
        "category_summary": [
            {
                "category": group["category"],
                "count": group["count"],
                "total_bytes": group["total_bytes"],
                "first_ea": group["entries"][0]["ea"],
                "last_ea": group["entries"][-1]["ea"],
                "evidence": group["evidence"],
            }
            for group in sorted(groups.values(), key=lambda item: str(item["category"]))
        ],
        "categories": [
            groups[key]
            for key in sorted(groups)
        ],
        "source_artifacts": {
            "function_inventory": "symbols/libqplay.function_inventory.json",
            "translation_overlay": "artifacts/symbol_translation_overlay.json",
            "symbol_export": "symbols/libqplay.symbols.json",
        },
        "symbol_export_loaded": len(symbols),
        "network_contacted": False,
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--inventory", default=DEFAULT_INVENTORY)
    parser.add_argument("--overlay", default=DEFAULT_OVERLAY)
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = generate(args)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(output),
        "unresolved": result["unresolved_default_sub_function_count"],
        "categories": [
            {"category": item["category"], "count": item["count"]}
            for item in result["category_summary"]
        ],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
