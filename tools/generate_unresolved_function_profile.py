#!/usr/bin/env python3
"""Profile IDA-created default functions that have no source symbol.

The alias import already covers every translated name exposed by the ELF. This helper
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


DEFAULT_BINARY = str(
    Path(__file__).resolve().parents[2]
    / "GraalOnline+Classic_1.8_APKPure"
    / "lib/arm64-v8a/libqplay.so"
)
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


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def branch_target(pc: int, instruction: int) -> int:
    return pc + sign_extend(instruction & 0x03FFFFFF, 26) * 4


def cleanup_wrapper_kind(
    item: dict[str, object], blob: bytes, symbol_names: dict[int, str]
) -> tuple[str, str] | None:
    """Recognize fixed-global compiler cleanup thunks by instruction shape."""

    size = value(item["size"])
    if size not in (12, 16):
        return None
    ea = value(item["ea"])
    words = [
        struct.unpack_from("<I", blob, ea + offset)[0]
        for offset in range(0, size, 4)
    ]
    if (words[0] & 0x9F00001F) != 0x90000000:
        return None
    if any((word & 0xFFC003FF) != 0x91000000 for word in words[1:-1]):
        return None
    if (words[-1] & 0xFC000000) != 0x14000000:
        return None

    target = branch_target(ea + size - 4, words[-1])
    demangled = symbol_names.get(target)
    targets = {
        "TString::clear(void)": (
            "tstring_static_cleanup_wrapper",
            "The function computes a fixed global TString address and tail-calls TString::clear; it is a compiler-generated static cleanup wrapper without an independent source body.",
        ),
        "TStringList::~TStringList()": (
            "tstringlist_static_cleanup_wrapper",
            "The function computes a fixed global TStringList address and tail-calls its destructor; it is a compiler-generated static cleanup wrapper without an independent source body.",
        ),
        "TGraalVar::~TGraalVar()": (
            "tgraalvar_static_cleanup_wrapper",
            "The function computes a fixed global TGraalVar address and tail-calls its destructor; it is a compiler-generated static cleanup wrapper without an independent source body.",
        ),
    }
    return targets.get(demangled)


def region_definitions() -> list[dict[str, object]]:
    """Return static-library gaps and isolated helpers with family evidence.

    These are deliberately broad address regions or explicit helper addresses,
    not guessed function names. Each item describes why its entries are treated
    as likely vendor code.
    """

    return [
        {
            "category": "gpc_static_internal",
            "start": 0x152200,
            "end": 0x153470,
            "family": "General Polygon Clipper",
            "additional_addresses": [0xE01A0],
            "evidence": "The main gap ends at gpc_free_polygon and follows TBitmap::readTGA; 0xe01a0 is called by gpc_tristrip_clip at 0x15504c and formats the gpc malloc failure diagnostic for tristrip node creation.",
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
            "additional_addresses": [0xE02AC],
            "evidence": "The entries sit between exported BZ2 routines and the zlib CRC transition; 0xe02ac is the unrolled byte and halfword comparison helper called by the bundled bzip2 decode loop at 0x27e0e4.",
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
            "additional_addresses": [0xE0454],
            "evidence": "The entries occupy the static gaps in the contiguous JPEG implementation region; 0xe0454 is called by the marker parser at 0x28db2c and 0x28dd94 and decodes a JPEG marker into the library's image state.",
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
        {
            "category": "tomcrypt_des_static_internal",
            "additional_addresses": [0x246B50],
            "family": "LibTomCrypt DES",
            "evidence": "0x246b50 is called by the exported DES and 3DES ECB routines and contains their shared 16-round block transform.",
        },
        {
            "category": "minizip_static_internal",
            "additional_addresses": [0x24840C, 0x249580],
            "family": "minizip",
            "evidence": "0x24840c is shared by the central-directory APIs, while 0x249580 is called by unzOpenCurrentFile3; both are internal minizip helpers between exported APIs.",
        },
        {
            "category": "compiler_branch_island",
            "additional_addresses": [0x1F94FC],
            "family": "compiler-generated branch veneer",
            "evidence": "0x1f94fc is a four-byte unconditional branch to the exact script-table getter TCachedStream_get_minfilecachesize at 0x1fa4fc. It is a compiler-generated veneer, not an independent source function.",
        },
    ]


def classify(
    item: dict[str, object],
    init_fini: set[int],
    blob: bytes,
    symbol_names: dict[int, str],
) -> tuple[str, str]:
    ea = value(item["ea"])
    if ea == 0xD2170:
        return "plt0_resolver", "The first 20-byte .plt entry is the AArch64 resolver slot, not an imported function."
    if ea in init_fini:
        return "init_or_fini_array_entry", "The address is referenced by the ELF .init_array or .fini_array."
    cleanup = cleanup_wrapper_kind(item, blob, symbol_names)
    if cleanup is not None:
        return cleanup
    for region in region_definitions():
        extra_addresses = {
            int(address) for address in region.get("additional_addresses", [])
        }
        in_region = (
            "start" in region
            and "end" in region
            and int(region["start"]) <= ea < int(region["end"])
        )
        if ea in extra_addresses or in_region:
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
    symbol_names = {
        value(item["ea"]): str(item.get("demangled") or "")
        for item in symbols
        if item.get("kind") == "plt_thunk"
    }
    unresolved = [
        dict(item, ea=value(item["ea"]))
        for item in overlay["unresolved_default_sub_functions"]
    ]

    groups: dict[str, dict[str, object]] = {}
    for item in unresolved:
        category, evidence = classify(item, init_fini, blob, symbol_names)
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
        item = {
            "category": region["category"],
            "family": region["family"],
            "evidence": region["evidence"],
        }
        if "start" in region and "end" in region:
            item["start"] = f"0x{int(region['start']):x}"
            item["end_exclusive"] = f"0x{int(region['end']):x}"
        if region.get("additional_addresses"):
            item["additional_addresses"] = [
                f"0x{int(address):x}"
                for address in region["additional_addresses"]
            ]
        regions.append(item)

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
