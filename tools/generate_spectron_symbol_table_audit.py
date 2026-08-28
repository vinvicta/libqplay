#!/usr/bin/env python3
"""Build an offline dynamic-symbol audit for the 1.8 and Spectron libraries.

The 2.2 library is described as stripped, which is true for its static symbol
table and DWARF data.  It still carries a large ``.dynsym`` table, though.
This report preserves that table and separates exact ELF facts from the
semantic names inferred later in IDA.  It never loads a library or opens a
network connection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from compare_spectron_native import (
    ELF64_HEADER,
    dynamic_symbols,
    section_table,
)


SHN_UNDEF = 0
SHN_ABS = 0xFFF1
STT_NAMES = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
}
BINDING_NAMES = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
    10: "GNU_UNIQUE",
}

FAMILY_PATTERNS = {
    "jni": re.compile(r"^(?:JNI_|Java_)", re.IGNORECASE),
    "cyassl_or_cyaint": re.compile(r"(?:CyaSSL|CyaInt|CyaTLS|TLS|X509|Cert)", re.IGNORECASE),
    "network_or_http": re.compile(
        r"(?:Socket|socket|connect|Connect|HTTP|http|send|Send|recv|Recv|Receive|Host|host|URL|Url)"
    ),
    "readable_game_names": re.compile(
        r"(?:TServer|TClient|TGUI|TGraal|Graal|WebTop|QPlay|Natives|Player|NPC)"
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_elf(path: Path) -> dict:
    data = path.read_bytes()
    header = ELF64_HEADER.unpack_from(data, 0)
    if header[0][:4] != b"\x7fELF" or header[0][4] != 2:
        raise ValueError(f"expected an ELF64 file: {path}")
    sections = section_table(data, header)
    symbols = dynamic_symbols(data, sections)
    return {
        "path": path.name,
        "size": len(data),
        "sha256": sha256(data),
        "machine": header[2],
        "entry_point": header[4],
        "program_header_count": header[10],
        "section_count": header[12],
        "sections": sections,
        "dynamic_symbols": symbols,
    }


def symbol_row(symbol: dict) -> dict:
    row = dict(symbol)
    row["type_name"] = STT_NAMES.get(symbol["type"], f"TYPE_{symbol['type']}")
    row["binding_name"] = BINDING_NAMES.get(
        symbol["binding"], f"BINDING_{symbol['binding']}"
    )
    row["defined"] = symbol["section_index"] != SHN_UNDEF
    row["section_defined"] = symbol["section_index"] not in {SHN_UNDEF, SHN_ABS}
    return row


def table_summary(symbols: list[dict]) -> dict:
    rows = [symbol_row(symbol) for symbol in symbols]
    named = [row for row in rows if row["name"]]
    defined = [row for row in rows if row["defined"]]
    section_defined = [row for row in rows if row["section_defined"]]

    def counts(items: list[dict], field: str, labels: dict) -> dict:
        result = Counter(item[field] for item in items)
        return {
            labels.get(key, f"{field}_{key}"): value
            for key, value in sorted(result.items())
        }

    return {
        "table_entries": len(rows),
        "named_entries": len(named),
        "unique_named_entries": len({row["name"] for row in named}),
        "undefined_entries": sum(not row["defined"] for row in rows),
        "absolute_entries": sum(row["section_index"] == SHN_ABS for row in rows),
        "defined_entries": len(defined),
        "section_defined_entries": len(section_defined),
        "type_counts": counts(rows, "type", STT_NAMES),
        "defined_type_counts": counts(defined, "type", STT_NAMES),
        "section_defined_type_counts": counts(section_defined, "type", STT_NAMES),
        "binding_counts": counts(rows, "binding", BINDING_NAMES),
        "defined_binding_counts": counts(defined, "binding", BINDING_NAMES),
    }


def section_summary(elf: dict) -> dict:
    sections = elf["sections"]
    names = {section["name"] for section in sections}
    expected = {
        ".dynsym",
        ".dynstr",
        ".symtab",
        ".strtab",
        ".debug_info",
        ".debug_line",
        ".debug_abbrev",
        ".debug_str",
        ".debug_ranges",
        ".gnu_debuglink",
    }
    selected = {}
    for name in sorted(expected | {".text", ".rodata"}):
        section = next((item for item in sections if item["name"] == name), None)
        selected[name] = None if section is None else {
            "index": section["index"],
            "address": section["address"],
            "offset": section["offset"],
            "size": section["size"],
            "flags": section["flags"],
            "entry_size": section["entry_size"],
        }
    return {
        "selected": selected,
        "symtab_present": ".symtab" in names,
        "static_string_table_present": ".strtab" in names,
        "debug_sections_present": any(name.startswith(".debug") for name in names),
        "gnu_debuglink_present": ".gnu_debuglink" in names,
    }


def matching_rows(rows: list[dict], pattern: re.Pattern[str]) -> list[dict]:
    return [
        row
        for row in rows
        if row["name"] and row["section_defined"] and pattern.search(row["name"])
    ]


def compact_row(row: dict) -> dict:
    return {
        "index": row["index"],
        "name": row["name"],
        "value": row["value"],
        "size": row["size"],
        "type": row["type"],
        "type_name": row["type_name"],
        "binding": row["binding"],
        "binding_name": row["binding_name"],
        "section_index": row["section_index"],
    }


def inspect(elf: dict) -> dict:
    rows = [symbol_row(symbol) for symbol in elf["dynamic_symbols"]]
    named_rows = [compact_row(row) for row in rows if row["name"]]
    defined_named_rows = [
        compact_row(row) for row in rows if row["name"] and row["defined"]
    ]
    families = {}
    for family, pattern in FAMILY_PATTERNS.items():
        matched = matching_rows(rows, pattern)
        families[family] = {
            "count": len(matched),
            "function_count": sum(row["type"] == 2 for row in matched),
            "names": [row["name"] for row in matched],
        }
    return {
        "input": {
            "path": elf["path"],
            "size": elf["size"],
            "sha256": elf["sha256"],
        },
        "elf": {
            "machine": elf["machine"],
            "entry_point": elf["entry_point"],
            "program_header_count": elf["program_header_count"],
            "section_count": elf["section_count"],
        },
        "sections": section_summary(elf),
        "dynamic_symbol_table": table_summary(elf["dynamic_symbols"]),
        "export_families": families,
        "named_symbols": named_rows,
        "defined_named_symbols": defined_named_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--spectron", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    original_elf = read_elf(args.original)
    spectron_elf = read_elf(args.spectron)
    original_rows = [symbol_row(symbol) for symbol in original_elf["dynamic_symbols"]]
    spectron_rows = [symbol_row(symbol) for symbol in spectron_elf["dynamic_symbols"]]
    original_names = {row["name"] for row in original_rows if row["name"]}
    spectron_names = {row["name"] for row in spectron_rows if row["name"]}
    shared_names = sorted(original_names & spectron_names)

    result = {
        "artifact": "spectron_symbol_table_audit_20260827",
        "analysis": "offline dynamic symbol and section audit",
        "network_contacted": False,
        "interpretation": [
            "Both libraries are ELF64 AArch64 shared objects.",
            "The Spectron build has no .symtab or DWARF sections, so its static source-name and debug metadata were stripped.",
            "The Spectron build retains .dynsym and .dynstr, including 5,782 section-defined FUNC rows in this parser's complete table.",
            "Most Spectron application C++ exports are still obfuscated mangled names. The retained CyaInt and CyaSSL names are useful anchors for the TLS audit, but they do not recover the missing 1.8 source names by themselves.",
            "The complete dynamic rows are preserved below so later IDA work can distinguish an exported target from a reviewed v18_ semantic alias.",
        ],
        "original": inspect(original_elf),
        "spectron": inspect(spectron_elf),
        "exact_name_overlap": {
            "shared_name_count": len(shared_names),
            "shared_names": shared_names,
            "original_unique_named_count": len(original_names),
            "spectron_unique_named_count": len(spectron_names),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "spectron_dynamic_entries": result["spectron"]["dynamic_symbol_table"]["table_entries"],
                "spectron_defined_functions": result["spectron"]["dynamic_symbol_table"]["section_defined_type_counts"].get("FUNC", 0),
                "shared_names": len(shared_names),
            }
        )
    )


if __name__ == "__main__":
    main()
