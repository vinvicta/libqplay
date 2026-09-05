#!/usr/bin/env python3
"""Export every entry retained in the comparison library's ELF dynsym table.

The input is a private native file extracted from an unverified comparison APK.
The output contains symbol metadata and mechanical C++ demangling only. It does
not execute the library, copy the APK into the repository, or open a socket.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from generate_cross_version_symbol_overlap import DEFAULT_TWO_TWO, ROOT, readelf


DEFAULT_CSV = ROOT / "symbols" / "libqplay_2.2_dynamic_symbols.csv"
DEFAULT_SUMMARY = ROOT / "symbols" / "libqplay_2.2_dynamic_symbols.summary.json"
SYMBOL_LINE = re.compile(r"^\s*(\d+):\s+(.+)$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.parent.resolve()))
    except ValueError:
        return "<private-input>/" + path.name


def parse_size(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value, 10)


def parse_dynamic_symbols(path: Path) -> list[dict[str, object]]:
    rows = []
    for line in readelf("--dyn-syms", "--wide", path=path).splitlines():
        if not SYMBOL_LINE.match(line):
            continue
        fields = line.split(None, 7)
        if len(fields) < 7:
            continue
        index = int(fields[0].rstrip(":"))
        value, size, symbol_type, binding, visibility, section = fields[1:7]
        raw_name = fields[7] if len(fields) == 8 else ""
        name, separator, version = raw_name.partition("@")
        rows.append(
            {
                "index": index,
                "name": raw_name,
                "demangle_input": name,
                "version": version if separator else "",
                "address": int(value, 16),
                "size": parse_size(size),
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "section": section,
                "defined": section != "UND",
            }
        )
    rows.sort(key=lambda row: int(row["index"]))
    return rows


def demangle(rows: list[dict[str, object]]) -> None:
    executable = shutil.which("c++filt")
    if executable is None:
        raise SystemExit("c++filt is required for the mechanical demangling column")
    inputs = [str(row["demangle_input"]) for row in rows]
    if not any(inputs):
        return
    result = subprocess.run(
        [executable, "-n"],
        input="\n".join(inputs) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    outputs = result.stdout.splitlines()
    if len(outputs) != len(inputs):
        raise RuntimeError(
            "c++filt returned a different number of lines than the dynsym table"
        )
    for row, output in zip(rows, outputs):
        row["demangled_name"] = output


def write_table(rows: list[dict[str, object]], output: Path) -> None:
    fields = [
        "index",
        "name",
        "demangled_name",
        "version",
        "address",
        "size",
        "type",
        "binding",
        "visibility",
        "section",
        "defined",
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            record = dict(row)
            record.pop("demangle_input", None)
            record["address"] = f"0x{int(record['address']):x}"
            writer.writerow(record)


def build_summary(input_path: Path, rows: list[dict[str, object]], csv_path: Path) -> dict:
    counts = collections.Counter(str(row["type"]) for row in rows)
    binding_counts = collections.Counter(str(row["binding"]) for row in rows)
    section_counts = collections.Counter(str(row["section"]) for row in rows)
    named = [row for row in rows if row["name"]]
    defined = [row for row in rows if row["defined"]]
    defined_named = [row for row in defined if row["name"]]
    defined_funcs = [row for row in defined_named if row["type"] == "FUNC"]
    defined_objects = [row for row in defined_named if row["type"] == "OBJECT"]
    try:
        csv_display = str(csv_path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        csv_display = "<external-output>/" + csv_path.name
    return {
        "schema": "libqplay.2-2-dynamic-symbol-table.v1",
        "artifact": "libqplay_2.2_dynamic_symbols",
        "analysis_date": "2026-09-04",
        "scope": "All entries retained in the unverified installed 2.2 ARM64 libqplay.so dynsym table",
        "source": {
            "path": display_path(input_path),
            "sha256": sha256_file(input_path),
            "size": input_path.stat().st_size,
        },
        "symbol_source": "readelf --dyn-syms --wide",
        "demangling": "c++filt -n applied to each name after any ELF symbol-version suffix",
        "entry_count": len(rows),
        "named_entry_count": len(named),
        "defined_entry_count": len(defined),
        "defined_named_entry_count": len(defined_named),
        "defined_function_count": len(defined_funcs),
        "defined_object_count": len(defined_objects),
        "type_counts": dict(sorted(counts.items())),
        "binding_counts": dict(sorted(binding_counts.items())),
        "section_counts": dict(sorted(section_counts.items())),
        "native_executed": False,
        "network_contacted": False,
        "unverified_input": True,
        "raw_data_policy": "The APK, native library, and companion hook library remain outside the repository.",
        "csv": csv_display,
        "limitations": [
            "Demangling is mechanical and does not recover semantic names for obfuscated application symbols.",
            "A dynamic symbol value and size are ELF metadata, not a verified IDA function boundary.",
            "The comparison package is unverified and modified, so this table is not evidence about an official stock 2.2 release.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="?", default=DEFAULT_TWO_TWO)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args()
    input_path = args.input.resolve()
    if not input_path.is_file():
        raise SystemExit(f"missing input: {input_path}")
    csv_path = args.csv if args.csv.is_absolute() else ROOT / args.csv
    summary_path = args.summary if args.summary.is_absolute() else ROOT / args.summary
    rows = parse_dynamic_symbols(input_path)
    demangle(rows)
    write_table(rows, csv_path)
    summary = build_summary(input_path, rows, csv_path)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "csv": str(csv_path),
                "entry_count": len(rows),
                "summary": str(summary_path),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
