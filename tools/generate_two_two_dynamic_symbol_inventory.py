#!/usr/bin/env python3
"""Export the retained 2.2 ARM64 dynamic-function name table.

The input is a private native file extracted from an unverified comparison APK.
The output contains only normalized dynamic function names, values, sizes, and
conservative family labels. It does not execute the library or copy the APK
into the repository.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path

from generate_cross_version_symbol_overlap import ROOT, classify, inspect


DEFAULT_INPUT = (
    ROOT.parent
    / "analysis"
    / "GraalOnline+Classic_2.2_installed"
    / "lib"
    / "arm64-v8a"
    / "libqplay.so"
)
DEFAULT_CSV = ROOT / "symbols" / "libqplay_2.2_dynamic_functions.csv"
DEFAULT_SUMMARY = ROOT / "symbols" / "libqplay_2.2_dynamic_functions.summary.json"


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


def write_inventory(info: dict, output: Path) -> tuple[int, dict[str, int]]:
    rows = []
    families: collections.Counter[str] = collections.Counter()
    for name, symbol in info["symbols"].items():
        family = classify(name)
        families[family] += 1
        rows.append(
            {
                "name": name,
                "address": f"0x{int(symbol['address']):x}",
                "size": int(symbol["size"]),
                "family": family,
            }
        )
    rows.sort(key=lambda row: (int(row["address"], 16), row["name"]))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["name", "address", "size", "family"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
    return len(rows), dict(sorted(families.items()))


def build_summary(input_path: Path, info: dict, count: int, families: dict[str, int], csv_path: Path) -> dict:
    text = info["text"]
    try:
        csv_display = str(csv_path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        csv_display = "<external-output>/" + csv_path.name
    return {
        "schema": "libqplay.2-2-dynamic-function-inventory.v1",
        "artifact": "libqplay_2.2_dynamic_functions",
        "analysis_date": "2026-09-04",
        "scope": "Retained defined FUNC entries in the unverified installed 2.2 ARM64 libqplay.so",
        "source": {
            "path": display_path(input_path),
            "sha256": sha256_file(input_path),
            "size": input_path.stat().st_size,
            "text_address": f"0x{int(text['address']):x}",
            "text_file_offset": f"0x{int(text['file_offset']):x}",
            "text_size": int(text["size"]),
        },
        "symbol_source": "readelf --dyn-syms --wide",
        "normalization": "Defined FUNC entries only; symbol-version suffixes are removed",
        "defined_function_count": count,
        "family_counts": families,
        "native_executed": False,
        "network_contacted": False,
        "unverified_input": True,
        "raw_data_policy": "The APK, native library, and companion hook library remain outside the repository.",
        "csv": csv_display,
        "limitations": [
            "This table does not recover stripped local symbols or prove that the comparison package is an official stock 2.2 release.",
            "A dynamic symbol value is an address anchor, not a verified function boundary in a future IDA database.",
            "Family labels are name-based triage buckets and are not independent source attribution.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="?", default=DEFAULT_INPUT)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args()
    input_path = args.input.resolve()
    if not input_path.is_file():
        raise SystemExit(f"missing input: {input_path}")
    csv_path = args.csv if args.csv.is_absolute() else ROOT / args.csv
    summary_path = args.summary if args.summary.is_absolute() else ROOT / args.summary
    info = inspect(input_path)
    count, families = write_inventory(info, csv_path)
    summary = build_summary(input_path, info, count, families, csv_path)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"csv": str(csv_path), "summary": str(summary_path), "defined_function_count": count}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
