#!/usr/bin/env python3
"""Find exact byte matches between the translated 1.8 IDA inventory and 2.2.

This is a conservative bridge for a future 2.2 IDA database. It compares the
exact function bytes at matching sizes, independent of symbol names. Unique
matches are exported as searchable candidates. Repeated byte sequences are
kept as ambiguous metadata and are not assigned a translated name.

The private inputs are never copied into the repository. The script does not
execute either library or open a network connection.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path

from generate_cross_version_symbol_overlap import (
    DEFAULT_ONE_EIGHT,
    DEFAULT_TWO_TWO,
    ROOT,
    classify,
    file_slice,
    inspect,
)


DEFAULT_ARTIFACT = ROOT / "artifacts" / "cross_version_exact_byte_match_review_20260904.json"
DEFAULT_CSV = ROOT / "symbols" / "libqplay_2.2_exact_byte_unique_matches.csv"
INVENTORY = ROOT / "symbols" / "libqplay.function_inventory.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_bytes(info: dict[str, object], address: int, size: int) -> str:
    return hashlib.sha256(file_slice(info, address, size)).hexdigest()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.parent.resolve()))
    except ValueError:
        return "<private-input>/" + path.name


def load_one_eight_inventory() -> list[dict[str, object]]:
    rows = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("the 1.8 function inventory must be a JSON list")
    return [
        row
        for row in rows
        if row.get("segment") == ".text" and int(row.get("size", 0)) > 0
    ]


def candidate_key(info: dict[str, object], row: dict[str, object], address_key: str) -> tuple[int, str]:
    address = int(row[address_key])
    size = int(row["size"])
    return size, digest_bytes(info, address, size)


def build_matches(one_eight: dict[str, object], two_two: dict[str, object]) -> dict[str, object]:
    inventory = load_one_eight_inventory()
    by_key: dict[tuple[int, str], list[dict[str, object]]] = collections.defaultdict(list)
    for row in inventory:
        key = candidate_key(one_eight, row, "ea")
        by_key[key].append(row)

    matched = []
    unique = []
    ambiguous = []
    cardinality = collections.Counter()
    family_counts: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)

    for name, symbol in sorted(two_two["symbols"].items()):
        target = {"name": name, "address": symbol["address"], "size": symbol["size"]}
        key = candidate_key(two_two, target, "address")
        hits = by_key.get(key, [])
        if not hits:
            continue
        byte_sha256 = key[1]
        family = classify(name)
        cardinality[len(hits)] += 1
        family_counts[family]["matched"] += 1
        if len(hits) == 1:
            old = hits[0]
            row = {
                "2.2_name": name,
                "2.2_address": f"0x{int(symbol['address']):x}",
                "size": int(symbol["size"]),
                "byte_sha256": byte_sha256,
                "family": family,
                "1.8_ida_name": old["name"],
                "1.8_raw_symbol": old.get("original_symbol"),
                "1.8_demangled_symbol": old.get("demangled_symbol"),
                "1.8_address": f"0x{int(old['ea']):x}",
                "address_delta_2.2_minus_1.8": f"0x{int(symbol['address']) - int(old['ea']):x}",
                "1.8_name_origin": old.get("name_origin"),
                "1.8_source_kind": old.get("source_kind"),
            }
            unique.append(row)
            family_counts[family]["unique"] += 1
        else:
            ambiguous.append(
                {
                    "2.2_name": name,
                    "2.2_address": f"0x{int(symbol['address']):x}",
                    "size": int(symbol["size"]),
                    "byte_sha256": byte_sha256,
                    "family": family,
                    "1.8_candidate_count": len(hits),
                }
            )
            family_counts[family]["ambiguous"] += 1
        matched.append(name)

    return {
        "inventory_function_count": len(inventory),
        "two_two_function_count": len(two_two["symbols"]),
        "matched_2.2_function_count": len(matched),
        "unique_match_count": len(unique),
        "ambiguous_match_count": len(ambiguous),
        "unmatched_2.2_function_count": len(two_two["symbols"]) - len(matched),
        "exact_byte_pair_count": sum(count * number for count, number in cardinality.items()),
        "candidate_cardinality": {str(k): v for k, v in sorted(cardinality.items())},
        "family_counts": {
            family: dict(sorted(counts.items()))
            for family, counts in sorted(family_counts.items())
        },
        "unique_candidates": unique,
        "ambiguous_targets": ambiguous,
    }


def write_csv(rows: list[dict[str, object]], output: Path) -> None:
    fields = [
        "2.2_name",
        "2.2_address",
        "size",
        "byte_sha256",
        "family",
        "1.8_ida_name",
        "1.8_raw_symbol",
        "1.8_demangled_symbol",
        "1.8_address",
        "address_delta_2.2_minus_1.8",
        "1.8_name_origin",
        "1.8_source_kind",
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_report(
    one_eight_path: Path,
    two_two_path: Path,
    matches: dict[str, object],
    csv_path: Path,
) -> dict[str, object]:
    one_eight = inspect(one_eight_path)
    two_two = inspect(two_two_path)
    try:
        csv_display = str(csv_path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        csv_display = "<external-output>/" + csv_path.name
    return {
        "schema": "libqplay.cross-version-exact-byte-match-review.v1",
        "artifact": "cross_version_exact_byte_match_review_20260904",
        "analysis_date": "2026-09-04",
        "inputs": {
            "1.8_arm64_libqplay": {
                "path": display_path(one_eight_path),
                "sha256": one_eight["sha256"],
                "size": one_eight["size"],
                "text": one_eight["text"],
                "inventory": "symbols/libqplay.function_inventory.json",
                "inventory_sha256": sha256_file(INVENTORY),
            },
            "2.2_arm64_libqplay": {
                "path": display_path(two_two_path),
                "sha256": two_two["sha256"],
                "size": two_two["size"],
                "text": two_two["text"],
                "symbol_source": "readelf --dyn-syms --wide",
                "unverified_input": True,
            },
        },
        "method": {
            "matching_key": "Exact SHA-256 of the function byte range, paired with exact function size",
            "1.8_candidates": "Nonzero-size .text functions from the translated IDA inventory",
            "2.2_targets": "Defined FUNC entries retained in the comparison library dynsym table",
            "unique_policy": "Only one 1.8 candidate receives a searchable translation candidate",
            "ambiguous_policy": "Repeated byte sequences are reported with their candidate count and remain unnamed",
            "limitations": "Exact bytes are strong static evidence but still require caller and data-reference review in a 2.2 IDA database.",
        },
        "native_executed": False,
        "network_contacted": False,
        "raw_data_policy": "APK and native files remain outside the repository; the report contains hashes and compact symbol metadata only.",
        "csv": csv_display,
        "results": matches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--one-eight", type=Path, default=DEFAULT_ONE_EIGHT)
    parser.add_argument("--two-two", type=Path, default=DEFAULT_TWO_TWO)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    args = parser.parse_args()

    one_eight_path = args.one_eight.resolve()
    two_two_path = args.two_two.resolve()
    if not one_eight_path.is_file():
        raise SystemExit(f"missing 1.8 input: {one_eight_path}")
    if not two_two_path.is_file():
        raise SystemExit(f"missing 2.2 input: {two_two_path}")
    if not INVENTORY.is_file():
        raise SystemExit(f"missing translated inventory: {INVENTORY}")

    one_eight = inspect(one_eight_path)
    two_two = inspect(two_two_path)
    matches = build_matches(one_eight, two_two)
    csv_path = args.csv if args.csv.is_absolute() else ROOT / args.csv
    artifact_path = args.artifact if args.artifact.is_absolute() else ROOT / args.artifact
    write_csv(matches["unique_candidates"], csv_path)
    report = build_report(one_eight_path, two_two_path, matches, csv_path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "ambiguous_match_count": matches["ambiguous_match_count"],
                "artifact": str(artifact_path),
                "matched_2.2_function_count": matches["matched_2.2_function_count"],
                "unique_match_count": matches["unique_match_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
