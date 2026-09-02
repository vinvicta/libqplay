#!/usr/bin/env python3
"""Summarize the remaining unnamed functions in a translated IDA inventory.

The translated inventory is normally exported from a private IDA database.
This report records addresses, sizes, xref counts, and coarse address buckets
without publishing a second full function inventory. It does not assign
speculative source names and never opens a network connection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT.parent / "analysis" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "ida_final_residual_audit_20260901.json"
DEFAULT_PROFILE = ROOT / "artifacts" / "ida_residual_profile.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def address_bucket(ea: int) -> str:
    return f"0x{ea & ~0xFFFF:05x}-0x{(ea & ~0xFFFF) + 0xFFFF:05x}"


def load_residual_classification(profile_path: Path, default_rows: list[dict]) -> dict | None:
    if not profile_path.is_file():
        return None
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile_rows = profile.get("residual_default_sub_functions")
    if not isinstance(profile_rows, list):
        return None
    inventory_eas = {int(row["ea"]) for row in default_rows}
    profile_eas = {int(row["ea"], 16) for row in profile_rows}
    if inventory_eas != profile_eas:
        return None
    return {
        "profile_path": profile_path.as_posix(),
        "profile_sha256": sha256_file(profile_path),
        "categories": profile.get("category_summary", []),
    }


def build_report(inventory_path: Path, profile_path: Path | None = None) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")

    default_rows = [row for row in document if row.get("is_default_sub")]
    default_rows.sort(key=lambda row: int(row["ea"]))
    residuals = [
        {
            "ea": f"0x{int(row['ea']):x}",
            "end_ea": f"0x{int(row['ea']) + int(row.get('size', 0)):x}",
            "size": int(row.get("size", 0)),
            "segment": row.get("segment"),
            "xrefs_to": row.get("xrefs_to"),
        }
        for row in default_rows
    ]
    buckets = Counter(address_bucket(int(row["ea"])) for row in default_rows)
    segments = Counter(row.get("segment") or "<unknown>" for row in default_rows)
    top_xrefs = sorted(
        (
            row for row in default_rows
            if isinstance(row.get("xrefs_to"), int) and row["xrefs_to"] > 0
        ),
        key=lambda row: (-row["xrefs_to"], int(row["ea"])),
    )[:40]
    classification = (
        load_residual_classification(profile_path, default_rows)
        if profile_path is not None
        else None
    )

    return {
        "schema": "libqplay.ida-final-residual-audit.v1",
        "tool": "tools/generate_final_residual_audit.py",
        "tool_version": 1,
        "analysis_date": "2026-09-01",
        "analysis_scope": "original ARM64 libqplay.so translated IDA inventory",
        "network_contacted": False,
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
            "elf_symbol_backed_functions": sum(row.get("name_origin") == "elf_symbol" for row in document),
            "named_non_elf_functions": sum(row.get("name_origin") == "ida_named_non_elf" for row in document),
            "default_sub_functions": len(default_rows),
            "segment_counts": dict(sorted(segments.items())),
            "address_bucket_counts": dict(sorted(buckets.items())),
        },
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "residual_classification": classification,
        "residual_functions": residuals,
        "most_referenced_residuals": [
            {
                "ea": f"0x{int(row['ea']):x}",
                "name": row.get("name"),
                "xrefs_to": row["xrefs_to"],
                "size": int(row.get("size", 0)),
            }
            for row in top_xrefs
        ],
        "interpretation": [
            "The 8601 translated aliases cover the names present in the retained ELF symbol export, including functions, thunks, and data.",
            "The residual list contains IDA-created code functions with no preserved source symbol in this APK.",
            "Addresses and behavior can be documented without inventing source names; a new alias should be added only when its role has evidence.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", nargs="?", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    inventory = args.inventory if args.inventory.is_absolute() else Path.cwd() / args.inventory
    profile = args.profile if args.profile.is_absolute() else Path.cwd() / args.profile
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not inventory.is_file():
        parser.error(f"IDA inventory does not exist: {inventory}")
    report = build_report(inventory, profile)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "binary_sha256": report["binary_sha256"],
        "inventory_rows": report["inventory"]["row_count"],
        "residual_count": len(report["residual_functions"]),
        "output": output.as_posix(),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
