#!/usr/bin/env python3
"""Record the exact zlib 1.2.5 ``inflate_fast`` match in the IDA inventory.

The residual routine at 0x28a2f4 was initially grouped with the neighboring
JPEG functions by a coarse address profile.  Its Huffman decode loop and
error strings instead match zlib's ``inflate_fast`` implementation.  This
small separate artifact keeps that correction visible and avoids attributing
the routine to the wrong dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT.parent / "analysis" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "ida_zlib_source_matches_20260902.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SOURCE_URL = "https://github.com/madler/zlib/blob/v1.2.5/inffast.c#L67"
SOURCE_ARCHIVE_URL = "https://github.com/madler/zlib/archive/refs/tags/v1.2.5.tar.gz"
SOURCE_ARCHIVE_SHA256 = "0e3d7cd92cad75a7f5f25d8e64744fbb8f71008d63fa8417e8d6c7c391487155"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_report(inventory_path: Path, require_applied: bool = False) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")
    rows = {int(item["ea"]): item for item in document}
    current = rows.get(0x28A2F4)
    if current is None:
        raise ValueError("zlib source match address is absent from inventory: 0x28a2f4")
    alias = "zlib_inflate_fast"
    current_name = current.get("name")
    is_alias = current_name == alias
    is_default = bool(current.get("is_default_sub")) or str(current_name).startswith(
        ("sub_", "nullsub_")
    )
    if require_applied and not is_alias:
        raise ValueError(
            f"zlib source match is not applied at 0x28a2f4: expected {alias}, got {current_name}"
        )
    if not is_alias and not is_default:
        raise ValueError(f"unexpected pre-existing name at 0x28a2f4: {current_name}")
    match = {
        "address": "0x28a2f4",
        "confidence": "exact",
        "current_ida_name": current_name,
        "ida_name": alias,
        "ida_name_origin": current.get("name_origin") if is_alias else None,
        "original_profile_category": "zlib_static_internal",
        "role": "zlib 1.2.5 fast DEFLATE decoder path",
        "size": int(current.get("size", 0)),
        "source_file": "inffast.c",
        "source_line": 67,
        "source_url": SOURCE_URL,
        "upstream_name": "inflate_fast",
        "xrefs_to": current.get("xrefs_to"),
        "evidence": (
            "The decompiled loop performs literal, length, and distance Huffman "
            "decoding, copies matched bytes, and contains the zlib invalid "
            "literal/length, invalid distance, and too-far-back diagnostics."
        ),
    }
    return {
        "artifact": "ida_zlib_source_matches_20260902",
        "schema": "libqplay.ida-zlib-source-match.v1",
        "tool": "tools/generate_zlib_source_matches.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": "exact source-role match for the corrected residual zlib routine in original ARM64 libqplay.so",
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "source": {
            "project": "zlib",
            "version": "1.2.5",
            "archive_url": SOURCE_ARCHIVE_URL,
            "archive_sha256": SOURCE_ARCHIVE_SHA256,
            "source_file": "inffast.c",
            "source_line": 67,
            "acquisition_note": (
                "The tagged source archive was downloaded once into a local "
                "pinned checkout for comparison. This report reads only the "
                "local IDA inventory."
            ),
        },
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "network_contacted": False,
        "match_count": 1,
        "applied_name_count": 1 if is_alias else 0,
        "matches": [match],
        "method": [
            "Use the zlib 1.2.5 source line as the role locator.",
            "Compare the ARM64 decompiler loop and diagnostic strings with inflate_fast.",
            "Keep the corrected family classification separate from the neighboring IJG libjpeg residuals.",
        ],
        "not_claimed": [
            "That every zlib source helper has a standalone machine function.",
            "That the source match proves all zlib inputs are bounded by the application wrapper.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", nargs="?", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--require-applied", action="store_true")
    args = parser.parse_args()
    inventory = args.inventory if args.inventory.is_absolute() else Path.cwd() / args.inventory
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not inventory.is_file():
        parser.error(f"IDA inventory does not exist: {inventory}")
    report = build_report(inventory, require_applied=args.require_applied)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": output.as_posix(),
                "match_count": report["match_count"],
                "applied_name_count": report["applied_name_count"],
                "inventory_rows": report["inventory"]["row_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
