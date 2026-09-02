#!/usr/bin/env python3
"""Record the exact static GIF decoder role at 0x2acb20.

The preserved GIF API symbols identify the surrounding library.  Both
``DGifGetLine`` and ``DGifGetPixel`` call the unnamed function at 0x2acb20,
and its loop is the GIF LZW line decompressor described by giflib's
``DGifDecompressLine`` implementation.  The exact giflib release embedded in
this APK is not claimed here, so the report pins the source role to a
versioned reference checkout rather than assigning a release number.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT.parent / "analysis" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "ida_giflib_source_matches_20260902.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SOURCE_URL = (
    "https://android.googlesource.com/platform/external/giflib/+"
    "/9aef3ea079a57c98a9207f8c3b95a5dc08ee74b5/dgif_lib.c#669"
)
SOURCE_COMMIT = "9aef3ea079a57c98a9207f8c3b95a5dc08ee74b5"


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
    current = rows.get(0x2ACB20)
    if current is None:
        raise ValueError("GIF source match address is absent from inventory: 0x2acb20")

    alias = "giflib_DGifDecompressLine"
    current_name = current.get("name")
    is_alias = current_name == alias
    is_default = bool(current.get("is_default_sub")) or str(current_name).startswith(
        ("sub_", "nullsub_")
    )
    if require_applied and not is_alias:
        raise ValueError(
            f"GIF source match is not applied at 0x2acb20: expected {alias}, got {current_name}"
        )
    if not is_alias and not is_default:
        raise ValueError(f"unexpected pre-existing name at 0x2acb20: {current_name}")

    match = {
        "address": "0x2acb20",
        "confidence": "exact_role",
        "current_ida_name": current_name,
        "ida_name": alias,
        "ida_name_origin": current.get("name_origin") if is_alias else None,
        "original_profile_category": "jpeg_static_internal",
        "corrected_profile_category": "gif_static_internal",
        "role": "giflib static GIF LZW line decompressor",
        "size": int(current.get("size", 0)),
        "source_file": "dgif_lib.c",
        "source_line": 669,
        "source_url": SOURCE_URL,
        "source_commit": SOURCE_COMMIT,
        "upstream_name": "DGifDecompressLine",
        "xrefs_to": current.get("xrefs_to"),
        "evidence": (
            "The function is referenced by the preserved DGifGetLine and "
            "DGifGetPixel symbols. Its 4095-entry prefix/suffix/stack state, "
            "clear and EOF codes, variable-width bit reader, dictionary "
            "growth, and line output match giflib's DGifDecompressLine role."
        ),
    }
    return {
        "artifact": "ida_giflib_source_matches_20260902",
        "schema": "libqplay.ida-giflib-source-match.v1",
        "tool": "tools/generate_giflib_source_matches.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": "exact source-role match for the static GIF decoder helper in original ARM64 libqplay.so",
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "source": {
            "project": "giflib",
            "version": None,
            "commit": SOURCE_COMMIT,
            "source_file": "dgif_lib.c",
            "source_line": 669,
            "source_url": SOURCE_URL,
            "acquisition_note": (
                "The source reference is pinned by commit for role comparison. "
                "The binary's exact giflib release has not been established."
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
            "Use preserved DGifGetLine and DGifGetPixel symbols to identify the callers.",
            "Compare the ARM64 state machine with the pinned giflib DGifDecompressLine role.",
            "Keep the exact giflib release open because the role evidence does not establish a release number.",
        ],
        "not_claimed": [
            "That the APK contains the exact giflib commit used as the source reference.",
            "That every giflib helper has a standalone machine function.",
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
