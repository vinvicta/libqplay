#!/usr/bin/env python3
"""Record exact FreeType 2.3.6 source matches in the current IDA inventory.

The address and name checks prevent this artifact from silently describing a
different binary or a rename that was not actually applied. The generator
only reads local JSON files and does not contact a network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT.parent / "analysis" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "ida_freetype_source_matches_20260901.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8"
SOURCE_REPOSITORY = "https://github.com/freetype/freetype2"
SOURCE_TAG = "VER-2-3-6"
SOURCE_COMMIT = "6174e17cf7cb3eef826d95c96757dbb0feea7bdb"


MATCHES = [
    {
        "address": "0x250e94",
        "upstream_name": "destroy_size",
        "source_file": "src/base/ftobjs.c",
        "source_line": 774,
        "evidence": "The generic finalizer, driver done_size callback, internal allocation free, and size free occur in the same order.",
    },
    {
        "address": "0x25e320",
        "upstream_name": "tt_get_kerning",
        "source_file": "src/truetype/ttdriver.c",
        "source_line": 106,
        "evidence": "The output vector is zeroed and the SFNT service supplies the horizontal kerning value when available.",
    },
    {
        "address": "0x25e35c",
        "upstream_name": "tt_face_get_location",
        "source_file": "src/truetype/ttpload.c",
        "source_line": 119,
        "evidence": "The loca table short and long offset paths, bounds checks, and entry-size handling match exactly.",
    },
    {
        "address": "0x25e4e4",
        "upstream_name": "tt_size_init",
        "source_file": "src/truetype/ttobjs.c",
        "source_line": 727,
        "evidence": "The bytecode and CVT state is cleared and the strike index is initialized to 0xffffffff as in the source.",
    },
    {
        "address": "0x25e504",
        "upstream_name": "TT_MulFix14",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1139,
        "evidence": "The high and low half multiply, 0x2000 rounding, 14-bit shift, and sign restoration are identical.",
    },
    {
        "address": "0x25e580",
        "upstream_name": "Direct_Move_X",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1634,
        "evidence": "The x-axis freedom-vector move and touch-X tag update match the interpreter callback.",
    },
    {
        "address": "0x25e5b0",
        "upstream_name": "Direct_Move_Y",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1646,
        "evidence": "The y-axis freedom-vector move and touch-Y tag update match the interpreter callback.",
    },
    {
        "address": "0x25e5e4",
        "upstream_name": "Direct_Move_Orig_X",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1668,
        "evidence": "The original-coordinate x-axis movement path matches the special interpreter callback.",
    },
    {
        "address": "0x25e5fc",
        "upstream_name": "Direct_Move_Orig_Y",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1679,
        "evidence": "The original-coordinate y-axis movement path matches the special interpreter callback.",
    },
    {
        "address": "0x25e618",
        "upstream_name": "Round_None",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1712,
        "evidence": "The compensation add or subtract rules and signed overflow clamps match the no-rounding function.",
    },
    {
        "address": "0x25e640",
        "upstream_name": "Project",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 2186,
        "evidence": "The helper computes a TT_DotFix14 result using the current projection vector fields.",
    },
    {
        "address": "0x25e6cc",
        "upstream_name": "Project_x",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 2242,
        "evidence": "The callback returns its x input and is assigned by Compute_Funcs to the horizontal projection slot.",
    },
    {
        "address": "0x25e6d4",
        "upstream_name": "Project_y",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 2269,
        "evidence": "The callback returns its y input and is assigned by Compute_Funcs to the vertical projection slot.",
    },
    {
        "address": "0x25e6dc",
        "upstream_name": "Ins_NPUSHW",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4621,
        "evidence": "The count bounds check, signed big-endian word reads, instruction pointer advance, and stack updates match.",
    },
    {
        "address": "0x25e770",
        "upstream_name": "Ins_PUSHW",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4676,
        "evidence": "The opcode-derived word count and signed instruction-stream reads match.",
    },
    {
        "address": "0x25e7f8",
        "upstream_name": "Ins_GC",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4717,
        "evidence": "The point validation, current or original projection selection, and result write match.",
    },
    {
        "address": "0x25e890",
        "upstream_name": "Ins_SCFS",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4758,
        "evidence": "The projection of the stack distance, freedom-vector move, twilight copy, and error path match.",
    },
    {
        "address": "0x25e950",
        "upstream_name": "Ins_GETINFO",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 6715,
        "evidence": "The version, rotation, stretch, and grayscale feature bits match the handler.",
    },
    {
        "address": "0x25e9a8",
        "upstream_name": "Ins_MD",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 4800,
        "evidence": "The two-point bounds checks, dual projection, scaling, and stack result match.",
    },
    {
        "address": "0x25eaf8",
        "upstream_name": "tt_size_request",
        "source_file": "src/truetype/ttdriver.c",
        "source_line": 179,
        "evidence": "The metrics request and scaling logic match, and the address occupies the corresponding driver class slot.",
    },
    {
        "address": "0x25ec84",
        "upstream_name": "Direct_Move_Orig",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1596,
        "evidence": "The freedom-vector movement updates original coordinates without setting touch flags.",
    },
    {
        "address": "0x25ed14",
        "upstream_name": "Direct_Move",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 1543,
        "evidence": "The freedom-vector movement updates current coordinates and sets the touch flags.",
    },
    {
        "address": "0x25edd0",
        "upstream_name": "Ins_ISECT",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 6036,
        "evidence": "The five-point intersection calculation, discriminant threshold, midpoint fallback, and touch-both flag match.",
    },
    {
        "address": "0x260050",
        "upstream_name": "Compute_Funcs",
        "source_file": "src/truetype/ttinterp.c",
        "source_line": 2289,
        "evidence": "The projection and movement callback selection, including the unpatented-hinting branch, matches the source.",
    },
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_report(inventory_path: Path) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")
    rows = {int(row["ea"]): row for row in document}
    output_matches = []
    for item in MATCHES:
        ea = int(item["address"], 16)
        row = rows.get(ea)
        if row is None:
            raise ValueError(f"source match address is absent from inventory: {item['address']}")
        if row.get("name") != item["upstream_name"]:
            raise ValueError(
                f"IDA name mismatch at {item['address']}: "
                f"expected {item['upstream_name']}, got {row.get('name')}"
            )
        if row.get("is_default_sub"):
            raise ValueError(f"source match remains a default sub_: {item['address']}")
        source_url = f"{SOURCE_REPOSITORY}/blob/{SOURCE_TAG}/{item['source_file']}#L{item['source_line']}"
        output_matches.append({
            **item,
            "ida_name": row["name"],
            "ida_name_origin": row.get("name_origin"),
            "size": int(row.get("size", 0)),
            "xrefs_to": row.get("xrefs_to"),
            "source_url": source_url,
            "confidence": "exact",
        })
    output_matches.sort(key=lambda item: int(item["address"], 16))
    return {
        "schema": "libqplay.ida-freetype-source-match.v1",
        "tool": "tools/generate_freetype_source_matches.py",
        "tool_version": 1,
        "analysis_date": "2026-09-01",
        "analysis_scope": "exact source matches for embedded FreeType and TrueType helpers in original ARM64 libqplay.so",
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "source": {
            "repository": SOURCE_REPOSITORY,
            "tag": SOURCE_TAG,
            "commit": SOURCE_COMMIT,
            "files": sorted({item["source_file"] for item in output_matches}),
            "acquisition_note": "The source was inspected from a local pinned checkout. Artifact generation reads local files only.",
        },
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "network_contacted": False,
        "match_count": len(output_matches),
        "matches": output_matches,
        "method": [
            "Compare the ARM64 decompiler body with the tagged upstream implementation.",
            "Use callback-table assignments, object field offsets, and neighboring source behavior as corroborating evidence.",
            "Require the current IDA inventory to contain the expected applied name before recording an exact match.",
        ],
        "not_claimed": [
            "That every remaining FreeType or JPEG routine has been matched.",
            "That this source tag accounts for local compiler or build-option changes outside the matched bodies.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", nargs="?", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    inventory = args.inventory if args.inventory.is_absolute() else Path.cwd() / args.inventory
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not inventory.is_file():
        parser.error(f"IDA inventory does not exist: {inventory}")
    report = build_report(inventory)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": output.as_posix(),
        "match_count": report["match_count"],
        "inventory_rows": report["inventory"]["row_count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
