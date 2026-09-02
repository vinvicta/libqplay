#!/usr/bin/env python3
"""Generate the focused static review for the native JPEG wrapper.

The embedded IJG role report handles source attribution. This companion keeps
the application wrapper's decoder-reported dimensions, shared bitmap
allocation, and scanline destination arithmetic tied to the original ARM64
inventory. The witness is a checked arithmetic example, not a malformed-JPEG
runtime reproduction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "symbols" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "jpeg_decoder_security_review_20260902.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
MASK32 = (1 << 32) - 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def u32(value: int) -> int:
    return value & MASK32


def function_row(rows: dict[int, dict], address: int, name: str) -> dict:
    row = rows.get(address)
    if row is None:
        raise ValueError(f"{name} is absent from the inventory at {address:#x}")
    if row.get("name") != name:
        raise ValueError(
            f"unexpected name at {address:#x}: {row.get('name')} != {name}"
        )
    size = row.get("size", 0)
    if isinstance(size, str):
        size = int(size, 0)
    return {"address": f"{address:#x}", "ida_name": name, "size": size}


def build_report(inventory_path: Path) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")
    rows = {int(item["ea"]): item for item in document}

    functions = {
        "jpeg_wrapper": function_row(rows, 0x150FA8, "TBitmap_readJPEG_TStream"),
        "bitmap_allocator": function_row(
            rows,
            0x1140B0,
            "TBitmap_allocateBitmap_uint_uint_bool_TBitmap_BitmapFormat",
        ),
        "bytes_per_pixel": function_row(
            rows, 0x11405C, "TBitmap_updateBytesPerPixel_void"
        ),
        "error_handler": function_row(rows, 0x150F20, "TBitmap_JPEG_errorExit"),
        "message_handler": function_row(
            rows, 0x150EB0, "TBitmap_JPEG_outputMessage"
        ),
    }

    width = 65535
    height = 21846
    output_components = 3
    mathematical_pixels = width * height
    mathematical_bitmap_bytes = mathematical_pixels * output_components
    wrapped_bitmap_bytes = u32(mathematical_bitmap_bytes)
    scanline_bytes = output_components * width
    if wrapped_bitmap_bytes != 65534 or scanline_bytes != 196605:
        raise AssertionError("JPEG arithmetic witness changed unexpectedly")

    return {
        "artifact": "jpeg_decoder_security_review_20260902",
        "schema": "libqplay.jpeg-decoder-security-review.v1",
        "tool": "tools/generate_jpeg_decoder_security_review.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": (
            "static review of the original ARM64 JPEG wrapper's decoder "
            "dimensions, shared bitmap allocation, and scanline destination"
        ),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "functions": functions,
        "scanline_boundary": {
            "id": "JPEG-001",
            "severity": "potential heap-buffer-overflow, conditional",
            "decoder_fields": {
                "output_width": width,
                "output_height": height,
                "output_components": output_components,
                "dimension_field_limit": 65535,
                "description": (
                    "The JPEG SOF dimension fields are 16-bit, so this "
                    "witness stays within the format's field range."
                ),
            },
            "addresses": [
                "0x151084",
                "0x1510a8",
                "0x1510b0",
                "0x1510b8",
                "0x1510c4",
                "0x11415c",
                "0x1141e4",
                "0x1510dc",
                "0x151120",
                "0x15112c",
                "0x151134",
            ],
            "instruction": (
                "TBitmap_readJPEG_TStream calls the bundled JPEG decoder, "
                "passes output_width and output_height to the shared bitmap "
                "allocator with the three-byte RGB format, then calculates "
                "output_components * output_width in W24. Each scanline is "
                "submitted to jpeg_read_scanlines with a destination pointer "
                "formed from the bitmap base plus a 32-bit row offset."
            ),
            "arithmetic_example": {
                "mathematical_pixel_count": mathematical_pixels,
                "mathematical_bitmap_bytes": mathematical_bitmap_bytes,
                "wrapped_bitmap_allocation_bytes": wrapped_bitmap_bytes,
                "scanline_copy_bytes": scanline_bytes,
                "first_scanline_excess_bytes": scanline_bytes - wrapped_bitmap_bytes,
            },
            "supporting_behavior": [
                "The wrapper checks the JPEG input stream length before creating the decoder, but it has no application pixel or decoded-byte cap after jpeg_start_decompress reports its dimensions.",
                "The RGB branch uses bitmap format 2, which the bytes-per-pixel helper maps to three bytes per pixel.",
                "The shared allocator stores its width-times-height-times-bytes-per-pixel product in a 32-bit field before memalign.",
                "The scanline loop does not compare the row copy length with the allocated bitmap capacity before calling jpeg_read_scanlines.",
            ],
            "assessment": (
                "The witness is within the JPEG dimension field range. Its "
                "mathematical RGB bitmap needs 4295032830 bytes, but the "
                "shared 32-bit allocation stores 65534 bytes while the first "
                "decoder scanline needs 196605 bytes. If the decoder accepts "
                "the dimensions, produces a scanline, and the wrapped-sized "
                "allocation returns storage, the first scanline can run past "
                "the bitmap allocation. This is a conditional static "
                "heap-overflow candidate, not a demonstrated crash."
            ),
        },
        "wrapper_hardening_gaps": [
            {
                "id": "JPEG-002",
                "severity": "availability and memory-pressure risk",
                "observation": (
                    "The wrapper delegates malformed syntax to the bundled "
                    "IJG decoder and installs an errorExit setjmp path, but "
                    "does not impose its own decoded pixel or cumulative "
                    "texture budget before jpeg_start_decompress and bitmap "
                    "allocation."
                ),
            },
            {
                "id": "JPEG-003",
                "severity": "parser robustness concern",
                "observation": (
                    "The wrapper uses a fixed local JPEG state area and a "
                    "stream callback. Exact library cleanup behavior on every "
                    "malformed input state should be checked in a bounded "
                    "harness rather than inferred from the normal path."
                ),
            },
        ],
        "not_claimed": [
            "That JPEG-001 reproduces without a bounded JPEG corpus and an ARM64 allocator harness.",
            "That the bundled IJG implementation accepts every dimension witness without failing earlier internal allocations.",
            "That a conditional overflow candidate is an exploitable code-execution primitive.",
            "That any specific historical IJG CVE maps directly to this binary without a vendor-source comparison.",
        ],
        "fuzzing_performed": False,
        "runtime_reproduction": False,
        "network_contacted": False,
        "overall_assessment": (
            "The JPEG wrapper needs checked size_t arithmetic and a small "
            "decoded-pixel or decoded-byte budget before the shared bitmap "
            "allocation. JPEG-001 is a conditional dimension-wrap candidate "
            "that should be validated only in a disposable, address-sanitized "
            "ARM64 harness."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    inventory = args.inventory
    output = args.output
    if not inventory.is_absolute():
        inventory = ROOT / inventory
    if not output.is_absolute():
        output = ROOT / output
    if not inventory.is_file():
        raise SystemExit(f"IDA inventory does not exist: {inventory}")
    report = build_report(inventory)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": output.as_posix(),
                "findings": [
                    report["scanline_boundary"]["id"],
                    report["wrapper_hardening_gaps"][0]["id"],
                    report["wrapper_hardening_gaps"][1]["id"],
                ],
                "inventory_rows": report["inventory"]["row_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
