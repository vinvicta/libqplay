#!/usr/bin/env python3
"""Generate the focused static review for the BMP and TGA readers.

The broader image report records the dispatch boundary. This companion keeps
the exact BMP palette and row-copy arithmetic, plus the TGA dimension
arithmetic, tied to the original ARM64 function inventory. The arithmetic
witnesses are static checks only. They are not malformed-image reproductions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "symbols" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "bmp_tga_decoder_security_review_20260902.json"
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
        "bmp_reader": function_row(rows, 0x115E28, "TBitmap_readMSBmp_TStream"),
        "tga_reader": function_row(rows, 0x152110, "TBitmap_readTGA_TStream"),
        "tga_loader": function_row(rows, 0x1515CC, "tga_load"),
        "bitmap_allocator": function_row(
            rows,
            0x1140B0,
            "TBitmap_allocateBitmap_uint_uint_bool_TBitmap_BitmapFormat",
        ),
        "bytes_per_pixel": function_row(
            rows, 0x11405C, "TBitmap_updateBytesPerPixel_void"
        ),
        "stream_read": function_row(rows, 0xF0684, "TStream_read_void_int"),
    }

    palette_count = 257
    palette_buffer_bytes = 1024
    palette_request_bytes = palette_count * 4
    if palette_request_bytes != 1028:
        raise AssertionError("BMP palette witness changed unexpectedly")

    bmp_width = 1 << 20
    bmp_height = 1366
    bmp_source_bits = 24
    bmp_destination_bytes_per_pixel = 3
    bmp_math_bytes = bmp_width * bmp_height * bmp_destination_bytes_per_pixel
    bmp_allocation_bytes = u32(bmp_math_bytes)
    bmp_row_bytes = (bmp_width * bmp_source_bits + 7) // 8
    bmp_row_bytes_padded = (bmp_row_bytes + 3) & ~3
    bmp_row_copy_bytes = bmp_width * bmp_destination_bytes_per_pixel
    if (
        bmp_allocation_bytes != 2097152
        or bmp_row_bytes_padded != 3145728
        or bmp_row_copy_bytes != 3145728
    ):
        raise AssertionError("BMP dimension witness changed unexpectedly")

    tga_width = 32768
    tga_height = 32768
    tga_bytes_per_pixel = 4
    tga_pixels = tga_width * tga_height
    tga_math_bytes = tga_pixels * tga_bytes_per_pixel
    tga_allocation_bytes = u32(tga_math_bytes)
    if tga_pixels != 1073741824 or tga_allocation_bytes != 0:
        raise AssertionError("TGA dimension witness changed unexpectedly")

    return {
        "artifact": "bmp_tga_decoder_security_review_20260902",
        "schema": "libqplay.bmp-tga-decoder-security-review.v1",
        "tool": "tools/generate_bmp_tga_decoder_security_review.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": (
            "static review of the original ARM64 BMP palette and row-copy "
            "boundaries, the shared bitmap allocator, and TGA dimension "
            "arithmetic"
        ),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "functions": functions,
        "bmp_palette_boundary": {
            "id": "BMP-001",
            "severity": "potential stack-buffer-overflow, conditional",
            "header_fields": {
                "bi_bit_count": [4, 8],
                "bi_compression": 0,
                "bi_clr_used": palette_count,
            },
            "addresses": [
                "0x115f64",
                "0x116114",
                "0x11611c",
                "0x116120",
                "0x11612c",
            ],
            "instruction": (
                "TBitmap_readMSBmp_TStream selects the 4 or 8 bit palette "
                "case from the DIB bit count, loads biClrUsed from the "
                "header, shifts that count left by two in W2, and passes the "
                "result to TStream_read. The destination is the fixed "
                "1,024-byte stack array at the function's SP+0x100 frame "
                "offset."
            ),
            "arithmetic_example": {
                "palette_entries": palette_count,
                "requested_bytes": palette_request_bytes,
                "fixed_stack_buffer_bytes": palette_buffer_bytes,
                "bytes_past_stack_buffer": palette_request_bytes
                - palette_buffer_bytes,
            },
            "supporting_behavior": [
                "TStream_read_void_int copies the requested positive length, capped only by bytes remaining in the stream, into the caller-provided destination.",
                "The normal biClrUsed value of zero is replaced with 256, which exactly fills the fixed buffer.",
                "The later palette loop stops at the end of that fixed buffer, but that does not prevent the earlier oversized TStream_read copy.",
            ],
            "assessment": (
                "A 4 or 8 bit BI_RGB BMP with biClrUsed greater than 256 and "
                "at least biClrUsed * 4 bytes remaining at the palette read "
                "can write beyond the fixed stack array. This is a static "
                "memory-corruption candidate. No malformed BMP was fuzzed, "
                "and no runtime crash or code-execution primitive was "
                "demonstrated."
            ),
        },
        "bmp_dimension_boundary": {
            "id": "BMP-002",
            "severity": "potential heap-buffer-overflow, conditional",
            "header_fields": {
                "bi_width": bmp_width,
                "bi_height": bmp_height,
                "bi_bit_count": bmp_source_bits,
                "bi_compression": 0,
                "destination_format": 2,
                "destination_bytes_per_pixel": bmp_destination_bytes_per_pixel,
            },
            "addresses": [
                "0x115fb4",
                "0x115fb8",
                "0x115fd0",
                "0x11601c",
                "0x116020",
                "0x116070",
                "0x11415c",
                "0x1141e4",
            ],
            "instruction": (
                "The BMP reader passes the header width and absolute height "
                "to TBitmap_allocateBitmap with destination format 2. The "
                "allocator maps format 2 to three bytes per pixel and stores "
                "height * width * bytes_per_pixel in a 32-bit field before "
                "calling memalign. The reader then passes width * three as "
                "the destination row length to TStream_read."
            ),
            "arithmetic_example": {
                "mathematical_bitmap_bytes": bmp_math_bytes,
                "wrapped_bitmap_allocation_bytes": bmp_allocation_bytes,
                "source_row_bytes_without_padding": bmp_row_bytes,
                "source_row_bytes_padded": bmp_row_bytes_padded,
                "destination_row_copy_bytes": bmp_row_copy_bytes,
                "first_row_shortfall_bytes": bmp_row_copy_bytes
                - bmp_allocation_bytes,
                "stream_bytes_needed_for_first_row": bmp_row_copy_bytes,
            },
            "supporting_behavior": [
                "The TStream_read_void_int implementation caps the copy by stream bytes remaining, but it does not know the allocation capacity of the bitmap destination.",
                "The 24-bit source row is already four-byte aligned for this width, so the first row copy length is the full 3 * width value.",
                "The header image-size field is read but is not used as a safety limit before the row loop.",
            ],
            "assessment": (
                "For the witness dimensions, the shared allocator stores "
                "2,097,152 bytes after 32-bit wrap, while the first 24-bit "
                "row copy requests 3,145,728 bytes. If the stream has that "
                "row available and the allocator returns the wrapped-sized "
                "buffer, the first read can run past the bitmap allocation. "
                "This is a conditional static heap-overflow candidate, not a "
                "fuzzing result."
            ),
        },
        "tga_dimension_boundary": {
            "id": "TGA-001",
            "severity": "potential heap-buffer-overflow, conditional",
            "header_fields": {
                "image_type": 2,
                "color_map_type": 0,
                "width": tga_width,
                "height": tga_height,
                "pixel_depth": 32,
            },
            "addresses": [
                "0x151684",
                "0x1516a4",
                "0x151810",
                "0x151814",
                "0x151818",
                "0x151ca4",
                "0x152168",
                "0x1521bc",
            ],
            "instruction": (
                "tga_load accepts 16-bit width and height fields, multiplies "
                "them in W registers, then multiplies the resulting pixel "
                "count by four for a 32-bit pixel buffer. The direct image "
                "decode writes pixels through the same 32-bit index arithmetic "
                "without checking the malloc result. TBitmap_readTGA_TStream "
                "also allocates the destination bitmap from the same wrapped "
                "dimension product and copies each source row into it."
            ),
            "arithmetic_example": {
                "pixel_count": tga_pixels,
                "mathematical_decoded_bytes": tga_math_bytes,
                "wrapped_tga_loader_allocation_bytes": tga_allocation_bytes,
                "wrapped_bitmap_allocation_bytes": tga_allocation_bytes,
                "first_pixel_write_bytes": tga_bytes_per_pixel,
            },
            "supporting_behavior": [
                "Image type 2 is accepted by the uncompressed true-color decode path.",
                "The 32-bit pixel count is nonzero, so the decode loop is entered even though the byte allocation wraps to zero.",
                "malloc(0) is not checked before the decoder stores the first pixel, and the wrapper does not validate the destination allocation before memcpy.",
            ],
            "assessment": (
                "A 32-bit 32,768 by 32,768 TGA produces a nonzero 32-bit "
                "pixel count but a zero-byte decoded allocation after the "
                "four-byte pixel multiplication wraps. Depending on allocator "
                "behavior, the first pixel store can dereference a null or "
                "zero-sized allocation, and the wrapper has a corresponding "
                "zero-sized destination copy. This is a conditional static "
                "memory-safety candidate. No malformed TGA was fuzzed and no "
                "runtime crash was observed."
            ),
        },
        "not_claimed": [
            "That any of these witnesses has been reproduced on a device or in an ARM64 sanitizer harness.",
            "That the native server will deliver a malicious BMP or TGA before authentication and resource-cache gates.",
            "That a conditional overflow candidate is an exploitable code-execution primitive.",
            "That every allocator configuration returns storage for a wrapped or zero-byte request.",
        ],
        "fuzzing_performed": False,
        "runtime_reproduction": False,
        "network_contacted": False,
        "overall_assessment": (
            "The BMP and TGA readers need checked size_t arithmetic and "
            "explicit format, dimension, palette, decoded-byte, and row-size "
            "limits before allocation or stream reads. BMP-001 is the sharpest "
            "direct fixed-buffer boundary. BMP-002 and TGA-001 are conditional "
            "dimension-wrap candidates that should be tested only in a bounded "
            "disposable ARM64 harness."
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
                    report["bmp_palette_boundary"]["id"],
                    report["bmp_dimension_boundary"]["id"],
                    report["tga_dimension_boundary"]["id"],
                ],
                "inventory_rows": report["inventory"]["row_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
