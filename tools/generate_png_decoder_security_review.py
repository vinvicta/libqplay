#!/usr/bin/env python3
"""Generate the focused static review for the embedded PNG/MNG path.

This report keeps the PNG dimension arithmetic separate from the broader
image-loader inventory. It records the exact ARM64 allocation and decode
boundaries, then gives a small arithmetic witness for the 32-bit wrap. The
witness is not a malformed-image reproduction and does not assign a runtime
impact that has not been tested.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT.parent / "analysis" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "png_decoder_security_review_20260902.json"
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
        "stream_entry": function_row(
            rows, 0x11B47C, "TImageAnimation_createFromStream_TStream"
        ),
        "png_parser": function_row(
            rows, 0x11F9D8, "TMNGAnimation_parsePicture_void"
        ),
        "png_decoder": function_row(
            rows, 0x11B7A0, "TMNGAnimation_decode_TMNGAnimationStep"
        ),
        "bitmap_wrapper": function_row(
            rows, 0x116FA0, "TBitmap_readPNG_TStream"
        ),
    }

    width = 65536
    height = 65537
    bit_depth = 8
    color_type = 6
    pixel_bits = 32
    mathematical_output = width * height * pixel_bits // 8
    output_product_u32 = u32(u32(width * height) * pixel_bits)
    output_capacity = output_product_u32 // 8
    row_bytes = (pixel_bits * width + 7) // 8
    mathematical_raw = (row_bytes + 1) * height
    raw_row_product_u32 = u32(pixel_bits * width)
    raw_row_bytes_u32 = u32(raw_row_product_u32 + 7) // 8
    raw_capacity = u32(raw_row_bytes_u32 * height + height)

    if output_capacity != 262144 or raw_capacity != 327681:
        raise AssertionError("PNG arithmetic witness changed unexpectedly")

    return {
        "artifact": "png_decoder_security_review_20260902",
        "schema": "libqplay.png-decoder-security-review.v1",
        "tool": "tools/generate_png_decoder_security_review.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": (
            "static review of PNG/MNG dimension arithmetic, decoded-output "
            "allocation, and the row decode path in the original ARM64 library"
        ),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "functions": functions,
        "observed_allocation_chain": [
            {
                "id": "PNG-ALLOC-OUTPUT",
                "addresses": [
                    "0x11b4a8",
                    "0x11b4b8",
                    "0x11b4bc",
                    "0x11b4cc",
                    "0x11b4d0",
                    "0x11b4d4",
                ],
                "instruction": (
                    "TImageAnimation_createFromStream multiplies width by "
                    "height and then by pixel bits in W registers, shifts the "
                    "32-bit result by three, sign-extends it, and passes it to "
                    "memalign for the decoded output buffer."
                ),
                "interpretation": (
                    "The output allocation is not calculated in a checked "
                    "size_t expression and has no visible dimension or pixel "
                    "budget."
                ),
            },
            {
                "id": "PNG-ALLOC-RAW",
                "addresses": [
                    "0x1203a0",
                    "0x1203a8",
                    "0x1203b0",
                    "0x1203b4",
                    "0x1203b8",
                    "0x1203bc",
                    "0x1203d4",
                ],
                "instruction": (
                    "TMNGAnimation_parsePicture computes the filtered row "
                    "size and height product in W registers, sign-extends the "
                    "wrapped result, and passes it to realloc for the raw "
                    "inflated scanline buffer."
                ),
                "interpretation": (
                    "The parser's raw-buffer size can wrap independently of "
                    "the mathematical PNG scanline requirement."
                ),
            },
            {
                "id": "PNG-CHECK-RAW",
                "addresses": [
                    "0x11b868",
                    "0x11b878",
                    "0x11b88c",
                    "0x11b890",
                    "0x11b894",
                ],
                "instruction": (
                    "TMNGAnimation_decode recomputes the expected filtered "
                    "scanline size with W-register multiplication and rejects "
                    "only when the stored 32-bit raw size is smaller than that "
                    "wrapped result."
                ),
                "interpretation": (
                    "A compressed stream whose inflated length equals the "
                    "wrapped value can satisfy the visible size check even "
                    "when the mathematical dimensions describe a much larger "
                    "image."
                ),
            },
            {
                "id": "PNG-ROW-DECODE",
                "addresses": [
                    "0x11c58c",
                    "0x11c598",
                    "0x11c59c",
                    "0x11d3d4",
                    "0x11d3e8",
                    "0x11d410",
                ],
                "instruction": (
                    "The decoder advances the source and destination row "
                    "pointers using the parsed dimensions. The generic 8-bit "
                    "RGBA path prepares X9 as the destination and calls memcpy "
                    "for each row."
                ),
                "interpretation": (
                    "The row loop has no independent check that its cumulative "
                    "writes remain within the output allocation calculated by "
                    "TImageAnimation_createFromStream."
                ),
            },
        ],
        "observed_dimension_arithmetic": {
            "id": "PNG-001",
            "severity": "potential heap-buffer-overflow, conditional",
            "format": {
                "width": width,
                "height": height,
                "bit_depth": bit_depth,
                "color_type": color_type,
                "pixel_bits": pixel_bits,
                "description": "legal PNG 8-bit RGBA IHDR values",
            },
            "arithmetic_example": {
                "width_times_height_u32": u32(width * height),
                "output_product_u32_before_shift": output_product_u32,
                "output_allocation_bytes": output_capacity,
                "output_required_bytes_mathematical": mathematical_output,
                "row_bytes_mathematical": row_bytes,
                "raw_required_bytes_mathematical": mathematical_raw,
                "raw_allocation_bytes": raw_capacity,
                "raw_check_value_after_32bit_wrap": raw_capacity,
                "output_shortfall_bytes": mathematical_output - output_capacity,
                "raw_shortfall_bytes": mathematical_raw - raw_capacity,
            },
            "evidence_chain": [
                "The PNG parser accepts the IHDR dimensions into the animation step without a visible application dimension cap.",
                "The parser's non-interlaced raw size is (ceil(pixel_bits * width / 8) + 1) * height, evaluated in W registers before SXTW.",
                "The stream entry allocates the decoded output as width * height * pixel_bits / 8, also evaluated in W registers before SXTW.",
                "The decoder compares the stored raw size against the same wrapped W-register expression and then enters a dimension-driven row loop.",
                "For this witness, a zlib stream that inflates to 327681 bytes would match the wrapped raw-size check while the output allocation is only 262144 bytes for a mathematical 17180131328-byte RGBA image.",
            ],
            "assessment": (
                "The allocation and row-decode arithmetic form a conditional "
                "static heap-overflow candidate. A small compressed PNG can "
                "carry dimensions whose 32-bit products wrap to small positive "
                "sizes, allowing the visible raw-size check to pass before the "
                "decoder processes the parsed row count. This conclusion is "
                "based on IDA disassembly and arithmetic only; it is not a "
                "fuzzing result or a runtime crash reproduction."
            ),
        },
        "broader_budget_gap": {
            "severity": "availability and memory-pressure risk",
            "observations": [
                "PNG IDAT chunks accumulate through realloc without a visible compressed-byte budget.",
                "MNG and animation frames are retained through the shared list path without a visible application frame-count budget.",
                "The image resource path is reachable from server-delivered packet-102 resources in the local trace, but the live service was not contacted.",
            ],
        },
        "not_claimed": [
            "That PNG-001 reproduces without a bounded malformed-PNG harness.",
            "That the allocator returns storage for the wrapped witness sizes on every Android libc configuration.",
            "That a remote server will deliver a malicious PNG before authentication or cache policy gates.",
            "That the finding is an exploitable code-execution primitive.",
        ],
        "fuzzing_performed": False,
        "runtime_reproduction": False,
        "network_contacted": False,
        "overall_assessment": (
            "The original PNG/MNG implementation has a concrete checked-size "
            "gap at both the raw scanline and decoded-output allocations. PNG-001 "
            "should be validated in a disposable ARM64 harness with strict "
            "address sanitization and hard process limits. A repair should use "
            "checked size_t arithmetic and reject dimensions, compressed IDAT "
            "bytes, decoded bytes, frame count, and cumulative texture memory "
            "before any allocation or decode."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_report(args.inventory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
