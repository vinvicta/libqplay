#!/usr/bin/env python3
"""Generate the focused static review of libqplay compression buffers.

This report keeps the shared output-buffer behavior tied to the original
ARM64 function inventory. The arithmetic witnesses model the signed 32-bit
comparisons and W-register doubling visible in the disassembly. They are
static examples, not malformed-packet or runtime reproductions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "symbols" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "compression_buffer_security_review_20260902.json"
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


def s32(value: int) -> int:
    value &= MASK32
    return value - (1 << 32) if value & (1 << 31) else value


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


def growth_trace(request: int, max_steps: int = 64) -> dict:
    """Model getCompressionBuffer's W32 doubling and signed B.GT test."""

    request_word = u32(request)
    capacity = 2
    states = [
        {
            "step": 0,
            "capacity_u32": capacity,
            "capacity_s32": s32(capacity),
        }
    ]
    seen = {capacity: 0}

    for step in range(1, max_steps + 1):
        if s32(request_word) <= s32(capacity):
            return {
                "request_u32": request_word,
                "request_s32": s32(request_word),
                "terminates": True,
                "states": states,
            }
        capacity = u32(capacity * 2)
        state = {
            "step": step,
            "capacity_u32": capacity,
            "capacity_s32": s32(capacity),
        }
        states.append(state)
        if capacity in seen:
            return {
                "request_u32": request_word,
                "request_s32": s32(request_word),
                "terminates": False,
                "cycle_start_step": seen[capacity],
                "cycle_step": step,
                "states": states,
            }
        seen[capacity] = step

    raise AssertionError("growth trace did not settle within the safety bound")


def rounded_capacity(request: int) -> int:
    """Model the terminating positive-size path for a power-of-two witness."""

    if request <= 2:
        return 2
    capacity = 2
    while request > capacity:
        capacity *= 2
    return capacity


def build_report(inventory_path: Path) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")
    rows = {int(item["ea"]): item for item in document}

    functions = {
        "buffer_helper": function_row(
            rows, 0xE4DD4, "TCompression_getCompressionBuffer_int"
        ),
        "zlib_compress_impl": function_row(
            rows,
            0xE4E5C,
            "TCompression_CompressBuf_impl_void_const_int_uchar_uint",
        ),
        "zlib_decompress": function_row(
            rows,
            0xE4FC8,
            "TCompression_DecompressBuf_void_const_int_uchar_uint",
        ),
        "bzip2_compress_impl": function_row(
            rows,
            0xE5144,
            "TCompression_CompressBuf2_impl_void_const_int_uchar_uint",
        ),
        "bzip2_decompress": function_row(
            rows,
            0xE5270,
            "TCompression_DecompressBuf2_void_const_int_uchar_uint",
        ),
        "string_append": function_row(
            rows, 0xF11BC, "TString_addbuffer_char_const_int"
        ),
        "new_protocol_parser": function_row(
            rows, 0x1FE31C, "TGraalConnection_parseProtocol_NewGraal_void"
        ),
        "old_protocol_parser": function_row(
            rows, 0x1FC598, "TGraalConnection_parseProtocol_OldGraal_void"
        ),
        "stream_read": function_row(rows, 0xF0684, "TStream_read_void_int"),
    }

    stalled_request = 0x40000001
    stalled_trace = growth_trace(stalled_request)
    if stalled_trace["terminates"]:
        raise AssertionError("the signed growth witness unexpectedly terminates")
    if stalled_trace["states"][-1]["capacity_u32"] != 0:
        raise AssertionError("the signed growth witness no longer reaches zero")

    compressor_input = stalled_request - 1024
    if compressor_input != 1073740801:
        raise AssertionError("compressor request witness changed unexpectedly")

    high_water_input = 4194305
    high_water_request = high_water_input + 1024
    high_water_capacity = rounded_capacity(high_water_request)
    if high_water_request != 4195329 or high_water_capacity != 8388608:
        raise AssertionError("high-water buffer witness changed unexpectedly")

    return {
        "artifact": "compression_buffer_security_review_20260902",
        "schema": "libqplay.compression-buffer-security-review.v1",
        "tool": "tools/generate_compression_buffer_security_review.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": (
            "static review of the shared zlib and bzip2 output buffer, "
            "protocol decompression callers, and 32-bit growth arithmetic"
        ),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "functions": functions,
        "shared_buffer_state": {
            "capacity_global_ea": "0x38c7f8",
            "buffer_global_ea": "0x38c800",
            "minimum_automatic_output_capacity": 65536,
            "automatic_retry_ceiling": 4194304,
            "capacity_rounding": "positive requests are rounded to a power of two",
            "lifetime_observation": (
                "The helper writes the new global capacity before realloc and "
                "no independent clear or shrink routine was identified in the "
                "reviewed data references."
            ),
        },
        "findings": [
            {
                "id": "COMP-001",
                "severity": "potential availability stall, conditional",
                "addresses": [
                    "0xe4dd4",
                    "0xe4df8",
                    "0xe4dfc",
                    "0xe4e00",
                    "0xe4e04",
                ],
                "instruction": (
                    "TCompression_getCompressionBuffer_int starts at a 32-bit "
                    "capacity of two, doubles it in W2, and uses signed B.GT "
                    "for the loop condition. The new capacity is stored before "
                    "the realloc call."
                ),
                "request_witness": {
                    "request_u32": stalled_request,
                    "request_s32": s32(stalled_request),
                    "hex": f"{stalled_request:#x}",
                    "growth_trace": stalled_trace,
                    "compressor_input_length_witness": compressor_input,
                    "compressor_input_length_hex": f"{compressor_input:#x}",
                    "request_expression": "input_length + 1024",
                    "request_sites": ["0xe4f14", "0xe4f20", "0xe51b8", "0xe51c8"],
                },
                "assessment": (
                    "For a positive request of 0x40000001, the W32 sequence "
                    "reaches 0x80000000, then zero, and remains zero while the "
                    "signed request comparison remains true. The helper does "
                    "not reach realloc. A compression caller would request this "
                    "value from an input length of 1073740801 before the added "
                    "1024 bytes. The reviewed stock NewGraal frame header carries "
                    "a three-byte length, so this witness is not shown reachable "
                    "through one ordinary incoming frame."
                ),
            },
            {
                "id": "COMP-002",
                "severity": "memory-pressure policy gap",
                "addresses": [
                    "0xe4e5c",
                    "0xe4f14",
                    "0xe4f20",
                    "0xe5144",
                    "0xe51b8",
                    "0xe51c8",
                    "0xe4fc8",
                    "0xe5270",
                ],
                "instruction": (
                    "Automatic zlib and bzip2 decompression starts at the larger "
                    "of the shared capacity and 64 KiB. After an "
                    "output-buffer-full result, each wrapper retries only while the next "
                    "capacity is at most 4 MiB. Compression, however, first "
                    "requests input_length + 1024 and the shared helper rounds "
                    "that request upward without the 4 MiB ceiling."
                ),
                "high_water_witness": {
                    "input_length": high_water_input,
                    "input_length_hex": f"{high_water_input:#x}",
                    "compressor_request": high_water_request,
                    "compressor_request_hex": f"{high_water_request:#x}",
                    "rounded_shared_capacity": high_water_capacity,
                    "subsequent_automatic_decompressor_start": high_water_capacity,
                    "subsequent_retry_ceiling": 4194304,
                },
                "assessment": (
                    "A compressor call with an input length of 4194305 requests "
                    "4195329 bytes and can raise the process-wide shared capacity "
                    "to 8388608 bytes before compression completes. A later "
                    "automatic decompression call starts from that 8 MiB high "
                    "water because it applies only a lower bound. If that call "
                    "still needs growth, its next attempt is rejected by the 4 MiB "
                    "retry test. This is a memory-policy inconsistency, not a "
                    "direct overflow finding."
                ),
            },
        ],
        "protocol_boundary": {
            "new_parser": {
                "address": "0x1fe31c",
                "header_format": "EILLLT",
                "declared_length_field_bytes": 3,
                "compression_selectors": {
                    "1": "zlib",
                    "2": "bzip2",
                },
                "decompressor_calls": {
                    "zlib": "0x1fe880",
                    "bzip2": "0x1fe868",
                },
            },
            "old_parser": {
                "address": "0x1fc598",
                "length_field": "two-byte length with extended-length form",
                "compression_modes": {
                    "3": "zlib",
                    "4": "zlib",
                    "5": "bzip2",
                    "6": "bzip2",
                },
            },
            "receive_accumulation": (
                "TGraalConnection_read_void appends socket data to a protocol "
                "TString. TSocketConnection_read_void limits one read to 8192 "
                "bytes, but no smaller aggregate frame or stream cap was visible "
                "in the reviewed path."
            ),
        },
        "allocation_and_append_observations": [
            {
                "address": "0xe4dd4",
                "observation": (
                    "The helper stores the requested rounded capacity before "
                    "realloc and does not check realloc itself. Decompressor "
                    "callers check the returned pointer; the persistent global "
                    "state after failure was not exercised at runtime."
                ),
            },
            {
                "address": "0xf11bc",
                "observation": (
                    "TString_addbuffer_char_const_int adds the old length and "
                    "append length in W32 arithmetic, passes the sign-extended "
                    "allocation expression to realloc or malloc, and does not "
                    "check the returned pointer before memcpy. This is an "
                    "extreme-size and allocation-failure hardening target, not "
                    "a packet-sized overflow claim."
                ),
            },
        ],
        "not_claimed": [
            "That COMP-001 is reachable from an ordinary stock NewGraal frame.",
            "That COMP-002 by itself corrupts memory or executes code.",
            "That the compressed input or decompressed output has been fuzzed.",
            "That any production endpoint was contacted during this review.",
            "That allocation failure or the signed-loop stall was reproduced on a device.",
        ],
        "fuzzing_performed": False,
        "runtime_reproduction": False,
        "network_contacted": False,
        "overall_assessment": (
            "The compression wrappers need checked size arithmetic, an explicit "
            "process-wide memory policy, and a bounded accumulated protocol "
            "buffer. The signed growth loop is the sharpest static hardening "
            "target, while the high-water behavior explains why the nominal "
            "4 MiB decompression ceiling should not be treated as a complete "
            "resource limit."
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
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": output.as_posix(),
                "findings": [item["id"] for item in report["findings"]],
                "inventory_rows": report["inventory"]["row_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
