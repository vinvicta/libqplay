#!/usr/bin/env python3
"""Clear the ARM64 loading flag after timers, immediately before drawing.

The JNI loop runs timers and packet processing before it reads
``loadingscreenenabled``.  This diagnostic uses that boundary to clear only
the byte read by the normal render decision, leaving startup, connector
handling, and packet dispatch unchanged.  The cave returns zero so the
original ``UXTB`` and conditional branch continue to execute normally.

This is a local diagnostic patch for the matching ARM64 library.  It does not
contact a live service and is not a release patch.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


PATCH_OFFSET = 0x244228
PATCH_ORIGINAL = bytes.fromhex("da 38 fa 97")  # bl getLoadingScreenEnabled
CAVE_OFFSET = 0x1F9508
CAVE_CAPACITY = 20
RESUME_OFFSET = 0x24422C
LOADING_FLAG_GOT = 0x375E30


def branch_link(site: int, target: int) -> int:
    delta = target - site
    if delta % 4:
        raise ValueError("AArch64 branch target is not instruction aligned")
    immediate = delta >> 2
    if not -(1 << 25) <= immediate < (1 << 25):
        raise ValueError("AArch64 BL target is outside its +/-128 MiB range")
    return 0x94000000 | (immediate & 0x03FFFFFF)


def branch(site: int, target: int) -> int:
    delta = target - site
    if delta % 4:
        raise ValueError("AArch64 branch target is not instruction aligned")
    immediate = delta >> 2
    if not -(1 << 25) <= immediate < (1 << 25):
        raise ValueError("AArch64 B target is outside its +/-128 MiB range")
    return 0x14000000 | (immediate & 0x03FFFFFF)


def adrp(register: int, site: int, target: int) -> int:
    page_delta = (target >> 12) - (site >> 12)
    if not -(1 << 20) <= page_delta < (1 << 20):
        raise ValueError("ADRP target is outside its +/-4 GiB range")
    immediate = page_delta & 0x1FFFFF
    return (
        0x90000000
        | ((immediate & 0x3) << 29)
        | (((immediate >> 2) & 0x7FFFF) << 5)
        | register
    )


def ldr_x(register: int, base: int, immediate: int) -> int:
    if immediate % 8 or not 0 <= immediate // 8 <= 0xFFF:
        raise ValueError("LDR offset must be an aligned 12-bit unsigned offset")
    return 0xF9400000 | ((immediate // 8) << 10) | (base << 5) | register


def patch(blob: bytearray) -> None:
    actual = bytes(blob[PATCH_OFFSET : PATCH_OFFSET + len(PATCH_ORIGINAL)])
    if actual != PATCH_ORIGINAL:
        raise SystemExit(
            f"unexpected bytes at 0x{PATCH_OFFSET:x}: {actual.hex(' ')}"
        )
    cave = bytes(blob[CAVE_OFFSET : CAVE_OFFSET + CAVE_CAPACITY])
    if cave != b"\x00" * CAVE_CAPACITY:
        raise SystemExit(f"ARM64 code cave at 0x{CAVE_OFFSET:x} is not zero-filled")

    instructions = (
        adrp(0, CAVE_OFFSET, LOADING_FLAG_GOT),
        ldr_x(0, 0, LOADING_FLAG_GOT & 0xFFF),
        0x3900001F,  # strb wzr, [x0]
        0x2A1F03E0,  # mov w0, wzr
        branch(CAVE_OFFSET + 16, RESUME_OFFSET),
    )
    replacement = b"".join(
        struct.pack("<I", instruction) for instruction in instructions
    )
    blob[CAVE_OFFSET : CAVE_OFFSET + CAVE_CAPACITY] = replacement
    blob[PATCH_OFFSET : PATCH_OFFSET + len(PATCH_ORIGINAL)] = struct.pack(
        "<I", branch_link(PATCH_OFFSET, CAVE_OFFSET)
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    patch(blob)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        "patched render-loop loading flag boundary; "
        f"sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
