#!/usr/bin/env python3
"""Force the diagnostic client's outgoing NewGraal RC4 key to a known value.

The game client negotiates a server-to-client RC4 key in packet 0xfc, then
generates a separate random client-to-server key before sending packet 5.
This diagnostic patch changes only the output-key setup call in
``TGraalConnection::setEncryptionOut``.  It rewrites the existing 16-byte
TString backing buffer in place and leaves the incoming RC4 setup untouched,
so a loopback responder can decrypt the client's login packet without the
server's private RSA key.

This is for offline protocol reconstruction only; it is not part of the
compatibility candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


CALL_SITE = 0x21495A
ORIGINAL_CALL = bytes.fromhex("e8 d1 6f ec ff")
# Alignment padding between the preceding destructor thunk and the next
# function.  This is deliberately kept below the 0x21d6e0 function start.
CAVE_VA = 0x21D6A9
CAVE_CAPACITY = 55
OUTPUT_KEY = b"0123456789abcdef"
RC4_CREATE_PLT = 0x0DB930
RETURN_SITE = 0x21495F
EXPECTED_CAVE = bytes.fromhex(
    "0f 1f 80 00 00 00 00 0f 1f 00 66 66 66 66 66 2e "
    "0f 1f 84"
) + bytes(CAVE_CAPACITY - 19)

ORIGINAL_ARM64_PATCH_SITE = 0x1FD6B4
ARM64_ORIGINAL_PREFIX = bytes.fromhex(
    "ff c3 00 d1 f3 53 00 a9 f5 5b 01 a9"
)
ORIGINAL_ARM64_CAVE_VA = 0x1F2DCC
ARM64_CAVE_CAPACITY = 128
ARM64_EXPECTED_CAVE = bytes(ARM64_CAVE_CAPACITY)


ARM64_VARIANTS = {
    "original": {
        "patch_site": ORIGINAL_ARM64_PATCH_SITE,
        "cave_va": ORIGINAL_ARM64_CAVE_VA,
        "expected_prefix": ARM64_ORIGINAL_PREFIX,
        "expected_cave": ARM64_EXPECTED_CAVE,
    },
}


def rel32(site: int, target: int) -> bytes:
    return struct.pack("<i", target - (site + 5))


def arm64_branch(site: int, target: int) -> bytes:
    delta = target - site
    if delta % 4:
        raise ValueError("ARM64 branch target is not instruction-aligned")
    immediate = delta // 4
    if not -(1 << 25) <= immediate < (1 << 25):
        raise ValueError("ARM64 B target is outside its 26-bit range")
    return struct.pack("<I", 0x14000000 | (immediate & 0x03FFFFFF))


def arm64_cbz_x(register: int, site: int, target: int) -> bytes:
    delta = target - site
    if delta % 4:
        raise ValueError("ARM64 CBZ target is not instruction-aligned")
    immediate = delta // 4
    if not -(1 << 18) <= immediate < (1 << 18):
        raise ValueError("ARM64 CBZ target is outside its 19-bit range")
    return struct.pack(
        "<I", 0xB4000000 | ((immediate & 0x7FFFF) << 5) | register
    )


def arm64_mov_w(register: int, immediate: int) -> bytes:
    if not 0 <= immediate <= 0xFFFF:
        raise ValueError("ARM64 MOVZ immediate must fit in 16 bits")
    return struct.pack("<I", 0x52800000 | (immediate << 5) | register)


def arm64_mov_imm64(register: int, value: int) -> bytes:
    if not 0 <= value < (1 << 64):
        raise ValueError("ARM64 immediate must fit in 64 bits")
    code = bytearray()
    for halfword in range(4):
        opcode = 0xD2800000 if halfword == 0 else 0xF2800000
        immediate = (value >> (halfword * 16)) & 0xFFFF
        code += struct.pack(
            "<I", opcode | (halfword << 21) | (immediate << 5) | register
        )
    return bytes(code)


def arm64_str_x(source: int, base: int, offset: int) -> bytes:
    if offset % 8 or not 0 <= offset // 8 < (1 << 12):
        raise ValueError("ARM64 STR X offset must be an aligned 12-bit scaled value")
    return struct.pack(
        "<I", 0xF9000000 | ((offset // 8) << 10) | (base << 5) | source
    )


def arm64_str_w(source: int, base: int, offset: int) -> bytes:
    if offset % 4 or not 0 <= offset // 4 < (1 << 12):
        raise ValueError("ARM64 STR W offset must be an aligned 12-bit scaled value")
    return struct.pack(
        "<I", 0xB9000000 | ((offset // 4) << 10) | (base << 5) | source
    )


def build_arm64_cave(cave_va: int, resume_site: int) -> bytes:
    """Build a trampoline that rewrites the existing key backing buffer."""

    key_low = int.from_bytes(OUTPUT_KEY[:8], "little")
    key_high = int.from_bytes(OUTPUT_KEY[8:], "little")
    code = bytearray()
    # The branch at the patch site replaces the original stack allocation.
    # Re-run it here, then resume at the original second instruction.
    code += struct.pack("<I", 0xD100C3FF)  # SUB SP, SP, #0x30
    # Keep x0-x3 untouched. The original function has not saved them yet.
    code += arm64_cbz_x(2, cave_va + len(code), resume_site)
    code += struct.pack("<I", 0xF9400044)  # LDR X4, [X2]
    code += arm64_mov_imm64(5, key_low)
    code += arm64_mov_imm64(6, key_high)
    code += arm64_mov_w(7, len(OUTPUT_KEY))
    code += arm64_str_w(7, 4, 0)  # length = 16
    code += arm64_str_x(5, 4, 8)
    code += arm64_str_x(6, 4, 16)
    code += arm64_branch(cave_va + len(code), resume_site)
    if len(code) > ARM64_CAVE_CAPACITY:
        raise ValueError(f"ARM64 trampoline is {len(code)} bytes")
    return code.ljust(ARM64_CAVE_CAPACITY, b"\x00")


def patch_x86(blob: bytearray) -> None:
    actual = blob[CALL_SITE : CALL_SITE + len(ORIGINAL_CALL)]
    if actual != ORIGINAL_CALL:
        raise SystemExit(
            f"unexpected bytes at 0x{CALL_SITE:x}: {actual.hex(' ')}"
        )
    cave = blob[CAVE_VA : CAVE_VA + CAVE_CAPACITY]
    if cave != EXPECTED_CAVE:
        raise SystemExit(
            f"unexpected code cave at 0x{CAVE_VA:x}: {cave.hex(' ')}"
        )

    # r12 points at the output cipherkey TString in setEncryptionOut. Its
    # backing buffer already has the required 16-byte allocation; overwrite
    # those bytes, call the normal RC4 constructor, and return to the store
    # immediately following the original call.
    code = bytearray()
    code += bytes.fromhex("49 8b 04 24")  # mov rax,[r12]
    code += bytes.fromhex("c7 40 08") + OUTPUT_KEY[0:4]
    code += bytes.fromhex("c7 40 0c") + OUTPUT_KEY[4:8]
    code += bytes.fromhex("c7 40 10") + OUTPUT_KEY[8:12]
    code += bytes.fromhex("c7 40 14") + OUTPUT_KEY[12:16]
    code += bytes.fromhex("4c 89 e7")  # mov rdi,r12
    call = CAVE_VA + len(code)
    code += b"\xe8" + rel32(call, RC4_CREATE_PLT)
    jump = CAVE_VA + len(code)
    code += b"\xe9" + rel32(jump, RETURN_SITE)
    if len(code) > CAVE_CAPACITY:
        raise SystemExit(f"code cave payload is {len(code)} bytes")

    blob[CAVE_VA : CAVE_VA + CAVE_CAPACITY] = code.ljust(
        CAVE_CAPACITY, b"\x90"
    )
    blob[CALL_SITE : CALL_SITE + len(ORIGINAL_CALL)] = (
        b"\xe9" + rel32(CALL_SITE, CAVE_VA)
    )


def patch_arm64(blob: bytearray) -> tuple[int, int]:
    config = ARM64_VARIANTS["original"]
    patch_site = config["patch_site"]
    cave_va = config["cave_va"]
    expected_prefix = config["expected_prefix"]
    expected_cave = config["expected_cave"]
    actual = blob[patch_site : patch_site + len(expected_prefix)]
    if actual != expected_prefix:
        raise SystemExit(
            f"unexpected bytes at 0x{patch_site:x}: {actual.hex(' ')}"
        )
    cave = blob[cave_va : cave_va + ARM64_CAVE_CAPACITY]
    if cave != expected_cave:
        raise SystemExit(
            f"unexpected ARM64 code cave at 0x{cave_va:x}: {cave.hex(' ')}"
        )
    blob[cave_va : cave_va + ARM64_CAVE_CAPACITY] = build_arm64_cave(
        cave_va, patch_site + 4
    )
    blob[patch_site : patch_site + 4] = arm64_branch(
        patch_site, cave_va
    )
    return patch_site, cave_va


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("x86_64", "arm64-v8a"), default="x86_64")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    if args.arch == "x86_64":
        patch_x86(blob)
        patch_site = CALL_SITE
        cave_va = CAVE_VA
    else:
        patch_site, cave_va = patch_arm64(blob)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        f"patched {args.arch} outgoing RC4 key at 0x{patch_site:x}; "
        f"cave=0x{cave_va:x}; key={OUTPUT_KEY!r}; "
        f"sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
