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


def rel32(site: int, target: int) -> bytes:
    return struct.pack("<i", target - (site + 5))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
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

    # r12 points at the output cipherkey TString in setEncryptionOut.  Its
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
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        f"patched outgoing RC4 key at 0x{CALL_SITE:x}; "
        f"key={OUTPUT_KEY!r}; sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
