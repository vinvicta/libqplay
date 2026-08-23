#!/usr/bin/env python3
"""Apply the reconstructed compatibility repairs to a native libqplay.so.

This is an offline patcher for the two APK architectures.  It deliberately
checks every original byte before writing, so it cannot silently patch a
different library revision.

Repairs:
  * swap normal setInDataHandlers pair operands (the script VM reverses the
    stack-built array on this build);
  * accept connector packages whose RSA signature no longer verifies; and
  * disable the expired embedded GraalWeb certificate check.

The last two repairs are compatibility diagnostics for this archival client;
they should only be used with a trusted connector/server endpoint.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PATCHES = {
    "x86_64": [
        (0x202EA5, bytes.fromhex("48 63 c9"), bytes.fromhex("87 ca 90"), "swap input handler operands"),
        (0x245009, bytes.fromhex("75 1d"), bytes.fromhex("eb 1d"), "accept connector RSA result"),
        (0x222270, bytes.fromhex("41 56 48 8d 35"), bytes.fromhex("c3 90 90 90 90"), "skip expired TLS certificate"),
    ],
    "arm64-v8a": [
        (0x1EA7AC, bytes.fromhex("00 d8 62 f8"), bytes.fromhex("00 d8 61 f8"), "lookup input handler by packet byte"),
        (0x1EA7B4, bytes.fromhex("40 d8 21 f8"), bytes.fromhex("40 d8 22 f8"), "store input handler by handler byte"),
        (0x22C5C8, bytes.fromhex("dc 00 00 35"), bytes.fromhex("06 00 00 14"), "accept connector RSA result"),
        (0x20AB20, bytes.fromhex("ff 43 01 d1"), bytes.fromhex("c0 03 5f d6"), "skip expired TLS certificate"),
    ],
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=sorted(PATCHES), required=True)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    for address, original, replacement, description in PATCHES[args.arch]:
        actual = blob[address : address + len(original)]
        if actual != original:
            raise SystemExit(
                f"unexpected bytes at 0x{address:x} for {description}: "
                f"{actual.hex(' ')}"
            )
        blob[address : address + len(replacement)] = replacement
        print(f"patched 0x{address:x}: {description}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(f"sha256={hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()
