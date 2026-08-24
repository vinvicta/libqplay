#!/usr/bin/env python3
"""Force the native loading-screen getter off in a diagnostic library.

This is a negative-control patch. It helps separate a missing GUI or script
startup package from a failure to reach the game-world state. The getter also
participates in startup sequencing, so this is not a production repair.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


SPECS = {
    "x86_64": (
        0x16EE80,
        bytes.fromhex("48 8b 05 39 b7 21 00 0f b6 00 c3"),
        bytes.fromhex("31 c0 c3") + bytes(8),
    ),
    "arm64-v8a": (
        0x15D35C,
        bytes.fromhex("c0 10 00 90 00 18 47 f9 00 00 40 39 c0 03 5f d6"),
        bytes.fromhex("00 00 80 52 c0 03 5f d6") + bytes(8),
    ),
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=sorted(SPECS), default="x86_64")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    patch_offset, original, replacement = SPECS[args.arch]
    blob = bytearray(args.input.read_bytes())
    actual = bytes(blob[patch_offset : patch_offset + len(original)])
    if actual != original:
        raise SystemExit(
            f"unexpected bytes at 0x{patch_offset:x}: {actual.hex(' ')}"
        )

    blob[patch_offset : patch_offset + len(original)] = replacement
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        f"patched {args.arch} loading-screen getter at 0x{patch_offset:x}; "
        f"sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
