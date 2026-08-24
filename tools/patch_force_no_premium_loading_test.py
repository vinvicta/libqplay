#!/usr/bin/env python3
"""Force the ARM64 environment setup through its non-premium branch.

``TClientEnvironment::sigcheck`` clears the native loading-screen flag only
when the decoded premium option is zero or negative.  The ARM64 diagnostic
client keeps the flag set while the x86_64 replay reaches the game renderer.
This test changes only that conditional branch so the original flag-clear
path runs, while leaving the rest of environment initialization and the
normal render loop untouched.

This is a local diagnostic patch for the matching ARM64 library.  It does not
contact a live service and is not a release patch.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


PATCH_OFFSET = 0x15CA7C
PATCH_ORIGINAL = bytes.fromhex("2d 02 00 54")  # b.le 0x15cac0
PATCH_REPLACEMENT = struct.pack("<I", 0x14000011)  # b 0x15cac0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    actual = bytes(blob[PATCH_OFFSET : PATCH_OFFSET + len(PATCH_ORIGINAL)])
    if actual != PATCH_ORIGINAL:
        raise SystemExit(
            f"unexpected bytes at 0x{PATCH_OFFSET:x}: {actual.hex(' ')}"
        )

    blob[PATCH_OFFSET : PATCH_OFFSET + len(PATCH_ORIGINAL)] = PATCH_REPLACEMENT
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        f"patched non-premium loading branch at 0x{PATCH_OFFSET:x}; "
        f"sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
