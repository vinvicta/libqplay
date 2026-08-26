#!/usr/bin/env python3
"""Restore the stock ARM64 premium loading branch in a diagnostic library.

This is the inverse of ``patch_force_no_premium_loading_test.py``.  It is used
for a matched negative control: the connector, transport, and resource path
can stay diagnostic while the loading-state branch returns to the original
``B.LE`` instruction.  The patcher checks the forced-branch bytes before
writing and does not contact a service.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PATCH_OFFSET = 0x15CA7C
PATCH_ORIGINAL = bytes.fromhex("11 00 00 14")  # b 0x15cac0
PATCH_REPLACEMENT = bytes.fromhex("2d 02 00 54")  # b.le 0x15cac0


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
        f"restored stock premium loading branch at 0x{PATCH_OFFSET:x}; "
        f"sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
