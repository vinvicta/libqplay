#!/usr/bin/env python3
"""Diagnostic x86_64 repair for reversed script handler pairs.

The VM builds the handler array in reverse stack order on this build.  The
native setInDataHandlers loop expects each normal pair as
  packet_type, handler_index
but receives
  handler_index, packet_type.

At the default-handler path, exchange the two byte values before the native
lookup/store.  The special 0xfc..0xff cases branch around this site and are
left unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PATCH_VA = 0x202EA5
ORIGINAL = bytes.fromhex("48 63 c9")
REPLACEMENT = bytes.fromhex("87 ca 90")  # xchg ecx, edx; nop


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    actual = blob[PATCH_VA : PATCH_VA + len(ORIGINAL)]
    if actual != ORIGINAL:
        raise SystemExit(
            f"unexpected bytes at 0x{PATCH_VA:x}: {actual.hex(' ')}"
        )
    blob[PATCH_VA : PATCH_VA + len(REPLACEMENT)] = REPLACEMENT
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        f"swapped normal setInDataHandlers pair order at 0x{PATCH_VA:x}; "
        f"sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
