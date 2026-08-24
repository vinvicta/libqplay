#!/usr/bin/env python3
"""Historical negative control for the handler-pair interpretation.

This patch is intentionally not a repair. The earlier analysis assumed that
the VM built the handler array in reverse stack order. The native
setInDataHandlers loop and the successful replay show that the actual pair is
already
  packet_type, handler_index
in this library revision.

The script remains useful only when reproducing the rejected xchg experiment.
It should not be used for a working diagnostic APK.
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
        f"applied rejected handler-pair negative control at 0x{PATCH_VA:x}; "
        f"sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
