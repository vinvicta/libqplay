#!/usr/bin/env python3
"""Route x86_64 legacy hostname resolution to the emulator's local proxy.

The patch replaces only ``resolveHost`` with ``127.0.0.1`` (network byte
order).  Combined with ``adb reverse tcp:80 tcp:<host-port>``, it lets a
read-only local capture server observe the connector request without
modifying the original APK or the remote service.
"""

from pathlib import Path
import argparse
import hashlib


FUNCTION_VA = 0x21D8D0
ORIGINAL_PREFIX = bytes.fromhex("48 8b 07 48 85 c0 74")
PATCH_PREFIX = bytes.fromhex("b8 7f 00 00 01 c3 90")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    if blob[FUNCTION_VA : FUNCTION_VA + len(ORIGINAL_PREFIX)] != ORIGINAL_PREFIX:
        raise SystemExit(
            f"unexpected bytes at 0x{FUNCTION_VA:x}: "
            f"{blob[FUNCTION_VA:FUNCTION_VA + len(ORIGINAL_PREFIX)].hex(' ')}"
        )

    blob[FUNCTION_VA : FUNCTION_VA + len(PATCH_PREFIX)] = PATCH_PREFIX
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        f"patched 0x{FUNCTION_VA:x}: "
        f"{ORIGINAL_PREFIX.hex(' ')} -> {PATCH_PREFIX.hex(' ')}"
    )
    print(f"sha256={hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()
