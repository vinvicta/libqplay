#!/usr/bin/env python3
"""Force recognized HTTPS URLs through the legacy parser's HTTP transport.

The parser still validates and strips the eight-byte ``https://`` prefix, but
these small instruction patches make its returned port 80 and its returned
SSL flag false.  This keeps the generated connector URL intact while
isolating the server response path from TLS.  It is diagnostic-only.
"""

from pathlib import Path
import argparse
import hashlib


PATCHES = [
    (0x2184B2, bytes.fromhex("19 c0"), bytes.fromhex("31 c0")),
    (0x2184B9, bytes.fromhex("05 bb 01 00 00"), bytes.fromhex("05 50 00 00 00")),
    (0x2184C5, bytes.fromhex("19 d2"), bytes.fromhex("31 d2")),
    (0x218565, bytes.fromhex("40 88 28"), bytes.fromhex("c6 00 00")),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    for address, original, replacement in PATCHES:
        if blob[address : address + len(original)] != original:
            raise SystemExit(
                f"unexpected bytes at 0x{address:x}: "
                f"{blob[address:address + len(original)].hex(' ')}"
            )
        blob[address : address + len(replacement)] = replacement
        print(f"patched 0x{address:x}: {original.hex(' ')} -> {replacement.hex(' ')}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(f"sha256={hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()
