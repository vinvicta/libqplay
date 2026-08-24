#!/usr/bin/env python3
"""Apply the connector compatibility diagnostics to a native libqplay.so.

This is an offline patcher for the two APK architectures.  It deliberately
checks every original byte before writing, so it cannot silently patch a
different library revision.

Diagnostics, enabled by default:
  * accept connector packages whose RSA signature no longer verifies; and
  * disable the expired embedded GraalWeb certificate check.

Use ``--skip-rsa-bypass`` when the response is already known to pass the
native wolfSSL check. The saved local connector fixture does, so this option
is the correct starting point for a package-preserving replay.

The last two repairs are compatibility diagnostics for this archival client;
they should only be used with a trusted connector/server endpoint.

The normal setInDataHandlers instructions are intentionally not patched. An
earlier operand-swap experiment was disproved by the decoded runtime table and
the successful no-swap replay. See docs/PROTOCOL.md for the evidence.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PATCHES = {
    "x86_64": [
        (0x245009, bytes.fromhex("75 1d"), bytes.fromhex("eb 1d"), "accept connector RSA result"),
        (0x222270, bytes.fromhex("41 56 48 8d 35"), bytes.fromhex("c3 90 90 90 90"), "skip expired TLS certificate"),
    ],
    "arm64-v8a": [
        (0x22C5C8, bytes.fromhex("dc 00 00 35"), bytes.fromhex("06 00 00 14"), "accept connector RSA result"),
        (0x20AB20, bytes.fromhex("ff 43 01 d1"), bytes.fromhex("c0 03 5f d6"), "skip expired TLS certificate"),
    ],
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=sorted(PATCHES), required=True)
    parser.add_argument(
        "--skip-rsa-bypass",
        action="store_true",
        help="leave the native connector RSA result branch unchanged",
    )
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
        if args.skip_rsa_bypass and description == "accept connector RSA result":
            print(f"left 0x{address:x} unchanged: {description}")
            continue
        blob[address : address + len(replacement)] = replacement
        print(f"patched 0x{address:x}: {description}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(f"sha256={hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()
