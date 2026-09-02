#!/usr/bin/env python3
"""Move the legacy connector's diagnostic HTTPS and HTTP ports.

This is a local-only diagnostic for an ADB reverse mapping or a test proxy.
It changes only the default ports selected by the URL parser. The HTTP/HTTPS
flag, hostname, certificate validation, and RSA package check are left
unchanged. It is not a production endpoint patch.

On ARM64, ``--fallback-port`` is optional and changes the two plain-HTTP
defaults independently. On x86_64, the compiler folded the HTTP and HTTPS
defaults into one expression, so the plain-HTTP port must be exactly 363 less
than the HTTPS port.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


ORIGINAL_ARM64_PATCHES = (
    (0x200DF0, bytes.fromhex("61 37 80 52")),
    (0x200F74, bytes.fromhex("61 37 80 52")),
)
X86_64_PATCH = (0x2184B9, bytes.fromhex("05 bb 01 00 00"))
X86_64_HTTP_DELTA = 0x16B


def arm64_mov_w(register: int, immediate: int) -> bytes:
    if not 0 <= immediate <= 0xFFFF:
        raise SystemExit("ARM64 diagnostic port must fit in a 16-bit immediate")
    return struct.pack("<I", 0x52800000 | (immediate << 5) | register)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("arm64-v8a", "x86_64"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument(
        "--fallback-port",
        type=int,
        help=(
            "optional plain-HTTP fallback port; on x86_64 it must equal "
            "--port - 363"
        ),
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    if args.fallback_port is not None and not 1 <= args.fallback_port <= 65535:
        raise SystemExit("fallback port must be between 1 and 65535")

    blob = bytearray(args.input.read_bytes())
    if args.arch == "arm64-v8a":
        patches = [
            (address, original, arm64_mov_w(1, args.port))
            for address, original in ORIGINAL_ARM64_PATCHES
        ]
        if args.fallback_port is not None:
            patches.extend(
                (
                    address,
                    original,
                    arm64_mov_w(0, args.fallback_port),
                )
                for address, original in (
                    (0x200DF4, bytes.fromhex("00 0a 80 52")),
                    (0x200F78, bytes.fromhex("00 0a 80 52")),
                )
            )
        fallback_port = args.fallback_port if args.fallback_port is not None else 80
    else:
        fallback_port = args.port - X86_64_HTTP_DELTA
        if fallback_port < 1:
            raise SystemExit("x86_64 HTTPS port must be greater than 363")
        if args.fallback_port is not None and args.fallback_port != fallback_port:
            raise SystemExit(
                "x86_64 fallback port is fixed at HTTPS port minus 363 "
                f"({fallback_port})"
            )
        patches = [(X86_64_PATCH[0], X86_64_PATCH[1], b"\x05" + struct.pack("<I", args.port))]

    for address, original, replacement in patches:
        actual = bytes(blob[address : address + len(original)])
        if actual != original:
            raise SystemExit(
                f"unexpected bytes at 0x{address:x}: {actual.hex(' ')}"
            )
        blob[address : address + len(replacement)] = replacement
        print(f"patched 0x{address:x}: {original.hex(' ')} -> {replacement.hex(' ')}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(f"diagnostic defaults: https={args.port} http={fallback_port}")
    print(f"sha256={hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()
