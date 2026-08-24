#!/usr/bin/env python3
"""Force recognized HTTPS URLs through the legacy parser's HTTP transport.

The parser still validates and strips the eight-byte ``https://`` prefix, but
these small instruction patches make its returned port configurable and its
returned SSL flag false. This keeps the generated connector URL intact while
isolating the server response path from TLS. It is diagnostic-only.
"""

from pathlib import Path
import argparse
import hashlib
import struct


def x86_patches(port: int) -> list[tuple[int, bytes, bytes]]:
    return [
        (0x2184B2, bytes.fromhex("19 c0"), bytes.fromhex("31 c0")),
        (
            0x2184B9,
            bytes.fromhex("05 bb 01 00 00"),
            b"\x05" + struct.pack("<I", port),
        ),
        (0x2184C5, bytes.fromhex("19 d2"), bytes.fromhex("31 d2")),
        (0x218565, bytes.fromhex("40 88 28"), bytes.fromhex("c6 00 00")),
    ]


def arm64_mov_w(register: int, immediate: int) -> bytes:
    if not 0 <= immediate <= 0xFFFF:
        raise SystemExit("ARM64 diagnostic port must fit in a 16-bit immediate")
    instruction = 0x52800000 | (immediate << 5) | register
    return struct.pack("<I", instruction)


def arm64_patches(port: int) -> list[tuple[int, bytes, bytes]]:
    move_w1_443 = bytes.fromhex("61 37 80 52")
    move_w0_80 = bytes.fromhex("00 0a 80 52")
    move_w1_port = arm64_mov_w(1, port)
    move_w0_port = arm64_mov_w(0, port)
    return [
        (0x200DE0, bytes.fromhex("f8 03 17 2a"), bytes.fromhex("f8 03 1f 2a")),
        (0x200DF0, move_w1_443, move_w1_port),
        (0x200DF4, move_w0_80, move_w0_port),
        (0x200F74, move_w1_443, move_w1_port),
        (0x200F78, move_w0_80, move_w0_port),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("x86_64", "arm64-v8a"), default="x86_64")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="diagnostic TCP port; defaults to 80 for x86_64 and 18080 for ARM64",
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    port = args.port if args.port is not None else (18080 if args.arch == "arm64-v8a" else 80)
    patches = x86_patches(port) if args.arch == "x86_64" else arm64_patches(port)
    blob = bytearray(args.input.read_bytes())
    for address, original, replacement in patches:
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
