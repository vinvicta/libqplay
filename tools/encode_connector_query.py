#!/usr/bin/env python3
"""Encode the legacy connector query without opening a network connection.

The native client uses DES-ECB with the bits in each key byte reversed. It
encrypts complete blocks only, leaves a short final block unchanged, then
Base64-encodes and URL-escapes the result. The list serializer also quotes an
entire item when it contains a space, so the build item is emitted as
``"b=Jul  4 2019 09:35:48"``.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEFAULT_KEY = "GP1Lq9Y4"
DEFAULT_VERSION = "6.15401"
DEFAULT_BUILD = "Jul  4 2019 09:35:48"


def reverse_key_bits(key: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in key)


def native_des_encrypt(data: bytes, key: bytes) -> bytes:
    """Mirror TEncryption::des_encryptmemory's full-block behavior."""

    if len(key) < 8:
        raise ValueError("DES key must contain at least eight bytes")
    native_key = reverse_key_bits(key[:8])
    full_length = len(data) // 8 * 8
    encryptor = Cipher(
        algorithms.TripleDES(native_key * 3), modes.ECB()
    ).encryptor()
    return (
        encryptor.update(data[:full_length])
        + encryptor.finalize()
        + data[full_length:]
    )


def escaped34(value: str) -> str:
    """Mirror the native list item's quote and backslash behavior."""

    needs_quotes = any(
        char == "\\"
        or char == '"'
        or char == ","
        or char == " "
        or ord(char) <= 0x1D
        for char in value
    )
    if not needs_quotes:
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_plaintext(
    premium: str, platform: str, version: str, build: str
) -> str:
    items = [
        f"g={premium}",
        f"p={platform}",
        f"v={version}",
        escaped34(f"b={build}"),
    ]
    return ",".join(items)


def encode_query(plaintext: str, key: str) -> str:
    encrypted = native_des_encrypt(plaintext.encode("utf-8"), key.encode("utf-8"))
    return quote(base64.b64encode(encrypted).decode("ascii"), safe="")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--premium", default="classic")
    parser.add_argument("--platform", default="android")
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--build", default=DEFAULT_BUILD)
    parser.add_argument("--key", default=DEFAULT_KEY)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--show-plaintext", action="store_true")
    args = parser.parse_args()

    plaintext = build_plaintext(
        args.premium, args.platform, args.version, args.build
    )
    encoded = encode_query(plaintext, args.key)
    if args.output:
        args.output.write_text(encoded)
    if args.show_plaintext:
        print(plaintext)
    print(encoded)


if __name__ == "__main__":
    main()
