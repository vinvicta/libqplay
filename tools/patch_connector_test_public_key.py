#!/usr/bin/env python3
"""Replace the connector verification key in a private diagnostic library.

This is a test-only alternative to the RSA-result branch bypass.  It lets a
locally generated connector package pass the native signature check when the
library is paired with the matching test key.  It does not include a private
key and it must not be used to replace the production verification key.

The native library stores the key as base64 text after DES encryption.  The
DES helper reverses the bit order in each byte of ``PjosLg8D`` and decrypts
complete blocks only.  The patcher mirrors that encoding and checks the
original text before writing, so it cannot silently modify another revision.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from parse_connector_response import EMBEDDED_RSA_KEY_B64, DES_KEY, reverse_key_bits


PATCH_OFFSETS = {
    "arm64-v8a": 0x2E1798,
    "x86_64": 0x3003D8,
}


def native_des_encrypt(data: bytes) -> bytes:
    """Mirror the native full-block DES transform in the opposite direction."""

    full_length = len(data) // 8 * 8
    cipher = Cipher(
        algorithms.TripleDES(reverse_key_bits(DES_KEY) * 3),
        modes.ECB(),
    ).encryptor()
    return cipher.update(data[:full_length]) + cipher.finalize() + data[full_length:]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=sorted(PATCH_OFFSETS), required=True)
    parser.add_argument("--public-key-der", type=Path, required=True)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    offset = PATCH_OFFSETS[args.arch]
    original = EMBEDDED_RSA_KEY_B64.encode("ascii")
    actual = bytes(blob[offset : offset + len(original)])
    if actual != original:
        raise SystemExit(
            f"unexpected connector key text at 0x{offset:x}: "
            f"{actual[:24]!r}"
        )

    public_key = serialization.load_der_public_key(args.public_key_der.read_bytes())
    key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1,
    )
    encrypted = native_des_encrypt(key_der)
    replacement = base64.b64encode(encrypted)
    if len(replacement) != len(original):
        raise SystemExit(
            "replacement key does not fit the fixed native string: "
            f"{len(replacement)} != {len(original)} bytes"
        )

    blob[offset : offset + len(original)] = replacement
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        f"patched {args.arch} connector public key at 0x{offset:x}; "
        f"key_der_bytes={len(key_der)}; "
        f"key_der_sha256={hashlib.sha256(key_der).hexdigest()}; "
        f"sha256={hashlib.sha256(blob).hexdigest()}"
    )


if __name__ == "__main__":
    main()
