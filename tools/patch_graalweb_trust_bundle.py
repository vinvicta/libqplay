#!/usr/bin/env python3
"""Replace the native GraalWeb PEM bundle while keeping TLS verification on.

The old client stores its trust bundle as Base64 text containing a DES-ECB
ciphertext. The native DES helper reverses the bit order in each byte of
``jhOdx9SY`` and decrypts complete eight-byte blocks only. This tool applies
the inverse transform to a user-supplied PEM bundle, checks the result by
round-tripping it through the native decoder, and replaces the fixed string
in a private copy of a matching library.

This is deliberately different from the certificate-skip diagnostic. The
patched library still loads the supplied certificates into CyaSSL and keeps
peer and hostname verification enabled. The supplied chain must be current
and authorized for the endpoint being tested. No private key is accepted or
written by this tool.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


CERT_TEXT_LENGTH = 12820
DES_KEY = b"jhOdx9SY"
EXPECTED_TEXT_SHA256 = (
    "c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0"
)
CERT_OFFSETS_BY_VARIANT = {
    "original": {
    "arm64-v8a": 0x2DCEF8,
    "x86_64": 0x2FCA80,
    "x86": 0x2ECB08,
    "armeabi": 0x21A438,
    },
    "spectron": {
        "arm64-v8a": 0x2EA9E0,
    },
}
# Kept as a compatibility alias for code that used the original offsets.
CERT_OFFSETS = CERT_OFFSETS_BY_VARIANT["original"]
PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\r?\n?",
    re.DOTALL,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reverse_key_bits(key: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in key)


def native_des_transform(data: bytes, *, encrypt: bool) -> bytes:
    """Mirror the native complete-block DES transform in either direction."""

    full_length = len(data) - (len(data) % 8)
    cipher = Cipher(
        algorithms.TripleDES(reverse_key_bits(DES_KEY) * 3), modes.ECB()
    )
    context = cipher.encryptor() if encrypt else cipher.decryptor()
    transformed = context.update(data[:full_length]) + context.finalize()
    return transformed + data[full_length:]


def normalize_bundle(bundle: bytes) -> tuple[bytes, int]:
    """Validate a PEM certificate-only bundle and normalize line endings."""

    if b"PRIVATE KEY" in bundle:
        raise ValueError("the trust bundle must not contain a private key")
    normalized = bundle.replace(b"\r\n", b"\n")
    blocks = PEM_CERTIFICATE.findall(normalized)
    if not blocks:
        raise ValueError("the bundle does not contain a PEM certificate")
    remainder = PEM_CERTIFICATE.sub(b"", normalized)
    if remainder.strip():
        raise ValueError("the bundle may contain only PEM certificate blocks")
    try:
        for block in blocks:
            x509.load_pem_x509_certificate(block)
    except ValueError as error:
        raise ValueError(
            "the bundle contains a malformed or unsupported PEM certificate"
        ) from error
    canonical = b"".join(
        block if block.endswith(b"\n") else block + b"\n" for block in blocks
    )
    return canonical, len(blocks)


def encode_native_bundle(bundle: bytes) -> bytes:
    ciphertext = native_des_transform(bundle, encrypt=True)
    encoded = base64.b64encode(ciphertext)
    if len(encoded) > CERT_TEXT_LENGTH:
        raise ValueError(
            "encoded replacement does not fit the native string: "
            f"{len(encoded)} > {CERT_TEXT_LENGTH} bytes"
        )
    decoded = base64.b64decode(encoded, validate=True)
    if native_des_transform(decoded, encrypt=False) != bundle:
        raise ValueError("native DES/Base64 round-trip did not reproduce the bundle")
    return encoded


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=sorted(CERT_OFFSETS_BY_VARIANT), default="original")
    parser.add_argument("--arch", choices=("arm64-v8a", "armeabi", "x86", "x86_64"), required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.input.read_bytes())
    offsets = CERT_OFFSETS_BY_VARIANT[args.variant]
    if args.arch not in offsets:
        raise SystemExit(
            f"{args.variant} has no trust-bundle slot for architecture {args.arch}"
        )
    offset = offsets[args.arch]
    expected = bytes(blob[offset : offset + CERT_TEXT_LENGTH])
    if len(expected) != CERT_TEXT_LENGTH or sha256(expected) != EXPECTED_TEXT_SHA256:
        raise SystemExit(
            f"unexpected embedded trust string at 0x{offset:x}: "
            f"length={len(expected)} sha256={sha256(expected)}"
        )
    if blob[offset + CERT_TEXT_LENGTH] != 0:
        raise SystemExit("embedded trust string is not NUL terminated")

    try:
        bundle, certificate_count = normalize_bundle(args.bundle.read_bytes())
        replacement = encode_native_bundle(bundle)
    except ValueError as error:
        raise SystemExit(f"invalid replacement bundle: {error}") from error
    padded = replacement.ljust(CERT_TEXT_LENGTH, b"\0")
    blob[offset : offset + CERT_TEXT_LENGTH] = padded
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)

    report = {
        "arch": args.arch,
        "offset": hex(offset),
        "certificate_count": certificate_count,
        "bundle_bytes": len(bundle),
        "bundle_sha256": sha256(bundle),
        "encoded_bytes": len(replacement),
        "encoded_sha256": sha256(replacement),
        "output_sha256": sha256(blob),
        "network_contacted": False,
    }
    print("patched native trust bundle")
    for key, value in report.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
