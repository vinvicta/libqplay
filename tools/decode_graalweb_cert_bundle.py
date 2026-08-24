#!/usr/bin/env python3
"""Recover the embedded GraalWeb trust bundle without opening a socket.

The old client stores a base64 string in the ARM64 library.  The native
decoder uses the ordinary RFC 4648 alphabet, then DES-ECB-decrypts complete
blocks with the bit order reversed in each key byte.  Any short final block
is left unchanged.  This script mirrors that behavior and prints certificate
metadata.  It writes the recovered PEM bundle only when ``--output`` is
provided.

The recovered material is historical trust data, not a current replacement
for the connector certificate.  Keep output files outside the repository.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

from Cryptodome.Cipher import DES
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding


DEFAULT_LIBRARY = Path(
    "GraalOnline+Classic_1.8_APKPure/lib/arm64-v8a/libqplay.so"
)
CERT_PREFIX = b"6erxf21jcqpGrZR4"
CERT_TEXT_LENGTH = 12820
DES_KEY = b"jhOdx9SY"
PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN ?CERTIFICATE-----.*?-----END ?CERTIFICATE-----\r?\n?",
    re.DOTALL,
)
EXPECTED_TEXT_SHA256 = (
    "c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reverse_bits_each_byte(data: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in data)


def recover_bundle(library: bytes) -> tuple[int, bytes, bytes, bytes]:
    start = library.find(CERT_PREFIX)
    if start < 0:
        raise ValueError("embedded certificate string was not found")
    end = library.find(b"\0", start)
    if end < 0:
        raise ValueError("embedded certificate string is not NUL terminated")

    encoded = library[start:end]
    if len(encoded) != CERT_TEXT_LENGTH:
        raise ValueError(
            f"unexpected encoded certificate length: {len(encoded)} "
            f"(expected {CERT_TEXT_LENGTH})"
        )
    if sha256(encoded) != EXPECTED_TEXT_SHA256:
        raise ValueError("embedded certificate hash does not match this build")

    ciphertext = base64.b64decode(encoded, validate=True)
    full_length = len(ciphertext) - (len(ciphertext) % 8)
    cipher = DES.new(reverse_bits_each_byte(DES_KEY), DES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext[:full_length]) + ciphertext[full_length:]
    return start, encoded, ciphertext, plaintext


def certificate_metadata(bundle: bytes) -> list[dict[str, object]]:
    pem_blocks = PEM_CERTIFICATE.findall(bundle)
    if not pem_blocks:
        raise ValueError("decrypted payload did not contain PEM certificates")

    result = []
    for index, pem in enumerate(pem_blocks):
        normalized_pem = pem.replace(
            b"-----BEGINCERTIFICATE-----", b"-----BEGIN CERTIFICATE-----"
        ).replace(b"-----ENDCERTIFICATE-----", b"-----END CERTIFICATE-----")
        cert = x509.load_pem_x509_certificate(normalized_pem)
        result.append(
            {
                "index": index,
                "pem_bytes": len(pem),
                "pem_sha256": sha256(pem),
                "normalized_pem_bytes": len(normalized_pem),
                "normalized_pem_sha256": sha256(normalized_pem),
                "marker_style": (
                    "missing-space" if b"BEGINCERTIFICATE" in pem else "standard"
                ),
                "der_sha256": sha256(cert.public_bytes(Encoding.DER)),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": format(cert.serial_number, "X").zfill(2),
                "not_before": cert.not_valid_before.isoformat() + "Z",
                "not_after": cert.not_valid_after.isoformat() + "Z",
                "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            }
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=Path, nargs="?", default=DEFAULT_LIBRARY)
    parser.add_argument(
        "--output",
        type=Path,
        help="optional PEM output path; keep it outside the repository",
    )
    args = parser.parse_args()

    library_bytes = args.library.read_bytes()
    offset, encoded, ciphertext, bundle = recover_bundle(library_bytes)
    certificates = certificate_metadata(bundle)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(bundle)

    summary = {
        "library": str(args.library),
        "library_sha256": sha256(library_bytes),
        "encoded_file_offset": hex(offset),
        "encoded_bytes": len(encoded),
        "encoded_sha256": sha256(encoded),
        "ciphertext_bytes": len(ciphertext),
        "ciphertext_sha256": sha256(ciphertext),
        "des_key": DES_KEY.decode("ascii"),
        "des_key_bit_reversed_hex": reverse_bits_each_byte(DES_KEY).hex(),
        "des_full_block_bytes": len(ciphertext) - (len(ciphertext) % 8),
        "des_unprocessed_tail_hex": ciphertext[len(ciphertext) - (len(ciphertext) % 8) :].hex(),
        "bundle_bytes": len(bundle),
        "bundle_sha256": sha256(bundle),
        "certificate_count": len(certificates),
        "certificates": certificates,
        "output": str(args.output) if args.output else None,
        "network_contacted": False,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
