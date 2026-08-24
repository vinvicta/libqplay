#!/usr/bin/env python3
"""Encode a certificate for the recovered game-server TLS script argument.

The connector script Base64-decodes string-table entry 143 before calling
``client.setSSLParameters``.  The native callback at ARM64 0x1eb964 then
decrypts complete DES-ECB blocks with the bit-reversed key ``NakFpz15`` and
leaves a short final block unchanged.  This tool performs the inverse for a
single certificate-only PEM input and writes an updated JSON string table when
``--output`` is supplied.

This is an offline preparation step.  The resulting string table still needs
to be compiled, packed, and signed for the intended client and endpoint.
Verification remains enabled.  No socket is opened.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from Cryptodome.Cipher import DES
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding


DEFAULT_STRING_INDEX = 143
DEFAULT_MAX_BASE64_CHARACTERS = 960
DES_KEY = b"NakFpz15"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reverse_bits_each_byte(data: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in data)


def native_des_encrypt(data: bytes) -> tuple[bytes, int]:
    """Mirror the native full-block-only DES transform in reverse."""

    full_length = len(data) - (len(data) % 8)
    cipher = DES.new(reverse_bits_each_byte(DES_KEY), DES.MODE_ECB)
    ciphertext = cipher.encrypt(data[:full_length]) + data[full_length:]
    return ciphertext, full_length


def native_des_decrypt(data: bytes) -> bytes:
    full_length = len(data) - (len(data) % 8)
    cipher = DES.new(reverse_bits_each_byte(DES_KEY), DES.MODE_ECB)
    return cipher.decrypt(data[:full_length]) + data[full_length:]


def read_strings(strings_path: Path) -> list[object]:
    values = json.loads(strings_path.read_text())
    if not isinstance(values, list):
        raise ValueError("the script strings file must contain a JSON array")
    return values


def certificate_metadata(certificate: x509.Certificate) -> dict[str, object]:
    der = certificate.public_bytes(Encoding.DER)
    return {
        "der_bytes": len(der),
        "der_sha256": sha256(der),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial": format(certificate.serial_number, "X").zfill(2),
        "not_before": certificate.not_valid_before.isoformat() + "Z",
        "not_after": certificate.not_valid_after.isoformat() + "Z",
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
    }


def read_single_certificate(certificate_path: Path) -> tuple[x509.Certificate, bytes]:
    pem = certificate_path.read_bytes()
    if b"PRIVATE KEY" in pem or b"CERTIFICATE REQUEST" in pem:
        raise ValueError("the replacement must be a certificate-only PEM file")
    if pem.count(b"-----BEGIN CERTIFICATE-----") != 1:
        raise ValueError("the replacement must contain exactly one PEM certificate")
    certificate = x509.load_pem_x509_certificate(pem)
    return certificate, certificate.public_bytes(Encoding.DER)


def write_strings(strings_path: Path, output_path: Path, values: list[object]) -> None:
    if output_path.resolve() == strings_path.resolve():
        raise ValueError("refusing to overwrite the input string table")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(values, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "strings_json",
        type=Path,
        help="HexaParser JSON string table from StartScript_Connector",
    )
    parser.add_argument(
        "certificate_pem",
        type=Path,
        help="one certificate-only PEM file for the authorized endpoint",
    )
    parser.add_argument("--string-index", type=int, default=DEFAULT_STRING_INDEX)
    parser.add_argument(
        "--output",
        type=Path,
        help="optional output JSON path; the input string table is never changed",
    )
    parser.add_argument(
        "--max-base64-characters",
        type=int,
        default=DEFAULT_MAX_BASE64_CHARACTERS,
        help="maximum encoded length for in-place-compatible replacement; use 0 to disable",
    )
    args = parser.parse_args()

    values = read_strings(args.strings_json)
    if args.string_index < 0 or args.string_index >= len(values):
        raise ValueError(f"string index {args.string_index} is outside the strings array")
    if not isinstance(values[args.string_index], str):
        raise ValueError(f"string index {args.string_index} is not a text literal")

    certificate, der = read_single_certificate(args.certificate_pem)
    ciphertext, full_length = native_des_encrypt(der)
    encoded = base64.b64encode(ciphertext).decode("ascii")
    if args.max_base64_characters and len(encoded) > args.max_base64_characters:
        raise ValueError(
            f"encoded certificate is {len(encoded)} characters, exceeding the "
            f"configured limit of {args.max_base64_characters}"
        )

    decoded = native_des_decrypt(base64.b64decode(encoded, validate=True))
    if decoded != der:
        raise ValueError("native DES round trip did not reproduce the certificate DER")
    parsed = x509.load_der_x509_certificate(decoded)
    if parsed.public_bytes(Encoding.DER) != der:
        raise ValueError("round-tripped DER certificate did not re-encode identically")

    original = values[args.string_index]
    values[args.string_index] = encoded
    if args.output:
        write_strings(args.strings_json, args.output, values)

    report = {
        "strings_json": str(args.strings_json),
        "output": str(args.output) if args.output else None,
        "script_string_index": args.string_index,
        "original_base64_characters": len(original),
        "replacement_base64_characters": len(encoded),
        "replacement_encoded_text_sha256": sha256(encoded.encode("ascii")),
        "ciphertext_bytes": len(ciphertext),
        "ciphertext_sha256": sha256(ciphertext),
        "des_key": DES_KEY.decode("ascii"),
        "des_key_bit_reversed_hex": reverse_bits_each_byte(DES_KEY).hex(),
        "des_full_block_bytes": full_length,
        "des_unprocessed_tail_hex": der[full_length:].hex(),
        "certificate": certificate_metadata(certificate),
        "native_callback_arm64": "0x1eb964",
        "verification_bypassed": False,
        "network_contacted": False,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
