#!/usr/bin/env python3
"""Decode the historical game-server certificate from StartScript_Connector.

The connector script Base64-decodes a string before passing it to
``client.setSSLParameters``.  The native callback at ARM64 0x1eb964 decrypts
complete DES-ECB blocks with the bit-reversed key ``NakFpz15`` and installs the
result as the game-server verify buffer.  This script mirrors that path
without opening a socket.

The recovered certificate is public historical trust material.  It is written
only when ``--output`` is supplied, and the output should normally stay
outside the repository.
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


DEFAULT_STRINGS = Path("analysis/StartScript_Connector.bytecode/strings.json")
DEFAULT_STRING_INDEX = 143
DES_KEY = b"NakFpz15"
EXPECTED_GRAALWEB_DER_SHA256 = (
    "2e6425395e91baab7be95d9918de198684bcb718800bff07113e7f336d06ce56"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reverse_bits_each_byte(data: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in data)


def native_des_decrypt(data: bytes) -> tuple[bytes, int]:
    """Mirror the native full-block-only DES transform."""

    full_length = len(data) - (len(data) % 8)
    cipher = DES.new(reverse_bits_each_byte(DES_KEY), DES.MODE_ECB)
    plaintext = cipher.decrypt(data[:full_length]) + data[full_length:]
    return plaintext, full_length


def read_script_string(strings_path: Path, index: int) -> str:
    values = json.loads(strings_path.read_text())
    if not isinstance(values, list):
        raise ValueError("the script strings file must contain a JSON array")
    if index < 0 or index >= len(values):
        raise ValueError(f"string index {index} is outside the strings array")
    value = values[index]
    if not isinstance(value, str):
        raise ValueError(f"string index {index} is not a text literal")
    return value


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "strings_json",
        type=Path,
        nargs="?",
        default=DEFAULT_STRINGS,
        help="HexaParser JSON string table from StartScript_Connector",
    )
    parser.add_argument("--string-index", type=int, default=DEFAULT_STRING_INDEX)
    parser.add_argument(
        "--output",
        type=Path,
        help="optional DER output path; keep it outside the repository",
    )
    args = parser.parse_args()

    encoded = read_script_string(args.strings_json, args.string_index)
    ciphertext = base64.b64decode(encoded, validate=True)
    decrypted, full_length = native_des_decrypt(ciphertext)
    certificate = x509.load_der_x509_certificate(decrypted)
    certificate_der = certificate.public_bytes(Encoding.DER)

    if certificate_der != decrypted:
        raise ValueError(
            "the decrypted bytes contain a DER certificate with unexpected re-encoding"
        )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(decrypted)

    report = {
        "strings_json": str(args.strings_json),
        "script_string_index": args.string_index,
        "base64_characters": len(encoded),
        "encoded_text_sha256": sha256(encoded.encode("ascii")),
        "ciphertext_bytes": len(ciphertext),
        "ciphertext_sha256": sha256(ciphertext),
        "des_key": DES_KEY.decode("ascii"),
        "des_key_bit_reversed_hex": reverse_bits_each_byte(DES_KEY).hex(),
        "des_full_block_bytes": full_length,
        "des_unprocessed_tail_hex": ciphertext[full_length:].hex(),
        "certificate": certificate_metadata(certificate),
        "matches_graalweb_bundle_first_certificate": (
            sha256(decrypted) == EXPECTED_GRAALWEB_DER_SHA256
        ),
        "native_callback_arm64": "0x1eb964",
        "network_contacted": False,
        "output": str(args.output) if args.output else None,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
