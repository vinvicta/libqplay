#!/usr/bin/env python3
"""Replace the game-server certificate literal in recovered GS2 source.

The recovered ``StartScript_Connector`` source has two calls to
``setSSLParameters``.  Both calls pass the same Base64 literal through
``base64decode``.  The native callback at ARM64 0x1eb964 decrypts that value
with the bit-reversed DES key ``NakFpz15`` before it installs the verify
buffer.  This tool prepares a source-level replacement for HexaParser and
leaves the input source unchanged.

This is an offline preparation step.  The resulting source still needs to be
compiled, packed, signed, and tested against an endpoint that the operator is
authorized to use.  Verification remains enabled, and no socket is opened.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from encode_game_server_tls_certificate import (
    DES_KEY,
    certificate_metadata,
    native_des_decrypt,
    native_des_encrypt,
    read_single_certificate,
    reverse_bits_each_byte,
    sha256,
)


DEFAULT_EXPECTED_OCCURRENCES = 2
DEFAULT_STRING_INDEX = 143

# Keep the match bounded by the call's semicolon.  The recovered source keeps
# each call on one line, but DOTALL also handles compiler/decompiler output
# that wraps the argument list.  Only the literal inside setSSLParameters is
# replaced, so other Base64 values such as the NewGraal parse key are left
# untouched.
SSL_CERTIFICATE_LITERAL = re.compile(
    r"(?P<prefix>\bsetSSLParameters\s*\((?:(?!;).)*?base64decode\s*\(\s*\")"
    r"(?P<encoded>[A-Za-z0-9+/=]+)"
    r"(?P<suffix>\"\s*\)\s*\))",
    re.DOTALL,
)


def read_text_preserving_newlines(path: Path) -> tuple[bytes, str]:
    raw = path.read_bytes()
    return raw, raw.decode("utf-8")


def decode_original_certificate(encoded: str) -> tuple[bytes, x509.Certificate]:
    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except Exception as exc:  # pragma: no cover - exact exception varies
        raise ValueError("an existing SSL certificate literal is not valid Base64") from exc
    der = native_des_decrypt(ciphertext)
    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise ValueError(
            "an existing SSL certificate literal does not decrypt to an X.509 DER certificate"
        ) from exc
    if certificate.public_bytes(Encoding.DER) != der:
        raise ValueError("an existing SSL certificate literal changed during DER re-encoding")
    return der, certificate


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "source_gs2",
        type=Path,
        help="recovered StartScript_Connector GS2 source",
    )
    parser.add_argument(
        "certificate_pem",
        type=Path,
        help="one certificate-only PEM file for the authorized endpoint",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="output GS2 path; the input source is never changed",
    )
    parser.add_argument(
        "--expected-occurrences",
        type=int,
        default=DEFAULT_EXPECTED_OCCURRENCES,
        help="require this many setSSLParameters certificate literals; 0 disables the check",
    )
    parser.add_argument(
        "--max-base64-characters",
        type=int,
        default=0,
        help="optional encoded length limit; 0 allows growth for recompilation",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="optional JSON report path",
    )
    args = parser.parse_args()

    if args.expected_occurrences < 0:
        raise ValueError("--expected-occurrences cannot be negative")
    if args.max_base64_characters < 0:
        raise ValueError("--max-base64-characters cannot be negative")
    if args.output.resolve() == args.source_gs2.resolve():
        raise ValueError("refusing to overwrite the input GS2 source")

    source_bytes, source = read_text_preserving_newlines(args.source_gs2)
    matches = list(SSL_CERTIFICATE_LITERAL.finditer(source))
    if args.expected_occurrences and len(matches) != args.expected_occurrences:
        raise ValueError(
            f"found {len(matches)} setSSLParameters certificate literals, expected "
            f"{args.expected_occurrences}"
        )
    if not matches:
        raise ValueError("no setSSLParameters certificate literal was found")

    original_details = []
    for match in matches:
        encoded = match.group("encoded")
        der, certificate = decode_original_certificate(encoded)
        original_details.append(
            {
                "base64_characters": len(encoded),
                "base64_sha256": sha256(encoded.encode("ascii")),
                "der_bytes": len(der),
                "der_sha256": sha256(der),
                "certificate": certificate_metadata(certificate),
            }
        )

    certificate, der = read_single_certificate(args.certificate_pem)
    ciphertext, full_length = native_des_encrypt(der)
    replacement = base64.b64encode(ciphertext).decode("ascii")
    if args.max_base64_characters and len(replacement) > args.max_base64_characters:
        raise ValueError(
            f"encoded certificate is {len(replacement)} characters, exceeding the "
            f"configured limit of {args.max_base64_characters}"
        )

    round_trip = native_des_decrypt(base64.b64decode(replacement, validate=True))
    if round_trip != der:
        raise ValueError("native DES round trip did not reproduce the replacement DER")
    if x509.load_der_x509_certificate(round_trip).public_bytes(Encoding.DER) != der:
        raise ValueError("round-tripped replacement is not a stable X.509 DER certificate")

    output_source = SSL_CERTIFICATE_LITERAL.sub(
        lambda match: match.group("prefix") + replacement + match.group("suffix"),
        source,
    )
    output_bytes = output_source.encode("utf-8")
    write_bytes(args.output, output_bytes)

    report = {
        "source_gs2": str(args.source_gs2),
        "output_gs2": str(args.output),
        "source_sha256": sha256(source_bytes),
        "output_sha256": sha256(output_bytes),
        "replaced_occurrences": len(matches),
        "script_string_index": DEFAULT_STRING_INDEX,
        "original_literals": original_details,
        "replacement_base64_characters": len(replacement),
        "replacement_encoded_text_sha256": sha256(replacement.encode("ascii")),
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
    if args.report:
        write_bytes(args.report, (json.dumps(report, indent=2) + "\n").encode("utf-8"))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
