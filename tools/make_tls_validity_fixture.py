#!/usr/bin/env python3
"""Create a self-signed certificate for a local TLS validity control.

The certificate is intended for a loopback responder and a private diagnostic
APK. It is never a replacement for the authorized certificate chain used by a
real endpoint. The private key should be written outside the repository.
"""

from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def parse_time(value: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp supplied on the command line."""

    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("certificate times must include a timezone")
    return parsed.astimezone(timezone.utc)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-prefix",
        type=Path,
        required=True,
        help="write PREFIX.crt and PREFIX.key",
    )
    parser.add_argument("--hostname", default="con.quattroplay.com")
    parser.add_argument("--not-before", required=True, type=parse_time)
    parser.add_argument("--not-after", required=True, type=parse_time)
    args = parser.parse_args()

    if args.not_after <= args.not_before:
        raise SystemExit("not-after must be later than not-before")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.hostname)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(args.not_before)
        .not_valid_after(args.not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(args.hostname)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    certificate_path = args.output_prefix.with_suffix(".crt")
    key_path = args.output_prefix.with_suffix(".key")
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    certificate_path.write_bytes(certificate_pem)
    key_path.write_bytes(key_pem)

    print(f"certificate={certificate_path}")
    print(f"private_key={key_path}")
    print(f"subject={certificate.subject.rfc4514_string()}")
    print(f"san={args.hostname}")
    print(f"not_before={args.not_before.isoformat().replace('+00:00', 'Z')}")
    print(f"not_after={args.not_after.isoformat().replace('+00:00', 'Z')}")
    print(f"pem_sha256={hashlib.sha256(certificate_pem).hexdigest()}")


if __name__ == "__main__":
    main()
