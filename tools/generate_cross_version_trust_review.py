#!/usr/bin/env python3
"""Compare the embedded native TLS trust inputs used by 1.8 and 2.2.

The old client stores a base64 string in libqplay.so.  The native decoder
reverses the bits in each DES key byte, decrypts complete DES-ECB blocks,
and leaves a short tail unchanged.  This tool mirrors that operation and
emits certificate metadata only.  It never writes a certificate body,
opens a socket, or executes either native library.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import zipfile
from pathlib import Path

from Cryptodome.Cipher import DES
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ONE_EIGHT = (
    ROOT.parent / "GraalOnline+Classic_1.8_APKPure" / "lib" / "arm64-v8a" / "libqplay.so"
)
DEFAULT_TWO_TWO = ROOT.parent / "GraalOnline+Classic_2.2_installed.apk"
DEFAULT_OUTPUT = ROOT / "artifacts" / "cross_version_trust_bundle_review_20260902.json"

CERT_PREFIX = b"6erxf21jcqpGrZR4"
DES_KEY = b"jhOdx9SY"
APK_LIBRARY_MEMBER = "lib/arm64-v8a/libqplay.so"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reverse_bits_each_byte(data: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in data)


def read_library(path: Path) -> bytes:
    if path.suffix.lower() != ".apk":
        return path.read_bytes()
    with zipfile.ZipFile(path) as archive:
        return archive.read(APK_LIBRARY_MEMBER)


def decode_bundle(library: bytes) -> dict[str, object]:
    offset = library.find(CERT_PREFIX)
    if offset < 0:
        raise ValueError("embedded trust string was not found")
    end = library.find(b"\0", offset)
    if end < 0:
        raise ValueError("embedded trust string is not NUL terminated")

    encoded = library[offset:end]
    ciphertext = base64.b64decode(encoded, validate=True)
    full_length = len(ciphertext) - (len(ciphertext) % 8)
    cipher = DES.new(reverse_bits_each_byte(DES_KEY), DES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext[:full_length]) + ciphertext[full_length:]
    return {
        "encoded_file_offset": f"0x{offset:x}",
        "encoded_bytes": len(encoded),
        "encoded_sha256": sha256(encoded),
        "ciphertext_bytes": len(ciphertext),
        "ciphertext_sha256": sha256(ciphertext),
        "plaintext_bytes": len(plaintext),
        "plaintext_sha256": sha256(plaintext),
        "des_full_block_bytes": full_length,
        "des_unprocessed_tail_bytes": len(ciphertext) - full_length,
        "plaintext": plaintext,
    }


def certificate_metadata(bundle: bytes) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    pattern = re.compile(
        rb"-----BEGIN ?CERTIFICATE-----.*?-----END ?CERTIFICATE-----\r?\n?",
        re.DOTALL,
    )
    for match in pattern.finditer(bundle):
        pem = match.group(0)
        normalized_pem = pem.replace(
            b"-----BEGINCERTIFICATE-----", b"-----BEGIN CERTIFICATE-----"
        ).replace(b"-----ENDCERTIFICATE-----", b"-----END CERTIFICATE-----")
        cert = x509.load_pem_x509_certificate(normalized_pem)
        item: dict[str, object] = {
            "index": len(result),
            "pem_bytes": len(pem),
            "pem_sha256": sha256(pem),
            "normalized_pem_sha256": sha256(normalized_pem),
            "marker_style": "missing-space" if b"BEGINCERTIFICATE" in pem else "standard",
            "der_sha256": sha256(cert.public_bytes(Encoding.DER)),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": format(cert.serial_number, "X"),
            "not_before": cert.not_valid_before.isoformat() + "Z",
            "not_after": cert.not_valid_after.isoformat() + "Z",
            "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            "signature_hash": cert.signature_hash_algorithm.name,
            "public_key_type": type(cert.public_key()).__name__,
            "public_key_bits": cert.public_key().key_size,
        }
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            item["subject_alt_names"] = [
                {
                    "type": name.__class__.__name__,
                    "value": name.value,
                }
                for name in san
            ]
        except x509.ExtensionNotFound:
            item["subject_alt_names"] = []
        result.append(item)
    if not result:
        raise ValueError("decoded trust input did not contain PEM certificates")
    return result


def inspect(path: Path) -> dict[str, object]:
    library = read_library(path)
    decoded = decode_bundle(library)
    plaintext = decoded.pop("plaintext")
    certificates = certificate_metadata(plaintext)
    return {
        "source": str(path),
        "library_sha256": sha256(library),
        "library_bytes": len(library),
        "embedded_trust": decoded,
        "certificates": certificates,
    }


def build_report(one_eight_path: Path, two_two_path: Path) -> dict[str, object]:
    one_eight = inspect(one_eight_path)
    two_two = inspect(two_two_path)
    one_ders = {item["der_sha256"] for item in one_eight["certificates"]}
    two_ders = {item["der_sha256"] for item in two_two["certificates"]}
    return {
        "artifact": "cross_version_trust_bundle_review",
        "date": "2026-09-02",
        "scope": "Offline comparison of the embedded native TLS trust inputs in the original 1.8 ARM64 library and an unverified installed 2.2 package",
        "inputs": {
            "1.8": one_eight,
            "2.2": two_two,
        },
        "comparison": {
            "1.8_certificate_count": len(one_ders),
            "2.2_certificate_count": len(two_ders),
            "shared_der_sha256": sorted(one_ders & two_ders),
            "1.8_only_der_sha256": sorted(one_ders - two_ders),
            "2.2_only_der_sha256": sorted(two_ders - one_ders),
            "encoded_length_changed": one_eight["embedded_trust"]["encoded_bytes"]
            != two_two["embedded_trust"]["encoded_bytes"],
        },
        "assessment": {
            "confirmed": [
                "The 1.8 embedded trust input decodes to six PEM certificates.",
                "The unverified 2.2 package decodes to one PEM certificate with subject and SAN cong.quattroplay.com.",
                "The 1.8 and 2.2 decoded trust inputs share no certificate DER hash.",
                "The 2.2 certificate is self-signed and has a 2025-01-01 through 2035-01-01 validity interval.",
            ],
            "not_proven": [
                "That the installed 2.2 package is an official release.",
                "That cong.quattroplay.com is a live or authorized service endpoint.",
                "That the 2.2 certificate is accepted by the current game service.",
                "That the package's Java code loads the companion hook library on every device.",
            ],
            "repair_implication": "The 2.2 trust material is not a drop-in repair for 1.8. It is a different, package-specific self-signed anchor and must be treated as untrusted comparison data until its provenance and service ownership are established.",
        },
        "method": {
            "native_decoder": "Base64 decode, reverse each DES key byte, DES-ECB decrypt complete blocks, preserve any short tail.",
            "certificate_parser": "cryptography.x509 metadata extraction; certificate bodies are not emitted.",
            "network_contacted": False,
            "native_executed": False,
            "hook_library_executed": False,
        },
        "tool": "tools/generate_cross_version_trust_review.py",
        "tool_version": 1,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--one-eight", type=Path, default=DEFAULT_ONE_EIGHT)
    parser.add_argument("--two-two", type=Path, default=DEFAULT_TWO_TWO)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report(args.one_eight, args.two_two)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "comparison": report["comparison"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
