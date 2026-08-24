#!/usr/bin/env python3
"""Parse and validate a legacy libqplay connector response offline.

The native implementation reverses the bit order in every DES key byte.  The
script mirrors that detail, validates the signed-package envelope, reproduces
the native wolfSSL RSA-SSL check, and RC4-decrypts the payload for ZIP
inspection.  It never opens a network connection.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import base64
import hashlib
import io
import json
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DES_KEY = b"PjosLg8D"
RC4_KEY = b"Pw0Y0G3BAcHcyOSI"
EMBEDDED_RSA_KEY_B64 = (
    "b5liime+ea5LcikkH/SrLHrb4wWwUExOhP3/5CMpy6RqhwCMekLWZF9bIW/"
    "BcgXRM0BHW89JCCGWPg49DScQT8CcyyA01F2l/VgmWOKjr4z85OdFybycO1xILkphi"
    "LrARyTzLlwhcE6j78LOgyQafOzZXIfnbpFJG8etF3OEXP6F5gijCnlZ6rKuJ1KL9391"
    "v2ccSNve5eJrAWUMt5GoCzxsNfBNFjhDf9pIOiACmlW9XnM5rAXNCK0hG5IbHaBVHH"
    "ENCaCKlZtBmTpJGSLWzjm/UFCHYOgos5IHnKMGW40ux8M/C1aCC0lXRYy5ZUBISRG5"
    "fqpcezAMMEPCMtZGCbjTgf9LBBGtAgMBAAE="
)


def reverse_key_bits(key: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in key)


def native_des_decrypt(data: bytes) -> bytes:
    """Mirror des_decryptmemory: DES-ECB, full blocks only, in place."""

    key = reverse_key_bits(DES_KEY)
    full_length = len(data) // 8 * 8
    decryptor = Cipher(
        algorithms.TripleDES(key * 3), modes.ECB()
    ).decryptor()
    return decryptor.update(data[:full_length]) + decryptor.finalize() + data[
        full_length:
    ]


def rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    out = bytearray()
    i = 0
    j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def native_rsa_ssl_recover(public_key, signature: bytes) -> bytes | None:
    """Recover the raw message accepted by wolfSSL ``RsaSSL_Verify``.

    The native wrapper calls ``RsaSSL_Verify`` and then compares its recovered
    message with the 32-byte SHA-256 digest calculated from the encrypted
    payload.  This is the PKCS#1 v1.5 type-1 block used by wolfSSL's
    ``RsaSSL_Sign`` and ``RsaSSL_Verify`` helpers.  It is not the ASN.1
    ``DigestInfo`` encoding used by ``cryptography``'s high-level
    ``public_key.verify(..., hashes.SHA256())`` API.
    """

    numbers = public_key.public_numbers()
    modulus_length = (public_key.key_size + 7) // 8
    if len(signature) != modulus_length:
        return None

    signature_integer = int.from_bytes(signature, "big")
    if signature_integer >= numbers.n:
        return None
    encoded_message = pow(signature_integer, numbers.e, numbers.n).to_bytes(
        modulus_length, "big"
    )
    if encoded_message[:2] != b"\x00\x01":
        return None

    separator = encoded_message.find(b"\x00", 2)
    if separator < 10:
        return None
    if any(byte != 0xFF for byte in encoded_message[2:separator]):
        return None
    return encoded_message[separator + 1 :]


def native_rsa_ssl_verify(public_key, signature: bytes, expected_message: bytes) -> bool:
    """Return whether native wolfSSL verification recovers ``expected_message``."""

    recovered_message = native_rsa_ssl_recover(public_key, signature)
    return recovered_message == expected_message


def parse_response(body: bytes) -> tuple[bytes, bytes, bytes]:
    if len(body) < 8:
        raise ValueError("response is shorter than the signed-package header")
    signature_length = int.from_bytes(body[:4], "big")
    signature_end = 4 + signature_length
    if signature_end + 4 > len(body):
        raise ValueError("signature length exceeds the response")
    payload_length = int.from_bytes(body[signature_end : signature_end + 4], "big")
    payload_start = signature_end + 4
    payload_end = payload_start + payload_length
    if payload_end > len(body):
        raise ValueError("encrypted payload length exceeds the response")
    return body[4:signature_end], body[payload_start:payload_end], body[payload_end:]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("response", type=Path)
    parser.add_argument("--write-key", type=Path)
    parser.add_argument("--write-decrypted", type=Path)
    args = parser.parse_args()

    body = args.response.read_bytes()
    signature, encrypted_payload, trailing = parse_response(body)
    key_der = native_des_decrypt(base64.b64decode(EMBEDDED_RSA_KEY_B64))
    public_key = serialization.load_der_public_key(key_der)

    expected_digest = hashlib.sha256(encrypted_payload).digest()
    signature_valid = native_rsa_ssl_verify(public_key, signature, expected_digest)

    standard_signature_valid = False
    try:
        public_key.verify(
            signature,
            encrypted_payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        standard_signature_valid = True
    except Exception:
        # The historical connector uses the native raw-digest form. A failure
        # here is expected even for a valid native signature.
        pass

    decrypted_payload = rc4(RC4_KEY, encrypted_payload)
    zip_names: list[str] = []
    zip_valid = False
    try:
        with zipfile.ZipFile(io.BytesIO(decrypted_payload)) as archive:
            zip_valid = archive.testzip() is None
            zip_names = archive.namelist()[:20]
            zip_count = len(archive.namelist())
    except zipfile.BadZipFile:
        zip_count = 0

    if args.write_key:
        args.write_key.write_bytes(key_der)
    if args.write_decrypted:
        args.write_decrypted.write_bytes(decrypted_payload)

    report = {
        "body_length": len(body),
        "signature_length": len(signature),
        "payload_length": len(encrypted_payload),
        "framing_end": 8 + len(signature) + len(encrypted_payload),
        "trailing_length": len(trailing),
        "encrypted_payload_sha256": hashlib.sha256(encrypted_payload).hexdigest(),
        "rsa_signature_scheme": "wolfssl-rsa-ssl-raw-sha256",
        "expected_rsa_message_length": len(expected_digest),
        "embedded_public_key_der_length": len(key_der),
        "embedded_public_key_der_sha256": hashlib.sha256(key_der).hexdigest(),
        "rsa_signature_valid": signature_valid,
        "standard_rsa_signature_valid": standard_signature_valid,
        "decrypted_payload_length": len(decrypted_payload),
        "decrypted_payload_sha256": hashlib.sha256(decrypted_payload).hexdigest(),
        "zip_valid": zip_valid,
        "zip_entry_count": zip_count,
        "zip_entries_preview": zip_names,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
