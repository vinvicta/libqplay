#!/usr/bin/env python3
"""Refresh the timestamp entry in a captured connector package.

This is a local diagnostic helper. It preserves the connector script and the
per-package key, changes only the encrypted ``.t`` entry, and re-wraps the
payload with the native outer RC4 key. The original RSA signature is retained,
so the result is intended for the already-patched local test client only.
"""

from __future__ import annotations

import argparse
import base64
import io
import struct
import time
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key

from decode_connector_scripts import (
    find_c_string,
    native_des_decrypt_memory,
    rc4,
)
from parse_connector_response import (
    EMBEDDED_RSA_KEY_B64,
    RC4_KEY,
    parse_response,
)


def recover_package_key(library: bytes, package: bytes) -> bytes:
    des_key = base64.b64decode(find_c_string(library, b"JZfkUMydBH0="))
    encrypted_private_key = base64.b64decode(
        find_c_string(library, b"pgmJ5Y/7DuOaPiotY/")
    )
    private_key_der = native_des_decrypt_memory(encrypted_private_key, des_key)
    private_key = load_der_private_key(private_key_der, password=None)
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        encrypted_rk = archive.read(".rk")
    return private_key.decrypt(encrypted_rk, padding.PKCS1v15())


def rewrite_timestamp(package: bytes, package_key: bytes, timestamp: str) -> bytes:
    entries: list[tuple[zipfile.ZipInfo, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        for info in archive.infolist():
            data = archive.read(info.filename)
            if info.filename == ".t":
                data = rc4(timestamp.encode("ascii"), package_key)
            entries.append((info, data))

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for info, data in entries:
            archive.writestr(info, data, compress_type=info.compress_type)
    return output.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=Path)
    parser.add_argument("response", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--timestamp",
        help="ASCII timestamp; defaults to the current Unix time with 9 decimals",
    )
    args = parser.parse_args()

    body = args.response.read_bytes()
    signature, encrypted_payload, trailing = parse_response(body)
    decrypted_package = rc4(encrypted_payload, RC4_KEY)
    package_key = recover_package_key(args.library.read_bytes(), decrypted_package)
    timestamp = args.timestamp or f"{time.time():.9f}"
    if len(timestamp.encode("ascii")) != 20:
        raise SystemExit("timestamp must be a 20-byte Unix timestamp with 9 decimals")
    updated_package = rewrite_timestamp(decrypted_package, package_key, timestamp)
    updated_payload = rc4(updated_package, RC4_KEY)
    updated = (
        struct.pack(">I", len(signature))
        + signature
        + struct.pack(">I", len(updated_payload))
        + updated_payload
        + trailing
    )
    args.output.write_bytes(updated)
    print(
        f"wrote {args.output} ({len(updated)} bytes); "
        f"timestamp={timestamp}; rsa_signature_preserved=true"
    )


if __name__ == "__main__":
    main()
