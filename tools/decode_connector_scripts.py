#!/usr/bin/env python3
"""Decode the connector script files from a captured package, offline.

The native compiler first DES-decrypts an embedded RSA private-key blob, uses
that key to decrypt the package's ``.rk`` entry, and then uses the resulting
RC4 key for the remaining script entries.  This reproduces those steps from
local files only; it never contacts a connector or game server.
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
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key


DEFAULT_LIBRARY = Path(
    "GraalOnline+Classic_1.8_APKPure/lib/x86_64/libqplay.so"
)
DEFAULT_PACKAGE = Path("analysis/live_connector_payload_local.zip")
DEFAULT_OUTPUT = Path("analysis")


def find_c_string(blob: bytes, prefix: bytes) -> bytes:
    start = blob.find(prefix)
    if start < 0:
        raise ValueError(f"embedded string not found: {prefix!r}")
    end = blob.find(b"\0", start)
    if end < 0:
        raise ValueError(f"unterminated embedded string: {prefix!r}")
    return blob[start:end]


def reverse_bits_each_byte(data: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in data)


def native_des_decrypt_memory(data: bytes, key: bytes) -> bytes:
    """Mirror TEncryption::des_decryptmemory's ECB/full-block behavior."""

    full_length = len(data) - (len(data) % 8)
    cipher = DES.new(reverse_bits_each_byte(key), DES.MODE_ECB)
    return cipher.decrypt(data[:full_length]) + data[full_length:]


def rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    output = bytearray()
    i = 0
    j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def printable_strings(data: bytes) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        result.append(
            {"offset": match.start(), "value": match.group().decode("ascii")}
        )
    return result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY)
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    library = args.library.read_bytes()
    des_key = base64.b64decode(find_c_string(library, b"JZfkUMydBH0="))
    encrypted_private_key = base64.b64decode(
        find_c_string(library, b"pgmJ5Y/7DuOaPiotY/")
    )
    private_key_der = native_des_decrypt_memory(encrypted_private_key, des_key)
    private_key = load_der_private_key(private_key_der, password=None)

    with zipfile.ZipFile(args.package) as package:
        encrypted_rk = package.read(".rk")
        encrypted_timestamp = package.read(".t")
        encrypted_script = package.read("NPCS/StartScript_Connector")

    rc4_key = private_key.decrypt(encrypted_rk, padding.PKCS1v15())
    timestamp = rc4(encrypted_timestamp, rc4_key)
    script = rc4(encrypted_script, rc4_key)

    args.output.mkdir(parents=True, exist_ok=True)
    script_path = args.output / "StartScript_Connector.dec.bin"
    timestamp_path = args.output / "StartScript_Connector.timestamp.txt"
    strings_path = args.output / "StartScript_Connector.strings.json"
    script_path.write_bytes(script)
    timestamp_path.write_bytes(timestamp + b"\n")
    strings_path.write_text(
        json.dumps(printable_strings(script), indent=2) + "\n",
        encoding="utf-8",
    )

    summary = {
        "library": str(args.library),
        "package": str(args.package),
        "private_key_der_length": len(private_key_der),
        "private_key_der_sha256": sha256(private_key_der),
        "rsa_key_bits": private_key.key_size,
        "rk_length": len(encrypted_rk),
        "rc4_key_length": len(rc4_key),
        "rc4_key_sha256": sha256(rc4_key),
        "timestamp": timestamp.decode("ascii"),
        "script_length": len(script),
        "script_sha256": sha256(script),
        "script_path": str(script_path),
        "timestamp_path": str(timestamp_path),
        "strings_path": str(strings_path),
        "endpoint_strings": [
            item["value"]
            for item in printable_strings(script)
            if isinstance(item["value"], str)
            and "graalonline.com:" in item["value"]
        ],
    }
    summary_path = args.output / "StartScript_Connector.summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
