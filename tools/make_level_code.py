#!/usr/bin/env python3
"""Re-key a known-good Graal encrypted level container for a local test.

This is intentionally a small diagnostic helper rather than a level compiler:
it preserves the decoded board/entity stream from an existing ``.code`` file
and rewrites only the server identity and signature fields.  The container's
DES key stream is derived from the level filename, so the file is re-encrypted
with the same native PRNG and per-byte bit-reversed DES keys used by libqplay.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from Cryptodome.Cipher import DES


DRAND_MULTIPLIER = 134775813
DRAND_INCREMENT = 1
LEVEL_SEED = 78121784


def reverse_bits_each_byte(data: bytes) -> bytes:
    return bytes(int(f"{value:08b}"[::-1], 2) for value in data)


def next_drand(state: int) -> tuple[int, int]:
    state = (DRAND_MULTIPLIER * state + DRAND_INCREMENT) & 0xFFFFFFFF
    return state, state & 0xFF


def level_seed(level_name: str) -> int:
    state = LEVEL_SEED
    for value in level_name.encode("utf-8"):
        state = (state * value) & 0xFFFFFFFF
    return state


def decrypt_container(raw: bytes, level_name: str) -> tuple[bytes, int]:
    if len(raw) < 4:
        raise ValueError("container is shorter than its four-byte header")
    encoded_length = struct.unpack_from("<I", raw, 0)[0]
    plaintext_length = encoded_length - 8
    ciphertext_length = (plaintext_length + 7) & ~7
    if plaintext_length <= 0:
        raise ValueError(f"invalid encoded plaintext length: {encoded_length}")
    expected_total = 4 + ciphertext_length + 8
    if len(raw) < expected_total:
        raise ValueError(
            f"container is truncated: expected {expected_total} bytes, got {len(raw)}"
        )

    state = level_seed(level_name)
    plaintext = bytearray()
    for offset in range(4, 4 + ciphertext_length, 8):
        key_bytes = bytearray()
        for _ in range(8):
            state, value = next_drand(state)
            key_bytes.append(value)
        cipher = DES.new(reverse_bits_each_byte(bytes(key_bytes)), DES.MODE_ECB)
        plaintext.extend(cipher.decrypt(raw[offset : offset + 8]))

    checksum = bytes(sum(plaintext[index::8]) & 0xFF for index in range(8))
    stored_checksum = raw[4 + ciphertext_length : 4 + ciphertext_length + 8]
    if checksum != stored_checksum:
        raise ValueError(
            f"checksum mismatch: calculated {checksum.hex()}, stored {stored_checksum.hex()}"
        )
    # The native reader allocates the original (unpadded) length and only
    # copies that many bytes into the returned stream; the extra decrypted
    # newline bytes exist only to complete the final DES block.
    return bytes(plaintext[:plaintext_length]), encoded_length


def encrypt_container(plaintext: bytes, level_name: str) -> bytes:
    padded = bytearray(plaintext)
    while len(padded) % 8:
        padded.append(0x0A)

    state = level_seed(level_name)
    ciphertext = bytearray()
    for offset in range(0, len(padded), 8):
        key_bytes = bytearray()
        for _ in range(8):
            state, value = next_drand(state)
            key_bytes.append(value)
        cipher = DES.new(reverse_bits_each_byte(bytes(key_bytes)), DES.MODE_ECB)
        ciphertext.extend(cipher.encrypt(bytes(padded[offset : offset + 8])))

    checksum = bytes(sum(padded[index::8]) & 0xFF for index in range(8))
    # The native writer stores the original stream length + 8, before its
    # newline padding.  The reader rounds that value up while consuming the
    # encrypted blocks.
    return struct.pack("<I", len(plaintext) + 8) + bytes(ciphertext) + checksum


def encode_signature(signature: int) -> bytes:
    if not 0 <= signature <= 0x3FFF:
        raise ValueError("signature must fit the two 7-bit encoded fields")
    return bytes(((signature >> 7) + 32, (signature & 0x7F) + 32))


def parse_header(plaintext: bytes) -> dict[str, object]:
    if not plaintext.startswith(b"GWEBL001"):
        raise ValueError("decoded container does not start with GWEBL001")
    cursor = 8

    def read_field() -> bytes:
        nonlocal cursor
        if cursor >= len(plaintext):
            raise ValueError("truncated GWEBL001 header")
        length = plaintext[cursor] - 32
        cursor += 1
        if length < 0 or cursor + length > len(plaintext):
            raise ValueError("invalid GWEBL001 length field")
        value = plaintext[cursor : cursor + length]
        cursor += length
        return value

    server_ipstr = read_field()
    if cursor + 2 + 5 > len(plaintext):
        raise ValueError("truncated GWEBL001 identity fields")
    signature_bytes = plaintext[cursor : cursor + 2]
    cursor += 2
    modtime = plaintext[cursor : cursor + 5]
    cursor += 5
    level_name = read_field()
    if cursor + 8 > len(plaintext):
        raise ValueError("truncated GWEBL001 version field")
    version = plaintext[cursor : cursor + 8]
    return {
        "server_ipstr": server_ipstr,
        "signature_bytes": signature_bytes,
        "modtime_bytes": modtime,
        "level_name": level_name,
        "version": version,
        "header_end": cursor + 8,
    }


def rewrite_identity(
    plaintext: bytes,
    *,
    server_ipstr: str,
    signature: int,
    level_name: str,
) -> bytes:
    header = parse_header(plaintext)
    old_ipstr = header["server_ipstr"]
    old_level_name = header["level_name"]
    new_ipstr = server_ipstr.encode("utf-8")
    new_level_name = level_name.encode("utf-8")
    if len(old_ipstr) != len(new_ipstr):
        raise ValueError(
            "serveripstr length must be unchanged for in-place re-keying "
            f"({len(old_ipstr)} != {len(new_ipstr)})"
        )

    cursor = 8
    ip_length = plaintext[cursor] - 32
    cursor += 1
    result = bytearray(plaintext)
    result[cursor : cursor + ip_length] = new_ipstr
    cursor += ip_length
    result[cursor : cursor + 2] = encode_signature(signature)
    cursor += 2 + 5

    old_name_length = result[cursor] - 32
    old_name_start = cursor + 1
    old_name_end = old_name_start + old_name_length
    if result[old_name_start:old_name_end] != old_level_name:
        raise ValueError("decoded level-name field changed while parsing")
    if old_name_end > len(result):
        raise ValueError("truncated level-name field")
    # The board stream follows the version field, so replacing this one
    # length-delimited field leaves all compressed board/entity data intact.
    return (
        bytes(result[:cursor])
        + bytes((32 + len(new_level_name),))
        + new_level_name
        + bytes(result[old_name_end:])
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="known-good encrypted .code file")
    parser.add_argument("output", type=Path, help="re-keyed encrypted .code file")
    parser.add_argument("--server-ipstr", required=True)
    parser.add_argument("--server-signature", type=int, default=73)
    parser.add_argument("--level-name", required=True)
    parser.add_argument(
        "--source-level-name",
        help="level name used to derive the input container's DES key; defaults to --level-name",
    )
    args = parser.parse_args()

    source_level_name = args.source_level_name or args.level_name
    decoded, encoded_length = decrypt_container(
        args.input.read_bytes(), source_level_name
    )
    rewritten = rewrite_identity(
        decoded,
        server_ipstr=args.server_ipstr,
        signature=args.server_signature,
        level_name=args.level_name,
    )
    output = encrypt_container(rewritten, args.level_name)
    expected_encoded_length = len(rewritten) + 8
    if len(output) < 4 or struct.unpack_from("<I", output, 0)[0] != expected_encoded_length:
        raise ValueError("re-keyed container has an inconsistent encoded length")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    print(
        f"wrote {args.output} ({len(output)} bytes); level={args.level_name} "
        f"serveripstr={args.server_ipstr} signature={args.server_signature}"
    )


if __name__ == "__main__":
    main()
