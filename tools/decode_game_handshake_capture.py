#!/usr/bin/env python3
"""Summarize a captured NewGraal client handshake.

This is an offline diagnostic for captures made by game_handshake_server.py.
The first client frame is the unencrypted RSA key exchange.  After the
server's synthetic fc response, the remaining client stream uses the
outgoing RC4 key supplied on the command line.

The default output intentionally reports only frame metadata and short body
prefixes; login fields are not dumped unless --dump-bodies is requested.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from game_handshake_server import read_newgraal_frames, rc4


def frame_summary(frame: dict, dump_bodies: bool) -> dict:
    body = frame["body"]
    item = {
        "compression": frame["compression"],
        "sequence": frame["sequence"],
        "length": frame["length"],
        "type": frame["type"],
        "body_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    if dump_bodies:
        item["body_hex"] = body.hex()
    else:
        item["body_prefix_hex"] = body[:16].hex()
        item["body_prefix_ascii"] = "".join(
            chr(value) if 32 <= value < 127 else "." for value in body[:32]
        )
    return item


def parse_capture(raw: bytes, key: bytes, dump_bodies: bool) -> dict:
    banner = b"GNP1905C"
    banner_offset = raw.find(banner)
    if banner_offset < 0:
        raise ValueError("GNP1905C banner not found")
    stream = raw[banner_offset + len(banner) :]

    initial_buffer = bytearray(stream)
    initial_frames = read_newgraal_frames(initial_buffer)
    if not initial_frames:
        raise ValueError("no complete initial frame found")

    encrypted_tail = bytes(initial_buffer)
    decrypted_tail = rc4(encrypted_tail, key)
    output_buffer = bytearray(decrypted_tail)
    output_frames = read_newgraal_frames(output_buffer)

    return {
        "capture_size": len(raw),
        "capture_sha256": hashlib.sha256(raw).hexdigest(),
        "banner_offset": banner_offset,
        "initial_frames": [frame_summary(frame, dump_bodies) for frame in initial_frames],
        "encrypted_tail_size": len(encrypted_tail),
        "decrypted_tail_remaining": len(output_buffer),
        "decrypted_output_frames": [
            frame_summary(frame, dump_bodies) for frame in output_frames
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument(
        "--key-hex",
        required=True,
        help="outgoing RC4 key in hexadecimal form",
    )
    parser.add_argument("--dump-bodies", action="store_true")
    args = parser.parse_args()

    key = bytes.fromhex(args.key_hex)
    if not key:
        raise SystemExit("RC4 key must not be empty")
    result = parse_capture(args.capture.read_bytes(), key, args.dump_bodies)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
