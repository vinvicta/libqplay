#!/usr/bin/env python3
"""Record the checked local patch plan for the supplied Spectron revision.

The audit reads the APK and its ARM64 native members, verifies their fixed
hashes, and records the byte guards used by the local-only builder.  It does
not apply a patch, load a library, or open a network connection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

from patch_spectron_webtop_safe_commands import EXPECTED_INPUT_SHA256, PATCHES as WEBTOP_PATCHES


EXPECTED_APK_SHA256 = (
    "5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c"
)
EXPECTED_QPLAY_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
)
EXPECTED_TRUST_SHA256 = (
    "c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0"
)
ARM64_LIB = "lib/arm64-v8a/libqplay.so"
ARM64_XPOSED = "lib/arm64-v8a/libxposed.so"
TRUST_OFFSET = 0x2EA9E0
TRUST_LENGTH = 12820
RESOLVER_OFFSET = 0x20C20C
RESOLVER_ORIGINAL = bytes.fromhex("ff 03 01 d1 f3 53 00 a9 f5 5b 01 a9")
RESOLVER_REPLACEMENT = bytes.fromhex("e0 0f 80 52 00 20 a0 72 c0 03 5f d6")
HTTPS_PORT_OFFSETS = (0x2065E0, 0x206764)
MOV_W1_443 = bytes.fromhex("61 37 80 52")
RC4_FUNCTION_OFFSET = 0x202FE8
RC4_FUNCTION_PREFIX = bytes.fromhex("ff c3 00 d1 f3 53 00 a9 f5 5b 01 a9")
RC4_CAVE_OFFSET = 0x1C4000
RC4_CAVE_LENGTH = 128
RC4_TEST_KEY = "0123456789abcdef"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hex_bytes(data: bytes) -> str:
    return data.hex()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--native", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    apk = args.apk.resolve()
    if sha256(apk.read_bytes()) != EXPECTED_APK_SHA256:
        raise SystemExit("unexpected Spectron APK hash")
    with zipfile.ZipFile(apk) as archive:
        qplay = archive.read(ARM64_LIB)
        xposed = archive.read(ARM64_XPOSED)
    if args.native:
        qplay = args.native.resolve().read_bytes()
    if sha256(qplay) != EXPECTED_QPLAY_SHA256:
        raise SystemExit("unexpected Spectron ARM64 libqplay hash")
    if sha256(xposed) != EXPECTED_INPUT_SHA256:
        raise SystemExit("unexpected Spectron ARM64 libxposed hash")

    trust = qplay[TRUST_OFFSET : TRUST_OFFSET + TRUST_LENGTH]
    if len(trust) != TRUST_LENGTH or sha256(trust) != EXPECTED_TRUST_SHA256:
        raise SystemExit("unexpected Spectron embedded trust text")
    if qplay[TRUST_OFFSET + TRUST_LENGTH] != 0:
        raise SystemExit("Spectron embedded trust text is not NUL terminated")
    if qplay[RESOLVER_OFFSET : RESOLVER_OFFSET + len(RESOLVER_ORIGINAL)] != RESOLVER_ORIGINAL:
        raise SystemExit("unexpected Spectron resolver prologue")
    for offset in HTTPS_PORT_OFFSETS:
        if qplay[offset : offset + len(MOV_W1_443)] != MOV_W1_443:
            raise SystemExit("unexpected Spectron HTTPS port instruction at 0x%x" % offset)
    if qplay[RC4_FUNCTION_OFFSET : RC4_FUNCTION_OFFSET + len(RC4_FUNCTION_PREFIX)] != RC4_FUNCTION_PREFIX:
        raise SystemExit("unexpected Spectron setEncryptionOut prologue")
    cave = qplay[RC4_CAVE_OFFSET : RC4_CAVE_OFFSET + RC4_CAVE_LENGTH]
    if cave != bytes(RC4_CAVE_LENGTH):
        raise SystemExit("Spectron RC4 trampoline cave is not unused zero-filled space")

    result = {
        "artifact": "spectron_loopback_patch_audit_20260828",
        "network_contacted": False,
        "input": {
            "apk_sha256": EXPECTED_APK_SHA256,
            "arm64_libqplay_sha256": EXPECTED_QPLAY_SHA256,
            "arm64_libxposed_sha256": EXPECTED_INPUT_SHA256,
            "trust_text_sha256": EXPECTED_TRUST_SHA256,
            "trust_text_length": TRUST_LENGTH,
            "file_offsets_equal_virtual_addresses": True,
        },
        "resolver_patch": {
            "file_offset": "0x20c20c",
            "function": "resolveHost",
            "original": hex_bytes(RESOLVER_ORIGINAL),
            "replacement": hex_bytes(RESOLVER_REPLACEMENT),
            "result": "127.0.0.1",
        },
        "https_port_patches": [
            {
                "file_offset": "0x%x" % offset,
                "original": hex_bytes(MOV_W1_443),
                "replacement": "computed ARM64 MOV W1,%d" % 18443,
            }
            for offset in HTTPS_PORT_OFFSETS
        ],
        "trust_patch": {
            "file_offset": "0x2ea9e0",
            "encoded_text_length": TRUST_LENGTH,
            "encoding": "native DES-ECB with bit-reversed jhOdx9SY, then Base64",
            "verification": "CyaSSL certificate and hostname verification remain enabled",
        },
        "rc4_patch": {
            "function_file_offset": "0x202fe8",
            "original_function_prefix": hex_bytes(RC4_FUNCTION_PREFIX),
            "cave_file_offset": "0x1c4000",
            "cave_length": RC4_CAVE_LENGTH,
            "cave_input_sha256": sha256(cave),
            "resume_file_offset": "0x202fec",
            "test_key": RC4_TEST_KEY,
            "purpose": "local responder only",
        },
        "webtop_safe_patch": {
            "input_sha256": EXPECTED_INPUT_SHA256,
            "patches": [
                {
                    "command": item["command"],
                    "file_offset": "0x%x" % item["file_offset"],
                    "original": item["original"].hex(),
                    "replacement": item["replacement"].hex(),
                    "branch_target": item["branch_target"],
                }
                for item in WEBTOP_PATCHES
            ],
            "purpose": "prevent the supplied WebTop control from terminating the private test client",
        },
        "preserved": [
            "Spectron connector script and endpoint host strings",
            "native TLS peer and hostname verification",
            "game-server protocol implementation",
            "original APK contents outside the selected ARM64 libraries",
        ],
        "warning": "Private loopback diagnostic plan only. It is not a production endpoint repair or a live-service result.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "network_contacted": False}, sort_keys=True))


if __name__ == "__main__":
    main()
