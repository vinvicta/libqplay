#!/usr/bin/env python3
"""Route a legacy hostname resolution call to the local test responder.

The patch replaces only ``resolveHost`` with ``127.0.0.1`` (network byte
order). Combined with the HTTP parser diagnostic and an ADB reverse mapping,
it lets a read-only local capture server observe the connector request without
modifying the original APK or the remote service.
"""

from pathlib import Path
import argparse
import hashlib


PATCH_VARIANTS = {
    "original": {
    "x86_64": (
        0x21D8D0,
        bytes.fromhex("48 8b 07 48 85 c0 74"),
        bytes.fromhex("b8 7f 00 00 01 c3 90"),
    ),
    "arm64-v8a": (
        0x206108,
        bytes.fromhex("ff 83 00 d1 f3 53 00 a9 f5 7b 01 a9"),
        bytes.fromhex("e0 0f 80 52 00 20 a0 72 c0 03 5f d6"),
    ),
    },
}

# Kept as a compatibility alias for callers that imported the original map.
PATCHES = PATCH_VARIANTS["original"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("arm64-v8a", "armeabi", "x86", "x86_64"), default="x86_64")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    patches = PATCH_VARIANTS["original"]
    if args.arch not in patches:
        raise SystemExit(
            f"no resolver patch for architecture {args.arch}"
        )
    function_va, original_prefix, patch_prefix = patches[args.arch]
    blob = bytearray(args.input.read_bytes())
    actual = blob[function_va : function_va + len(original_prefix)]
    if actual != original_prefix:
        raise SystemExit(
            f"unexpected bytes at 0x{function_va:x}: {actual.hex(' ')}"
        )

    blob[function_va : function_va + len(patch_prefix)] = patch_prefix
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(
        f"patched 0x{function_va:x}: "
        f"{original_prefix.hex(' ')} -> {patch_prefix.hex(' ')}"
    )
    print(f"sha256={hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()
