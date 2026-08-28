#!/usr/bin/env python3
"""Select the existing non-premium loading clear in Spectron ARM64.

The target's translated ``TClientEnvironment::sigcheck`` routine branches
around its loading flag clear when the decoded premium option is positive.
This diagnostic changes only that conditional branch so execution reaches the
already present clear block.  It is a private test control, not a release
patch, and it never contacts a network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PATCH_OFFSET = 0x15FAD8
PATCH_ORIGINAL = bytes.fromhex("2d 02 00 54")  # b.le 0x15fb1c
PATCH_REPLACEMENT = bytes.fromhex("11 00 00 14")  # b 0x15fb1c
BRANCH_TARGET = "0x15fb1c"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_bytes(source: bytes) -> tuple[bytes, list[dict]]:
    actual = source[PATCH_OFFSET : PATCH_OFFSET + len(PATCH_ORIGINAL)]
    if actual != PATCH_ORIGINAL:
        raise ValueError(
            "unexpected Spectron branch at 0x%x: expected %s, found %s"
            % (PATCH_OFFSET, PATCH_ORIGINAL.hex(), actual.hex())
        )
    output = bytearray(source)
    output[PATCH_OFFSET : PATCH_OFFSET + len(PATCH_ORIGINAL)] = PATCH_REPLACEMENT
    record = {
        "file_offset": "0x%x" % PATCH_OFFSET,
        "original": PATCH_ORIGINAL.hex(),
        "replacement": PATCH_REPLACEMENT.hex(),
        "branch_target": BRANCH_TARGET,
        "operation": "force the existing non-premium loading clear",
    }
    return bytes(output), [record]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    source = args.input.read_bytes()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite an existing output")
    patched, records = patch_bytes(source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    result = {
        "artifact": "spectron_nonpremium_loading_patch",
        "network_contacted": False,
        "input": str(args.input),
        "input_sha256": sha256(source),
        "output": str(args.output),
        "output_sha256": sha256(patched),
        "patches": records,
        "interpretation": [
            "The target conditional now reaches the existing loading flag clear block.",
            "No connector, TLS, packet, renderer, or WebTop code is changed.",
            "This is a private translated-ARM64 diagnostic control only.",
        ],
    }
    serialized = json.dumps(result, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
