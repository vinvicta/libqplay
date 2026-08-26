#!/usr/bin/env python3
"""Disable the destructive WebTop commands in a supplied ARM64 libxposed.

This is a local diagnostic control for an APK the analyst owns. It changes
only the three command-selection branches for crash, freeze, and abort. The
branches become unconditional jumps to the next command comparison, so those
messages become no-ops while load_menu, setscript, and gs2call are untouched.
The input is never overwritten and the expected original bytes are checked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED_INPUT_SHA256 = (
    "0300bf22966ff43a03495292493530e8e048032a808f80132e5360d8f8bdf456"
)

PATCHES = (
    {
        "command": "crash",
        "file_offset": 0x8433C,
        "original": bytes.fromhex("e0000035"),
        "replacement": bytes.fromhex("07000014"),
        "branch_target": "0x84358",
    },
    {
        "command": "freeze",
        "file_offset": 0x84378,
        "original": bytes.fromhex("80000035"),
        "replacement": bytes.fromhex("04000014"),
        "branch_target": "0x84388",
    },
    {
        "command": "abort",
        "file_offset": 0x843A8,
        "original": bytes.fromhex("40010035"),
        "replacement": bytes.fromhex("0a000014"),
        "branch_target": "0x843D0",
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_bytes(source: bytes) -> tuple[bytes, list[dict]]:
    output = bytearray(source)
    records = []
    for patch in PATCHES:
        offset = patch["file_offset"]
        original = patch["original"]
        actual = bytes(output[offset : offset + len(original)])
        if actual != original:
            raise ValueError(
                "%s at 0x%x: expected %s, found %s"
                % (patch["command"], offset, original.hex(), actual.hex())
            )
        output[offset : offset + len(original)] = patch["replacement"]
        records.append(
            {
                "command": patch["command"],
                "file_offset": "0x%x" % offset,
                "original": original.hex(),
                "replacement": patch["replacement"].hex(),
                "branch_target": patch["branch_target"],
            }
        )
    return bytes(output), records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    source = args.input.read_bytes()
    source_hash = sha256(source)
    if source_hash != EXPECTED_INPUT_SHA256:
        raise ValueError(
            "unexpected libxposed input hash: expected %s, found %s"
            % (EXPECTED_INPUT_SHA256, source_hash)
        )
    if args.output.exists():
        raise FileExistsError("refusing to overwrite an existing output")
    patched, records = patch_bytes(source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    result = {
        "artifact": "spectron_webtop_safe_command_patch",
        "input": str(args.input),
        "input_sha256": source_hash,
        "output": str(args.output),
        "output_sha256": sha256(patched),
        "patches": records,
        "network_contacted": False,
        "interpretation": [
            "The three destructive command branches now skip to the next dispatcher comparison.",
            "The remaining WebTop commands and the qplay library are untouched.",
            "This is a private diagnostic control and does not establish that the Spectron package is otherwise playable.",
        ],
    }
    serialized = json.dumps(result, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
