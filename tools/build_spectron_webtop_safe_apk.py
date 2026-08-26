#!/usr/bin/env python3
"""Build a private Spectron APK with destructive WebTop commands disabled.

The supplied Spectron package is copied with its contents unchanged except
for the ARM64 ``libxposed.so`` command branches for crash, freeze, and abort.
The output is zip-aligned and signed with a caller-supplied local keystore.
This is a diagnostic control only. It does not contact a network or alter the
original APK.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


EXPECTED_APK_SHA256 = (
    "5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c"
)
EXPECTED_LIBXPOSED_SHA256 = (
    "0300bf22966ff43a03495292493530e8e048032a808f80132e5360d8f8bdf456"
)
LIBXPOSED_MEMBER = "lib/arm64-v8a/libxposed.so"
PATCHES = (
    ("crash", 0x8433C, bytes.fromhex("e0000035"), bytes.fromhex("07000014"), "0x84358"),
    ("freeze", 0x84378, bytes.fromhex("80000035"), bytes.fromhex("04000014"), "0x84388"),
    ("abort", 0x843A8, bytes.fromhex("40010035"), bytes.fromhex("0a000014"), "0x843D0"),
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def patch_libxposed(source: bytes) -> tuple[bytes, list[dict]]:
    output = bytearray(source)
    records = []
    for command, offset, expected, replacement, target in PATCHES:
        actual = bytes(output[offset : offset + len(expected)])
        if actual != expected:
            raise ValueError(
                "%s at 0x%x: expected %s, found %s"
                % (command, offset, expected.hex(), actual.hex())
            )
        output[offset : offset + len(expected)] = replacement
        records.append(
            {
                "command": command,
                "file_offset": "0x%x" % offset,
                "original": expected.hex(),
                "replacement": replacement.hex(),
                "branch_target": target,
            }
        )
    return bytes(output), records


def safe_member(member: str) -> None:
    path = PurePosixPath(member)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe APK member path: %s" % member)


def make_unsigned_apk(apk: Path, output: Path, patched_lib: bytes) -> dict:
    replaced = False
    removed_signatures = 0
    with zipfile.ZipFile(apk) as source, zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED
    ) as destination:
        for info in sorted(source.infolist(), key=lambda item: item.filename):
            safe_member(info.filename)
            if info.filename.startswith("META-INF/"):
                removed_signatures += 1
                continue
            data = patched_lib if info.filename == LIBXPOSED_MEMBER else source.read(info)
            if info.filename == LIBXPOSED_MEMBER:
                replaced = True
            if info.is_dir():
                continue
            output_info = zipfile.ZipInfo(info.filename, date_time=(1980, 1, 1, 0, 0, 0))
            # Android 11 and newer reject compressed resources.arsc for
            # packages targeting API 30 or later. zipalign will place it on a
            # four-byte boundary after it is stored without compression.
            output_info.compress_type = (
                zipfile.ZIP_STORED
                if info.filename == "resources.arsc"
                else zipfile.ZIP_DEFLATED
            )
            output_info.external_attr = 0o100644 << 16
            destination.writestr(output_info, data)
    if not replaced:
        raise ValueError("APK does not contain %s" % LIBXPOSED_MEMBER)
    return {"removed_signature_entries": removed_signatures, "replaced_member": LIBXPOSED_MEMBER}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("output", type=Path, help="signed diagnostic APK")
    parser.add_argument("--zipalign", type=Path, required=True)
    parser.add_argument("--apksigner", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--ks-pass", default="android")
    parser.add_argument("--key-pass", default="android")
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    apk = args.apk.resolve()
    output = args.output.resolve()
    for path, label in (
        (apk, "APK"),
        (args.zipalign, "zipalign"),
        (args.apksigner, "apksigner"),
        (args.keystore, "keystore"),
    ):
        if not path.is_file():
            raise SystemExit("%s does not exist: %s" % (label, path))
    if output.exists():
        raise FileExistsError("refusing to overwrite an existing output")
    apk_hash = sha256_file(apk)
    if apk_hash != EXPECTED_APK_SHA256:
        raise ValueError("unexpected Spectron APK hash: %s" % apk_hash)
    with zipfile.ZipFile(apk) as archive:
        source_lib = archive.read(LIBXPOSED_MEMBER)
    source_lib_hash = sha256_bytes(source_lib)
    if source_lib_hash != EXPECTED_LIBXPOSED_SHA256:
        raise ValueError("unexpected embedded libxposed hash: %s" % source_lib_hash)
    patched_lib, patch_records = patch_libxposed(source_lib)

    with tempfile.TemporaryDirectory(prefix="spectron-webtop-safe-") as temporary:
        work = Path(temporary)
        unsigned = work / "unsigned.apk"
        aligned = work / "aligned.apk"
        zip_record = make_unsigned_apk(apk, unsigned, patched_lib)
        subprocess.run(
            [str(args.zipalign), "-f", "-p", "4", str(unsigned), str(aligned)],
            check=True,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                str(args.apksigner),
                "sign",
                "--ks",
                str(args.keystore),
                "--ks-pass",
                "pass:%s" % args.ks_pass,
                "--key-pass",
                "pass:%s" % args.key_pass,
                "--out",
                str(output),
                str(aligned),
            ],
            check=True,
        )

    subprocess.run([str(args.apksigner), "verify", str(output)], check=True)
    result = {
        "artifact": "spectron_webtop_safe_apk_build",
        "network_contacted": False,
        "input_apk": str(apk),
        "input_apk_sha256": apk_hash,
        "input_libxposed_sha256": source_lib_hash,
        "output_apk": str(output),
        "output_apk_sha256": sha256_file(output),
        "output_libxposed_sha256": sha256_bytes(patched_lib),
        "abi": "arm64-v8a",
        "zip": zip_record,
        "patches": patch_records,
        "interpretation": [
            "The ARM64 WebTop crash, freeze, and abort command branches now skip to the next dispatcher comparison.",
            "All qplay libraries and the remaining WebTop command branches are unchanged.",
            "The package is a private signed diagnostic control and is not evidence of production compatibility.",
        ],
    }
    serialized = json.dumps(result, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
