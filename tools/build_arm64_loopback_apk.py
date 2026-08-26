#!/usr/bin/env python3
"""Build the reproducible ARM64 loopback diagnostic APK.

The build keeps the original connector bytecode and applies only the native
edits used by the local replay:

* the connector compatibility edits;
* the loopback HTTP parser and hostname resolver;
* the deterministic outgoing RC4 key used by the local responder; and
* the native loading-state candidate at ``0x15ca7c``.

This produces a debug-signed diagnostic package for a private emulator or
device.  It does not configure a production endpoint, publish an APK, or
contact a network service.  The output contains only ``arm64-v8a`` so an
x86_64 emulator cannot silently select another ABI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
ARM64_LIB = "lib/arm64-v8a/libqplay.so"
PATCH_TOOLS = (
    "patch_compatibility_repairs.py",
    "patch_force_http_parser_test.py",
    "patch_localhost_resolver_test.py",
    "patch_fixed_output_rc4_key_test.py",
    "patch_force_no_premium_loading_test.py",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_patch(tool: str, args: list[str]) -> None:
    command = [sys.executable, str(ROOT / "tools" / tool), *args]
    subprocess.run(command, cwd=ROOT, check=True)


def safe_stage_path(stage: Path, member: str) -> Path | None:
    path = PurePosixPath(member)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit(f"unsafe APK member path: {member}")
    if not path.parts:
        return None
    return stage.joinpath(*path.parts)


def stage_apk(apk: Path, stage: Path) -> None:
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            member = info.filename
            if member.startswith("META-INF/"):
                continue
            if member.startswith("lib/") and not member.startswith("lib/arm64-v8a/"):
                continue
            target = safe_stage_path(stage, member)
            if target is None or info.is_dir():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))


def make_unsigned_apk(stage: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                name = path.relative_to(stage).as_posix()
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, path.read_bytes())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path, help="original APK")
    parser.add_argument("output", type=Path, help="debug-signed diagnostic APK")
    parser.add_argument(
        "--native",
        type=Path,
        help="original ARM64 libqplay.so; defaults to the APK member",
    )
    parser.add_argument(
        "--zipalign",
        type=Path,
        required=True,
        help="Android zipalign executable",
    )
    parser.add_argument(
        "--apksigner",
        type=Path,
        required=True,
        help="Android apksigner executable",
    )
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--ks-pass", default="android")
    parser.add_argument("--key-pass", default="android")
    parser.add_argument(
        "--skip-rsa-bypass",
        action="store_true",
        help="retain the native RSA branch instead of applying its local diagnostic bypass",
    )
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--keep-work-dir",
        type=Path,
        help="preserve staging files under this directory for inspection",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    apk = args.apk.resolve()
    output = args.output.resolve()
    native_input = args.native.resolve() if args.native else None
    for path, label in (
        (apk, "APK"),
        (args.zipalign, "zipalign"),
        (args.apksigner, "apksigner"),
        (args.keystore, "keystore"),
    ):
        if not path.is_file():
            raise SystemExit(f"{label} does not exist: {path}")
    if native_input and not native_input.is_file():
        raise SystemExit(f"native library does not exist: {native_input}")
    output.parent.mkdir(parents=True, exist_ok=True)

    temp_context = None
    if args.keep_work_dir:
        work = args.keep_work_dir.resolve()
        work.mkdir(parents=True, exist_ok=True)
    else:
        temp_context = tempfile.TemporaryDirectory(prefix="libqplay-arm64-build-")
        work = Path(temp_context.name)

    try:
        stage = work / "stage"
        stage_apk(apk, stage)
        if native_input is None:
            with zipfile.ZipFile(apk) as archive:
                try:
                    native_bytes = archive.read(ARM64_LIB)
                except KeyError as error:
                    raise SystemExit(f"APK has no {ARM64_LIB}; pass --native") from error
            native_input = work / "libqplay.original.so"
            native_input.write_bytes(native_bytes)
        else:
            shutil.copy2(native_input, work / "libqplay.original.so")
            native_input = work / "libqplay.original.so"

        compatibility = work / "libqplay.compatibility.so"
        run_patch(
            "patch_compatibility_repairs.py",
            [
                "--arch",
                "arm64-v8a",
                *(["--skip-rsa-bypass"] if args.skip_rsa_bypass else []),
                str(native_input),
                str(compatibility),
            ],
        )
        http = work / "libqplay.http.so"
        run_patch(
            "patch_force_http_parser_test.py",
            ["--arch", "arm64-v8a", "--port", "18080", str(compatibility), str(http)],
        )
        loopback = work / "libqplay.loopback.so"
        run_patch(
            "patch_localhost_resolver_test.py",
            ["--arch", "arm64-v8a", str(http), str(loopback)],
        )
        diagnostic = work / "libqplay.diagnostic.so"
        run_patch(
            "patch_fixed_output_rc4_key_test.py",
            ["--arch", "arm64-v8a", str(loopback), str(diagnostic)],
        )
        final_native = work / "libqplay.nonpremium.so"
        run_patch(
            "patch_force_no_premium_loading_test.py",
            [str(diagnostic), str(final_native)],
        )

        staged_native = stage / ARM64_LIB
        staged_native.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(final_native, staged_native)
        unsigned = work / "unsigned.apk"
        aligned = work / "aligned.apk"
        make_unsigned_apk(stage, unsigned)
        subprocess.run(
            [str(args.zipalign), "-f", "-p", "4", str(unsigned), str(aligned)],
            check=True,
        )
        subprocess.run(
            [
                str(args.apksigner),
                "sign",
                "--ks",
                str(args.keystore),
                "--ks-pass",
                f"pass:{args.ks_pass}",
                "--key-pass",
                f"pass:{args.key_pass}",
                "--out",
                str(output),
                str(aligned),
            ],
            check=True,
        )
        subprocess.run([str(args.apksigner), "verify", str(output)], check=True)

        report = {
            "artifact": "arm64_loopback_diagnostic_apk_build",
            "network_contacted": False,
            "input_apk": str(apk),
            "input_apk_sha256": sha256(apk),
            "input_native_sha256": sha256(native_input),
            "output_apk": str(output),
            "output_apk_sha256": sha256(output),
            "output_native_sha256": sha256(final_native),
            "abi": "arm64-v8a",
            "deterministic_zip_timestamps": True,
            "connector_script_unchanged": True,
            "rsa_bypass_applied": not args.skip_rsa_bypass,
            "patches": list(PATCH_TOOLS),
            "loading_branch": {
                "address": "0x15ca7c",
                "operation": "force the existing non-premium initialization branch",
            },
            "warning": "Private loopback diagnostic package only. Not a production client.",
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finally:
        if temp_context is not None:
            temp_context.cleanup()


if __name__ == "__main__":
    main()
