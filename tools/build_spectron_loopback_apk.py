#!/usr/bin/env python3
"""Build a private Spectron ARM64 loopback diagnostic APK.

The builder keeps the supplied 2.2 package and connector script, then applies
only local-test edits to its ARM64 native libraries:

* replace the embedded connector trust bundle with a caller-supplied PEM;
* route the Spectron connector hostname to ``127.0.0.1``;
* move the two HTTPS parser defaults to a non-privileged local port; and
* install the deterministic outgoing RC4 key used by the local game
  responder.

By default it also disables the three destructive WebTop command branches
that caused the supplied package to crash during the earlier control run.
The edit is opt-out with ``--keep-webtop-commands``.  The output is an
ARM64-only, debug-signed package for a private emulator or device.  It never
contacts a connector, game server, or other network service.
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

from patch_spectron_webtop_safe_commands import patch_bytes as patch_webtop_bytes


ROOT = Path(__file__).resolve().parents[1]
ARM64_LIB = "lib/arm64-v8a/libqplay.so"
ARM64_XPOSED = "lib/arm64-v8a/libxposed.so"
EXPECTED_APK_SHA256 = (
    "5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c"
)
EXPECTED_QPLAY_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
)
EXPECTED_XPOSED_SHA256 = (
    "0300bf22966ff43a03495292493530e8e048032a808f80132e5360d8f8bdf456"
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def safe_stage_path(stage: Path, member: str) -> Path:
    path = PurePosixPath(member)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("unsafe APK member path: %s" % member)
    return stage.joinpath(*path.parts)


def stage_apk(apk: Path, stage: Path) -> None:
    """Copy package contents while retaining only the ARM64 native ABI."""

    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            member = info.filename
            if member.startswith("META-INF/"):
                continue
            if member.startswith("lib/") and not member.startswith("lib/arm64-v8a/"):
                continue
            if info.is_dir():
                continue
            target = safe_stage_path(stage, member)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))


def make_unsigned_apk(stage: Path, output: Path) -> None:
    """Create a deterministic unsigned APK from a staging tree."""

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(stage.rglob("*")):
            if not path.is_file():
                continue
            name = path.relative_to(stage).as_posix()
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            # Android 11 and newer reject compressed resources.arsc for
            # packages targeting API 30 or later.
            info.compress_type = (
                zipfile.ZIP_STORED if name == "resources.arsc" else zipfile.ZIP_DEFLATED
            )
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def run_patch(tool: str, arguments: list[str]) -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tools" / tool), *arguments],
        cwd=ROOT,
        check=True,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path, help="supplied Spectron APK")
    parser.add_argument("output", type=Path, help="signed diagnostic APK")
    parser.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="certificate-only PEM bundle for cong.quattroplay.com",
    )
    parser.add_argument(
        "--native",
        type=Path,
        help="exact Spectron ARM64 libqplay.so; defaults to the APK member",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18443,
        help="private local connector port",
    )
    parser.add_argument("--zipalign", type=Path, required=True)
    parser.add_argument("--apksigner", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--ks-pass", default="android")
    parser.add_argument("--key-pass", default="android")
    parser.add_argument(
        "--keep-webtop-commands",
        action="store_true",
        help="leave Spectron's crash, freeze, and abort branches unchanged",
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
    bundle = args.bundle.resolve()
    native_argument = args.native.resolve() if args.native else None

    for path, label in (
        (apk, "APK"),
        (bundle, "trust bundle"),
        (args.zipalign, "zipalign"),
        (args.apksigner, "apksigner"),
        (args.keystore, "keystore"),
    ):
        if not path.is_file():
            raise SystemExit("%s does not exist: %s" % (label, path))
    if native_argument and not native_argument.is_file():
        raise SystemExit("native library does not exist: %s" % native_argument)
    if output.exists():
        raise SystemExit("refusing to overwrite an existing output: %s" % output)
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")

    input_apk_sha256 = sha256_file(apk)
    if input_apk_sha256 != EXPECTED_APK_SHA256:
        raise SystemExit(
            "unexpected Spectron APK hash: expected %s, found %s"
            % (EXPECTED_APK_SHA256, input_apk_sha256)
        )

    temporary_context = None
    if args.keep_work_dir:
        work = args.keep_work_dir.resolve()
        work.mkdir(parents=True, exist_ok=True)
    else:
        temporary_context = tempfile.TemporaryDirectory(prefix="spectron-loopback-")
        work = Path(temporary_context.name)

    try:
        stage = work / "stage"
        stage_apk(apk, stage)

        if native_argument is None:
            with zipfile.ZipFile(apk) as archive:
                native_bytes = archive.read(ARM64_LIB)
            native_source = work / "libqplay.original.so"
            native_source.write_bytes(native_bytes)
        else:
            native_source = work / "libqplay.original.so"
            shutil.copy2(native_argument, native_source)
            native_bytes = native_source.read_bytes()
        input_native_sha256 = sha256_bytes(native_bytes)
        if input_native_sha256 != EXPECTED_QPLAY_SHA256:
            raise SystemExit(
                "unexpected Spectron ARM64 libqplay hash: expected %s, found %s"
                % (EXPECTED_QPLAY_SHA256, input_native_sha256)
            )

        trust = work / "libqplay.trust.so"
        run_patch(
            "patch_graalweb_trust_bundle.py",
            [
                "--variant",
                "spectron",
                "--arch",
                "arm64-v8a",
                "--bundle",
                str(bundle),
                str(native_source),
                str(trust),
            ],
        )
        loopback = work / "libqplay.loopback.so"
        run_patch(
            "patch_localhost_resolver_test.py",
            [
                "--variant",
                "spectron",
                "--arch",
                "arm64-v8a",
                str(trust),
                str(loopback),
            ],
        )
        port = work / "libqplay.port.so"
        run_patch(
            "patch_connector_tls_port_test.py",
            [
                "--variant",
                "spectron",
                "--arch",
                "arm64-v8a",
                "--port",
                str(args.port),
                str(loopback),
                str(port),
            ],
        )
        fixed_key = work / "libqplay.fixed-key.so"
        run_patch(
            "patch_fixed_output_rc4_key_test.py",
            [
                "--variant",
                "spectron",
                "--arch",
                "arm64-v8a",
                str(port),
                str(fixed_key),
            ],
        )

        staged_native = stage / ARM64_LIB
        staged_native.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(fixed_key, staged_native)

        with zipfile.ZipFile(apk) as archive:
            xposed_source = archive.read(ARM64_XPOSED)
        input_xposed_sha256 = sha256_bytes(xposed_source)
        if input_xposed_sha256 != EXPECTED_XPOSED_SHA256:
            raise SystemExit(
                "unexpected Spectron ARM64 libxposed hash: expected %s, found %s"
                % (EXPECTED_XPOSED_SHA256, input_xposed_sha256)
            )
        if args.keep_webtop_commands:
            xposed_bytes = xposed_source
            webtop_patch_records = []
        else:
            xposed_bytes, webtop_patch_records = patch_webtop_bytes(xposed_source)
        staged_xposed = stage / ARM64_XPOSED
        staged_xposed.parent.mkdir(parents=True, exist_ok=True)
        staged_xposed.write_bytes(xposed_bytes)

        unsigned = work / "unsigned.apk"
        aligned = work / "aligned.apk"
        make_unsigned_apk(stage, unsigned)
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

        report = {
            "artifact": "spectron_loopback_diagnostic_apk_build",
            "network_contacted": False,
            "input_apk": str(apk),
            "input_apk_sha256": input_apk_sha256,
            "input_native_sha256": input_native_sha256,
            "input_libxposed_sha256": input_xposed_sha256,
            "output_apk": str(output),
            "output_apk_sha256": sha256_file(output),
            "output_native_sha256": sha256_file(fixed_key),
            "output_libxposed_sha256": sha256_bytes(xposed_bytes),
            "abi": "arm64-v8a",
            "connector_host": "cong.quattroplay.com",
            "connector_port": args.port,
            "trust_bundle": str(bundle),
            "trust_bundle_sha256": sha256_file(bundle),
            "deterministic_zip_timestamps": True,
            "connector_script_unchanged": True,
            "native_certificate_verification_preserved": True,
            "webtop_safe_commands_applied": not args.keep_webtop_commands,
            "webtop_patch_records": webtop_patch_records,
            "patches": [
                "patch_graalweb_trust_bundle.py --variant spectron",
                "patch_localhost_resolver_test.py --variant spectron",
                "patch_connector_tls_port_test.py --variant spectron",
                "patch_fixed_output_rc4_key_test.py --variant spectron",
            ]
            + ([] if args.keep_webtop_commands else ["patch_spectron_webtop_safe_commands.py"]),
            "warning": "Private loopback diagnostic package only. Not a production client.",
        }
        serialized = json.dumps(report, indent=2, sort_keys=True)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(serialized + "\n", encoding="utf-8")
        print(serialized)
    finally:
        if temporary_context is not None:
            temporary_context.cleanup()


if __name__ == "__main__":
    main()
