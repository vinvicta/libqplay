#!/usr/bin/env python3
"""Build an ARM64 diagnostic APK with native connector verification intact.

The builder starts with the original package and applies only the edits needed
for a private loopback test:

* replace the historical GraalWeb trust bundle with a supplied PEM bundle;
* route the legacy connector hostname to ``127.0.0.1``;
* move the connector port to a non-privileged local port; and
* use the fixed RC4 output key expected by the local game responder.

The RSA result branch, certificate verification code, connector script, and
loading state are left unchanged unless ``--force-nonpremium-loading`` is
explicitly requested. The output is a debug-signed private diagnostic package.
It does not contact a live endpoint and is not a production APK builder.
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
from pathlib import Path

from build_arm64_loopback_apk import (
    ARM64_LIB,
    make_unsigned_apk,
    run_patch,
    safe_stage_path,
    sha256,
    stage_apk,
)


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path, help="original APK")
    parser.add_argument("output", type=Path, help="debug-signed diagnostic APK")
    parser.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="certificate-only PEM bundle for the native trust slot",
    )
    parser.add_argument(
        "--native",
        type=Path,
        help="original ARM64 libqplay.so; defaults to the APK member",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18443,
        help="private connector port used by the local responder",
    )
    parser.add_argument(
        "--fallback-port",
        type=int,
        help="optional private plain-HTTP connector fallback port",
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
        "--force-nonpremium-loading",
        action="store_true",
        help="also select the tested native startup path that clears loadingstate",
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
    native_input = args.native.resolve() if args.native else None

    for path, label in (
        (apk, "APK"),
        (bundle, "trust bundle"),
        (args.zipalign, "zipalign"),
        (args.apksigner, "apksigner"),
        (args.keystore, "keystore"),
    ):
        if not path.is_file():
            raise SystemExit(f"{label} does not exist: {path}")
    if native_input and not native_input.is_file():
        raise SystemExit(f"native library does not exist: {native_input}")
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    output.parent.mkdir(parents=True, exist_ok=True)

    temp_context = None
    if args.keep_work_dir:
        work = args.keep_work_dir.resolve()
        work.mkdir(parents=True, exist_ok=True)
    else:
        temp_context = tempfile.TemporaryDirectory(prefix="libqplay-arm64-trust-")
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
            copied = work / "libqplay.original.so"
            shutil.copy2(native_input, copied)
            native_input = copied

        trust = work / "libqplay.trust.so"
        run_patch(
            "patch_graalweb_trust_bundle.py",
            [
                "--arch",
                "arm64-v8a",
                "--bundle",
                str(bundle),
                str(native_input),
                str(trust),
            ],
        )
        loopback = work / "libqplay.loopback.so"
        run_patch(
            "patch_localhost_resolver_test.py",
            ["--arch", "arm64-v8a", str(trust), str(loopback)],
        )
        port = work / "libqplay.port.so"
        run_patch(
            "patch_connector_tls_port_test.py",
            [
                "--arch",
                "arm64-v8a",
                "--port",
                str(args.port),
                *(
                    ["--fallback-port", str(args.fallback_port)]
                    if args.fallback_port is not None
                    else []
                ),
                str(loopback),
                str(port),
            ],
        )
        fixed_key = work / "libqplay.fixed-key.so"
        run_patch(
            "patch_fixed_output_rc4_key_test.py",
            ["--arch", "arm64-v8a", str(port), str(fixed_key)],
        )
        final_native = fixed_key
        if args.force_nonpremium_loading:
            final_native = work / "libqplay.nonpremium.so"
            run_patch(
                "patch_force_no_premium_loading_test.py",
                [str(fixed_key), str(final_native)],
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
            "artifact": "arm64_native_trust_control_build",
            "network_contacted": False,
            "input_apk": str(apk),
            "input_apk_sha256": sha256(apk),
            "input_native_sha256": sha256(native_input),
            "trust_bundle": str(bundle),
            "trust_bundle_sha256": sha256(bundle),
            "output_apk": str(output),
            "output_apk_sha256": sha256(output),
            "output_native_sha256": sha256(final_native),
            "abi": "arm64-v8a",
            "connector_port": args.port,
            "connector_fallback_port": (
                args.fallback_port if args.fallback_port is not None else 80
            ),
            "deterministic_zip_timestamps": True,
            "connector_script_unchanged": True,
            "native_rsa_bypass_applied": False,
            "native_certificate_verification_preserved": True,
            "loading_branch_patch_applied": args.force_nonpremium_loading,
            "patches": [
                "patch_graalweb_trust_bundle.py",
                "patch_localhost_resolver_test.py",
                "patch_connector_tls_port_test.py",
                "patch_fixed_output_rc4_key_test.py",
            ]
            + (["patch_force_no_premium_loading_test.py"] if args.force_nonpremium_loading else []),
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
