#!/usr/bin/env python3
"""Audit the unverified installed 2.2 comparison APK offline.

The generic manifest, DEX, ZIP, certificate, and ELF inventory is shared with
``audit_original_apk.py``. This wrapper adds a small metadata-only review of
the companion native library's runtime-hook indicators. It never installs,
loads, or executes either native library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

from audit_original_apk import audit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_APK = ROOT.parent / "GraalOnline+Classic_2.2_installed.apk"
DEFAULT_OUTPUT = ROOT / "artifacts" / "comparison_apk_security_audit_20260902.json"
HOOK_MEMBER = "lib/arm64-v8a/libxposed.so"


def marker_review(apk_path: Path) -> dict[str, object]:
    markers = (
        b"libqplay.so",
        b"dlopen",
        b"dlsym",
        b"mprotect",
        b"pthread_create",
        b"inline hook",
        b"Frida",
    )
    with ZipFile(apk_path) as archive:
        data = archive.read(HOOK_MEMBER)

    def offsets(marker: bytes) -> list[int]:
        result = []
        position = data.find(marker)
        while position >= 0 and len(result) < 8:
            result.append(position)
            position = data.find(marker, position + 1)
        return result

    return {
        "member": HOOK_MEMBER,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "markers": {
            marker.decode("ascii"): {
                "count": data.count(marker),
                "first_offsets": offsets(marker),
            }
            for marker in markers
            if marker in data
        },
    }


def build_report(apk_path: Path) -> dict[str, object]:
    report = audit(apk_path)
    hook = marker_review(apk_path)
    report["schema"] = "libqplay.comparison-apk-security-audit.v1"
    report["analysis_date"] = "2026-09-02"
    report["analysis_scope"] = "offline static inventory of the unverified installed 2.2 comparison APK"
    report["input_role"] = "comparison package only; not evidence about an official or stock 2.2 release"
    report["native_hook_review"] = hook
    report["findings"].append({
        "id": "CMP-001",
        "severity": "high-interest",
        "confidence": "confirmed static capability, runtime reachability untested",
        "title": "The comparison package includes a native library that can alter qplay at runtime",
        "evidence": [
            "The APK contains lib/arm64-v8a/libxposed.so.",
            "The companion ELF imports dlopen, dlsym, and mprotect and contains markers for libqplay.so, pthread_create, and an inline-hook status message.",
        ],
        "impact": "A companion library with this surface can resolve the game library and modify executable pages, so its presence changes the trust boundary and invalidates direct stock-behavior comparisons.",
        "limit": "This pass did not load or execute the library and does not claim that every hook runs on every device. The detailed static target review is recorded in docs/ABI_2_2_COMPARISON.md.",
    })
    report["reproduction"] = {
        "command": "python3 tools/audit_comparison_apk.py /path/to/GraalOnline+Classic_2.2_installed.apk --output artifacts/comparison_apk_security_audit_20260902.json",
        "side_effects": "Reads the APK and writes only the requested JSON report. Temporary files created by the shared audit are removed on exit.",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", nargs="?", type=Path, default=DEFAULT_APK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    apk_path = args.apk if args.apk.is_absolute() else Path.cwd() / args.apk
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not apk_path.is_file():
        parser.error(f"APK does not exist: {apk_path}")
    report = build_report(apk_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "input_sha256": report["input"]["sha256"],
        "findings": len(report["findings"]),
        "dex_files": len(report["dex"]),
        "native_files": len(report["native"]),
        "output": output.as_posix(),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
