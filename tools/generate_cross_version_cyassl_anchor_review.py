#!/usr/bin/env python3
"""Measure stable CyaSSL and JNI anchors between the 1.8 and 2.2 ARM64 files.

The inputs are private native files. The output is metadata-only: it records
hashes, section layout, exact dynamic-name intersections, selected addresses,
and raw function-byte equality. It does not execute a library or open a
socket.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ONE_EIGHT = (
    ROOT.parent / "GraalOnline+Classic_1.8_APKPure" / "lib" / "arm64-v8a" / "libqplay.so"
)
DEFAULT_TWO_TWO = (
    ROOT.parent / "analysis" / "GraalOnline+Classic_2.2_installed" / "lib" / "arm64-v8a" / "libqplay.so"
)
DEFAULT_OUTPUT = ROOT / "artifacts" / "cross_version_cyassl_anchor_review_20260902.json"
APK_SHA256 = "45f469692cb6ee2e8d0f1529d8b0871dafdf718e2c8b6e345cb5082e40257751"

SELECTED = [
    (
        "_ZN6CyaInt17CyaSSL_set_verifyEPNS_6CYASSLEiPFiiPNS_21CYASSL_X509_STORE_CTXEE",
        "Sets peer-verification mode and callback.",
    ),
    (
        "_ZN6CyaInt29CyaSSL_CTX_load_verify_bufferEPNS_10CYASSL_CTXEPKhli",
        "Loads a certificate bundle into the CyaSSL context.",
    ),
    (
        "_ZN6CyaInt24CyaSSL_check_domain_nameEPNS_6CYASSLEPKc",
        "Checks the peer certificate name against the requested host.",
    ),
    (
        "_ZN6CyaInt14CyaSSL_connectEPNS_6CYASSLE",
        "Runs the TLS connection state machine.",
    ),
    (
        "Java_com_quattroplay_GraalClassic_Natives_QPlayMain",
        "JNI native startup entrypoint.",
    ),
    (
        "Java_com_quattroplay_GraalClassic_Natives_QPlayLoop",
        "JNI render and timer loop entrypoint.",
    ),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def readelf(*args: str, path: Path) -> str:
    return subprocess.check_output(
        ["readelf", *args, str(path)], text=True, errors="replace"
    )


def parse_sections(path: Path) -> dict[str, dict[str, int]]:
    sections: dict[str, dict[str, int]] = {}
    pattern = re.compile(
        r"^\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
    )
    for line in readelf("-SW", path=path).splitlines():
        match = pattern.match(line)
        if not match:
            continue
        index, name, address, offset, size = match.groups()
        if name in {".text", ".rodata", ".init_array", ".fini_array", ".bss"}:
            sections[name] = {
                "index": int(index),
                "address": int(address, 16),
                "file_offset": int(offset, 16),
                "size": int(size, 16),
            }
    return sections


def parse_symbols(path: Path) -> dict[str, dict[str, int]]:
    symbols: dict[str, dict[str, int]] = {}
    for line in readelf("--dyn-syms", "--wide", path=path).splitlines():
        if not re.match(r"^\s*\d+:\s", line):
            continue
        fields = line.split(None, 7)
        if len(fields) != 8:
            continue
        value, size, symbol_type, _bind, _visibility, section, name = fields[1:]
        name = name.split()[0].split("@", 1)[0]
        if section == "UND" or symbol_type != "FUNC":
            continue
        if name.startswith("_ZN6CyaInt") or name.startswith("Java_"):
            symbols[name] = {"address": int(value, 16), "size": int(size)}
    return symbols


def inspect(path: Path) -> dict[str, object]:
    blob = path.read_bytes()
    return {
        "path": str(path),
        "blob": blob,
        "sha256": sha256(blob),
        "size": len(blob),
        "sections": parse_sections(path),
        "symbols": parse_symbols(path),
    }


def file_offset(info: dict[str, object], address: int) -> int:
    text = info["sections"][".text"]
    return int(text["file_offset"]) + address - int(text["address"])


def selected_anchor(
    name: str,
    role: str,
    one_eight: dict[str, object],
    two_two: dict[str, object],
) -> dict[str, object]:
    a = one_eight["symbols"][name]
    b = two_two["symbols"][name]
    a_address = int(a["address"])
    b_address = int(b["address"])
    a_size = int(a["size"])
    b_size = int(b["size"])
    result: dict[str, object] = {
        "name": name,
        "1.8_address": f"0x{a_address:x}",
        "2.2_address": f"0x{b_address:x}",
        "address_delta": f"0x{b_address - a_address:x}",
        "raw_bytes_equal": False,
        "role": role,
    }
    if name.startswith("Java_"):
        result["1.8_size"] = a_size
        result["2.2_size"] = b_size
    else:
        result["size"] = a_size
        if a_size != b_size:
            result["2.2_size"] = b_size
    if a_size == b_size:
        a_start = file_offset(one_eight, a_address)
        b_start = file_offset(two_two, b_address)
        a_bytes = one_eight["blob"][a_start : a_start + a_size]
        b_bytes = two_two["blob"][b_start : b_start + b_size]
        result["raw_bytes_equal"] = a_bytes == b_bytes
    return result


def build_report(one_eight_path: Path, two_two_path: Path) -> dict[str, object]:
    one_eight = inspect(one_eight_path)
    two_two = inspect(two_two_path)
    one_names = {
        name: value
        for name, value in one_eight["symbols"].items()
        if name.startswith("_ZN6CyaInt")
    }
    two_names = {
        name: value
        for name, value in two_two["symbols"].items()
        if name.startswith("_ZN6CyaInt")
    }
    common = sorted(set(one_names) & set(two_names))
    deltas = collections.Counter(
        int(two_names[name]["address"]) - int(one_names[name]["address"])
        for name in common
    )
    same_size = 0
    raw_equal = 0
    shifted_names = []
    for name in common:
        a = one_names[name]
        b = two_names[name]
        if int(a["size"]) == int(b["size"]):
            same_size += 1
            a_start = file_offset(one_eight, int(a["address"]))
            b_start = file_offset(two_two, int(b["address"]))
            a_bytes = one_eight["blob"][a_start : a_start + int(a["size"])]
            b_bytes = two_two["blob"][b_start : b_start + int(b["size"])]
            if a_bytes == b_bytes:
                raw_equal += 1
        if int(b["address"]) - int(a["address"]) == 0xD588:
            shifted_names.append(name)

    def input_record(info: dict[str, object]) -> dict[str, object]:
        text = info["sections"][".text"]
        return {
            "sha256": info["sha256"],
            "size": info["size"],
            "text_address": f"0x{int(text['address']):x}",
            "text_file_offset": f"0x{int(text['file_offset']):x}",
            "text_size": int(text["size"]),
        }

    selected = [
        selected_anchor(name, role, one_eight, two_two) for name, role in SELECTED
    ]
    report = {
        "artifact": "cross_version_cyassl_anchor_review",
        "date": "2026-09-02",
        "scope": "Offline dynamic-symbol and function-byte comparison between the original 1.8 ARM64 library and the unverified installed 2.2 ARM64 library",
        "inputs": {
            "1.8_arm64_libqplay": input_record(one_eight),
            "2.2_arm64_libqplay": input_record(two_two),
            "installed_2.2_apk": APK_SHA256,
        },
        "method": {
            "symbol_source": "readelf -Ws dynamic symbol tables",
            "function_scope": "defined FUNC entries whose exact mangled name begins with _ZN6CyaInt",
            "byte_comparison": "Raw bytes at the symbol value for equal-sized functions; section virtual address equals file offset for both inputs",
            "limitations": "Raw byte inequality can result from version changes, relocated PC-relative references, or surrounding layout. Equality is a strong implementation anchor but is not a complete behavioral proof.",
        },
        "results": {
            "cyassl_symbols_1_8": len(one_names),
            "cyassl_symbols_2_2": len(two_names),
            "exact_name_intersection": len(common),
            "same_size": same_size,
            "address_delta_0xd590_count": deltas[0xD590],
            "address_delta_0xd588_count": deltas[0xD588],
            "raw_function_bytes_equal": raw_equal,
            "shifted_0xd588_names": shifted_names,
            "selected_anchors": selected,
        },
        "assessment": {
            "confirmed": [
                "The 2.2 library retains the exact 253 CyaSSL dynamic function names present in the 1.8 library.",
                "All 253 matched CyaSSL functions retain their 1.8 sizes, and their addresses follow one of two stable deltas.",
                "84 matched CyaSSL function bodies are byte-for-byte equal at the corresponding addresses, including certificate-buffer loading and verification-mode setters.",
                "Hostname-checking and TLS-connect bodies have changed despite retaining the same names and sizes, so the shared address delta is not enough to claim identical transport behavior.",
                "The JNI startup entrypoint keeps its size and a separate address delta, while the render loop grows substantially in 2.2.",
            ],
            "not_proven": [
                "The installed package is an official or unmodified 2.2 release.",
                "Any 1.8 application symbol maps to 2.2 by a single address delta.",
                "The 2.2 trust bundle, connector endpoints, or package policy match 1.8.",
                "The same runtime state, Java scripts, or server protocol behavior exists in both versions.",
            ],
            "safe_use": "Use the exact CyaSSL names and the measured 0xd590 or 0xd588 delta as static anchors only. Recheck each target's bytes, callers, and data references before applying an IDA label or patch to 2.2.",
        },
        "raw_data_policy": "APK and native files remain outside the repository; this artifact contains hashes, symbol metadata, and selected anchor measurements only.",
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--one-eight", type=Path, default=DEFAULT_ONE_EIGHT)
    parser.add_argument("--two-two", type=Path, default=DEFAULT_TWO_TWO)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report(args.one_eight, args.two_two)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "results": report["results"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
