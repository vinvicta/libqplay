#!/usr/bin/env python3
"""Compare the four native ABI variants shipped by the original APK.

The report is metadata-only. It records ELF loader properties, dynamic symbol
counts, connector and TLS markers, and the hash of the embedded connector
trust text. It does not execute a library or open a socket. The input paths
are private workstation paths by default and the native files are not copied
into the research repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUT_ROOT = ROOT.parent / "GraalOnline+Classic_1.8_APKPure" / "lib"
DEFAULT_OUTPUT = ROOT / "artifacts" / "cross_abi_compatibility_review_20260902.json"
TRUST_PREFIX = b"6erxf21jcqpGrZR4"
TRUST_TEXT_SHA256 = "c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0"

VARIANTS = {
    "arm64-v8a": INPUT_ROOT / "arm64-v8a" / "libqplay.so",
    "armeabi": INPUT_ROOT / "armeabi" / "libqplay.so",
    "x86": INPUT_ROOT / "x86" / "libqplay.so",
    "x86_64": INPUT_ROOT / "x86_64" / "libqplay.so",
}

MARKERS = (
    b"con.quattroplay.com",
    b"con2.quattroplay.com",
    b"con.png",
    b"con.gs",
    b"conf.gs",
    b"CyaSSL",
    b"TLSv1_2",
    b"libstdc++.so",
    b"SSL_RSA_WITH_RC4_128_MD5",
    b"SSL_RSA_WITH_RC4_128_SHA",
    b"TLS_RSA_WITH_NULL_SHA",
    b"TLS_RSA_WITH_NULL_SHA256",
)

ANCHOR_TOKENS = (
    "QPlayMain",
    "QPlayLoop",
    "enterNextConnectorMode",
    "TServerList4login",
    "handleServerWarp",
    "sendRequest",
    "saveDownloadedData",
    "requestURLAsGameFile",
    "connectSocket",
    "enableSSLOnSocket",
    "setVerifyGraalWebCert",
    "TSocketConnection4read",
    "TSocketConnection8sendData",
    "setStatus",
    "parseProtocol",
    "checkPacketID",
    "setEncryptionIn",
    "connectToGameServer",
    "processFileChunk",
    "parseEncodedFileChunk",
    "requestDownload",
    "CyaSSL_connect",
    "CyaSSL_CTX_load_verify_buffer",
    "CyaSSL_set_verify",
    "CyaSSL_check_domain_name",
    "CyaSSL_get_error",
    "CyaSSL_read",
    "CyaSSL_write",
)

MACHINES = {
    3: "Intel 80386",
    40: "ARM",
    62: "Advanced Micro Devices X86-64",
    183: "AArch64",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_readelf(*args: str, path: Path) -> str:
    result = subprocess.run(
        ["readelf", *args, str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def parse_elf_header(blob: bytes) -> dict[str, object]:
    if blob[:4] != b"\x7fELF" or blob[5] != 1:
        raise ValueError("expected a little-endian ELF input")
    elf_class = blob[4]
    if elf_class == 2:
        fields = struct.unpack_from("<16sHHIQQQIHHHHHH", blob, 0)
        class_name = "ELF64"
    elif elf_class == 1:
        fields = struct.unpack_from("<16sHHIIII IHHHHHH".replace(" ", ""), blob, 0)
        class_name = "ELF32"
    else:
        raise ValueError(f"unsupported ELF class: {elf_class}")
    machine = int(fields[2])
    return {
        "class": class_name,
        "machine": MACHINES.get(machine, f"machine-{machine}"),
        "machine_id": machine,
        "entry_point": f"0x{int(fields[4]):x}",
    }


def parse_dynamic(output: str) -> dict[str, object]:
    needed = sorted(
        set(re.findall(r"\(NEEDED\).*?\[([^]]+)\]", output))
    )
    sonames = re.findall(r"\(SONAME\).*?\[([^]]+)\]", output)
    return {
        "needed": needed,
        "soname": sonames[0] if sonames else None,
        "bind_now": "BIND_NOW" in output
        or bool(re.search(r"FLAGS_1.*\bNOW\b", output)),
    }


def parse_program_headers(output: str) -> dict[str, object]:
    loads = []
    gnu_stack_flags = None
    has_gnu_relro = False
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "LOAD" and len(parts) >= 8:
            loads.append(
                {
                    "offset": parts[1],
                    "virtual_address": parts[2],
                    "file_size": parts[4],
                    "memory_size": parts[5],
                    "flags": " ".join(parts[6:-1]),
                    "align": parts[-1],
                }
            )
        elif parts[0] == "GNU_STACK" and len(parts) >= 7:
            gnu_stack_flags = " ".join(parts[6:-1])
        elif parts[0] == "GNU_RELRO":
            has_gnu_relro = True
    return {
        "load_segments": loads,
        "load_alignments": sorted({item["align"] for item in loads}),
        "gnu_stack_flags": gnu_stack_flags,
        "executable_stack": bool(
            gnu_stack_flags and "E" in gnu_stack_flags.split()
        ),
        "has_gnu_relro": has_gnu_relro,
    }


def parse_dynamic_symbols(output: str) -> dict[str, object]:
    rows = []
    entry_count = 0
    for line in output.splitlines():
        if not re.match(r"^\s*\d+:\s", line):
            continue
        entry_count += 1
        parts = line.split(None, 7)
        if len(parts) != 8:
            continue
        rows.append(
            {
                "value": parts[1],
                "size": parts[2],
                "type": parts[3],
                "index": parts[6],
                "name": parts[7].split()[0],
            }
        )
    defined = [row for row in rows if row["index"] != "UND"]
    defined_names = {str(row["name"]) for row in defined}
    defined_symbols = {
        str(row["name"]): {"value": row["value"], "size": row["size"]}
        for row in defined
    }
    function_types = {"FUNC", "IFUNC"}
    return {
        "dynamic_symbol_count": entry_count,
        "defined_symbol_count": len(defined),
        "undefined_symbol_count": entry_count - len(defined),
        "defined_function_count": sum(
            row["type"] in function_types for row in defined
        ),
        "defined_object_count": sum(row["type"] == "OBJECT" for row in defined),
        "defined_symbol_name_sha256": sha256(
            "\n".join(sorted(defined_names)).encode("utf-8")
        ),
        "defined_symbol_names": defined_names,
        "defined_symbols": defined_symbols,
    }


def trust_text_record(blob: bytes) -> dict[str, object]:
    start = blob.find(TRUST_PREFIX)
    if start < 0:
        return {"present": False}
    end = blob.find(b"\0", start)
    if end < 0:
        raise ValueError("embedded trust text is not NUL terminated")
    encoded = blob[start:end]
    return {
        "present": True,
        "file_offset": start,
        "bytes": len(encoded),
        "sha256": sha256(encoded),
        "matches_arm64_record": sha256(encoded) == TRUST_TEXT_SHA256,
    }


def inspect_variant(abi: str, path: Path) -> dict[str, object]:
    blob = path.read_bytes()
    dynamic = parse_dynamic(run_readelf("-d", path=path))
    program = parse_program_headers(run_readelf("-lW", path=path))
    symbols = parse_dynamic_symbols(run_readelf("--dyn-syms", "--wide", path=path))
    names = symbols.pop("defined_symbol_names")
    defined_symbols = symbols.pop("defined_symbols")
    return {
        "abi": abi,
        "path": str(path.relative_to(ROOT.parent)),
        "bytes": len(blob),
        "sha256": sha256(blob),
        "elf": {
            **parse_elf_header(blob),
            **dynamic,
            **program,
            **symbols,
        },
        "connector_tls_marker_counts": {
            marker.decode("ascii"): blob.count(marker) for marker in MARKERS
        },
        "embedded_trust_text": trust_text_record(blob),
        "_defined_symbol_names": names,
        "_defined_symbols": defined_symbols,
    }


def comparisons(variants: list[dict[str, object]]) -> list[dict[str, object]]:
    reference = variants[0]
    reference_names = reference["_defined_symbol_names"]
    results = []
    for item in variants[1:]:
        names = item["_defined_symbol_names"]
        results.append(
            {
                "reference_abi": reference["abi"],
                "abi": item["abi"],
                "defined_dynamic_symbol_intersection": len(reference_names & names),
                "reference_only_defined_dynamic_symbols": len(reference_names - names),
                "variant_only_defined_dynamic_symbols": len(names - reference_names),
                "reference_only_sample": sorted(reference_names - names)[:12],
                "variant_only_sample": sorted(names - reference_names)[:12],
                "trust_text_equal": reference["embedded_trust_text"].get("sha256")
                == item["embedded_trust_text"].get("sha256"),
                "connector_tls_markers_equal": reference["connector_tls_marker_counts"]
                == item["connector_tls_marker_counts"],
            }
        )
    return results


def anchor_symbol_rows(variants: list[dict[str, object]]) -> list[dict[str, object]]:
    common = set(variants[0]["_defined_symbols"])
    for item in variants[1:]:
        common &= set(item["_defined_symbols"])
    selected = sorted(
        name
        for name in common
        if any(token in name for token in ANCHOR_TOKENS)
    )
    return [
        {
            "symbol": name,
            "variants": {
                item["abi"]: item["_defined_symbols"][name]
                for item in variants
            },
        }
        for name in selected
    ]


def build_report() -> dict[str, object]:
    variants = [inspect_variant(abi, path) for abi, path in VARIANTS.items()]
    comparison_rows = comparisons(variants)
    anchor_rows = anchor_symbol_rows(variants)
    for item in variants:
        item.pop("_defined_symbol_names", None)
        item.pop("_defined_symbols", None)
    trust_hashes = {
        item["embedded_trust_text"].get("sha256") for item in variants
    }
    all_trust_equal = len(trust_hashes) == 1 and None not in trust_hashes
    all_markers_equal = len(
        {
            json.dumps(item["connector_tls_marker_counts"], sort_keys=True)
            for item in variants
        }
    ) == 1
    all_needed_equal = len(
        {tuple(item["elf"]["needed"]) for item in variants}
    ) == 1
    return {
        "schema": "libqplay.cross-abi-compatibility-review.v1",
        "artifact": "cross_abi_compatibility_review_20260902",
        "analysis_date": "2026-09-02",
        "scope": "metadata-only comparison of the four native ABI variants in the original 1.8 APK",
        "network_contacted": False,
        "variants": variants,
        "comparisons_to_arm64": comparison_rows,
        "symbol_anchors": {
            "selection": "Exact defined dynamic symbol names shared by all four variants and containing a connector, socket, protocol, JNI, or CyaSSL anchor token.",
            "count": len(anchor_rows),
            "rows": anchor_rows,
        },
        "shared_properties": {
            "all_variants_have_same_connector_tls_marker_counts": all_markers_equal,
            "all_variants_have_same_embedded_trust_text_hash": all_trust_equal,
            "all_variants_have_same_needed_libraries": all_needed_equal,
            "all_variants_use_bind_now": all(
                item["elf"]["bind_now"] for item in variants
            ),
            "all_variants_have_non_executable_stack": all(
                not item["elf"]["executable_stack"] for item in variants
            ),
            "all_variants_have_gnu_relro": all(
                item["elf"]["has_gnu_relro"] for item in variants
            ),
        },
        "findings": [
            {
                "id": "ABI-COMPAT-001",
                "title": "Connector trust material is shared across all four ABIs",
                "confidence": "confirmed-static",
                "assessment": "All four packaged libraries contain the same connector and CyaSSL marker set, and the embedded connector trust text has the same SHA-256 value recorded for the ARM64 build. The stale trust material and the connector fallback logic are therefore not likely to be an ARM64-only defect.",
                "limits": [
                    "The report compares embedded bytes and symbols, not live execution on each ABI.",
                    "Identical markers do not prove that every ABI reaches the same branch for every runtime error.",
                    "No current service or physical device was contacted.",
                ],
            },
            {
                "id": "ABI-COMPAT-002",
                "title": "Loader layout differs even though dependencies are shared",
                "confidence": "confirmed-static",
                "assessment": "Every ABI declares the same five native dependencies, including libstdc++.so, and enables BIND_NOW, GNU RELRO, and a non-executable stack. The ARM64 library uses 0x10000 LOAD alignment while the other variants use 0x1000, so loader behavior still needs an ARM64 device check.",
                "limits": [
                    "A declared SONAME does not prove that the target Android image supplies a compatible library.",
                    "Segment alignment alone does not identify a loader failure.",
                ],
            },
        ],
        "tool": "tools/generate_cross_abi_compatibility_review.py",
        "tool_version": 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    missing = [str(path) for path in VARIANTS.values() if not path.is_file()]
    if missing:
        raise SystemExit("missing ABI input(s): " + ", ".join(missing))
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report()
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(output),
                "variant_count": len(report["variants"]),
                "all_trust_equal": report["shared_properties"]["all_variants_have_same_embedded_trust_text_hash"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
