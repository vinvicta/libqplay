#!/usr/bin/env python3
"""Export exact-name 1.8 to 2.2 translation candidates.

This is an offline metadata pass. It compares defined ARM64 FUNC entries and
function bytes in the original 1.8 library with the corresponding entries in
an unverified 2.2 library. A 2.2 APK is accepted directly so the raw native
file does not need to be copied into the repository. The output is a lookup
artifact, not an instruction to patch a target database without checking its
callers and data references.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from pathlib import Path

from generate_cross_version_symbol_overlap import (
    ROOT,
    classify,
    file_slice,
    inspect,
)


DEFAULT_ONE_EIGHT = (
    ROOT.parent / "GraalOnline+Classic_1.8_APKPure" / "lib" / "arm64-v8a" / "libqplay.so"
)
DEFAULT_TWO_TWO = ROOT.parent / "GraalOnline+Classic_2.2_installed.apk"
DEFAULT_OUTPUT = ROOT / "artifacts" / "cross_version_translation_candidates_20260902.json"
TWO_TWO_MEMBER = "lib/arm64-v8a/libqplay.so"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_input(path: Path, archive_member: str | None = None) -> tuple[dict[str, object], dict[str, object]]:
    """Return inspected ELF metadata and public source metadata."""

    if path.suffix.lower() != ".apk":
        info = inspect(path)
        return info, {
            "kind": "ELF",
            "sha256": info["sha256"],
            "size": info["size"],
            "source": path.name,
        }

    member = archive_member or TWO_TWO_MEMBER
    apk_data = path.read_bytes()
    with zipfile.ZipFile(path) as archive:
        try:
            native_data = archive.read(member)
        except KeyError as exc:
            raise ValueError(f"missing APK member: {member}") from exc

    with tempfile.NamedTemporaryFile(prefix="qplay-", suffix=".so") as handle:
        handle.write(native_data)
        handle.flush()
        info = inspect(Path(handle.name))
    return info, {
        "kind": "APK member",
        "apk_sha256": sha256(apk_data),
        "member": member,
        "native_sha256": sha256(native_data),
        "native_size": len(native_data),
        "source": path.name,
    }


def input_record(info: dict[str, object], source: dict[str, object]) -> dict[str, object]:
    text = info["text"]
    return {
        **source,
        "text_address": f"0x{int(text['address']):x}",
        "text_file_offset": f"0x{int(text['file_offset']):x}",
        "text_size": int(text["size"]),
        "defined_func_names": len(info["symbols"]),
    }


def build_report(one_eight_path: Path, two_two_path: Path, archive_member: str | None) -> dict[str, object]:
    one_eight, one_source = load_input(one_eight_path)
    two_two, two_source = load_input(two_two_path, archive_member)
    one_names = one_eight["symbols"]
    two_names = two_two["symbols"]
    common = sorted(set(one_names) & set(two_names))
    mappings: list[dict[str, object]] = []
    raw_equal_count = 0
    same_size_count = 0

    for name in common:
        a = one_names[name]
        b = two_names[name]
        a_address = int(a["address"])
        b_address = int(b["address"])
        a_size = int(a["size"])
        b_size = int(b["size"])
        same_size = a_size == b_size
        raw_equal = False
        if same_size:
            same_size_count += 1
            raw_equal = file_slice(one_eight, a_address, a_size) == file_slice(
                two_two, b_address, b_size
            )
            raw_equal_count += int(raw_equal)
        mappings.append(
            {
                "name": name,
                "family": classify(name),
                "1.8_address": f"0x{a_address:x}",
                "2.2_address": f"0x{b_address:x}",
                "address_delta": f"0x{b_address - a_address:x}",
                "1.8_size": a_size,
                "2.2_size": b_size,
                "size_equal": same_size,
                "raw_bytes_equal": raw_equal,
            }
        )

    return {
        "schema": "libqplay.cross-version-translation-candidates.v1",
        "artifact": "cross_version_translation_candidates_20260902",
        "analysis_date": "2026-09-02",
        "scope": "Offline exact-name mapping between defined ARM64 FUNC entries in the original 1.8 library and an unverified installed 2.2 package",
        "network_contacted": False,
        "native_executed": False,
        "inputs": {
            "1.8_arm64_libqplay": input_record(one_eight, one_source),
            "2.2_arm64_libqplay": input_record(two_two, two_source),
        },
        "method": {
            "symbol_source": "readelf --dyn-syms --wide",
            "matching": "Exact normalized dynamic FUNC name, with symbol-version suffixes removed",
            "address_mapping": "The 2.2 address is the value of the matching dynamic symbol, not a guessed global offset",
            "byte_comparison": "Raw bytes are compared only when both symbol sizes are equal and ranges map inside each .text section",
            "limitations": "The installed package is unverified and modified. Exact names and equal bytes are static candidates, not proof of identical callers, data references, or runtime behavior.",
        },
        "results": {
            "defined_func_names_1_8": len(one_names),
            "defined_func_names_2_2": len(two_names),
            "exact_name_intersection": len(common),
            "same_size": same_size_count,
            "raw_function_bytes_equal": raw_equal_count,
            "mappings": mappings,
        },
        "use_policy": [
            "Use the exact name as the first lookup key in a 2.2 IDA database.",
            "Check the target function boundary, size, callers, data references, and nearby strings before applying a label.",
            "Treat a nonmatching size or byte sequence as a review signal, not as a failed universal translation rule.",
            "Do not use this artifact to patch the installed hook library or to infer stock 2.2 behavior.",
        ],
        "raw_data_policy": "APK and native files remain outside the repository; this artifact contains hashes, symbol metadata, and mapping measurements only.",
        "tool": "tools/generate_cross_version_translation_candidates.py",
        "tool_version": 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--one-eight", type=Path, default=DEFAULT_ONE_EIGHT)
    parser.add_argument("--two-two", type=Path, default=DEFAULT_TWO_TWO)
    parser.add_argument("--two-two-member", default=TWO_TWO_MEMBER)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    for path in (args.one_eight, args.two_two):
        if not path.is_file():
            raise SystemExit(f"missing input: {path}")
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(args.one_eight, args.two_two, args.two_two_member)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(output),
        "exact_name_intersection": report["results"]["exact_name_intersection"],
        "same_size": report["results"]["same_size"],
        "raw_function_bytes_equal": report["results"]["raw_function_bytes_equal"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
