#!/usr/bin/env python3
"""Compare retained ARM64 function names between the 1.8 and 2.2 libraries.

The inputs are private native files. The output is metadata-only: it records
hashes, exact dynamic-name overlap, size equality, address-delta clusters,
selected anchors, and raw function-byte equality. It does not execute a
library or open a socket.
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
DEFAULT_OUTPUT = ROOT / "artifacts" / "cross_version_symbol_overlap_20260902.json"
APK_SHA256 = "45f469692cb6ee2e8d0f1529d8b0871dafdf718e2c8b6e345cb5082e40257751"

SELECTED = [
    (
        "FT_Init_FreeType",
        "Bundled FreeType initialization anchor.",
    ),
    (
        "jpeg_start_decompress",
        "Bundled JPEG decompression anchor.",
    ),
    (
        "DGifOpen",
        "Bundled GIF decoder anchor.",
    ),
    (
        "yajl_parse",
        "Bundled JSON parser anchor.",
    ),
    (
        "deflate",
        "Bundled zlib compression anchor.",
    ),
    (
        "BZ2_bzDecompress",
        "Bundled bzip2 decompression anchor.",
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


def parse_number(value: str) -> int:
    return int(value, 0) if value.lower().startswith("0x") else int(value, 10)


def readelf(*args: str, path: Path) -> str:
    return subprocess.check_output(
        ["readelf", *args, str(path)], text=True, errors="replace"
    )


def parse_text_section(path: Path) -> dict[str, int]:
    pattern = re.compile(
        r"^\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
    )
    for line in readelf("-SW", path=path).splitlines():
        match = pattern.match(line)
        if match and match.group(2) == ".text":
            return {
                "address": int(match.group(3), 16),
                "file_offset": int(match.group(4), 16),
                "size": int(match.group(5), 16),
            }
    raise ValueError(f"missing .text section: {path}")


def parse_symbols(path: Path) -> dict[str, dict[str, int]]:
    symbols: dict[str, dict[str, int]] = {}
    for line in readelf("--dyn-syms", "--wide", path=path).splitlines():
        if not re.match(r"^\s*\d+:\s", line):
            continue
        fields = line.split(None, 7)
        if len(fields) != 8:
            continue
        value, size, symbol_type, _bind, _visibility, section, name = fields[1:]
        if section == "UND" or symbol_type != "FUNC":
            continue
        normalized = name.split()[0].split("@", 1)[0]
        symbols[normalized] = {
            "address": int(value, 16),
            "size": parse_number(size),
        }
    return symbols


def inspect(path: Path) -> dict[str, object]:
    blob = path.read_bytes()
    return {
        "path": str(path),
        "blob": blob,
        "sha256": sha256(blob),
        "size": len(blob),
        "text": parse_text_section(path),
        "symbols": parse_symbols(path),
    }


def file_slice(info: dict[str, object], address: int, size: int) -> bytes:
    text = info["text"]
    start = int(text["file_offset"]) + address - int(text["address"])
    end = start + size
    if start < 0 or end > len(info["blob"]):
        raise ValueError(f"function range is outside the file: 0x{address:x}")
    return info["blob"][start:end]


def classify(name: str) -> str:
    """Return a conservative name-family label for compact aggregate counts."""

    lower = name.lower()
    if name.startswith("_ZN6CyaInt"):
        return "CyaSSL"
    if name.startswith("Java_"):
        return "JNI"
    if name.startswith(("FT_", "FTC_", "TT_", "t1_", "af_", "cff_", "ft_", "ps_", "sfnt_", "tt_")):
        return "FreeType/TrueType"
    if name.startswith(("DGif", "EGif", "Gif")):
        return "GIF"
    if name.startswith("BZ2_") or "BZ2_" in name:
        return "bzip2"
    if "yajl" in lower:
        return "YAJL"
    if any(
        token in lower
        for token in (
            "jpeg",
            "jdiv",
            "jcopy",
            "jinit",
            "jdh",
            "jccoef",
            "jchuff",
            "jcmaster",
            "jcomapi",
            "jcprep",
            "jcsample",
            "jctrans",
            "jerror",
            "jfdct",
            "jmem",
            "jquant",
            "jutils",
        )
    ):
        return "JPEG-like"
    if name.startswith(("adler32", "crc32", "deflate", "inflate", "gz", "zError", "zlib")):
        return "zlib"
    if re.search(r"(arc4|aes|hmac|sha|md5|rsa|des|rng|base64|dsa|_mp_|mp_)", lower):
        return "crypto-like"
    return "other"


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
        "1.8_size": a_size,
        "2.2_size": b_size,
        "size_equal": a_size == b_size,
        "raw_bytes_equal": False,
        "role": role,
    }
    if a_size == b_size:
        result["raw_bytes_equal"] = file_slice(one_eight, a_address, a_size) == file_slice(
            two_two, b_address, b_size
        )
    return result


def input_record(info: dict[str, object]) -> dict[str, object]:
    text = info["text"]
    return {
        "path": str(Path(info["path"]).relative_to(ROOT.parent)),
        "sha256": info["sha256"],
        "size": info["size"],
        "text_address": f"0x{int(text['address']):x}",
        "text_file_offset": f"0x{int(text['file_offset']):x}",
        "text_size": int(text["size"]),
        "defined_func_names": len(info["symbols"]),
    }


def build_report(one_eight_path: Path, two_two_path: Path) -> dict[str, object]:
    one_eight = inspect(one_eight_path)
    two_two = inspect(two_two_path)
    one_names = one_eight["symbols"]
    two_names = two_two["symbols"]
    common = sorted(set(one_names) & set(two_names))

    delta_counts = collections.Counter(
        int(two_names[name]["address"]) - int(one_names[name]["address"])
        for name in common
    )
    same_size = 0
    raw_equal = 0
    category_rows: dict[str, dict[str, object]] = {}
    for name in common:
        a = one_names[name]
        b = two_names[name]
        size_equal = int(a["size"]) == int(b["size"])
        equal = False
        if size_equal:
            same_size += 1
            equal = file_slice(one_eight, int(a["address"]), int(a["size"])) == file_slice(
                two_two, int(b["address"]), int(b["size"])
            )
            raw_equal += int(equal)

        family = classify(name)
        row = category_rows.setdefault(
            family,
            {
                "common_names": 0,
                "same_size": 0,
                "raw_bytes_equal": 0,
                "address_deltas": collections.Counter(),
                "sample_names": [],
            },
        )
        row["common_names"] += 1
        row["same_size"] += int(size_equal)
        row["raw_bytes_equal"] += int(equal)
        row["address_deltas"][int(b["address"]) - int(a["address"])] += 1
        if len(row["sample_names"]) < 8:
            row["sample_names"].append(name)

    categories = {}
    for family in sorted(category_rows):
        row = category_rows[family]
        categories[family] = {
            "common_names": row["common_names"],
            "same_size": row["same_size"],
            "raw_bytes_equal": row["raw_bytes_equal"],
            "address_deltas": [
                {"delta": f"0x{delta:x}", "count": count}
                for delta, count in sorted(
                    row["address_deltas"].items(),
                    key=lambda item: (-item[1], item[0]),
                )
            ],
            "sample_names": row["sample_names"],
        }

    selected = [
        selected_anchor(name, role, one_eight, two_two)
        for name, role in SELECTED
        if name in one_names and name in two_names
    ]
    return {
        "schema": "libqplay.cross-version-symbol-overlap.v1",
        "artifact": "cross_version_symbol_overlap_20260902",
        "analysis_date": "2026-09-02",
        "scope": "Offline comparison of defined ARM64 FUNC names and function bytes between the original 1.8 library and the unverified installed 2.2 library",
        "network_contacted": False,
        "inputs": {
            "1.8_arm64_libqplay": input_record(one_eight),
            "2.2_arm64_libqplay": input_record(two_two),
            "installed_2.2_apk_sha256": APK_SHA256,
        },
        "method": {
            "symbol_source": "readelf --dyn-syms --wide",
            "function_scope": "Defined FUNC entries, with symbol-version suffixes removed from names for exact-name matching",
            "byte_comparison": "Raw bytes at the symbol value for equal-sized functions, mapped through each input's .text section",
            "family_labels": "Conservative name-prefix or name-token buckets used only for aggregate counts; the other bucket is not a source identification",
            "limitations": "Raw byte inequality can result from implementation changes, relocated PC-relative references, or surrounding layout. Equality is a useful static anchor but is not a complete behavioral proof.",
        },
        "family_rules": {
            "CyaSSL": "Exact name prefix _ZN6CyaInt",
            "JNI": "Exact name prefix Java_",
            "FreeType/TrueType": "Known FreeType and TrueType export prefixes such as FT_, FTC_, TT_, t1_, cff_, and sfnt_",
            "GIF": "Names beginning DGif, EGif, or Gif",
            "bzip2": "Names beginning BZ2_ or containing the BZ2_ token",
            "YAJL": "Names containing the yajl token",
            "JPEG-like": "Known JPEG export tokens such as jpeg, jinit, jdiv, and jfdct",
            "zlib": "Known zlib export prefixes such as deflate, inflate, crc32, adler32, and zlib",
            "crypto-like": "Common legacy helper tokens such as Arc4, AES, HMAC, SHA, MD5, RSA, DES, RNG, and Base64",
            "other": "Names not matched by a prior rule",
        },
        "results": {
            "defined_func_names_1_8": len(one_names),
            "defined_func_names_2_2": len(two_names),
            "exact_name_intersection": len(common),
            "1_8_only_names": len(set(one_names) - set(two_names)),
            "2_2_only_names": len(set(two_names) - set(one_names)),
            "same_size": same_size,
            "raw_function_bytes_equal": raw_equal,
            "address_delta_histogram": [
                {"delta": f"0x{delta:x}", "count": count}
                for delta, count in sorted(
                    delta_counts.items(), key=lambda item: (-item[1], item[0])
                )
            ],
            "1_8_only_sample": sorted(set(one_names) - set(two_names))[:12],
            "2_2_only_sample": sorted(set(two_names) - set(one_names))[:12],
            "families": categories,
            "selected_anchors": selected,
        },
        "assessment": {
            "confirmed": [
                "The two inputs share 835 exact defined dynamic function names after symbol-version suffix normalization.",
                "The shared names fall into several address-delta clusters rather than one universal translation offset.",
                "830 shared functions retain the same exported size, and 279 are byte-for-byte equal at their corresponding file locations.",
                "The bundled dependency families provide useful static anchors, while JNI entrypoints show multiple independent layout changes.",
            ],
            "not_proven": [
                "The installed 2.2 package is official or unmodified.",
                "A shared name has identical callers, data references, or runtime behavior.",
                "An address translated by a family delta is safe to patch without rechecking its bytes and cross-references.",
                "The two packages use the same connector, trust material, package policy, or server protocol behavior.",
            ],
            "safe_use": "Use exact names as the first lookup key. For a candidate 2.2 translation, recheck the measured size, raw bytes, callers, and data references in the target IDA database before applying a label or patch.",
        },
        "raw_data_policy": "APK and native files remain outside the repository; this artifact contains hashes, symbol metadata, aggregate measurements, and selected names only.",
        "tool": "tools/generate_cross_version_symbol_overlap.py",
        "tool_version": 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--one-eight", type=Path, default=DEFAULT_ONE_EIGHT)
    parser.add_argument("--two-two", type=Path, default=DEFAULT_TWO_TWO)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    missing = [
        str(path)
        for path in (args.one_eight, args.two_two)
        if not path.is_file()
    ]
    if missing:
        raise SystemExit("missing input(s): " + ", ".join(missing))
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(args.one_eight, args.two_two)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "exact_name_intersection": report["results"]["exact_name_intersection"],
                "raw_function_bytes_equal": report["results"]["raw_function_bytes_equal"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
