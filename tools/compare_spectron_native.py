#!/usr/bin/env python3
"""Compare two ELF64 ARM64 native libraries without executing either file.

This is deliberately an offline comparison helper. It parses the ELF header,
section table, dynamic symbol table, and printable strings directly from the
files. It does not load a library, contact a service, or attempt to infer
semantic names from an obfuscated build.
"""

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


ELF64_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_SECTION = struct.Struct("<IIQQQQIIQQ")
ELF64_SYMBOL = struct.Struct("<IBBHQQ")
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_c_string(blob, offset):
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")


def section_table(data, header):
    shoff = header[6]
    shentsize = header[11]
    shnum = header[12]
    shstrndx = header[13]
    raw = []
    for index in range(shnum):
        start = shoff + index * shentsize
        raw.append(ELF64_SECTION.unpack_from(data, start))
    shstr = raw[shstrndx]
    shstr_blob = data[shstr[4] : shstr[4] + shstr[5]]
    sections = []
    for index, item in enumerate(raw):
        name = read_c_string(shstr_blob, item[0])
        sections.append(
            {
                "index": index,
                "name": name,
                "type": item[1],
                "flags": item[2],
                "address": item[3],
                "offset": item[4],
                "size": item[5],
                "link": item[6],
                "info": item[7],
                "alignment": item[8],
                "entry_size": item[9],
            }
        )
    return sections


def dynamic_symbols(data, sections):
    by_name = {section["name"]: section for section in sections}
    dynsym = by_name.get(".dynsym")
    dynstr = by_name.get(".dynstr")
    if not dynsym or not dynstr:
        return []

    string_blob = data[dynstr["offset"] : dynstr["offset"] + dynstr["size"]]
    entry_size = dynsym["entry_size"] or ELF64_SYMBOL.size
    count = dynsym["size"] // entry_size
    symbols = []
    for index in range(count):
        start = dynsym["offset"] + index * entry_size
        fields = ELF64_SYMBOL.unpack_from(data, start)
        name = read_c_string(string_blob, fields[0])
        symbols.append(
            {
                "index": index,
                "name": name,
                "value": fields[4],
                "size": fields[5],
                "type": fields[1] & 0x0F,
                "binding": fields[1] >> 4,
                "section_index": fields[3],
            }
        )
    return symbols


def printable_strings(data):
    return list(PRINTABLE_RE.finditer(data))


def matching_runs(data, needle):
    matches = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return matches
        left = offset
        while left > 0 and 0x20 <= data[left - 1] <= 0x7E:
            left -= 1
        right = offset + len(needle)
        while right < len(data) and 0x20 <= data[right] <= 0x7E:
            right += 1
        run = data[left:right]
        matches.append(
            {
                "offset": offset,
                "run_offset": left,
                "run_length": len(run),
                "run_sha256": sha256(run),
            }
        )
        start = offset + len(needle)


def symbol_summary(symbols):
    names = {symbol["name"] for symbol in symbols if symbol["name"]}
    return {
        "table_entries": len(symbols),
        "named_entries": len(names),
        "function_entries": sum(symbol["type"] == 2 for symbol in symbols),
        "object_entries": sum(symbol["type"] == 1 for symbol in symbols),
        "cxx_mangled_entries": sum(symbol["name"].startswith("_Z") for symbol in symbols),
        "readable_application_entries": sum(
            any(token in symbol["name"] for token in ("TServer", "TClient", "TGraal", "Java_", "JNI_"))
            for symbol in symbols
        ),
        "names": names,
    }


def inspect(label, path, needles):
    data = Path(path).read_bytes()
    header = ELF64_HEADER.unpack_from(data, 0)
    if header[0][:4] != b"\x7fELF" or header[0][4] != 2:
        raise ValueError("expected an ELF64 file: %s" % path)
    sections = section_table(data, header)
    symbols = dynamic_symbols(data, sections)
    string_matches = printable_strings(data)
    symbol_data = symbol_summary(symbols)
    symbol_names = symbol_data.pop("names")
    return {
        "label": label,
        "file_size": len(data),
        "sha256": sha256(data),
        "machine": header[2],
        "entry_point": header[4],
        "program_header_count": header[10],
        "section_count": header[12],
        "sections": [
            {
                "name": section["name"],
                "address": section["address"],
                "offset": section["offset"],
                "size": section["size"],
                "flags": section["flags"],
            }
            for section in sections
            if section["name"]
        ],
        "dynamic_symbols": symbol_data,
        "printable_string_count": len(string_matches),
        "needles": {needle.decode("ascii"): matching_runs(data, needle) for needle in needles},
        "_symbol_names": symbol_names,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--spectron", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    needles = [
        b"PjosLg8D",
        b"b5liime+ea5Lcikk",
        b"6erxf21jcqpGrZR4",
        b"SetSigningCertificate",
        b"GRAALRELOADED-version:",
        b"127.0.0.1",
        b"graal://",
        b"graal3://",
    ]
    original = inspect("original ARM64 libqplay", args.original, needles)
    spectron = inspect("Spectron ARM64 libqplay", args.spectron, needles)
    shared_names = original["_symbol_names"] & spectron["_symbol_names"]
    original.pop("_symbol_names")
    spectron.pop("_symbol_names")

    result = {
        "comparison": "offline ELF64 ARM64 native-library comparison",
        "original": original,
        "spectron": spectron,
        "dynamic_symbol_name_overlap": {
            "exact_shared_names": len(shared_names),
            "shared_names": sorted(shared_names),
            "original_named_names": original["dynamic_symbols"]["named_entries"],
            "spectron_named_names": spectron["dynamic_symbols"]["named_entries"],
        },
        "interpretation": [
            "The entry point and section offsets differ, so original ARM64 virtual addresses cannot be copied into Spectron.",
            "The exact embedded connector key and trust markers can be compared by offset and run hash without treating them as current credentials.",
            "A low dynamic-symbol name overlap with obfuscated C++ names is evidence of a separate native build, not evidence that its protocol is compatible with 1.8.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "shared_dynamic_names": len(shared_names)}))


if __name__ == "__main__":
    main()
