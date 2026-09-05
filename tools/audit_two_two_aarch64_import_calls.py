#!/usr/bin/env python3
"""Inventory direct AArch64 import callsites in the comparison 2.2 library.

The scanner reuses the conservative ELF and PLT parser used for the original
1.8 import review. It maps direct BL and unconditional B transfers to the
retained 2.2 dynamic-function names. Indirect calls and runtime reachability
remain outside the result. The input is never executed and no network service
is contacted.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from audit_aarch64_import_calls import parse_elf, scan_direct_transfers
from generate_cross_version_symbol_overlap import DEFAULT_TWO_TWO, ROOT, inspect


DEFAULT_OUTPUT = ROOT / "artifacts" / "comparison_2_2_aarch64_import_callsite_review_20260904.json"


IMPORT_CLASS = {
    "accept": "socket-server-boundary",
    "bind": "socket-server-boundary",
    "connect": "socket-client-boundary",
    "dlopen": "runtime-loader-boundary",
    "dlsym": "runtime-loader-boundary",
    "execvp": "process-execution-boundary",
    "fork": "process-creation-boundary",
    "gethostbyname": "legacy-dns-resolution",
    "ioctl": "device-metadata-boundary",
    "listen": "socket-server-boundary",
    "open": "file-open-boundary",
    "opendir": "directory-enumeration",
    "recv": "socket-stream-read",
    "recvfrom": "socket-datagram-read",
    "send": "socket-stream-write",
    "sendto": "socket-datagram-write",
    "socket": "socket-creation",
    "sscanf": "text-parsing-boundary",
    "unlink": "file-deletion-boundary",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.parent.resolve()))
    except ValueError:
        return "<private-input>/" + path.name


def load_dynamic_functions(binary: Path) -> list[dict[str, object]]:
    info = inspect(binary)
    functions = []
    text = info["text"]
    text_start = int(text["address"])
    text_end = text_start + int(text["size"])
    for name, symbol in info["symbols"].items():
        start = int(symbol["address"])
        size = int(symbol["size"])
        if symbol and size > 0 and text_start <= start < text_end and start + size <= text_end:
            functions.append(
                {
                    "start": start,
                    "end": start + size,
                    "address": f"0x{start:x}",
                    "name": name,
                }
            )
    return sorted(functions, key=lambda item: (int(item["start"]), item["name"]))


def build_report(binary: Path) -> dict[str, object]:
    parsed = parse_elf(binary)
    functions = load_dynamic_functions(binary)
    calls = scan_direct_transfers(parsed, functions)
    imports = []
    for symbol_index, symbol in sorted(
        parsed["undefined_symbols"].items(), key=lambda item: item[1]["name"]
    ):
        relocation = parsed["plt_by_symbol"].get(symbol_index)
        direct_calls = sorted(
            calls.get(symbol_index, []), key=lambda item: int(item["callsite"], 16)
        )
        item = {
            "name": symbol["name"],
            "symbol_index": symbol_index,
            "plt_stub": f"0x{relocation['plt_stub']:x}" if relocation else None,
            "got": f"0x{relocation['got']:x}" if relocation else None,
            "direct_call_count": len(direct_calls),
            "direct_calls": direct_calls,
        }
        if symbol["name"] in IMPORT_CLASS:
            item["classification"] = IMPORT_CLASS[symbol["name"]]
        imports.append(item)

    direct_call_count = sum(item["direct_call_count"] for item in imports)
    imports_with_calls = [item for item in imports if item["direct_call_count"]]
    highlighted = [item for item in imports if item["name"] in IMPORT_CLASS]
    return {
        "schema": "libqplay.comparison-2-2-aarch64-import-callsite-review.v1",
        "artifact": "comparison_2_2_aarch64_import_callsite_review_20260904",
        "analysis_date": "2026-09-04",
        "scope": "Direct AArch64 BL and unconditional B transfers from the unverified installed 2.2 ARM64 libqplay.so to undefined ELF symbols",
        "input": {
            "path": display_path(binary),
            "sha256": sha256_file(binary),
            "size": binary.stat().st_size,
            "architecture": "AArch64 ELF64 little-endian",
            "unverified_comparison_input": True,
        },
        "function_source": {
            "source": "readelf --dyn-syms --wide",
            "defined_dynamic_function_count": len(functions),
        },
        "elf": {
            "text_address": f"0x{parsed['text'][3]:x}",
            "text_size": parsed["text"][5],
            "plt_address": f"0x{parsed['plt'][3]:x}",
            "plt_size": parsed["plt"][5],
            "plt_entry_count": len(parsed["plt_by_symbol"]),
            "undefined_symbol_count": len(parsed["undefined_symbols"]),
        },
        "method": {
            "transfer_types": ["bl", "b"],
            "caller_resolution": "Containing retained defined dynamic FUNC range when one exists",
            "limitations": [
                "Indirect calls through BLR, function pointers, virtual tables, or data tables are not included.",
                "A direct callsite proves an imported capability in the file, not runtime reachability or input control.",
                "Obfuscated caller names are preserved exactly; no semantic name is inferred from their spelling.",
            ],
        },
        "summary": {
            "imports_with_direct_calls": len(imports_with_calls),
            "direct_call_count": direct_call_count,
            "tail_call_count": sum(
                1
                for item in imports
                for call in item["direct_calls"]
                if call["transfer"] == "b"
            ),
            "imports_without_direct_calls": len(imports) - len(imports_with_calls),
            "highlighted_imports_with_calls": {
                item["name"]: item["direct_call_count"]
                for item in highlighted
                if item["direct_call_count"]
            },
            "classification_counts": dict(
                sorted(
                    collections.Counter(
                        item.get("classification", "other-import")
                        for item in imports_with_calls
                    ).items()
                )
            ),
        },
        "security_observations": [
            {
                "id": "CMP22-IMPORT-001",
                "severity": "high-interest",
                "classification": "process-capability",
                "status": "confirmed-static-capability-unproven-runtime-reachability",
                "evidence": [
                    "fork has two direct callsites at 0x19bb44 and 0x19bb94.",
                    "execvp has one direct callsite at 0x19bc58.",
                    "The containing retained dynamic function is _ZN10IMzlIaJILV10vRZrAaJE9gERK10C8THgaTQxF at 0x19bb08.",
                ],
                "interpretation": "The comparison qplay file contains a process-creation and executable-handoff path. The callsite scan does not establish its arguments, trigger, or stock startup reachability.",
                "next_test": "In a disposable offline analysis, resolve the containing function's string and data references in a 2.2 IDA database before assigning a semantic label or considering any runtime test.",
            },
            {
                "id": "CMP22-IMPORT-002",
                "severity": "high-interest",
                "classification": "runtime-loader-capability",
                "status": "confirmed-static-capability-unproven-runtime-reachability",
                "evidence": [
                    "dlopen and dlsym each have one direct callsite at 0x2531c0 and 0x2531d0.",
                    "Both calls are contained by _Z10_al0FaXqUXPKcPc at 0x253164.",
                ],
                "interpretation": "The qplay binary itself can perform runtime library loading and symbol lookup. This is separate evidence from the companion libxposed.so and should not be attributed to the hook library without a call-argument review.",
                "next_test": "Resolve the path and symbol strings used by the containing function in IDA, without loading the companion library.",
            },
            {
                "id": "CMP22-IMPORT-003",
                "severity": "medium",
                "classification": "anti-instrumentation-path",
                "status": "confirmed-static-capability-unproven-runtime-reachability",
                "evidence": [
                    "inet_aton is called by _Z18detect_frida_loop2Pv at 0x24f6a8.",
                    "sscanf is called by _Z16DetectFridaLoop1bbb at 0x24a8f4 and by _Z24scan_executable_segmentsPc at 0x24f510.",
                    "The existing comparison review identifies these named functions as the anti-instrumentation scan cluster.",
                ],
                "interpretation": "The file contains direct callsites supporting a process or address scan cluster. This complements, but does not replace, the separate static finding that the unverified package also carries a native hook library.",
                "next_test": "Compare the callsite cluster against a verified stock 2.2 build and inspect only offline string and data references.",
            },
            {
                "id": "CMP22-IMPORT-004",
                "severity": "medium",
                "classification": "native-socket-and-file-boundaries",
                "status": "confirmed-static-capability-unproven-runtime-reachability",
                "evidence": [
                    "The direct-call scan finds connect, socket, send, recv, gethostbyname, bind, listen, and accept in the native socket helpers.",
                    "The scan finds unlink in _ZN10wiULgacZUI10W3z0fa_X54ERK10C8THgaTQxF at 0xE79E4.",
                    "The scan finds open in the GIF file loader and seed-generation helper.",
                ],
                "interpretation": "The stripped 2.2 library preserves both client and conditional local-server socket capabilities, plus file deletion and file-open paths. These imports are capabilities, not proof of a vulnerable input path.",
                "next_test": "Use the existing 1.8 socket-policy and package-path reviews as hypotheses, then verify the corresponding 2.2 caller and data references in IDA.",
            },
        ],
        "native_executed": False,
        "network_contacted": False,
        "raw_data_policy": "The APK and native files remain outside the repository; this artifact contains hashes, import metadata, and direct callsite records only.",
        "imports": imports,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_TWO_TWO)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"native file does not exist: {binary}")
    output = args.output if args.output.is_absolute() else ROOT / args.output
    report = build_report(binary)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), **report["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
