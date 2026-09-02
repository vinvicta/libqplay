#!/usr/bin/env python3
"""Inventory direct AArch64 calls from libqplay into undefined ELF symbols.

This is a read-only fallback for the focused IDA callsite exports. It parses
the original ELF, maps .rela.plt entries to AArch64 PLT stubs, scans .text for
direct BL and tail-call B instructions, and uses the checked-in function
inventory to name the containing function. It does not disassemble arbitrary
instructions, execute the library, modify an IDB, or contact a network service.

The result is intentionally compact. It records every undefined symbol and
only the direct callsites or tail-call transfers that were found for that
symbol. Indirect calls, function-pointer calls, and calls through data tables
are outside this scan.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import struct
from pathlib import Path


DEFAULT_BINARY = str(
    Path(__file__).resolve().parents[2]
    / "GraalOnline+Classic_1.8_APKPure"
    / "lib/arm64-v8a/libqplay.so"
)
DEFAULT_INVENTORY = "symbols/libqplay.function_inventory.json"
DEFAULT_OUTPUT = "artifacts/original_aarch64_import_callsite_inventory_20260830.json"

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF_SECTION = struct.Struct("<IIQQQQIIQQ")
ELF_SYMBOL = struct.Struct("<IBBHQQ")
ELF_RELA = struct.Struct("<QQq")
SHN_UNDEF = 0
R_AARCH64_JUMP_SLOT = 0x402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def c_string(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


def parse_elf(path: Path) -> dict:
    blob = path.read_bytes()
    header = ELF_HEADER.unpack_from(blob, 0)
    ident = header[0]
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise ValueError("expected a little-endian ELF64 input")
    if header[2] != 0xB7:
        raise ValueError("expected an AArch64 ELF input")

    sections = [
        ELF_SECTION.unpack_from(blob, header[6] + index * header[11])
        for index in range(header[12])
    ]
    shstr = sections[header[13]]
    section_names = blob[shstr[4] : shstr[4] + shstr[5]]
    named_sections = {
        c_string(section_names, section[0]): section
        for section in sections
    }

    def section_data(name: str) -> bytes:
        section = named_sections[name]
        return blob[section[4] : section[4] + section[5]]

    dynstr = section_data(".dynstr")
    dynsym_section = named_sections[".dynsym"]
    dynsym = []
    for index in range(dynsym_section[5] // dynsym_section[9]):
        item = ELF_SYMBOL.unpack_from(blob, dynsym_section[4] + index * dynsym_section[9])
        dynsym.append(
            {
                "index": index,
                "name": c_string(dynstr, item[0]),
                "value": item[4],
                "size": item[5],
                "section_index": item[3],
            }
        )

    rela_section = named_sections[".rela.plt"]
    relocations = []
    for index in range(rela_section[5] // rela_section[9]):
        offset, info, addend = ELF_RELA.unpack_from(
            blob, rela_section[4] + index * rela_section[9]
        )
        symbol_index = info >> 32
        relocation_type = info & 0xFFFFFFFF
        symbol = dynsym[symbol_index]
        relocations.append(
            {
                "index": index,
                "got": offset,
                "type": relocation_type,
                "symbol_index": symbol_index,
                "name": symbol["name"],
                "addend": addend,
            }
        )

    text = named_sections[".text"]
    plt = named_sections[".plt"]
    if plt[5] < 32 or (plt[5] - 32) // 16 != len(relocations):
        raise ValueError("unexpected AArch64 PLT or relocation count")

    undefined_symbols = {
        item["index"]: item
        for item in dynsym
        if item["section_index"] == SHN_UNDEF and item["name"]
    }
    plt_by_symbol = {}
    for relocation in relocations:
        if relocation["type"] != R_AARCH64_JUMP_SLOT:
            continue
        if relocation["symbol_index"] not in undefined_symbols:
            continue
        relocation["plt_stub"] = plt[3] + 32 + relocation["index"] * 16
        plt_by_symbol[relocation["symbol_index"]] = relocation

    return {
        "blob": blob,
        "sections": named_sections,
        "text": text,
        "plt": plt,
        "undefined_symbols": undefined_symbols,
        "plt_by_symbol": plt_by_symbol,
        "sha256": sha256_file(path),
    }


def load_functions(path: Path) -> list[dict]:
    records = json.loads(path.read_text(encoding="utf-8"))
    functions = []
    for record in records:
        if record.get("segment") != ".text":
            continue
        start = int(record["ea"])
        end = start + int(record["size"])
        functions.append(
            {
                "start": start,
                "end": end,
                "address": "0x%x" % start,
                "name": record.get("name") or "",
            }
        )
    return sorted(functions, key=lambda item: item["start"])


def containing_function(functions: list[dict], starts: list[int], address: int) -> dict | None:
    index = bisect.bisect_right(starts, address) - 1
    if index < 0:
        return None
    candidate = functions[index]
    return candidate if address < candidate["end"] else None


def scan_direct_transfers(parsed: dict, functions: list[dict]) -> dict[int, list[dict]]:
    blob = parsed["blob"]
    text = parsed["text"]
    raw = blob[text[4] : text[4] + text[5]]
    stub_to_symbol = {
        item["plt_stub"]: item["symbol_index"]
        for item in parsed["plt_by_symbol"].values()
    }
    starts = [item["start"] for item in functions]
    calls: dict[int, list[dict]] = {index: [] for index in parsed["undefined_symbols"]}

    for offset in range(0, len(raw) - 3, 4):
        instruction = struct.unpack_from("<I", raw, offset)[0]
        if instruction & 0xFC000000 == 0x94000000:
            transfer = "bl"
        elif instruction & 0xFC000000 == 0x14000000:
            transfer = "b"
        else:
            continue
        callsite = text[3] + offset
        immediate = instruction & 0x03FFFFFF
        if immediate & (1 << 25):
            immediate -= 1 << 26
        target = callsite + immediate * 4
        symbol_index = stub_to_symbol.get(target)
        if symbol_index is None:
            continue
        function = containing_function(functions, starts, callsite)
        calls[symbol_index].append(
            {
                "callsite": "0x%x" % callsite,
                "target": "0x%x" % target,
                "transfer": transfer,
                "caller": function["address"] if function else None,
                "caller_name": function["name"] if function else None,
            }
        )
    return calls


MANUAL_CONTEXT = {
    "__cxa_pure_virtual": {
        "classification": "virtual-dispatch-fallback",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The symbol has a PLT entry but no direct BL or B transfer in the "
            "text scan. The ELF contains ABS64 references from virtual tables, "
            "so this is a C++ fallback target rather than evidence of a normal "
            "application call path."
        ),
    },
    "__sF": {
        "classification": "stdio-global-data",
        "confidence": "confirmed-static-import-context",
        "note": (
            "This undefined symbol is an ELF GLOB_DAT object reference for the "
            "stdio FILE state, not a PLT call target. It is listed for import "
            "completeness but has no direct callsite."
        ),
    },
    "accept": {
        "classification": "socket-server-boundary",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is TSocketConnection_acceptSocket_void. "
            "The surrounding native class also has a script-table bind callback, "
            "so this is a local socket-server capability that needs an explicit "
            "port and address policy review."
        ),
    },
    "bind": {
        "classification": "socket-server-boundary",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is TSocketConnection_bindSocket_int_bool. "
            "The TSocket property table registers bind through "
            "jump_TSocket_bind_int_bool, with separate allowed-port and "
            "allowed-outbound-socket setters in the checked-in script inventory."
        ),
    },
    "connect": {
        "classification": "socket-client-boundary",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is TSocketConnection_connectSocket_TString_const_int. "
            "It creates an IPv4 TCP socket, resolves a host when needed, and "
            "uses nonblocking connect status before any optional TLS setup."
        ),
    },
    "gethostbyname": {
        "classification": "legacy-dns-resolution",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers are the socket resolver and the local-IP helper. "
            "This is the legacy IPv4 resolver path, not proof of a particular "
            "remote hostname or a successful network request."
        ),
    },
    "listen": {
        "classification": "socket-server-boundary",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is TSocketConnection_bindSocket_int_bool. "
            "This confirms a listen step in the native socket helper, but does "
            "not establish that the stock connector starts a listener."
        ),
    },
    "getsockname": {
        "classification": "local-socket-metadata",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers are the native local-IP and local-port helpers. "
            "The callsite inventory does not show peer data leaving the process."
        ),
    },
    "getsockopt": {
        "classification": "nonblocking-connect-poll",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is TSocketConnection_checkConnecting_void, "
            "which reads SO_ERROR after a zero-timeout select on an in-progress "
            "connect."
        ),
    },
    "gethostname": {
        "classification": "local-device-metadata",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is GetHostName_void. This is a device-name "
            "read and is separate from the connector hostname resolver."
        ),
    },
    "opendir": {
        "classification": "directory-enumeration",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers enumerate game folders, level-path cache data, and "
            "the dormant CyaSSL certificate-directory API. The import alone is "
            "not an arbitrary-file finding."
        ),
    },
    "readdir": {
        "classification": "directory-enumeration",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers are the same three directory walkers as opendir. "
            "Input limits and symlink behavior remain caller-specific."
        ),
    },
    "closedir": {
        "classification": "directory-enumeration",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The directory handles are closed by the native folder and trust "
            "directory helpers."
        ),
    },
    "recv": {
        "classification": "socket-stream-read",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers are the plain TSocket read helper and the native "
            "TSocketConnection stream reader. The framed HTTP and game paths "
            "apply their own state handling above this import."
        ),
    },
    "recvfrom": {
        "classification": "socket-datagram-read",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is TSocketConnection_read_void, in its UDP "
            "branch. The same read path records the sender address and port "
            "before appending received bytes."
        ),
    },
    "select": {
        "classification": "nonblocking-connect-poll",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is TSocketConnection_checkConnecting_void, "
            "which performs a zero-timeout write-set poll for status-4 sockets."
        ),
    },
    "send": {
        "classification": "socket-stream-write",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers are the plain TSocket send helper and the native "
            "TSocketConnection stream writer."
        ),
    },
    "sendto": {
        "classification": "socket-datagram-write",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The only direct caller is TSocketConnection_sendData_void_const_int, "
            "in the UDP send branch. This confirms datagram support without "
            "identifying a live destination."
        ),
    },
    "setsockopt": {
        "classification": "socket-configuration",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers configure the local listener and disable Nagle delay "
            "on the native connection helper."
        ),
    },
    "socket": {
        "classification": "socket-creation",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers create sockets for the native bind helper, the "
            "nonblocking connector, and the eth0 MAC-address ioctl path. The "
            "import does not identify which branch ran at runtime."
        ),
    },
    "unlink": {
        "classification": "file-deletion-boundary",
        "confidence": "confirmed-static-import-context",
        "note": (
            "The two transfers are unconditional B tail calls from "
            "TFiles_deleteFile_TString_const. This is why a BL-only scan would "
            "miss the import; caller-side path policy remains the safety boundary."
        ),
    },
    "getenv": {
        "classification": "environment-configuration",
        "confidence": "confirmed-static-import-context",
        "note": (
            "Direct callers include the default installation-path helper and "
            "bundled JPEG memory setup. The installation-path value should be "
            "included in any future executable-replacement provenance review."
        ),
    },
}


def build_report(parsed: dict, functions: list[dict], calls: dict[int, list[dict]], binary: Path, inventory: Path) -> dict:
    imports = []
    for symbol_index, symbol in sorted(parsed["undefined_symbols"].items(), key=lambda item: item[1]["name"]):
        relocation = parsed["plt_by_symbol"].get(symbol_index)
        rows = sorted(calls.get(symbol_index, []), key=lambda item: int(item["callsite"], 16))
        item = {
            "name": symbol["name"],
            "symbol_index": symbol_index,
            "plt_stub": "0x%x" % relocation["plt_stub"] if relocation else None,
            "got": "0x%x" % relocation["got"] if relocation else None,
            "direct_call_count": len(rows),
            "direct_calls": rows,
        }
        if symbol["name"] in MANUAL_CONTEXT:
            item["review_context"] = MANUAL_CONTEXT[symbol["name"]]
        imports.append(item)

    direct_calls = sum(item["direct_call_count"] for item in imports)
    with_calls = [item for item in imports if item["direct_call_count"]]
    return {
        "schema": "libqplay.original-aarch64-import-callsite-inventory.v1",
        "artifact": "original_aarch64_import_callsite_inventory_20260830",
        "scope": (
            "read-only scan of direct AArch64 BL and unconditional B instructions in the original "
            "1.8 ARM64 ELF, mapped through .rela.plt and the checked-in function inventory"
        ),
        "network_contacted": False,
        "limitations": [
            "The scan covers direct BL calls and unconditional B tail-call transfers to PLT stubs only.",
            "Conditional branches, indirect calls such as BLR, and calls through data or function-pointer tables are not included.",
            "A callsite proves an imported capability and containing function, not that the path is reachable in the stock runtime.",
        ],
        "binary": {
            "path": str(binary),
            "sha256": parsed["sha256"],
            "architecture": "AArch64 ELF64 little-endian",
        },
        "inventory": {
            "path": str(inventory),
            "sha256": sha256_file(inventory),
            "function_count": len(functions),
        },
        "elf": {
            "text_address": "0x%x" % parsed["text"][3],
            "text_size": parsed["text"][5],
            "plt_address": "0x%x" % parsed["plt"][3],
            "plt_size": parsed["plt"][5],
            "plt_entry_count": len(parsed["plt_by_symbol"]),
            "undefined_symbol_count": len(parsed["undefined_symbols"]),
        },
        "summary": {
            "imports_with_direct_calls": len(with_calls),
            "direct_call_count": direct_calls,
            "tail_call_count": sum(
                1
                for item in imports
                for call in item["direct_calls"]
                if call["transfer"] == "b"
            ),
            "imports_without_direct_calls": len(imports) - len(with_calls),
        },
        "imports": imports,
        "interpretation": [
            "The socket-server imports are real native capabilities. The checked-in TSocket property table ties bind to jump_TSocket_bind_int_bool and records separate allowlist setters; the static init callback clears both allowlist strings before script code can replace them.",
            "The UDP imports are reached by the same socket class through its datagram send and receive branches. This establishes a native UDP path, not a live endpoint or proof that the stock script uses it.",
            "The local metadata imports expose host and socket information to native helpers. They are not evidence that those values are transmitted.",
            "Directory enumeration appears in ordinary resource discovery and in the dormant certificate-directory loader. The existing path review already treats the latter as a separate API boundary.",
            "The result complements, rather than replaces, the IDA exports. It is deliberately limited to direct control transfers and does not assign new source names.",
        ],
        "security_observations": [
            {
                "id": "SOCKET-001",
                "severity": "medium",
                "classification": "conditional-local-listener",
                "status": "confirmed-static-capability-unproven-runtime-reachability",
                "evidence": [
                    "TSocketProperties registers bind at script-table record 0x3864f0 through jump_TSocket_bind_int_bool at 0x205b94.",
                    "TSocketConnection_bindSocket_int_bool calls socket, setsockopt, bind, and listen at the recorded AArch64 callsites.",
                    "TSocketConnection_acceptSocket_void calls accept at 0x206e60.",
                    "The static init callback at 0xe0ab4 clears the allowed-socket and allowed-port string state, and callbacks at 0x204688 and 0x204678 replace those values."
                ],
                "interpretation": "An activated script may have a native local listener capability subject to the old allowlist semantics. The stock connector path is not shown to start a listener, and no runtime bind or external exposure was tested.",
                "next_test": "Use a disposable loopback-only script and inspect the bound address, port policy, and accept path on an instrumented local build."
            },
            {
                "id": "SOCKET-002",
                "severity": "low",
                "classification": "conditional-udp-capability",
                "status": "confirmed-static-capability-unproven-runtime-reachability",
                "evidence": [
                    "TSocketProperties registers sendudp through jump_TSocket_sendUDP_TString_const_TString_const_int at 0x2052e4.",
                    "TSocketConnection_sendData_void_const_int reaches sendto at 0x2071f0.",
                    "TSocketConnection_read_void reaches recvfrom at 0x207730 and records sender metadata in its datagram branch."
                ],
                "interpretation": "The native class contains a script-visible UDP send entry and a datagram receive branch. This does not identify a live destination or show that the stock connector uses UDP.",
                "next_test": "Exercise only a loopback datagram peer and record whether script-created sockets can select the UDP branch after the allowlist checks."
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(DEFAULT_BINARY))
    parser.add_argument("--inventory", type=Path, default=Path(DEFAULT_INVENTORY))
    parser.add_argument("--output", type=Path, default=Path(DEFAULT_OUTPUT))
    args = parser.parse_args()

    parsed = parse_elf(args.binary)
    functions = load_functions(args.inventory)
    calls = scan_direct_transfers(parsed, functions)
    report = build_report(parsed, functions, calls, args.binary, args.inventory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **report["summary"]}, sort_keys=True))


if __name__ == "__main__":
    main()
