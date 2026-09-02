#!/usr/bin/env python3
"""Recover static TScriptProperty tables from an ARM64 libqplay binary.

The old client keeps script names and callback pointers in regular 0x30-byte
records. This tool follows direct calls to the imported addProps and addFuncs
stubs, reconstructs the table arguments from the preceding AArch64
instructions, and writes a reviewable table inventory. It does not modify the
binary or an IDA database.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import re
import struct
import subprocess
from collections import defaultdict
from pathlib import Path


DEFAULT_BINARY = str(
    Path(__file__).resolve().parents[2]
    / "GraalOnline+Classic_1.8_APKPure"
    / "lib/arm64-v8a/libqplay.so"
)
DEFAULT_INVENTORY = "symbols/libqplay.function_inventory.json"
DEFAULT_SYMBOLS = "symbols/libqplay.symbols.csv"
DEFAULT_SEMANTIC = "artifacts/ida_semantic_labels.json"
DEFAULT_CANDIDATES = "artifacts/native_callback_candidates.json"
DEFAULT_OUTPUT = "artifacts/script_table_inventory.json"

TEXT_END = 0x34C610
PAGE_DATA_THRESHOLD = 0x35D210
DATA_VA_FILE_DELTA = 0x10000
RECORD_SIZE = 0x30


def sign_extend(value: int, bits: int) -> int:
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def branch_target(pc: int, word: int) -> int:
    return pc + sign_extend((word & 0x03FFFFFF) << 2, 28)


def va_to_offset(va: int) -> int:
    if va >= PAGE_DATA_THRESHOLD:
        return va - DATA_VA_FILE_DELTA
    return va


def read_u64(binary: bytes, va: int) -> int:
    offset = va_to_offset(va)
    if offset < 0 or offset + 8 > len(binary):
        return 0
    return struct.unpack_from("<Q", binary, offset)[0]


def read_encoded_string(binary: bytes, va: int) -> bytes:
    offset = va_to_offset(va)
    if offset < 0 or offset >= len(binary):
        return b""
    end = binary.find(b"\0", offset)
    if end < 0:
        end = len(binary)
    return binary[offset:end]


def decode_script_name(binary: bytes, va: int) -> tuple[str, str, bool]:
    raw = read_encoded_string(binary, va)
    decoded = []
    exact = True
    length = len(raw)
    for index, encoded in enumerate(raw):
        # Static tables are C strings, so encodesimple cannot leave an
        # encoded zero byte in place. The table generator stores a sentinel
        # instead. TScriptProperty later calls codesimplefix0, which detects
        # that sentinel and restores the zero before decodesimple runs.
        signed_encoded = encoded if encoded < 0x80 else encoded - 0x100
        value = -11 - signed_encoded - length
        sentinel_test = ((value >> 2) & 0x3F) | ((value & 3) << 6)
        if sentinel_test == index:
            signed_encoded = 0

        value = -11 - signed_encoded - length
        decoded_byte = (
            (value << 6) - index + ((value >> 2) & 0x3F)
        ) & 0xFF
        if 32 <= decoded_byte < 127:
            decoded.append(chr(decoded_byte))
        else:
            decoded.append("?")
            exact = False
    decoded_name = "".join(decoded)
    identifier_chars = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$:"
    )
    if decoded_name and exact and all(character in identifier_chars for character in decoded_name):
        return decoded_name, raw.hex(), True
    if raw and all(32 <= byte < 127 for byte in raw):
        return raw.decode("ascii"), raw.hex(), True
    return decoded_name, raw.hex(), exact


def instruction(binary: bytes, va: int) -> int:
    return struct.unpack_from("<I", binary, va)[0]


def update_register_state(word: int, pc: int, state: dict[int, int]) -> None:
    """Track the small set of AArch64 instructions used for table arguments."""

    if (word & 0x9F000000) == 0x90000000:
        register = word & 31
        immlo = (word >> 29) & 3
        immhi = (word >> 5) & 0x7FFFF
        state[register] = (pc & ~0xFFF) + (
            sign_extend((immhi << 2) | immlo, 21) << 12
        )
        return

    if (word & 0x7F000000) == 0x11000000 and not (word & 0x20000000):
        source = (word >> 5) & 31
        destination = word & 31
        immediate = ((word >> 10) & 0xFFF) << (12 if (word >> 22) & 1 else 0)
        if source in state:
            state[destination] = state[source] + (
                -immediate if (word >> 30) & 1 else immediate
            )
        return

    if (word & 0x7F800000) == 0x52800000:
        destination = word & 31
        state[destination] = ((word >> 5) & 0xFFFF) << (16 * ((word >> 21) & 3))
        return

    # MOV is the ORR alias with the zero register as its first source.
    if (word & 0xFFE0FFE0) == 0xAA0003E0:
        source = (word >> 16) & 31
        destination = word & 31
        if source in state:
            state[destination] = state[source]


def load_call_targets(symbol_path: pathlib.Path) -> dict[str, int]:
    targets = {
        "properties": 0xD94E0,
        "functions": 0xD6E80,
    }
    try:
        with symbol_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        for row in rows:
            alias = row.get("alias", "")
            if alias == "plt_TScriptProperty_addProps_TProperties_TPropertyPropDef_int":
                targets["properties"] = int(row["ea"])
            elif alias == "plt_TScriptProperty_addFuncs_TProperties_TPropertyFuncDef_int":
                targets["functions"] = int(row["ea"])
    except (OSError, ValueError, KeyError):
        pass
    return targets


def load_maps(
    semantic_path: pathlib.Path, candidate_path: pathlib.Path
) -> tuple[dict[int, dict], dict[int, dict]]:
    semantic = json.loads(semantic_path.read_text(encoding="utf-8"))
    semantic_by_va = {
        int(item["va"], 16): item for item in semantic.get("labels", [])
    }

    candidates = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate_by_va = {}
    for key, values in candidates.items():
        if key == "source" or not isinstance(values, list):
            continue
        for item in values:
            candidate_by_va[int(item["va"], 16)] = item
    return semantic_by_va, candidate_by_va


def load_functions(inventory_path: pathlib.Path) -> list[dict]:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    return sorted(
        (
            item
            for item in inventory
            if item.get("size") and item.get("ea", 0) < TEXT_END
        ),
        key=lambda item: item["ea"],
    )


def load_unwind_ranges(binary_path: pathlib.Path) -> dict[int, dict[str, str]]:
    """Read code ranges emitted as FDEs in the ELF .eh_frame section."""

    try:
        output = subprocess.run(
            ["readelf", "--debug-dump=frames", "--wide", str(binary_path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return {}

    ranges = {}
    for line in output.splitlines():
        match = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if not match:
            continue
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        if end > start:
            ranges[start] = {
                "start_va": f"0x{start:x}",
                "end_va": f"0x{end:x}",
                "source": "ELF .eh_frame FDE",
            }
    return ranges


def containing_function(functions: list[dict], address: int) -> dict | None:
    match = None
    for function in functions:
        start = function["ea"]
        if start <= address < start + function["size"]:
            if match is None or start > match["ea"]:
                match = function
    return match


def find_registration_calls(
    binary: bytes, functions: list[dict], call_targets: dict[str, int]
) -> list[dict]:
    target_to_kind = {value: key for key, value in call_targets.items()}
    registrations = []
    for function in functions:
        start = function["ea"]
        end = min(start + function["size"], len(binary))
        state: dict[int, int] = {}
        for pc in range(start, end, 4):
            word = instruction(binary, pc)
            if (word & 0xFC000000) in (0x94000000, 0x14000000):
                target = branch_target(pc, word)
                kind = target_to_kind.get(target)
                if kind:
                    registrations.append(
                        {
                            "kind": kind,
                            "caller_va": f"0x{start:x}",
                            "caller_name": function["name"],
                            "call_va": f"0x{pc:x}",
                            "table_va": state.get(1),
                            "count": state.get(2),
                        }
                    )
            update_register_state(word, pc, state)
    return registrations


def sanitize_name(name: str) -> str:
    pieces = []
    for character in name:
        if character.isalnum() or character == "_":
            pieces.append(character)
        else:
            pieces.append("_")
    sanitized = "".join(pieces).strip("_")
    return sanitized or "unnamed"


def owner_prefix(caller_name: str) -> str:
    base = caller_name
    for suffix in ("_void", "__"):
        if suffix in base:
            base = base.split(suffix, 1)[0]
    first = base.split("_", 1)[0]
    if first.endswith("Properties"):
        return first[: -len("Properties")]
    if first == "gsfunctions":
        parts = base.split("_")
        if len(parts) > 1:
            return "GSFunctions" + parts[1].capitalize()
        return "GSFunctions"
    if first == "main":
        parts = base.split("_")
        return "Main" + "".join(part.capitalize() for part in parts[1:2])
    if first == "guiCanvas":
        return "GuiCanvas"
    if first == "guiTextEditCtrl":
        return "GuiTextEditCtrl"
    if first == "chessrating":
        return "ChessRating"
    return first


def owner_specific_prefix(caller_name: str) -> str:
    """Return a stable class-like prefix for resolving name collisions."""

    base = caller_name
    for suffix in ("_void", "__"):
        if suffix in base:
            base = base.split(suffix, 1)[0]
    first = base.split("_", 1)[0]
    if first in {"gsfunctions", "main"}:
        return owner_prefix(caller_name)
    return first


def proposed_name(owner: str, kind: str, role: str, script_name: str) -> str:
    prefix = owner_prefix(owner)
    safe_name = sanitize_name(script_name)
    if kind == "properties":
        return f"{prefix}_{role}_{safe_name}"
    return f"{prefix}_script_{safe_name}"


def replace_name_prefix(name: str, prefix: str) -> str:
    """Replace only the generated owner prefix, preserving the script role."""

    for marker in ("_script_", "_get_", "_set_"):
        marker_index = name.find(marker)
        if marker_index >= 0:
            return prefix + name[marker_index:]
    return prefix + "_" + name.rsplit("_", 1)[-1]


def disambiguate_proposed_names(callbacks: list[dict]) -> None:
    """Make generated names unique while keeping collisions easy to review."""

    by_name: dict[str, list[dict]] = defaultdict(list)
    for callback in callbacks:
        name = callback.get("proposed_name")
        if name:
            by_name[name].append(callback)

    used = {
        callback.get("proposed_name")
        for callback in callbacks
        if callback.get("proposed_name")
    }
    for original_name, entries in sorted(by_name.items()):
        if len(entries) < 2:
            continue
        # Keep the original spelling available for the first owner that does
        # not need a more specific prefix. This is deterministic for a static
        # address map and avoids an arbitrary numeric suffix in the common case.
        used.discard(original_name)
        for entry in sorted(entries, key=lambda item: int(item["va"], 16)):
            owners = sorted({role["owner"] for role in entry.get("roles", [])})
            replacement = None
            for owner in owners:
                candidate = replace_name_prefix(
                    original_name, owner_specific_prefix(owner)
                )
                if candidate not in used:
                    replacement = candidate
                    break
            if replacement is None:
                suffix = 2
                while f"{original_name}_{suffix}" in used:
                    suffix += 1
                replacement = f"{original_name}_{suffix}"
            entry["proposed_name"] = replacement
            used.add(replacement)


def coverage_for_target(
    target: int,
    functions_by_ea: dict[int, dict],
    semantic_by_va: dict[int, dict],
    candidate_by_va: dict[int, dict],
    unwind_by_ea: dict[int, dict[str, str]],
) -> dict:
    if target in semantic_by_va:
        item = semantic_by_va[target]
        return {
            "status": "semantic_label",
            "name": item.get("name"),
            "current_ida_name": functions_by_ea.get(target, {}).get("name"),
            "has_function_boundary": target in functions_by_ea,
        }
    if target in candidate_by_va:
        item = candidate_by_va[target]
        return {
            "status": "native_callback_candidate",
            "name": item.get("proposed_name"),
            "current_ida_name": functions_by_ea.get(target, {}).get(
                "name", item.get("current_ida_name")
            ),
            "has_function_boundary": target in functions_by_ea,
        }
    function = functions_by_ea.get(target)
    if function is None:
        coverage = {
            "status": "no_function_boundary",
            "name": None,
            "current_ida_name": None,
            "has_function_boundary": False,
        }
        if target in unwind_by_ea:
            coverage["eh_frame_boundary"] = unwind_by_ea[target]
        return coverage
    if function.get("is_default_sub"):
        return {
            "status": "untranslated_default_sub",
            "name": None,
            "current_ida_name": function.get("name"),
            "has_function_boundary": True,
        }
    return {
        "status": "existing_named_function",
        "name": function.get("name"),
        "current_ida_name": function.get("name"),
        "has_function_boundary": True,
    }


def make_table(
    binary: bytes,
    registration: dict,
    functions_by_ea: dict[int, dict],
    semantic_by_va: dict[int, dict],
    candidate_by_va: dict[int, dict],
    unwind_by_ea: dict[int, dict[str, str]],
) -> dict:
    table_va = registration["table_va"]
    count = registration["count"]
    table = {
        "kind": registration["kind"],
        "caller_va": registration["caller_va"],
        "caller_name": registration["caller_name"],
        "call_va": registration["call_va"],
        "table_va": f"0x{table_va:x}" if table_va is not None else None,
        "count": count,
        "record_size": RECORD_SIZE,
        "records": [],
    }
    if table_va is None or count is None:
        table["dynamic_table"] = True
        return table

    for index in range(count):
        record_va = table_va + index * RECORD_SIZE
        name_pointer = read_u64(binary, record_va)
        script_name, raw_hex, name_exact = decode_script_name(binary, name_pointer)
        record = {
            "index": index,
            "record_va": f"0x{record_va:x}",
            "script_name": script_name,
            "script_name_raw_hex": raw_hex,
            "script_name_exact": name_exact,
        }
        if registration["kind"] == "properties":
            targets = {
                "getter": read_u64(binary, record_va + 0x10),
                "setter": read_u64(binary, record_va + 0x18),
            }
        else:
            targets = {"callback": read_u64(binary, record_va + 0x18)}

        callbacks = []
        for role, target in targets.items():
            if not target:
                record[f"{role}_va"] = None
                continue
            status = coverage_for_target(
                target,
                functions_by_ea,
                semantic_by_va,
                candidate_by_va,
                unwind_by_ea,
            )
            callback = {
                "role": role,
                "va": f"0x{target:x}",
                **status,
            }
            if (
                status["status"] in {"untranslated_default_sub", "no_function_boundary"}
                and name_exact
                and "?" not in script_name
            ):
                callback["proposed_name"] = proposed_name(
                    registration["caller_name"],
                    registration["kind"],
                    "get" if role == "getter" else "set" if role == "setter" else "callback",
                    script_name,
                )
            callbacks.append(callback)
            record[f"{role}_va"] = f"0x{target:x}"
        record["callbacks"] = callbacks
        table["records"].append(record)
    return table


def build_unique_callbacks(tables: list[dict]) -> list[dict]:
    grouped: dict[int, dict] = {}
    for table in tables:
        for record in table["records"]:
            for callback in record.get("callbacks", []):
                target = int(callback["va"], 16)
                entry = grouped.setdefault(
                    target,
                    {
                        "va": callback["va"],
                        "status": callback["status"],
                        "name": callback.get("name"),
                        "current_ida_name": callback.get("current_ida_name"),
                        "has_function_boundary": callback.get("has_function_boundary"),
                        "eh_frame_boundary": callback.get("eh_frame_boundary"),
                        "proposed_name": callback.get("proposed_name"),
                        "roles": [],
                    },
                )
                entry["roles"].append(
                    {
                        "kind": table["kind"],
                        "owner": table["caller_name"],
                        "table_va": table["table_va"],
                        "record_va": record["record_va"],
                        "script_name": record["script_name"],
                        "role": callback["role"],
                        "script_name_exact": record["script_name_exact"],
                    }
                )
                if callback.get("proposed_name") and not entry.get("proposed_name"):
                    entry["proposed_name"] = callback["proposed_name"]
                if not record["script_name_exact"]:
                    entry["name_review_required"] = True
    callbacks = [grouped[target] for target in sorted(grouped)]
    disambiguate_proposed_names(callbacks)
    return callbacks


def generate(args: argparse.Namespace) -> dict:
    binary_path = pathlib.Path(args.binary)
    inventory_path = pathlib.Path(args.inventory)
    symbols_path = pathlib.Path(args.symbols)
    semantic_path = pathlib.Path(args.semantic)
    candidate_path = pathlib.Path(args.candidates)
    binary = binary_path.read_bytes()
    functions = load_functions(inventory_path)
    functions_by_ea = {item["ea"]: item for item in functions}
    unwind_by_ea = load_unwind_ranges(binary_path)
    semantic_by_va, candidate_by_va = load_maps(semantic_path, candidate_path)
    call_targets = load_call_targets(symbols_path)
    registrations = find_registration_calls(binary, functions, call_targets)
    tables = [
        make_table(
            binary,
            registration,
            functions_by_ea,
            semantic_by_va,
            candidate_by_va,
            unwind_by_ea,
        )
        for registration in registrations
    ]
    unique_callbacks = build_unique_callbacks(tables)
    callback_statuses = defaultdict(int)
    uncertain_names = 0
    for table in tables:
        for record in table["records"]:
            if not record["script_name_exact"]:
                uncertain_names += 1
    for callback in unique_callbacks:
        callback_statuses[callback["status"]] += 1
    exact_untranslated = sum(
        1
        for callback in unique_callbacks
        if callback["status"] in {"untranslated_default_sub", "no_function_boundary"}
        and callback.get("proposed_name")
    )
    name_review_targets = sum(
        1
        for callback in unique_callbacks
        if callback["status"] in {"untranslated_default_sub", "no_function_boundary"}
        and callback.get("name_review_required")
        and not callback.get("proposed_name")
    )

    binary_label = str(binary_path)
    marker = "GraalOnline+Classic_1.8_APKPure"
    if marker in binary_label:
        binary_label = binary_label[binary_label.index(marker) :]
    else:
        binary_label = binary_path.name

    result = {
        "binary": {
            "path": binary_label,
            "sha256": hashlib.sha256(binary).hexdigest(),
            "architecture": "arm64-v8a",
        },
        "purpose": (
            "Complete static script-property and script-function table map. "
            "The inventory is evidence for later IDA labels and does not "
            "change the binary or contact a network."
        ),
        "decoder": {
            "record_size": RECORD_SIZE,
            "encoded_name_helper": "THashList::encodesimple inverse",
            "zero_byte_repair_helper": "THashList::codesimplefix0 sentinel",
            "literal_names_are_preserved": True,
            "uncertain_names_use_question_marks": True,
            "unwind_boundary_source": "ELF .eh_frame FDE",
        },
        "registration_stubs": {
            "addProps_plt": f"0x{call_targets['properties']:x}",
            "addFuncs_plt": f"0x{call_targets['functions']:x}",
        },
        "summary": {
            "registration_calls": len(registrations),
            "property_tables": sum(1 for item in tables if item["kind"] == "properties"),
            "function_tables": sum(1 for item in tables if item["kind"] == "functions"),
            "declared_property_records": sum(
                item["count"] or 0 for item in tables if item["kind"] == "properties"
            ),
            "declared_function_records": sum(
                item["count"] or 0 for item in tables if item["kind"] == "functions"
            ),
            "static_property_records": sum(
                len(item["records"])
                for item in tables
                if item["kind"] == "properties"
            ),
            "static_function_records": sum(
                len(item["records"])
                for item in tables
                if item["kind"] == "functions"
            ),
            "dynamic_table_calls": sum(
                1 for item in tables if item.get("dynamic_table")
            ),
            "unique_callback_targets": len(unique_callbacks),
            "unique_callback_statuses": dict(sorted(callback_statuses.items())),
            "records_with_uncertain_names": uncertain_names,
            "exact_untranslated_targets": exact_untranslated,
            "exact_untranslated_with_function_boundary": sum(
                1
                for callback in unique_callbacks
                if callback["status"] == "untranslated_default_sub"
                and callback.get("proposed_name")
            ),
            "targets_requiring_name_review": name_review_targets,
            "no_function_boundary_with_eh_frame": sum(
                1
                for callback in unique_callbacks
                if callback["status"] == "no_function_boundary"
                and callback.get("eh_frame_boundary")
            ),
        },
        "tables": tables,
        "unique_callbacks": unique_callbacks,
        "network_contacted": False,
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--inventory", default=DEFAULT_INVENTORY)
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--semantic", default=DEFAULT_SEMANTIC)
    parser.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = generate(args)
    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
