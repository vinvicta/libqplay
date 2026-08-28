#!/usr/bin/env python3
"""Create the reviewed target-only label for loadvarsfromarray.

The target callback has an exact decoded table name, but no demonstrated 1.8
script callback counterpart. The body converts array cells through the target
readString virtual slot and feeds the resulting list to loadVarsFromArray.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


ARTIFACT = "spectron_tgraalvar_target_only_labels_20260828"
TARGET_EA = 0x218870
TARGET_TABLE_RECORD = 0x39AA90
TARGET_NAME_POINTER = 0x2EE208
TARGET_CALLBACK_XREF = 0x39AAA8
TARGET_ADJACENT_LOADVARS_EA = 0x2187BC
TARGET_ADJACENT_LOADVARS_VENEER = 0x2187B8
DATA_VA_FILE_DELTA = 0x10000
DATA_VA_FILE_THRESHOLD = 0x35D210
RECORD_SIZE = 0x30

METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def va_to_offset(va: int) -> int:
    return va - DATA_VA_FILE_DELTA if va >= DATA_VA_FILE_THRESHOLD else va


def read_u64(binary: bytes, va: int) -> int:
    offset = va_to_offset(va)
    if offset < 0 or offset + 8 > len(binary):
        raise ValueError("address is outside the target binary: 0x%x" % va)
    return struct.unpack_from("<Q", binary, offset)[0]


def read_encoded_string(binary: bytes, va: int) -> bytes:
    offset = va_to_offset(va)
    if offset < 0 or offset >= len(binary):
        raise ValueError("string address is outside the target binary: 0x%x" % va)
    end = binary.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated target table string at 0x%x" % va)
    return binary[offset:end]


def decode_script_name(binary: bytes, va: int) -> tuple[str, bytes]:
    raw = read_encoded_string(binary, va)
    decoded = []
    length = len(raw)
    for index, encoded in enumerate(raw):
        signed_encoded = encoded if encoded < 0x80 else encoded - 0x100
        value = -11 - signed_encoded - length
        sentinel_test = ((value >> 2) & 0x3F) | ((value & 3) << 6)
        if sentinel_test == index:
            signed_encoded = 0
        value = -11 - signed_encoded - length
        decoded.append(((value << 6) - index + ((value >> 2) & 0x3F)) & 0xFF)
    try:
        return bytes(decoded).decode("ascii"), raw
    except UnicodeDecodeError as error:
        raise ValueError("target table name is not ASCII") from error


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--spectron-binary", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact", default=ARTIFACT)
    args = parser.parse_args()

    document = load(args.spectron_features)
    by_ea = {int(row["ea"], 16): row for row in document["functions"]}
    target = by_ea.get(TARGET_EA)
    if target is None:
        raise ValueError("missing target feature row at 0x218870")
    if target.get("name") != "sub_218870":
        raise ValueError("unexpected target name at 0x218870: %s" % target.get("name"))
    if target.get("end_ea") != "0x218954":
        raise ValueError("unexpected target boundary at 0x218870")
    if not target.get("is_default_name"):
        raise ValueError("target function is not a default IDA name")

    binary = args.spectron_binary.read_bytes()
    decoded_name, raw_name = decode_script_name(binary, TARGET_NAME_POINTER)
    if decoded_name != "loadvarsfromarray":
        raise ValueError("unexpected target table name: %s" % decoded_name)
    if len(raw_name) != 17:
        raise ValueError("unexpected encoded target table-name length")
    if read_u64(binary, TARGET_TABLE_RECORD) != TARGET_NAME_POINTER:
        raise ValueError("target table name pointer does not match the reviewed row")
    if read_u64(binary, TARGET_TABLE_RECORD + 0x18) != TARGET_EA:
        raise ValueError("target callback cell does not match 0x218870")
    if TARGET_TABLE_RECORD - 0x39AA60 != RECORD_SIZE:
        raise ValueError("unexpected target table row spacing")

    label = {
        "target_ea": "0x218870",
        "current_name": target["name"],
        "function_end": target["end_ea"],
        "proposed_name": "spectron_TGraalVar_script_loadvarsfromarray_TGraalVar",
        "target_default_name": target.get("is_default_name", False),
        "target_metrics": {field: target.get(field) for field in METRIC_FIELDS},
        "target_string_refs": target.get("string_refs", []),
        "target_direct_call_names": target.get("direct_call_names", []),
        "script_name": decoded_name,
        "target_function_table_record": "0x39aa90",
        "target_callback_xref": "0x39aaa8",
        "target_name_pointer": "0x2ee208",
        "target_name_raw_hex": raw_name.hex(),
        "target_name_raw_length": len(raw_name),
        "adjacent_loadvars_veneer": "0x2187b8",
        "adjacent_loadvars_implementation": "0x2187bc",
        "adjacent_loadvars_name": "v18_TGraalVar_loadVarsFromArray_TStringList",
        "operation": "allocates a target string-list object, walks the source variable array at a2+56, converts each non-null child through virtual slot +184 (readString), adds the converted value to the list, and feeds that list to loadVarsFromArray",
        "source_counterpart": None,
        "source_counterpart_status": "not-demonstrated",
        "confidence": "high",
        "match_kind": "reviewed-target-only-tgraalvar-script-label",
        "evidence": [
            "The target table record at 0x39aa90 contains the encoded name pointer 0x2ee208 and callback cell 0x39aaa8, which points to sub_218870.",
            "The target table-name decoder produces the exact ASCII name loadvarsfromarray from the 17-byte encoded string.",
            "The body allocates vuuHgangcF, reads the source array at a2+56, calls the target virtual readString slot +184 for each child, and adds each result to the new list.",
            "The body then calls the adjacent target loadVarsFromArray implementation at 0x2187bc through G0gxgajWBw::YyvaMa69r8, establishing the wrapper's script-runtime role.",
            "No original 1.8 script callback address is claimed. The source database contains loadVarsFromArray as a method, but this target wrapper's callback identity and body are recorded separately.",
        ],
        "name_action": "rename-with-spectron-prefix",
    }

    result = {
        "schema_version": 1,
        "artifact": args.artifact,
        "scope": "reviewed target-only label for the Spectron TGraalVar loadvarsfromarray script callback",
        "network_contacted": False,
        "inputs": {
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "target_table_record": "0x39aa90",
            "target_table_record_size": "0x30",
            "target_name_pointer": "0x2ee208",
            "target_callback_xref": "0x39aaa8",
            "adjacent_target_rows": [
                "0x39aa60 loadvars",
                "0x39aa90 loadvarsfromarray",
                "0x39aac0 loadfolder",
            ],
            "mapping_boundary": "This is a target-only descriptive label. It does not assert that a matching 1.8 script callback was found.",
        },
        "summary": {
            "label_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": 1,
            "source_counterpart_count": 0,
            "target_only_count": 1,
        },
        "labels": [label],
        "interpretation": [
            "The spectron_ prefix marks a target-specific descriptive label rather than a restored source symbol.",
            "The decoded table name, exact callback cell, adjacent loadvars row, virtual readString call, and final loadVarsFromArray call make the target role high confidence.",
            "The absence of a demonstrated 1.8 callback counterpart is kept explicit so the target-only label is not mistaken for a cross-build mapping.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
