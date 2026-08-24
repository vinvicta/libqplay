#!/usr/bin/env python3
"""Insert the proven loading-screen assignment into original connector bytecode.

HexaParser source recompilation is useful for reading the recovered GS2, but
its output is not bytecode-compatible with this old native VM in the current
fixture. The original stream already contains the same assignment in
``printDisconnectError``. This tool copies that exact instruction sequence
into ``onServerLogin`` and updates only the function offsets and branch
targets that move because of the insertion.

The input is a decoded ``StartScript_Connector`` stream. It is never
overwritten, and this tool performs no network or APK operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from disassemble_connector_bytecode import add_string_values, parse_instructions


RECORD_HEADER = struct.Struct(">II")
BRANCH_OPCODES = {0x01, 0x02, 0x04}
TARGET_INSTRUCTION_NAME = "onServerLogin"
INSERT_BEFORE_NAME = "reconnections"
ASSIGNMENT_NAME = "loadingscreenenabled"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_records(blob: bytes) -> tuple[list[tuple[int, bytes]], dict[int, bytes]]:
    records: list[tuple[int, bytes]] = []
    by_type: dict[int, bytes] = {}
    cursor = 0
    while cursor < len(blob):
        if cursor + RECORD_HEADER.size > len(blob):
            raise ValueError(f"truncated record header at {cursor}")
        record_type, length = RECORD_HEADER.unpack_from(blob, cursor)
        start = cursor + RECORD_HEADER.size
        end = start + length
        if end > len(blob):
            raise ValueError(f"truncated record body at {cursor}")
        if record_type in by_type:
            raise ValueError(f"duplicate record type {record_type}")
        body = blob[start:end]
        records.append((record_type, body))
        by_type[record_type] = body
        cursor = end
    if set(by_type) != {1, 2, 3, 4}:
        raise ValueError(f"unexpected record types: {sorted(by_type)}")
    return records, by_type


def function_table(body: bytes) -> list[tuple[int, int, int]]:
    """Return ``(offset, offset_position, name_end)`` entries for record 2."""

    result: list[tuple[int, int, int]] = []
    cursor = 0
    while cursor < len(body):
        if cursor + 4 > len(body):
            raise ValueError("truncated function offset")
        offset_position = cursor
        offset = struct.unpack_from(">I", body, cursor)[0]
        cursor += 4
        name_end = body.find(b"\0", cursor)
        if name_end < 0:
            raise ValueError("unterminated function name")
        result.append((offset, offset_position, name_end))
        cursor = name_end + 1
    return result


def function_names(body: bytes) -> list[tuple[int, int, int, str]]:
    result = []
    cursor = 0
    while cursor < len(body):
        if cursor + 4 > len(body):
            raise ValueError("truncated function offset")
        offset_position = cursor
        offset = struct.unpack_from(">I", body, cursor)[0]
        cursor += 4
        name_end = body.find(b"\0", cursor)
        if name_end < 0:
            raise ValueError("unterminated function name")
        name = body[cursor:name_end].decode("utf-8", "replace")
        result.append((offset, offset_position, name_end, name))
        cursor = name_end + 1
    return result


def operand2_width(body: bytes, serialized_offset: int) -> int:
    if serialized_offset + 1 >= len(body):
        raise ValueError("missing operand-2 modifier")
    modifier = body[serialized_offset + 1]
    widths = {0xF3: 1, 0xF4: 2, 0xF5: 4}
    try:
        return widths[modifier]
    except KeyError as error:
        raise ValueError(
            f"unexpected branch operand modifier 0x{modifier:02x}"
        ) from error


def encode_operand2(modifier: int, value: int) -> bytes:
    if modifier == 0xF3:
        return bytes((modifier, value & 0xFF))
    if modifier == 0xF4:
        return bytes((modifier,)) + struct.pack(">h", value)
    if modifier == 0xF5:
        return bytes((modifier,)) + struct.pack(">i", value)
    raise ValueError(f"unsupported operand-2 modifier 0x{modifier:02x}")


def patch_function_offsets(body: bytes, insertion_index: int, delta: int) -> bytes:
    result = bytearray(body)
    for offset, position, _, _ in function_names(body):
        if offset >= insertion_index:
            struct.pack_into(">I", result, position, offset + delta)
    return bytes(result)


def patch_branch_targets(
    body: bytes,
    instructions: list[dict[str, object]],
    insertion_index: int,
    insertion_offset: int,
    byte_delta: int,
    instruction_delta: int,
) -> bytes:
    result = bytearray(body[:insertion_offset] + body[insertion_offset:])
    for instruction in instructions:
        opcode = int(instruction["opcode"])
        if opcode not in BRANCH_OPCODES or "operand2" not in instruction:
            continue
        target = int(instruction["operand2"])
        if target < insertion_index:
            continue
        old_offset = int(instruction["serialized_offset"])
        new_offset = old_offset + (byte_delta if old_offset >= insertion_offset else 0)
        modifier = result[new_offset + 1]
        replacement = encode_operand2(modifier, target + instruction_delta)
        width = operand2_width(result, new_offset)
        if len(replacement) != width + 1:
            raise ValueError("branch operand width changed")
        result[new_offset + 1 : new_offset + 2 + width] = replacement
    return bytes(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    if args.input.resolve() == args.output.resolve():
        raise SystemExit("refusing to overwrite the input bytecode")

    source = args.input.read_bytes()
    records, by_type = parse_records(source)
    strings = by_type[3].split(b"\0")
    if ASSIGNMENT_NAME.encode() not in strings:
        raise SystemExit("existing loading-screen assignment was not found")

    names = function_names(by_type[2])
    target_function = next(
        (item for item in names if item[3] == TARGET_INSTRUCTION_NAME), None
    )
    if target_function is None:
        raise SystemExit("onServerLogin function was not found")
    instructions = parse_instructions(by_type[4])
    add_string_values(
        instructions,
        [item.decode("utf-8", "replace") for item in strings],
    )
    insertion_index = next(
        (
            int(item["index"])
            for item in instructions
            if item.get("operand1_string") == INSERT_BEFORE_NAME
            and int(item["index"]) >= target_function[0]
            and int(item["index"]) < target_function[0] + 100
        ),
        None,
    )
    if insertion_index is None:
        raise SystemExit("onServerLogin reconnection reset was not found")

    assignment = next(
        (
            item
            for item in instructions
            if item.get("operand1_string") == ASSIGNMENT_NAME
        ),
        None,
    )
    if assignment is None:
        raise SystemExit("existing loading-screen assignment instruction was not found")
    assignment_index = int(assignment["index"])
    assignment_end = next(
        (
            int(item["serialized_offset"])
            for item in instructions
            if int(item["index"]) == assignment_index + 3
        ),
        None,
    )
    if assignment_end is None:
        raise SystemExit("could not determine existing assignment length")
    assignment_start = int(assignment["serialized_offset"])
    assignment_bytes = by_type[4][assignment_start:assignment_end]
    if len(assignment_bytes) != 6:
        raise SystemExit(
            f"unexpected loading assignment length: {len(assignment_bytes)}"
        )

    insertion_offset = next(
        int(item["serialized_offset"])
        for item in instructions
        if int(item["index"]) == insertion_index
    )
    old_instructions = len(instructions)
    new_instruction_count = old_instructions + 3
    new_type4 = (
        by_type[4][:insertion_offset]
        + assignment_bytes
        + by_type[4][insertion_offset:]
    )
    new_type4 = patch_branch_targets(
        new_type4,
        instructions,
        insertion_index,
        insertion_offset,
        len(assignment_bytes),
        3,
    )
    new_type2 = patch_function_offsets(by_type[2], insertion_index, 3)

    output_records = []
    for record_type, body in records:
        if record_type == 2:
            body = new_type2
        elif record_type == 4:
            body = new_type4
        output_records.append(RECORD_HEADER.pack(record_type, len(body)) + body)
    output = b"".join(output_records)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)

    report = {
        "input": str(args.input),
        "output": str(args.output),
        "input_sha256": sha256(source),
        "output_sha256": sha256(output),
        "target_function": TARGET_INSTRUCTION_NAME,
        "insertion_before": INSERT_BEFORE_NAME,
        "insertion_instruction_index": insertion_index,
        "insertion_serialized_offset": insertion_offset,
        "copied_assignment": ASSIGNMENT_NAME,
        "copied_assignment_bytes": len(assignment_bytes),
        "instruction_count_before": old_instructions,
        "instruction_count_after": new_instruction_count,
        "trailing_bytes": 0,
        "verification_bypassed": False,
        "network_contacted": False,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
