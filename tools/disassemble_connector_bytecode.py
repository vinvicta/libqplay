#!/usr/bin/env python3
"""Parse and lightly disassemble the decoded connector script.

The native TScript loader stores four big-endian records in the decoded
connector file.  This is intentionally an offline parser: it does not need
IDA, an APK install, or a network connection.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


DEFAULT_INPUT = Path("analysis/StartScript_Connector.dec.bin")
DEFAULT_OUTPUT = Path("analysis/StartScript_Connector.bytecode")


OPCODE_NAMES = {
    0x01: "JUMP",
    0x02: "JUMP_IF_TRUE_POP",
    0x04: "JUMP_IF_FALSE_POP",
    0x06: "CALL",
    0x07: "RETURN",
    0x14: "PUSH_NUMBER",
    0x15: "PUSH_STRING_LITERAL",
    0x16: "PUSH_STRING_OPERAND",
    0x17: "PUSH_UNDEFINED",
    0x18: "PUSH_ONE",
    0x20: "POP",
    0x21: "TO_FLOAT",
    0x22: "TO_STRING",
    0x23: "DEREF_STRING",
    0x24: "TO_OBJECT",
    0x25: "MAKE_ARRAY",
    0x32: "ASSIGN",
    0x33: "MASS_ASSIGN",
    0x46: "COMPARE_EQ",
    0x4B: "COMPARE_GE_OR_GT",
    0xBD: "PUSH_UNIVERSE",
}


def parse_records(blob: bytes) -> dict[int, bytes]:
    records: dict[int, bytes] = {}
    pos = 0
    while pos < len(blob):
        if pos + 8 > len(blob):
            raise ValueError(f"truncated record header at {pos}")
        record_type, body_length = struct.unpack(">II", blob[pos : pos + 8])
        body_start = pos + 8
        body_end = body_start + body_length
        if body_end > len(blob):
            raise ValueError(f"truncated record body at {pos}")
        if record_type in records:
            raise ValueError(f"duplicate record type {record_type}")
        records[record_type] = blob[body_start:body_end]
        pos = body_end
    if pos != len(blob) or set(records) != {1, 2, 3, 4}:
        raise ValueError(f"unexpected records: {sorted(records)}")
    return records


def parse_functions(body: bytes) -> list[dict[str, object]]:
    """Parse TScript's 0-based instruction entry table (record type 2)."""

    result: list[dict[str, object]] = []
    pos = 0
    while pos + 4 <= len(body):
        instruction_offset = struct.unpack(">I", body[pos : pos + 4])[0]
        name_start = pos + 4
        name_end = body.find(b"\0", name_start)
        if name_end < 0:
            raise ValueError(f"unterminated function name at {name_start}")
        result.append(
            {
                "offset": instruction_offset,
                "name": body[name_start:name_end].decode("utf-8", "replace"),
            }
        )
        # The next offset begins immediately after the name terminator.  This
        # is the same one-byte overlap used by TScript::setStream.
        pos = name_end + 1
    if pos != len(body):
        raise ValueError(f"trailing type-2 bytes at {pos}")
    return result


def parse_strings(body: bytes) -> list[str]:
    return [item.decode("utf-8", "replace") for item in body.split(b"\0")]


def signed(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=True)


def parse_instructions(body: bytes) -> list[dict[str, object]]:
    """Parse type-4 serializer modifiers into 0-based TScriptCom records."""

    result: list[dict[str, object]] = []
    pos = 0
    while pos < len(body):
        opcode = body[pos]
        if opcode == 0xF0:
            if not result or pos + 1 >= len(body):
                raise ValueError(f"bad operand-1 byte at {pos}")
            result[-1]["operand1"] = body[pos + 1]
            pos += 2
        elif opcode == 0xF1:
            if not result or pos + 3 > len(body):
                raise ValueError(f"bad operand-1 word at {pos}")
            result[-1]["operand1"] = int.from_bytes(body[pos + 1 : pos + 3], "big")
            pos += 3
        elif opcode == 0xF2:
            if not result or pos + 5 > len(body):
                raise ValueError(f"bad operand-1 dword at {pos}")
            result[-1]["operand1"] = signed(body[pos + 1 : pos + 5])
            pos += 5
        elif opcode == 0xF3:
            if not result or pos + 2 > len(body):
                raise ValueError(f"bad operand-2 byte at {pos}")
            result[-1]["operand2"] = signed(body[pos + 1 : pos + 2])
            pos += 2
        elif opcode == 0xF4:
            if not result or pos + 3 > len(body):
                raise ValueError(f"bad operand-2 word at {pos}")
            result[-1]["operand2"] = signed(body[pos + 1 : pos + 3])
            pos += 3
        elif opcode == 0xF5:
            if not result or pos + 5 > len(body):
                raise ValueError(f"bad operand-2 dword at {pos}")
            result[-1]["operand2"] = signed(body[pos + 1 : pos + 5])
            pos += 5
        elif opcode == 0xF6:
            if not result:
                raise ValueError(f"string operand without instruction at {pos}")
            end = body.find(b"\0", pos + 1)
            if end < 0:
                raise ValueError(f"unterminated string operand at {pos}")
            result[-1]["operand2_string"] = body[pos + 1 : end].decode(
                "utf-8", "replace"
            )
            pos = end + 1
        else:
            result.append({"index": len(result), "serialized_offset": pos, "opcode": opcode})
            pos += 1
    return result


def add_string_values(instructions: list[dict[str, object]], strings: list[str]) -> None:
    for item in instructions:
        operand = item.get("operand1")
        if isinstance(operand, int) and 0 <= operand < len(strings):
            item["operand1_string"] = strings[operand]


def format_instruction(item: dict[str, object]) -> str:
    opcode = int(item["opcode"])
    name = OPCODE_NAMES.get(opcode, f"OP_{opcode:02X}")
    line = f"{int(item['index']):04d}: {opcode:02X} {name}"
    if "operand1" in item:
        line += f" operand1={item['operand1']}"
        if item.get("operand1_string"):
            line += f" {item['operand1_string']!r}"
    if "operand2" in item:
        line += f" operand2={item['operand2']}"
    if "operand2_string" in item:
        line += f" operand2_string={item['operand2_string']!r}"
    return line


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    records = parse_records(args.input.read_bytes())
    functions = parse_functions(records[2])
    strings = parse_strings(records[3])
    instructions = parse_instructions(records[4])
    add_string_values(instructions, strings)

    starts = sorted(
        [(int(item["offset"]), str(item["name"])) for item in functions],
        key=lambda item: item[0],
    )
    ranges = []
    for index, (start, name) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(instructions)
        ranges.append({"name": name, "start": start, "end": end})

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "instructions.json").write_text(
        json.dumps(instructions, indent=2) + "\n", encoding="utf-8"
    )
    (args.output / "functions.json").write_text(
        json.dumps(ranges, indent=2) + "\n", encoding="utf-8"
    )
    (args.output / "strings.json").write_text(
        json.dumps(strings, indent=2) + "\n", encoding="utf-8"
    )

    selected = {
        "onCreated",
        "onInitProtocol",
        "sendLogin",
        "sendLoginNewProtocol",
        "setDataHandlersNewProtocol",
        "onServerLogin",
        "onData",
        "onReconnect",
        "onServerWarp",
        "sendPasswordAndIDs",
    }
    lines = [
        "# Decoded `StartScript_Connector` bytecode",
        "",
        f"Records: type 1/2/3/4; instructions: {len(instructions)}; strings: {len(strings)}.",
        "Function offsets are zero-based TScript instruction indices.",
        "",
        "## Function entry table",
        "",
    ]
    for item in ranges:
        lines.append(f"- `{item['name']}`: {item['start']}..{item['end'] - 1}")
    lines.extend(["", "## Selected functions", ""])
    for item in ranges:
        if item["name"] not in selected:
            continue
        lines.append(f"### `{item['name']}` ({item['start']}..{item['end'] - 1})")
        lines.append("")
        for instruction in instructions[item["start"] : item["end"]]:
            lines.append(f"`{format_instruction(instruction)}`  ")
        lines.append("")
    (args.output / "selected.md").write_text("\n".join(lines), encoding="utf-8")

    summary = {
        "input": str(args.input),
        "record_lengths": {str(key): len(value) for key, value in records.items()},
        "instruction_count": len(instructions),
        "string_count": len(strings),
        "function_count": len(functions),
        "functions": ranges,
        "output_directory": str(args.output),
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
