#!/usr/bin/env python3
"""Undo the observed stack order of HexaParser brace literals.

The recovered connector bytecode is a useful compatibility fixture for the
old native script VM.  HexaParser decompiles its brace literals in reverse
order because the VM builds those literals on a stack.  Reversing the
comma-separated literal elements before recompiling restores the order seen
in the original script.  This small adapter is deliberately conservative:
it only rewrites brace pairs that begin and end on the same source line and
look like data literals rather than statement blocks.

It is not a general GS2 source rewriter.  Keep the input and output files
separate so the original decompiler output remains available for comparison.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def split_items(body: str) -> list[str]:
    """Split a literal body at commas outside quoted strings."""

    items: list[str] = []
    start = 0
    in_string = False
    escaped = False
    for index, char in enumerate(body):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == ",":
            items.append(body[start:index].strip())
            start = index + 1
    items.append(body[start:].strip())
    return items


def rewrite_line(line: str) -> str:
    """Reverse same-line brace literals while preserving source formatting."""

    output: list[str] = []
    cursor = 0
    while cursor < len(line):
        open_brace = find_outside_string(line, "{", cursor)
        if open_brace < 0:
            output.append(line[cursor:])
            break
        close_brace = find_outside_string(line, "}", open_brace + 1)
        if close_brace < 0:
            output.append(line[cursor:])
            break
        output.append(line[cursor : open_brace + 1])
        body = line[open_brace + 1 : close_brace]
        items = split_items(body)
        if len(items) > 1 and looks_like_data_literal(body):
            output.append(", ".join(reversed(items)))
        else:
            output.append(body)
        output.append("}")
        cursor = close_brace + 1
    return "".join(output)


def find_outside_string(line: str, needle: str, start: int) -> int:
    """Find a character outside a quoted GS2 string."""

    in_string = False
    escaped = False
    for index in range(start, len(line)):
        char = line[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == needle:
            return index
    return -1


def looks_like_data_literal(body: str) -> bool:
    """Avoid changing one-line statement blocks or call argument lists."""

    return ";" not in body and "(" not in body and ")" not in body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    source = args.input.read_text(encoding="utf-8")
    rewritten = "".join(rewrite_line(line) for line in source.splitlines(keepends=True))
    args.output.write_text(rewritten, encoding="utf-8")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
