#!/usr/bin/env python3
"""Find instruction text matching a regular expression in a function range.

Set ``LIBQPLAY_INSTRUCTION_SEARCH_START`` and ``LIBQPLAY_INSTRUCTION_SEARCH_END``
to select the range and ``LIBQPLAY_INSTRUCTION_SEARCH_PATTERN`` to select the
IDA disassembly text. The helper is read-only and is intended for locating
small static initializers by their immediate stores or calls.
"""

from __future__ import annotations

import json
import os
import re

import ida_auto
import ida_funcs
import ida_lines
import ida_ua
import idautils


def main() -> None:
    ida_auto.auto_wait()
    start = int(os.environ["LIBQPLAY_INSTRUCTION_SEARCH_START"], 0)
    end = int(os.environ["LIBQPLAY_INSTRUCTION_SEARCH_END"], 0)
    pattern = re.compile(
        os.environ.get("LIBQPLAY_INSTRUCTION_SEARCH_PATTERN", "."),
        re.IGNORECASE,
    )
    rows = []
    for function_start in idautils.Functions(start, end):
        function = ida_funcs.get_func(function_start)
        if function is None:
            continue
        matches = []
        for item in idautils.FuncItems(function.start_ea):
            line = ida_lines.generate_disasm_line(item, 0) or ""
            text = ida_lines.tag_remove(line)
            if pattern.search(text):
                matches.append(
                    {
                        "ea": "0x%x" % item,
                        "mnemonic": ida_ua.print_insn_mnem(item),
                        "text": text,
                    }
                )
        if matches:
            rows.append(
                {
                    "function_start": "0x%x" % function.start_ea,
                    "function_end": "0x%x" % function.end_ea,
                    "name": ida_funcs.get_func_name(function.start_ea),
                    "matches": matches,
                }
            )
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
