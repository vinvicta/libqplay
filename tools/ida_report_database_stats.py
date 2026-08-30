#!/usr/bin/env python3
"""Print compact function and naming statistics for the active IDA database.

This is intentionally read-only. It is used by the IDALIB verification step
after a translation pass, and it does not export the full inventory or modify
the database.
"""

from __future__ import annotations

import json
import re

import ida_auto
import ida_funcs
import ida_nalt
import ida_name


DEFAULT_SUB = re.compile(r"^sub_[0-9A-Fa-f]+$")


ida_auto.auto_wait()
function_count = ida_funcs.get_func_qty()
default_sub_count = 0
named_function_count = 0
name_count = 0

for index in range(function_count):
    function = ida_funcs.getn_func(index)
    if function is None:
        continue
    name = ida_name.get_name(function.start_ea) or ""
    if name:
        name_count += 1
        named_function_count += 1
    if DEFAULT_SUB.fullmatch(name):
        default_sub_count += 1

print(
    json.dumps(
        {
            "database": ida_nalt.get_input_file_path(),
            "function_count": function_count,
            "named_function_count": named_function_count,
            "default_sub_count": default_sub_count,
            "name_count_on_function_heads": name_count,
        },
        sort_keys=True,
    )
)
