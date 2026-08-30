#!/usr/bin/env python3
"""Apply the reviewed CyaSSL and bundled-library aliases in active IDA.

The script does not save a database. Use IDA's save-as operation or the IDA
MCP save tool after checking the resulting counts. The aliases are kept in
separate audit files because they are role matches, not preserved ELF names.
"""

import os
from pathlib import Path


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")


def run_source(relative_path):
    source_path = REPO / relative_path
    source = source_path.read_text(encoding="utf-8")
    exec(compile(source, str(source_path), "exec"), globals(), globals())


os.environ["CYASSL_APPLY_RENAMES"] = "1"
run_source("tools/ida_apply_cyassl_static_aliases.py")

os.environ["STATIC_LIBRARY_APPLY_RENAMES"] = "1"
run_source("tools/ida_apply_static_library_aliases.py")
