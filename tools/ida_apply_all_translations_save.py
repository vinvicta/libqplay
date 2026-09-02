#!/usr/bin/env python3
"""Apply the prepared translations and save a packed IDA database copy.

This script is intended for a disposable database opened by IDALIB or IDA's
headless runner. Set ``LIBQPLAY_TRANSLATION_OUTPUT`` to a new ``.i64`` path.
The input database is never replaced. Saving explicitly through
``ida_loader.save_database`` matters for packed databases because closing an
IDALIB session can leave its temporary unpacked components beside the input
file instead of producing a new packed copy.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import ida_loader


REPO = Path(__file__).resolve().parents[1]
output_value = os.environ.get("LIBQPLAY_TRANSLATION_OUTPUT")
if not output_value:
    raise RuntimeError("LIBQPLAY_TRANSLATION_OUTPUT must name a new .i64 file")

output_path = Path(output_value).expanduser().resolve()
if output_path.suffix != ".i64":
    raise RuntimeError(f"translation output must end in .i64: {output_path}")
if output_path.exists():
    raise RuntimeError(f"refusing to overwrite an existing translation output: {output_path}")

source_path = REPO / "tools/ida_apply_all_translations.py"
source = source_path.read_text(encoding="utf-8")
source = source.replace("APPLY_BOUNDARIES = False", "APPLY_BOUNDARIES = True", 1)
source = source.replace("APPLY_RENAMES = False", "APPLY_RENAMES = True", 1)
exec(compile(source, str(source_path), "exec"), globals(), globals())

if not ida_loader.save_database(str(output_path), ida_loader.DBFL_COMP):
    raise RuntimeError(f"IDA could not save the packed translation copy: {output_path}")

print(
    json.dumps(
        {
            "output": str(output_path),
            "saved": True,
            "packed": True,
            "apply_boundaries": True,
            "apply_renames": True,
        },
        sort_keys=True,
    )
)
