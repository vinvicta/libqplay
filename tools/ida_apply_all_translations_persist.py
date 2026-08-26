#!/usr/bin/env python3
"""Run the combined translation pass under IDALIB and let the caller save.

This is intended for a disposable copy opened by
``idalib/examples/idacli.py``. The default remains review-only. Set
``LIBQPLAY_APPLY_TRANSLATIONS=1`` only when the input database is a copy that
can be discarded or inspected before it replaces anything else. The IDALIB
runner closes the database after this script returns, which gives it a chance
to persist the edits normally.
"""

from __future__ import annotations

import os
from pathlib import Path


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
APPLY = os.environ.get("LIBQPLAY_APPLY_TRANSLATIONS") == "1"
source_path = REPO / "tools/ida_apply_all_translations.py"
source = source_path.read_text(encoding="utf-8")
source = source.replace(
    "APPLY_BOUNDARIES = False",
    "APPLY_BOUNDARIES = %s" % APPLY,
    1,
)
source = source.replace(
    "APPLY_RENAMES = False",
    "APPLY_RENAMES = %s" % APPLY,
    1,
)
exec(compile(source, str(source_path), "exec"), globals(), globals())
