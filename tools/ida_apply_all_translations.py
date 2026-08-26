"""Run every prepared translation pass in one IDA session.

The default mode is review-only. Set APPLY_BOUNDARIES and APPLY_RENAMES to
True after checking the individual reports. Boundary creation is kept behind
its own switch because five native callbacks and twenty script callbacks need
new function ranges, including two ranges that split an existing IDA function.
"""

from pathlib import Path


APPLY_BOUNDARIES = False
APPLY_RENAMES = False
REPO = Path("/home/v/Desktop/graal-decomp/libqplay")


def run_source(relative_path, replacements):
    source_path = REPO / relative_path
    source = source_path.read_text(encoding="utf-8")
    for old, new in replacements:
        source = source.replace(old, new, 1)
    exec(compile(source, str(source_path), "exec"), globals(), globals())


run_source(
    "tools/ida_apply_native_callback_candidates.py",
    (
        ("APPLY_BOUNDARIES = False", "APPLY_BOUNDARIES = %s" % APPLY_BOUNDARIES),
        ("APPLY_RENAMES = False", "APPLY_RENAMES = %s" % APPLY_RENAMES),
    ),
)
run_source(
    "tools/ida_apply_script_table_inventory.py",
    (("APPLY_RENAMES = False", "APPLY_RENAMES = %s" % APPLY_RENAMES),),
)
run_source(
    "tools/ida_apply_script_table_boundaries.py",
    (
        ("APPLY_BOUNDARIES = False", "APPLY_BOUNDARIES = %s" % APPLY_BOUNDARIES),
        ("APPLY_RENAMES = False", "APPLY_RENAMES = %s" % APPLY_RENAMES),
    ),
)
run_source(
    "tools/ida_apply_unresolved_function_candidates.py",
    (("APPLY_RENAMES = False", "APPLY_RENAMES = %s" % APPLY_RENAMES),),
)
