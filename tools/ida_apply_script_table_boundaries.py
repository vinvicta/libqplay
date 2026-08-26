"""Review or apply .eh_frame-backed boundaries for exact script callbacks.

The complete script-table inventory contains 20 exact callback addresses that
the saved IDA function inventory did not mark as function starts. Each one has
an ELF .eh_frame FDE beginning at the callback address. Two are inside a
larger function range saved by IDA, so the apply mode can split that range at
the independently proven FDE start before adding the callback function. The
default mode only writes a review plan. Set APPLY_BOUNDARIES and
APPLY_RENAMES explicitly after checking the plan inside IDA.
"""

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name


APPLY_BOUNDARIES = False
APPLY_RENAMES = False
INVENTORY_PATH = "/home/v/Desktop/graal-decomp/libqplay/artifacts/script_table_inventory.json"
OUTPUT_PATH = "/home/v/Desktop/graal-decomp/analysis/script_table_boundary_apply.json"


def load_inventory():
    with open(INVENTORY_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_candidates(document):
    candidates = []
    for item in document.get("unique_callbacks", []):
        if item.get("status") != "no_function_boundary":
            continue
        if not item.get("proposed_name"):
            continue
        boundary = item.get("eh_frame_boundary")
        if not boundary:
            continue
        candidates.append(item)
    return candidates


def append_comment(ea, comment):
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    combined = comment if not existing else existing + " | " + comment
    ida_bytes.set_cmt(ea, combined, False)
    return True


def evidence_comment(candidate):
    roles = []
    for role in candidate.get("roles", []):
        roles.append(
            "%s %s at %s (%s)"
            % (
                role["kind"],
                role["owner"],
                role["record_va"],
                role["script_name"],
            )
        )
    boundary = candidate["eh_frame_boundary"]
    return (
        "Script table boundary from %s %s-%s: %s"
        % (
            boundary["source"],
            boundary["start_va"],
            boundary["end_va"],
            "; ".join(roles),
        )
    )


def resolve_or_define(candidate):
    start = int(candidate["va"], 16)
    end = int(candidate["eh_frame_boundary"]["end_va"], 16)
    if end <= start:
        return None, "the .eh_frame range is invalid", False, False

    function = ida_funcs.get_func(start)
    boundary_added = False
    split_existing = False
    if function is None:
        if not APPLY_BOUNDARIES:
            return (
                None,
                "the .eh_frame range is ready but APPLY_BOUNDARIES is false",
                False,
                False,
            )
        if not ida_funcs.add_func(start, end):
            return None, "IDA rejected the .eh_frame function range", False, False
        function = ida_funcs.get_func(start)
        boundary_added = True
    elif function.start_ea != start:
        if function.end_ea < end:
            return (
                None,
                "the containing IDA function ends before the .eh_frame range",
                False,
                False,
            )
        if not APPLY_BOUNDARIES:
            return (
                None,
                "the .eh_frame start is inside an existing function; "
                "APPLY_BOUNDARIES is false",
                False,
                False,
            )
        old_start = function.start_ea
        old_end = function.end_ea
        if not ida_funcs.set_func_end(old_start, start):
            return (
                None,
                "IDA rejected the split at the .eh_frame function start",
                False,
                False,
            )
        function = ida_funcs.get_func(start)
        if function is None:
            if not ida_funcs.add_func(start, end):
                ida_funcs.set_func_end(old_start, old_end)
                return (
                    None,
                    "IDA rejected the .eh_frame function after the split",
                    False,
                    False,
                )
            function = ida_funcs.get_func(start)
        if function is None:
            ida_funcs.set_func_end(old_start, old_end)
            return (
                None,
                "IDA did not expose the split function after boundary creation",
                False,
                False,
            )
        split_existing = True
        boundary_added = True

    if function is None:
        return (
            None,
            "IDA did not expose the function after boundary creation",
            False,
            split_existing,
        )
    if function.start_ea != start:
        return None, "IDA resolved a different function start", False, split_existing
    if function.end_ea != end:
        return None, "IDA resolved a different function end", False, split_existing
    return function, None, boundary_added, split_existing


def proposed_name_is_available(ea, proposed_name):
    existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, proposed_name)
    return existing_ea in (ida_idaapi.BADADDR, ea), existing_ea


def apply_candidates(candidates):
    plan = []
    failures = []
    boundaries_added = 0
    functions_split = 0
    renamed = 0
    comments = 0

    for candidate in candidates:
        boundary = candidate["eh_frame_boundary"]
        item = {
            "va": candidate["va"],
            "proposed_name": candidate["proposed_name"],
            "eh_frame_boundary": boundary,
            "function_start": None,
            "function_end": None,
            "roles": candidate.get("roles", []),
        }
        function, error, boundary_added, split_existing = resolve_or_define(candidate)
        if error:
            item["error"] = error
            failures.append(item)
            plan.append(item)
            continue

        item["function_start"] = int(function.start_ea)
        item["function_end"] = int(function.end_ea)
        item["boundary_added"] = boundary_added
        item["split_existing_function"] = split_existing
        if boundary_added:
            boundaries_added += 1
        if split_existing:
            functions_split += 1

        available, existing_ea = proposed_name_is_available(
            function.start_ea, candidate["proposed_name"]
        )
        if not available:
            item["error"] = "proposed name is already used at 0x%x" % existing_ea
            failures.append(item)
            plan.append(item)
            continue

        if APPLY_RENAMES:
            if not ida_name.set_name(
                function.start_ea, candidate["proposed_name"], ida_name.SN_NOCHECK
            ):
                item["error"] = "IDA rejected the proposed name"
                failures.append(item)
                plan.append(item)
                continue
            renamed += 1
            if append_comment(function.start_ea, evidence_comment(candidate)):
                comments += 1
        plan.append(item)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    result = {
        "apply_boundaries": APPLY_BOUNDARIES,
        "apply_renames": APPLY_RENAMES,
        "candidate_count": len(candidates),
        "resolved_count": len(candidates) - len(failures),
        "boundaries_added": boundaries_added,
        "functions_split": functions_split,
        "renamed_count": renamed,
        "comments_added": comments,
        "failures": failures,
        "plan": plan,
    }
    with open(OUTPUT_PATH, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return result


ida_auto.auto_wait()
document = load_inventory()
result = apply_candidates(load_candidates(document))
print(
    json.dumps(
        {
            "output": OUTPUT_PATH,
            "apply_boundaries": result["apply_boundaries"],
            "apply_renames": result["apply_renames"],
            "candidate_count": result["candidate_count"],
            "resolved_count": result["resolved_count"],
            "boundaries_added": result["boundaries_added"],
            "functions_split": result["functions_split"],
            "renamed_count": result["renamed_count"],
            "comments_added": result["comments_added"],
            "failure_count": len(result["failures"]),
        },
        ensure_ascii=False,
    )
)
