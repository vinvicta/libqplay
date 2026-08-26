"""Review or apply selected unresolved-function role candidates in IDA.

The default mode is review-only. Set APPLY_RENAMES to True only after checking
the generated plan against the matching ARM64 IDB. These are analysis aliases,
not claims about names recovered from the ELF.
"""

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name


APPLY_RENAMES = False
CANDIDATE_PATH = "/home/v/Desktop/graal-decomp/libqplay/artifacts/unresolved_function_candidates.json"
OUTPUT_PATH = "/home/v/Desktop/graal-decomp/analysis/unresolved_function_candidate_apply.json"


def load_candidates():
    with open(CANDIDATE_PATH, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("status") != "candidates_not_yet_applied_to_ida":
        raise RuntimeError("candidate artifact status is not an unapplied plan")
    return document["candidates"]


def resolve_candidate(candidate):
    ea = int(candidate["va"], 16)
    current_name = candidate["current_ida_name"]
    named_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, current_name)
    if named_ea == ida_idaapi.BADADDR:
        return None, "current IDA name was not found"
    function = ida_funcs.get_func(named_ea)
    if function is None:
        return None, "resolved address is not a function"
    if function.start_ea != ea:
        return None, "current name resolves to a different function"
    return ea, None


def proposed_name_is_available(ea, proposed_name):
    existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, proposed_name)
    return existing_ea in (ida_idaapi.BADADDR, ea), existing_ea


def append_comment(ea, candidate):
    comment = "Unresolved-function role candidate: " + "; ".join(candidate["evidence"])
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    ida_bytes.set_cmt(ea, comment if not existing else existing + " | " + comment, False)
    return True


def apply_candidates(candidates):
    plan = []
    failures = []
    renamed = 0
    comments = 0
    for candidate in candidates:
        ea, error = resolve_candidate(candidate)
        item = {
            "va": candidate["va"],
            "current_ida_name": candidate["current_ida_name"],
            "proposed_name": candidate["proposed_name"],
            "resolved_ea": ea,
        }
        if error:
            item["error"] = error
            failures.append(item)
            plan.append(item)
            continue
        item["resolved_name"] = ida_name.get_name(ea)
        available, existing_ea = proposed_name_is_available(ea, candidate["proposed_name"])
        if not available:
            item["error"] = "proposed name is already used at 0x%x" % existing_ea
            failures.append(item)
            plan.append(item)
            continue
        if APPLY_RENAMES:
            if not ida_name.set_name(ea, candidate["proposed_name"], ida_name.SN_NOCHECK):
                item["error"] = "IDA rejected the proposed name"
                failures.append(item)
                plan.append(item)
                continue
            renamed += 1
            if append_comment(ea, candidate):
                comments += 1
        plan.append(item)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    result = {
        "apply_renames": APPLY_RENAMES,
        "candidate_count": len(candidates),
        "resolved_count": len(candidates) - len(failures),
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
result = apply_candidates(load_candidates())
print(
    json.dumps(
        {
            "output": OUTPUT_PATH,
            "apply_renames": result["apply_renames"],
            "candidate_count": result["candidate_count"],
            "resolved_count": result["resolved_count"],
            "renamed_count": result["renamed_count"],
            "comments_added": result["comments_added"],
            "failure_count": len(result["failures"]),
        },
        ensure_ascii=False,
    )
)
