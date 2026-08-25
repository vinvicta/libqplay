"""Review or apply native callback candidates in the active IDA database.

Run this from the IDA Pro MCP bridge with ``py_exec_file``. The default mode is
review-only. Set ``APPLY_RENAMES = True`` after checking the printed plan. The
script resolves each current IDA name, which avoids applying a candidate to a
different function if an IDB has changed.
"""

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name


APPLY_RENAMES = False
CANDIDATE_PATH = "/home/v/Desktop/graal-decomp/libqplay/artifacts/native_callback_candidates.json"
OUTPUT_PATH = "/home/v/Desktop/graal-decomp/analysis/native_callback_candidate_apply.json"


def load_candidates():
    with open(CANDIDATE_PATH, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("status") != "candidates_not_yet_applied_to_ida":
        raise RuntimeError("candidate artifact status is not an unapplied plan")
    return document["callbacks"]


def resolve_candidate(candidate):
    current_name = candidate["current_ida_name"]
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, current_name)
    if ea == ida_idaapi.BADADDR:
        return None, "current IDA name was not found"
    if ida_funcs.get_func(ea) is None:
        return None, "resolved address is not a function"
    return ea, None


def append_evidence_comment(ea, candidate):
    comment = "Native callback candidate: " + "; ".join(candidate["evidence"])
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    combined = comment if not existing else existing + " | " + comment
    ida_bytes.set_cmt(ea, combined, False)
    return True


def apply_candidates(candidates):
    plan = []
    renamed = 0
    comments = 0
    failures = []
    for candidate in candidates:
        ea, error = resolve_candidate(candidate)
        item = {
            "current_ida_name": candidate["current_ida_name"],
            "proposed_name": candidate["proposed_name"],
            "va": candidate["va"],
            "resolved_ea": int(ea) if ea is not None else None,
        }
        if error:
            item["error"] = error
            failures.append(item)
            plan.append(item)
            continue

        item["resolved_name"] = ida_name.get_name(ea)
        if APPLY_RENAMES:
            if ida_name.set_name(ea, candidate["proposed_name"], ida_name.SN_NOCHECK):
                renamed += 1
            else:
                item["error"] = "IDA rejected the proposed name"
                failures.append(item)
                plan.append(item)
                continue
            if append_evidence_comment(ea, candidate):
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
print(json.dumps({
    "output": OUTPUT_PATH,
    "apply_renames": result["apply_renames"],
    "candidate_count": result["candidate_count"],
    "resolved_count": result["resolved_count"],
    "renamed_count": result["renamed_count"],
    "comments_added": result["comments_added"],
    "failures": result["failures"],
}, ensure_ascii=False))
