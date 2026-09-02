"""Review or apply exact names recovered from script registration tables.

This is intentionally separate from the smaller curated callback helper. The
inventory contains every table record, while this script only considers unique
targets with an exact script name and a saved IDA function boundary. The
default mode is review-only. Set ``APPLY_RENAMES = True`` after inspecting the
generated plan inside IDA.
"""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name


APPLY_RENAMES = False
REPO = Path(__file__).resolve().parents[1]
INVENTORY_PATH = str(REPO / "artifacts/script_table_inventory.json")
OUTPUT_PATH = str(REPO.parent / "analysis/script_table_candidate_apply.json")


def load_inventory():
    with open(INVENTORY_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_candidates(document):
    candidates = []
    for item in document.get("unique_callbacks", []):
        if item.get("status") not in {"untranslated_default_sub", "no_function_boundary"}:
            continue
        if not item.get("proposed_name"):
            continue
        if item.get("name_review_required"):
            continue
        if not item.get("has_function_boundary"):
            continue
        candidates.append(item)
    return candidates


def resolve_candidate(candidate):
    current_name = candidate.get("current_ida_name")
    if not current_name:
        return None, "the saved inventory has no current IDA name"
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, current_name)
    if ea == ida_idaapi.BADADDR:
        return None, "current IDA name was not found"
    function = ida_funcs.get_func(ea)
    if function is None:
        return None, "resolved address is not a function"
    expected_ea = ida_kernwin.str2ea(candidate["va"])
    if expected_ea == ida_idaapi.BADADDR:
        return None, "candidate VA could not be resolved by IDA"
    if function.start_ea != expected_ea:
        return None, "current name resolves to a different function than the candidate VA"
    return ea, None


def proposed_name_is_available(ea, proposed_name):
    existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, proposed_name)
    return existing_ea in (ida_idaapi.BADADDR, ea), existing_ea


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
    return "Script table candidate: " + "; ".join(roles)


def append_comment(ea, comment):
    existing = ida_bytes.get_cmt(ea, False) or ""
    if comment in existing:
        return False
    combined = comment if not existing else existing + " | " + comment
    ida_bytes.set_cmt(ea, combined, False)
    return True


def apply_candidates(candidates):
    plan = []
    failures = []
    renamed = 0
    comments = 0
    for candidate in candidates:
        item = {
            "va": candidate["va"],
            "current_ida_name": candidate.get("current_ida_name"),
            "proposed_name": candidate["proposed_name"],
            "resolved_ea": None,
            "roles": candidate.get("roles", []),
        }
        ea, error = resolve_candidate(candidate)
        if error:
            item["error"] = error
            failures.append(item)
            plan.append(item)
            continue
        item["resolved_ea"] = int(ea)
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
            if append_comment(ea, evidence_comment(candidate)):
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
document = load_inventory()
result = apply_candidates(load_candidates(document))
print(json.dumps({
    "output": OUTPUT_PATH,
    "apply_renames": result["apply_renames"],
    "candidate_count": result["candidate_count"],
    "resolved_count": result["resolved_count"],
    "renamed_count": result["renamed_count"],
    "comments_added": result["comments_added"],
    "failure_count": len(result["failures"]),
}, ensure_ascii=False))
