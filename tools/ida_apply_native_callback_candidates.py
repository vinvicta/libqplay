"""Review or apply native callback and static-state candidates in IDA.

Run this from the IDA Pro MCP bridge with ``py_exec_file`` or from IDALIB. The
default mode is review-only. Set ``APPLY_BOUNDARIES = True`` to create the five
missing FDE-backed function ranges, then set ``APPLY_RENAMES = True`` after
checking the printed plan. The script resolves each current IDA name, which
avoids applying a candidate to a different function if an IDB has changed.
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


APPLY_BOUNDARIES = False
APPLY_RENAMES = False
REPO = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = str(REPO / "artifacts/native_callback_candidates.json")
OUTPUT_PATH = str(REPO.parent / "analysis/native_callback_candidate_apply.json")


def load_candidates():
    with open(CANDIDATE_PATH, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("status") not in {
        "candidates_not_yet_applied_to_ida",
        "candidates_applied_to_verified_ida_v14",
    }:
        raise RuntimeError("candidate artifact status is not a recognized plan")
    groups = (
        "callbacks",
        "static_initializers",
        "sound_wrappers",
        "sound_table_followup",
        "server_player_properties",
        "server_player_functions",
        "server_npc_properties",
        "server_npc_functions",
        "server_level_properties",
        "server_level_functions",
        "server_weapon_properties",
        "server_bomb_properties",
        "explosion_properties",
        "server_chest_properties",
        "server_extra_properties",
        "server_flying_properties",
        "server_sign_properties",
        "projectile_properties",
        "server_level_link_properties",
        "tiles_layer_properties",
        "tiles_layer_functions",
    )
    return [candidate for group in groups for candidate in document.get(group, [])]


def resolve_candidate(candidate):
    current_name = candidate["current_ida_name"]
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, current_name)
    if ea == ida_idaapi.BADADDR:
        return None, "current IDA name was not found", False
    function = ida_funcs.get_func(ea)
    boundary_added = False
    if function is None:
        boundary = candidate.get("function_boundary")
        if boundary is None:
            return None, "resolved address is not a function", False
        start_ea = int(boundary["start_va"], 16)
        end_ea = int(boundary["end_va"], 16)
        if start_ea != ea:
            return None, "stored function boundary does not start at the callback VA", False
        if not APPLY_BOUNDARIES:
            return None, "the .eh_frame range is ready but APPLY_BOUNDARIES is false", False
        ida_funcs.add_func(start_ea, end_ea)
        function = ida_funcs.get_func(start_ea)
        if function is None:
            return None, "IDA could not create the .eh_frame-backed function", False
        if function.start_ea != start_ea or function.end_ea != end_ea:
            return None, "IDA created a different function range than the .eh_frame FDE", False
        ea = start_ea
        boundary_added = True
    expected_ea = ida_kernwin.str2ea(candidate["va"])
    if expected_ea == ida_idaapi.BADADDR:
        return None, "candidate VA could not be resolved by IDA", False
    if function.start_ea != expected_ea:
        return None, "current name resolves to a different function than the candidate VA", False
    return ea, None, boundary_added


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
    boundaries_added = 0
    failures = []
    for candidate in candidates:
        ea, error, boundary_resolved = resolve_candidate(candidate)
        item = {
            "current_ida_name": candidate["current_ida_name"],
            "proposed_name": candidate["proposed_name"],
            "va": candidate["va"],
            "resolved_ea": int(ea) if ea is not None else None,
        }
        if candidate.get("function_boundary"):
            item["function_boundary"] = candidate["function_boundary"]
        if error:
            item["error"] = error
            failures.append(item)
            plan.append(item)
            continue

        if candidate.get("function_boundary") and boundary_resolved:
            boundaries_added += 1
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
        "apply_boundaries": APPLY_BOUNDARIES,
        "apply_renames": APPLY_RENAMES,
        "candidate_count": len(candidates),
        "resolved_count": len(candidates) - len(failures),
        "boundaries_added": boundaries_added,
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
    "apply_boundaries": result["apply_boundaries"],
    "apply_renames": result["apply_renames"],
    "candidate_count": result["candidate_count"],
    "resolved_count": result["resolved_count"],
    "boundaries_added": result["boundaries_added"],
    "renamed_count": result["renamed_count"],
    "comments_added": result["comments_added"],
    "failures": result["failures"],
}, ensure_ascii=False))
