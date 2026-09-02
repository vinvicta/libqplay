#!/usr/bin/env python3
"""Build the final residual report for the persisted IDA translation copy.

The public unresolved-function profile describes the 488 default functions in
the pre-persistence inventory. The role-candidate pass names 28 application or
engine entries, the first CyaSSL pass names 11 static TLS and crypto roles, and
the next static-library pass names 27 zlib, bzip2, minizip, GPC, CyaSSL,
LibTomCrypt, and YAJL roles. IDA reclassifies one compiler branch veneer as a
thunk when the saved copy is reopened. A later source comparison also names
24 embedded FreeType and TrueType routines from the pinned FreeType 2.3.6
source. This helper subtracts those known changes and emits the exact residual
count in the latest persisted database. It only reads JSON files and performs
no network operation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


DEFAULT_PROFILE = "artifacts/unresolved_function_profile.json"
DEFAULT_ROLES = "artifacts/unresolved_function_candidates.json"
DEFAULT_STATIC_ROLES = [
    "artifacts/cyassl_static_role_audit_20260826.json",
    "artifacts/static_library_role_audit_20260826.json",
]
DEFAULT_OUTPUT = "artifacts/ida_residual_profile.json"

CURRENT_DATABASE = {
    "path": "analysis/libqplay_translated_from_active_v9.i64",
    "sha256": "860cd26c43c0c4a98e7939c5bbe7c02fa92c35662d11e86eb8e7a84bc64b116f",
    "bytes": 61286570,
    "format": "packed IDA 9.3 database",
    "close_reopen_verified": False,
    "function_count": 11297,
}

REANALYZED_FUNCTIONS = {
    0x0E01A0: {
        "new_name": "gpc_abort_malloc_failure_tristrip_node",
        "reason": (
            "IDA function at 0xe01a0 was identified as the GPC tristrip "
            "allocation-failure abort from its fixed diagnostic and exit path."
        ),
    },
    0x152200: {
        "new_name": "gpc_free_sbtree",
        "reason": (
            "The helper recursively frees the scanbeam tree passed through "
            "gpc_build_lmt and matches the upstream GPC free_sbtree role."
        ),
    },
    0x152898: {
        "new_name": "gpc_build_sbt",
        "reason": (
            "The helper flattens the scanbeam tree into the sorted scanbeam "
            "array and matches the upstream GPC build_sbt role."
        ),
    },
    0x1F94FC: {
        "new_name": "j_TCachedStream_get_minfilecachesize",
        "reason": (
            "IDA reclassified the four-byte unconditional branch veneer as a "
            "named thunk to TCachedStream_get_minfilecachesize when the "
            "persisted translation copy was rebuilt."
        ),
    },
    0x250E94: {
        "new_name": "destroy_size",
        "reason": (
            "The cleanup body matches FreeType 2.3.6 destroy_size: it runs "
            "the generic and driver finalizers, frees size->internal, and "
            "then frees the size object."
        ),
    },
    0x25E320: {
        "new_name": "tt_get_kerning",
        "reason": (
            "The helper initializes the kerning vector and delegates the x "
            "coordinate to the TrueType SFNT service, matching the pinned "
            "FreeType 2.3.6 tt_get_kerning implementation."
        ),
    },
    0x25E35C: {
        "new_name": "tt_face_get_location",
        "reason": (
            "The loca-table offset and short/long format handling match the "
            "pinned FreeType 2.3.6 tt_face_get_location implementation."
        ),
    },
    0x25E4E4: {
        "new_name": "tt_size_init",
        "reason": (
            "The size initialization fields and reset values match the "
            "pinned FreeType 2.3.6 tt_size_init implementation."
        ),
    },
    0x25E504: {
        "new_name": "TT_MulFix14",
        "reason": (
            "The split multiply, 0x2000 rounding, 14-bit shift, and sign "
            "restore match the pinned FreeType 2.3.6 TT_MulFix14 helper."
        ),
    },
    0x25E580: {
        "new_name": "Direct_Move_X",
        "reason": (
            "The x-axis point movement and touch flag behavior match the "
            "pinned FreeType 2.3.6 Direct_Move_X interpreter callback."
        ),
    },
    0x25E5B0: {
        "new_name": "Direct_Move_Y",
        "reason": (
            "The y-axis point movement and touch flag behavior match the "
            "pinned FreeType 2.3.6 Direct_Move_Y interpreter callback."
        ),
    },
    0x25E5E4: {
        "new_name": "Direct_Move_Orig_X",
        "reason": (
            "The original-coordinate x movement behavior matches the pinned "
            "FreeType 2.3.6 Direct_Move_Orig_X callback."
        ),
    },
    0x25E5FC: {
        "new_name": "Direct_Move_Orig_Y",
        "reason": (
            "The original-coordinate y movement behavior matches the pinned "
            "FreeType 2.3.6 Direct_Move_Orig_Y callback."
        ),
    },
    0x25E618: {
        "new_name": "Round_None",
        "reason": (
            "The signed compensation and overflow clamps match the pinned "
            "FreeType 2.3.6 Round_None implementation."
        ),
    },
    0x25E640: {
        "new_name": "Project",
        "reason": (
            "The projection-vector fixed-point dot product matches the pinned "
            "FreeType 2.3.6 Project interpreter callback."
        ),
    },
    0x25E6CC: {
        "new_name": "Project_x",
        "reason": (
            "The callback returns its x input and occupies the projection "
            "slot selected by Compute_Funcs, matching FreeType 2.3.6."
        ),
    },
    0x25E6D4: {
        "new_name": "Project_y",
        "reason": (
            "The callback returns its y input and occupies the projection "
            "slot selected by Compute_Funcs, matching FreeType 2.3.6."
        ),
    },
    0x25E6DC: {
        "new_name": "Ins_NPUSHW",
        "reason": (
            "The count check, signed big-endian word reads, and instruction "
            "state updates match the pinned FreeType 2.3.6 Ins_NPUSHW."
        ),
    },
    0x25E770: {
        "new_name": "Ins_PUSHW",
        "reason": (
            "The opcode-derived word count and signed stream reads match the "
            "pinned FreeType 2.3.6 Ins_PUSHW implementation."
        ),
    },
    0x25E7F8: {
        "new_name": "Ins_GC",
        "reason": (
            "The point validation, projection choice, and current-coordinate "
            "write match the pinned FreeType 2.3.6 Ins_GC handler."
        ),
    },
    0x25E890: {
        "new_name": "Ins_SCFS",
        "reason": (
            "The projection, freedom-vector move, and twilight copy behavior "
            "match the pinned FreeType 2.3.6 Ins_SCFS handler."
        ),
    },
    0x25E950: {
        "new_name": "Ins_GETINFO",
        "reason": (
            "The version and graphics-state feature bits match the pinned "
            "FreeType 2.3.6 Ins_GETINFO handler."
        ),
    },
    0x25E9A8: {
        "new_name": "Ins_MD",
        "reason": (
            "The two-point validation, dual projection, scaling, and stack "
            "result match the pinned FreeType 2.3.6 Ins_MD handler."
        ),
    },
    0x25EAF8: {
        "new_name": "tt_size_request",
        "reason": (
            "The metrics request and scaling path match the pinned FreeType "
            "2.3.6 tt_size_request driver callback and its class-table slot."
        ),
    },
    0x25EC84: {
        "new_name": "Direct_Move_Orig",
        "reason": (
            "The freedom-vector movement of original coordinates without touch "
            "flags matches the pinned FreeType 2.3.6 Direct_Move_Orig."
        ),
    },
    0x25ED14: {
        "new_name": "Direct_Move",
        "reason": (
            "The freedom-vector movement of current coordinates with touch flags "
            "matches the pinned FreeType 2.3.6 Direct_Move."
        ),
    },
    0x25EDD0: {
        "new_name": "Ins_ISECT",
        "reason": (
            "The five-point intersection math, discriminant fallback, and touch "
            "flags match the pinned FreeType 2.3.6 Ins_ISECT handler."
        ),
    },
    0x260050: {
        "new_name": "Compute_Funcs",
        "reason": (
            "The projection and movement callback selection, including the "
            "unpatented-hinting branch, matches the pinned FreeType 2.3.6 "
            "Compute_Funcs implementation."
        ),
    },
}


def address(value: int | str) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def generate(
    profile: dict,
    roles: dict,
    static_roles: list[dict] | dict | None = None,
) -> dict:
    role_by_ea = {address(item["va"]): item for item in roles["candidates"]}
    if static_roles is None:
        static_documents = []
    elif isinstance(static_roles, dict):
        static_documents = [static_roles]
    else:
        static_documents = list(static_roles)
    static_by_ea = {}
    static_sources = []
    for document in static_documents:
        static_sources.append(document["artifact"])
        for item in document.get("aliases", []):
            ea = address(item["va"])
            if ea in static_by_ea:
                raise ValueError(f"duplicate static role address: 0x{ea:x}")
            static_by_ea[ea] = item
    profile_entries = [
        entry
        for group in profile["categories"]
        for entry in group["entries"]
    ]
    profile_by_ea = {address(item["ea"]): item for item in profile_entries}

    missing_roles = sorted(set(role_by_ea) - set(profile_by_ea))
    if missing_roles:
        raise ValueError(
            "role candidates missing from profile: "
            + ", ".join(f"0x{ea:x}" for ea in missing_roles)
        )
    missing_static_roles = sorted(set(static_by_ea) - set(profile_by_ea))
    if missing_static_roles:
        raise ValueError(
            "static CyaSSL aliases missing from profile: "
            + ", ".join(f"0x{ea:x}" for ea in missing_static_roles)
        )

    residual = []
    removed_roles = []
    removed_static_roles = []
    removed_reanalyzed = []
    for group in profile["categories"]:
        category = group["category"]
        for original in group["entries"]:
            ea = address(original["ea"])
            if ea in role_by_ea:
                candidate = role_by_ea[ea]
                removed_roles.append(
                    {
                        "ea": f"0x{ea:x}",
                        "proposed_name": candidate["proposed_name"],
                        "confidence": candidate["confidence"],
                    }
                )
                continue
            if ea in static_by_ea:
                alias = static_by_ea[ea]
                removed_static_roles.append(
                    {
                        "ea": f"0x{ea:x}",
                        "proposed_name": alias["proposed_name"],
                        "confidence": alias["confidence"],
                        "source_match": alias["source_match"],
                    }
                )
                continue
            if ea in REANALYZED_FUNCTIONS:
                item = REANALYZED_FUNCTIONS[ea]
                removed_reanalyzed.append(
                    {
                        "ea": f"0x{ea:x}",
                        "new_name": item["new_name"],
                        "reason": item["reason"],
                    }
                )
                continue
            residual.append(
                {
                    "ea": f"0x{ea:x}",
                    "category": category,
                    "current_ida_name": original["current_ida_name"],
                    "segment": original["segment"],
                    "size": original["size"],
                }
            )

    residual.sort(key=lambda item: address(item["ea"]))
    if len(removed_roles) != roles["candidate_count"]:
        raise ValueError("role removal count does not match candidate artifact")
    expected_static_count = sum(
        document["alias_count"] for document in static_documents
    )
    if len(removed_static_roles) != expected_static_count:
        raise ValueError("static role removal count does not match audit artifacts")
    expected = profile["unresolved_default_sub_function_count"] - len(
        removed_roles
    ) - len(removed_static_roles) - len(removed_reanalyzed)
    if len(residual) != expected:
        raise ValueError(
            f"residual count mismatch: expected {expected}, got {len(residual)}"
        )

    groups = {}
    for item in residual:
        group = groups.setdefault(
            item["category"],
            {"category": item["category"], "count": 0, "total_bytes": 0, "entries": []},
        )
        group["count"] += 1
        group["total_bytes"] += item["size"]
        group["entries"].append(item)

    evidence_by_category = {
        item["category"]: item["evidence"]
        for item in profile["category_summary"]
    }
    category_summary = []
    for category in sorted(groups):
        group = groups[category]
        entries = group["entries"]
        category_summary.append(
            {
                "category": category,
                "count": group["count"],
                "total_bytes": group["total_bytes"],
                "first_ea": entries[0]["ea"],
                "last_ea": entries[-1]["ea"],
                "evidence": evidence_by_category[category],
            }
        )

    database = {
        **CURRENT_DATABASE,
        "default_sub_function_count": len(residual),
    }

    result = {
        "schema_version": 1,
        "artifact": "ida_persisted_residual_profile",
        "purpose": (
            "Account for every default sub_ function left in the persisted "
            "IDA translation copy without inventing source names."
        ),
        "binary": profile["binary"],
        "binary_sha256": profile["binary_sha256"],
        "database": database,
        "pre_persistence_snapshot": {
            "profile": "artifacts/unresolved_function_profile.json",
            "default_sub_function_count": profile["default_sub_function_count"],
            "unresolved_default_sub_function_count": profile[
                "unresolved_default_sub_function_count"
            ],
        },
        "applied_role_aliases": {
            "source": "artifacts/unresolved_function_candidates.json",
            "count": len(removed_roles),
            "entries": sorted(removed_roles, key=lambda item: address(item["ea"])),
        },
        "applied_static_role_aliases": {
            "sources": [
                f"artifacts/{artifact}.json" for artifact in static_sources
            ],
            "count": len(removed_static_roles),
            "entries": sorted(
                removed_static_roles, key=lambda item: address(item["ea"])
            ),
        },
        "ida_reclassified_functions": removed_reanalyzed,
        "remaining_default_sub_function_count": len(residual),
        "category_summary": category_summary,
        "categories": [groups[key] for key in sorted(groups)],
        "residual_default_sub_functions": residual,
        "translation_limit": (
            "These entries are IDA-created functions with no surviving source "
            "name in the APK. Library-family evidence is recorded where "
            "available, but family membership is not converted into a guessed "
            "source symbol."
        ),
        "source_artifacts": {
            "profile": "artifacts/unresolved_function_profile.json",
            "role_candidates": "artifacts/unresolved_function_candidates.json",
            "static_role_aliases": [
                f"artifacts/{artifact}.json" for artifact in static_sources
            ],
            "validation": "artifacts/ida_translation_validation.json",
        },
        "network_contacted": False,
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--roles", default=DEFAULT_ROLES)
    parser.add_argument(
        "--static-roles",
        action="append",
        default=None,
        help="static role audit JSON; may be supplied more than once",
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    static_paths = args.static_roles or DEFAULT_STATIC_ROLES
    result = generate(
        load(args.profile),
        load(args.roles),
        [load(path) for path in static_paths],
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "remaining_default_sub_function_count": result[
                    "remaining_default_sub_function_count"
                ],
                "categories": [
                    {"category": item["category"], "count": item["count"]}
                    for item in result["category_summary"]
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
