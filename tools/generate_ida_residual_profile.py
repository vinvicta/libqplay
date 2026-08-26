#!/usr/bin/env python3
"""Build the final residual report for the persisted IDA translation copy.

The public unresolved-function profile describes the 488 default functions in
the pre-persistence inventory. The role-candidate pass names 28 application or
engine entries, the first CyaSSL pass names 11 static TLS and crypto roles, and
the next static-library pass names 27 zlib, bzip2, minizip, GPC, CyaSSL,
LibTomCrypt, and YAJL roles. IDA reclassifies one compiler branch veneer as a
thunk when the saved copy is reopened. This helper subtracts those known
changes and emits the exact residual count in the latest persisted database.
It only reads JSON files and performs no network operation.
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

REANALYZED_FUNCTIONS = {
    0x1F94FC: {
        "new_name": "j_TCachedStream_get_minfilecachesize",
        "reason": (
            "IDA reclassified the four-byte unconditional branch veneer as a "
            "named thunk to TCachedStream_get_minfilecachesize when the "
            "persisted translation copy was rebuilt."
        ),
    }
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

    if static_documents:
        latest_static = static_documents[-1]
        database = {
            "path": latest_static["database"]["path"],
            "sha256": latest_static["database"]["sha256"],
            "format": latest_static["database"]["format"],
            "close_reopen_verified": latest_static["database"]["close_reopen_verified"],
            "function_count": latest_static["database"]["function_count"],
            "default_sub_function_count": len(residual),
        }
    else:
        database = {
            "path": "analysis/libqplay_translated_all_v2.i64",
            "sha256": "0306a53f164fc9f860f24eb248039a94172959053daa6464d4a1effe35026a89",
            "format": "packed IDA 9.3 database",
            "close_reopen_verified": True,
            "function_count": 11297,
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
