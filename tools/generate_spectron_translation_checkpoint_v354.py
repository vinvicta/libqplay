#!/usr/bin/env python3
"""Create the v354 checkpoint for the compact core residual pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260830_v354"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v353"
TARGET_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
PARENT_CHECKPOINT_DATABASE_SHA256 = "03959f04419cb3900cf68b41283138c458c46e6dbede9c1ba9d1acbf15c6b63a"
PARENT_DATABASE_OBSERVED_SHA256 = "e4caba5dba37c84c90ab26d0d358de5a2484058a4a1c186e12af19c01f4da62d"
DATABASE_SHA256 = "27eccea1a8ac243724b3df040055332cd486ca6171a7aa57d66123d4e115bef0"
EXPECTED_SEMANTIC_SUMMARY = {
    "ambiguous_functions": 1001,
    "mapped_functions": 4268,
    "mapped_high_confidence": 4207,
    "mapped_medium_confidence": 61,
    "original_functions": 11308,
    "spectron_functions": 11707,
    "unique_spectron_targets": 4268,
    "unmatched_functions": 75,
}
EXPECTED_NAME_ORIGINS = {
    "ida_named_or_other": 4052,
    "target_jni_export": 2,
    "target_named_export": 756,
    "target_only_descriptive": 439,
    "translated_v18_alias": 6458,
}
EXPECTED_DYNAMIC_SUMMARY = {
    "defined_named_symbol_count": 6600,
    "location_counts": {
        "ida_data_item": 482,
        "ida_function_exact": 5782,
        "ida_noncode_item": 336,
        "undefined_or_zero_value": 170,
    },
    "name_match_counts": {
        "item_name_match": 1639,
        "item_name_mismatch": 5131,
        "value_name_match": 1639,
        "value_name_mismatch": 5131,
    },
    "named_dynamic_symbol_count": 6770,
    "status_counts": {
        "exact_retained_dynamic_name": 1639,
        "linker_boundary_alias_mismatch": 7,
        "other_retained_target_name": 118,
        "source_backed_v18_alias": 4814,
        "target_only_descriptive": 22,
        "undefined_import_with_plt_stub": 169,
        "undefined_no_target_address": 1,
    },
}
EXPECTED_BOUNDARY = {
    "defined_function_symbol_count": 5782,
    "ida_exact_start_count": 5782,
    "ida_missing_exact_start_count": 0,
    "row_count": 5782,
}
EXPECTED_ANCHOR_SUMMARY = {
    "address_delta_groups": {
        "+0x1ffc": 1,
        "+0x2630": 1,
        "+0x39d8": 1,
        "+0x3a54": 1,
        "+0xbe8": 1,
        "+0xbec": 1,
        "+0xe48": 1,
        "+0xfbc": 1,
        "-0x270": 1,
    },
    "anchor_count": 9,
    "exact_shape_anchor_count": 0,
    "existing_alias_role_correction_count": 1,
    "high_confidence_count": 9,
    "layout_change_anchor_count": 9,
    "new_context_anchor_count": 9,
    "promoted_unmatched_count": 9,
    "target_default_name_count": 0,
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-checkpoint", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--anchor-artifact", required=True, type=Path)
    parser.add_argument("--application-report", required=True, type=Path)
    parser.add_argument("--verification-report", required=True, type=Path)
    parser.add_argument("--name-audit", required=True, type=Path)
    parser.add_argument("--boundary-audit", required=True, type=Path)
    parser.add_argument("--dynamic-symbol-coverage", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--target-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    anchors = load(args.anchor_artifact)
    application = load(args.application_report)
    verification = load(args.verification_report)
    name_audit = load(args.name_audit)
    boundary = load(args.boundary_audit)
    dynamic = load(args.dynamic_symbol_coverage)
    semantic_map = load(args.semantic_map)
    target_features = load(args.target_features)

    require(parent.get("artifact") == PARENT_ARTIFACT, "unexpected parent checkpoint")
    require(
        parent.get("database", {}).get("sha256") == PARENT_CHECKPOINT_DATABASE_SHA256,
        "parent checkpoint database hash changed",
    )
    require(anchors.get("artifact") == "spectron_compact_core_manual_translation_anchors_20260830", "unexpected compact-core anchor artifact")
    require(anchors.get("network_contacted") is False, "compact-core anchor artifact is not offline")
    require(anchors.get("summary") == EXPECTED_ANCHOR_SUMMARY, "compact-core anchor summary changed")
    require(len(anchors.get("anchors", [])) == 9, "compact-core anchor count changed")
    require(
        application.get("expected_artifact") == "spectron_compact_core_manual_translation_anchors_20260830"
        and application.get("apply") is True
        and application.get("anchor_count") == 9
        and application.get("resolved_count") == 9
        and application.get("renamed_count") == 8
        and application.get("comments_added") == 8
        and application.get("failure_count") == 0
        and application.get("saved") is True
        and application.get("verified") is True,
        "compact-core application report changed",
    )
    require(
        verification.get("expected_artifact") == "spectron_compact_core_manual_translation_anchors_20260830"
        and verification.get("anchor_count") == 9
        and verification.get("verified_name_count") == 9
        and verification.get("failure_count") == 0
        and verification.get("function_count") == 11707
        and verification.get("verified") is True,
        "compact-core reopen verification changed",
    )
    require(
        name_audit.get("network_contacted") is False
        and name_audit.get("input_sha256") == TARGET_BINARY_SHA256
        and name_audit.get("function_count") == 11707
        and name_audit.get("default_name_count") == 0
        and name_audit.get("name_origins") == EXPECTED_NAME_ORIGINS,
        "v354 name audit changed",
    )
    require(
        boundary.get("network_contacted") is False
        and boundary.get("input_sha256") == TARGET_BINARY_SHA256
        and {
            "defined_function_symbol_count": boundary.get("defined_function_symbol_count"),
            "ida_exact_start_count": boundary.get("ida_exact_start_count"),
            "ida_missing_exact_start_count": boundary.get("ida_missing_exact_start_count"),
            "row_count": len(boundary.get("rows", [])),
        }
        == EXPECTED_BOUNDARY,
        "v354 dynamic boundary audit changed",
    )
    require(
        dynamic.get("network_contacted") is False
        and dynamic.get("input_sha256") == TARGET_BINARY_SHA256
        and dynamic.get("summary") == EXPECTED_DYNAMIC_SUMMARY,
        "v354 dynamic symbol coverage changed",
    )
    require(
        semantic_map.get("network_contacted") is False
        and semantic_map.get("summary") == EXPECTED_SEMANTIC_SUMMARY
        and semantic_map.get("compact_core_translation_v354", {}).get("anchor_count") == 9,
        "v354 semantic map changed",
    )
    require(
        target_features.get("artifact") == "ida_function_features"
        and target_features.get("network_contacted") is False
        and target_features.get("function_count") == 11707,
        "v354 feature export changed",
    )
    require(args.database.is_file(), "v354 database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == DATABASE_SHA256, "v354 database hash changed")

    result = copy.deepcopy(parent)
    result["artifact"] = ARTIFACT
    result["network_contacted"] = False
    result["parent_checkpoint"] = {
        "artifact": parent["artifact"],
        "path": str(args.parent_checkpoint),
        "sha256": sha256_path(args.parent_checkpoint),
    }
    result["database"] = {
        **parent["database"],
        "path": str(args.database),
        "sha256": database_sha256,
        "function_count": name_audit["function_count"],
        "default_sub_function_count": name_audit["default_name_count"],
        "default_name_count": name_audit["default_name_count"],
        "close_reopen_verified": True,
        "parent_database_observed_after_v353_idalib_reads_sha256": PARENT_DATABASE_OBSERVED_SHA256,
    }
    result["inputs"] = {
        **parent.get("inputs", {}),
        "v354_compact_core_anchor_artifact": str(args.anchor_artifact),
        "v354_compact_core_anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "v354_compact_core_application_report": str(args.application_report),
        "v354_compact_core_application_report_sha256": sha256_path(args.application_report),
        "v354_compact_core_verification_report": str(args.verification_report),
        "v354_compact_core_verification_report_sha256": sha256_path(args.verification_report),
        "v354_name_audit": str(args.name_audit),
        "v354_name_audit_sha256": sha256_path(args.name_audit),
        "v354_boundary_audit": str(args.boundary_audit),
        "v354_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v354_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v354_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        "v354_semantic_map": str(args.semantic_map),
        "v354_semantic_map_sha256": sha256_path(args.semantic_map),
        "v354_target_features": str(args.target_features),
        "v354_target_features_sha256": sha256_path(args.target_features),
    }
    result["compact_core_translation_v354"] = {
        "anchor_artifact": str(args.anchor_artifact),
        "anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "application_report": str(args.application_report),
        "application_report_sha256": sha256_path(args.application_report),
        "verification_report": str(args.verification_report),
        "verification_report_sha256": sha256_path(args.verification_report),
        "anchor_count": anchors["summary"]["anchor_count"],
        "high_confidence_count": anchors["summary"]["high_confidence_count"],
        "layout_change_anchor_count": anchors["summary"]["layout_change_anchor_count"],
        "renamed_count": application["renamed_count"],
        "existing_alias_role_correction_count": anchors["summary"]["existing_alias_role_correction_count"],
        "reopen_verified": verification["verified"],
        "semantic_summary": semantic_map["summary"],
        "folded_or_removed_rows_not_promoted": semantic_map["compact_core_translation_v354"]["folded_or_removed_rows_not_promoted"],
    }
    result["name_coverage_audit_v354"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["dynamic_function_boundary_audit_v354"] = {
        "artifact_path": str(args.boundary_audit),
        "artifact_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
    }
    result["dynamic_symbol_coverage_audit_v354"] = {
        "artifact_path": str(args.dynamic_symbol_coverage),
        "artifact_sha256": sha256_path(args.dynamic_symbol_coverage),
        "summary": dynamic["summary"],
    }
    result["semantic_function_translation_v354"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
        "source_backed_translation_change": True,
        "target_only_label_change": False,
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v354 pass adds nine high-confidence compact-core correspondences. Eight receive new v18_ aliases, while one existing Android cleanup alias is promoted with explicit source-backed provenance."
    )
    result["interpretation"].append(
        "Four source rows remain explicitly unresolved because the 2.2 rebuild appears to fold or remove them: encoded hash membership converged with the target object-membership wrapper, THashStrings::listNames has no retained target body, TLog::echo has no separate target body, and TInitStatics::initVars is absent as a central target routine."
    )
    result["interpretation"].append(
        "The v354 copy was derived from the parent IDB after later IDALIB evidence reads had added database metadata. The observed parent hash is recorded separately so the new copy remains reproducible without rewriting the historical v353 checkpoint."
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": ARTIFACT,
                "database_sha256": database_sha256,
                "semantic_summary": semantic_map["summary"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
