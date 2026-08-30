#!/usr/bin/env python3
"""Create the v352 checkpoint for the existing-alias reconciliation pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260829_v352"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v351"
DATABASE_SHA256 = "0fb0662dffea1f1f6223e0e52745a19505687a79cf47f207280ce098f61b87f0"
TARGET_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
RECONCILIATION_ARTIFACT = "spectron_existing_v18_alias_reconciliation_20260829"
EXPECTED_SEMANTIC_SUMMARY = {
    "ambiguous_functions": 1001,
    "mapped_functions": 4254,
    "mapped_high_confidence": 4193,
    "mapped_medium_confidence": 61,
    "original_functions": 11308,
    "spectron_functions": 11707,
    "unique_spectron_targets": 4254,
    "unmatched_functions": 89,
}
EXPECTED_NAME_ORIGINS = {
    "ida_named_or_other": 4052,
    "target_jni_export": 7,
    "target_named_export": 764,
    "target_only_descriptive": 439,
    "translated_v18_alias": 6445,
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
    parser.add_argument("--reconciliation-artifact", required=True, type=Path)
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
    reconciliation = load(args.reconciliation_artifact)
    application = load(args.application_report)
    verification = load(args.verification_report)
    name_audit = load(args.name_audit)
    boundary = load(args.boundary_audit)
    dynamic_coverage = load(args.dynamic_symbol_coverage)
    semantic_map = load(args.semantic_map)
    target_features = load(args.target_features)

    require(parent.get("artifact") == PARENT_ARTIFACT, "unexpected parent checkpoint")
    require(parent.get("database", {}).get("sha256") == DATABASE_SHA256, "parent database hash changed")
    require(reconciliation.get("artifact") == RECONCILIATION_ARTIFACT, "unexpected reconciliation artifact")
    require(reconciliation.get("network_contacted") is False, "reconciliation contacted the network")
    require(
        reconciliation.get("summary") == {
            "anchor_count": 509,
            "exact_shape_prior_count": 0,
            "high_confidence_count": 508,
            "layout_change_prior_count": 509,
            "medium_confidence_count": 1,
            "new_target_name_count": 0,
            "provenance_artifact_count": 336,
            "reconciled_unmatched_count": 509,
            "remaining_unmatched_without_existing_alias": 89,
            "target_default_name_count": 0,
        },
        "reconciliation summary changed",
    )
    require(
        application.get("artifact") == "spectron_existing_v18_alias_reconciliation_application"
        and application.get("expected_artifact") == RECONCILIATION_ARTIFACT
        and application.get("apply") is False
        and application.get("anchor_count") == 509
        and application.get("resolved_count") == 509
        and application.get("renamed_count") == 0
        and application.get("comments_added") == 0
        and application.get("failure_count") == 0
        and application.get("saved") is False
        and application.get("database_changed") is False
        and application.get("verified") is True,
        "reconciliation application report changed",
    )
    require(
        verification.get("artifact") == "spectron_existing_v18_alias_reconciliation_verification"
        and verification.get("expected_artifact") == RECONCILIATION_ARTIFACT
        and verification.get("anchor_count") == 509
        and verification.get("verified_name_count") == 509
        and verification.get("failure_count") == 0
        and verification.get("function_count") == 11707
        and verification.get("verified") is True
        and verification.get("database_changed") is False,
        "reconciliation verification report changed",
    )
    require(
        name_audit.get("network_contacted") is False
        and name_audit.get("input_sha256") == TARGET_BINARY_SHA256
        and name_audit.get("function_count") == 11707
        and name_audit.get("default_name_count") == 0
        and name_audit.get("name_origins") == EXPECTED_NAME_ORIGINS,
        "name audit changed",
    )
    require(
        boundary.get("network_contacted") is False
        and boundary.get("input_sha256") == TARGET_BINARY_SHA256
        and boundary.get("defined_function_symbol_count") == 5782
        and boundary.get("ida_exact_start_count") == 5782
        and boundary.get("ida_missing_exact_start_count") == 0
        and len(boundary.get("rows", [])) == 5782,
        "dynamic boundary audit changed",
    )
    require(
        dynamic_coverage.get("network_contacted") is False
        and dynamic_coverage.get("input_sha256") == TARGET_BINARY_SHA256,
        "dynamic symbol coverage changed",
    )
    require(
        semantic_map.get("network_contacted") is False
        and semantic_map.get("summary") == EXPECTED_SEMANTIC_SUMMARY
        and semantic_map.get("carried_forward", {}).get("existing_alias_rows_reconciled") == 509
        and semantic_map.get("carried_forward", {}).get("manual_matches_added") == 509
        and semantic_map.get("carried_forward", {}).get("unmatched_rows_promoted") == 509,
        "semantic map changed",
    )
    require(
        target_features.get("artifact") == "ida_function_features"
        and target_features.get("network_contacted") is False
        and target_features.get("function_count") == 11707,
        "target feature export changed",
    )
    require(args.database.is_file(), "database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == DATABASE_SHA256, "v352 database hash changed")

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
        "close_reopen_verified": parent["database"].get("close_reopen_verified", True),
    }
    result["inputs"] = {
        **parent.get("inputs", {}),
        "v352_reconciliation_artifact": str(args.reconciliation_artifact),
        "v352_reconciliation_artifact_sha256": sha256_path(args.reconciliation_artifact),
        "v352_reconciliation_application_report": str(args.application_report),
        "v352_reconciliation_application_report_sha256": sha256_path(args.application_report),
        "v352_reconciliation_verification_report": str(args.verification_report),
        "v352_reconciliation_verification_report_sha256": sha256_path(args.verification_report),
        "v352_semantic_map": str(args.semantic_map),
        "v352_semantic_map_sha256": sha256_path(args.semantic_map),
        "v352_target_features": str(args.target_features),
        "v352_target_features_sha256": sha256_path(args.target_features),
    }
    result["existing_v18_alias_reconciliation_v352"] = {
        "artifact": str(args.reconciliation_artifact),
        "artifact_sha256": sha256_path(args.reconciliation_artifact),
        "application_report": str(args.application_report),
        "application_report_sha256": sha256_path(args.application_report),
        "verification_report": str(args.verification_report),
        "verification_report_sha256": sha256_path(args.verification_report),
        "reconciled_alias_count": reconciliation["summary"]["anchor_count"],
        "high_confidence_count": reconciliation["summary"]["high_confidence_count"],
        "medium_confidence_count": reconciliation["summary"]["medium_confidence_count"],
        "remaining_unmatched_without_existing_alias": reconciliation["summary"][
            "remaining_unmatched_without_existing_alias"
        ],
        "target_database_changed": False,
        "reopen_verified": verification["verified"],
    }
    result["semantic_function_translation_v352"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
        "source_backed_translation_change": True,
        "target_only_label_change": False,
        "target_database_changed": False,
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v352 pass reconciles 509 target functions whose reviewed v18_ aliases were already present in the target IDB but absent from the current semantic map. Each pair is tied to one prior anchor artifact and verified against the current target feature export."
    )
    result["interpretation"].append(
        "This is a semantic-map-only correction. The v352 database is byte-for-byte identical to v351, so no new IDA names, comments, boundaries, or code changes were applied in this pass. Eighty-nine source rows still lack a unique existing v18_ alias."
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": ARTIFACT,
                "database_sha256": database_sha256,
                "semantic_summary": semantic_map["summary"],
                "reconciled_alias_count": reconciliation["summary"]["anchor_count"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
