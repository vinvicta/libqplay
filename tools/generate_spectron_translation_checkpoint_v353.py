#!/usr/bin/env python3
"""Create the v353 checkpoint for the retained JNI callback pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260829_v353"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v352"
DATABASE_SHA256 = "03959f04419cb3900cf68b41283138c458c46e6dbede9c1ba9d1acbf15c6b63a"
TARGET_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
EXPECTED_SEMANTIC_SUMMARY = {
    "ambiguous_functions": 1001,
    "mapped_functions": 4259,
    "mapped_high_confidence": 4198,
    "mapped_medium_confidence": 61,
    "original_functions": 11308,
    "spectron_functions": 11707,
    "unique_spectron_targets": 4259,
    "unmatched_functions": 84,
}
EXPECTED_NAME_ORIGINS = {
    "ida_named_or_other": 4052,
    "target_jni_export": 2,
    "target_named_export": 764,
    "target_only_descriptive": 439,
    "translated_v18_alias": 6450,
}
EXPECTED_DYNAMIC_STATUS = {
    "exact_retained_dynamic_name": 1647,
    "linker_boundary_alias_mismatch": 7,
    "other_retained_target_name": 119,
    "source_backed_v18_alias": 4805,
    "target_only_descriptive": 22,
    "undefined_import_with_plt_stub": 169,
    "undefined_no_target_address": 1,
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
    require(parent.get("database", {}).get("sha256") == "0fb0662dffea1f1f6223e0e52745a19505687a79cf47f207280ce098f61b87f0", "parent database hash changed")
    require(anchors.get("artifact") == "spectron_jni_callbacks_manual_translation_anchors_20260829", "unexpected JNI anchor artifact")
    require(anchors.get("network_contacted") is False, "JNI anchor artifact is not offline")
    require(anchors.get("summary", {}).get("anchor_count") == 5, "JNI anchor count changed")
    require(anchors.get("summary", {}).get("high_confidence_count") == 5, "JNI confidence count changed")
    require(
        application.get("expected_artifact") == "spectron_jni_callbacks_manual_translation_anchors_20260829"
        and application.get("apply") is True
        and application.get("anchor_count") == 5
        and application.get("resolved_count") == 5
        and application.get("renamed_count") == 5
        and application.get("failure_count") == 0
        and application.get("saved") is True
        and application.get("verified") is True,
        "JNI application report changed",
    )
    require(
        verification.get("expected_artifact") == "spectron_jni_callbacks_manual_translation_anchors_20260829"
        and verification.get("anchor_count") == 5
        and verification.get("verified_name_count") == 5
        and verification.get("failure_count") == 0
        and verification.get("function_count") == 11707
        and verification.get("verified") is True,
        "JNI verification report changed",
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
        dynamic.get("network_contacted") is False
        and dynamic.get("input_sha256") == TARGET_BINARY_SHA256
        and dynamic.get("summary", {}).get("status_counts") == EXPECTED_DYNAMIC_STATUS,
        "dynamic symbol coverage changed",
    )
    require(
        semantic_map.get("network_contacted") is False
        and semantic_map.get("summary") == EXPECTED_SEMANTIC_SUMMARY
        and semantic_map.get("jni_callbacks_translation_v353", {}).get("anchor_count") == 5,
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
    require(database_sha256 == DATABASE_SHA256, "v353 database hash changed")

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
    }
    result["inputs"] = {
        **parent.get("inputs", {}),
        "v353_jni_callback_anchor_artifact": str(args.anchor_artifact),
        "v353_jni_callback_anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "v353_jni_callback_application_report": str(args.application_report),
        "v353_jni_callback_application_report_sha256": sha256_path(args.application_report),
        "v353_jni_callback_verification_report": str(args.verification_report),
        "v353_jni_callback_verification_report_sha256": sha256_path(args.verification_report),
        "v353_name_audit": str(args.name_audit),
        "v353_name_audit_sha256": sha256_path(args.name_audit),
        "v353_boundary_audit": str(args.boundary_audit),
        "v353_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v353_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v353_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        "v353_semantic_map": str(args.semantic_map),
        "v353_semantic_map_sha256": sha256_path(args.semantic_map),
        "v353_target_features": str(args.target_features),
        "v353_target_features_sha256": sha256_path(args.target_features),
    }
    result["jni_callbacks_translation_v353"] = {
        "artifact": str(args.anchor_artifact),
        "artifact_sha256": sha256_path(args.anchor_artifact),
        "application_report": str(args.application_report),
        "application_report_sha256": sha256_path(args.application_report),
        "verification_report": str(args.verification_report),
        "verification_report_sha256": sha256_path(args.verification_report),
        "anchor_count": anchors["summary"]["anchor_count"],
        "high_confidence_count": anchors["summary"]["high_confidence_count"],
        "renamed_count": application["renamed_count"],
        "target_database_changed": True,
        "reopen_verified": verification["verified"],
        "semantic_summary": semantic_map["summary"],
    }
    result["semantic_function_translation_v353"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
        "source_backed_translation_change": True,
        "target_only_label_change": False,
        "target_database_changed": True,
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v353 pass resolves five source rows whose JNI export names survived unchanged in both builds. Direct pseudocode review confirms the callback roles despite target-side class renaming and expected lifecycle additions."
    )
    result["interpretation"].append(
        "The v353 database is a new analysis copy of v351. It prefixes the five retained JNI names with v18_, appends review comments, and leaves code bytes and function boundaries unchanged."
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": ARTIFACT, "database_sha256": database_sha256, "semantic_summary": semantic_map["summary"]}, sort_keys=True))


if __name__ == "__main__":
    main()
