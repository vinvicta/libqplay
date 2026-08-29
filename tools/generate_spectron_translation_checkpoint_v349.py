#!/usr/bin/env python3
"""Create the v349 checkpoint for the exact sound-wrapper translation pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260829_v349"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v348"
EXPECTED_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
EXPECTED_PARENT_DATABASE_SHA256 = "40ff536a25df6624d1ac25bc9052e85d107dddb996dc5e46b791d1df936a75c0"
EXPECTED_DATABASE_SHA256 = "ede4f9187e01c4a415181f423dd9c7b8467deb38595d399dcb19341fd9203faf"
EXPECTED_LABEL_ARTIFACT = "spectron_sounds_exact_manual_translation_anchors_20260829"
EXPECTED_LABEL_SUMMARY = {
    "address_delta_groups": {"+0xbb0": 4, "+0xbd4": 2, "+0xbe8": 1, "+0xbf0": 3},
    "anchor_count": 10,
    "exact_shape_anchor_count": 10,
    "high_confidence_count": 10,
    "layout_change_anchor_count": 0,
    "new_context_anchor_count": 10,
    "target_default_name_count": 0,
}
EXPECTED_NAME_ORIGINS = {
    "ida_named_or_other": 4052,
    "target_jni_export": 7,
    "target_named_export": 768,
    "target_only_descriptive": 439,
    "translated_v18_alias": 6441,
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
        "item_name_match": 1656,
        "item_name_mismatch": 5114,
        "value_name_match": 1656,
        "value_name_mismatch": 5114,
    },
    "named_dynamic_symbol_count": 6770,
    "status_counts": {
        "exact_retained_dynamic_name": 1656,
        "linker_boundary_alias_mismatch": 7,
        "other_retained_target_name": 119,
        "source_backed_v18_alias": 4796,
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
EXPECTED_SEMANTIC_SUMMARY = {
    "ambiguous_functions": 1004,
    "mapped_functions": 3732,
    "mapped_high_confidence": 3672,
    "mapped_medium_confidence": 60,
    "original_functions": 11308,
    "spectron_functions": 11707,
    "unique_spectron_targets": 3732,
    "unmatched_functions": 608,
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
    parser.add_argument("--label-artifact", required=True, type=Path)
    parser.add_argument("--application-report", required=True, type=Path)
    parser.add_argument("--verification-report", required=True, type=Path)
    parser.add_argument("--name-audit", required=True, type=Path)
    parser.add_argument("--boundary-audit", required=True, type=Path)
    parser.add_argument("--dynamic-symbol-coverage", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--feature-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    labels = load(args.label_artifact)
    application = load(args.application_report)
    verification = load(args.verification_report)
    name_audit = load(args.name_audit)
    boundary = load(args.boundary_audit)
    dynamic_coverage = load(args.dynamic_symbol_coverage)
    semantic_map = load(args.semantic_map)
    feature_export = load(args.feature_export)

    require(parent.get("artifact") == PARENT_ARTIFACT, "unexpected parent checkpoint")
    require(parent["database"]["sha256"] == EXPECTED_PARENT_DATABASE_SHA256, "parent database hash is not v348")
    require(labels.get("artifact") == EXPECTED_LABEL_ARTIFACT, "unexpected sound anchor artifact")
    require(labels.get("network_contacted") is False, "sound anchor contacted the network")
    require(labels.get("summary") == EXPECTED_LABEL_SUMMARY, "sound anchor summary changed")
    require(len(labels.get("anchors", [])) == 10, "sound anchor count changed")
    require(
        application.get("apply")
        and application.get("expected_artifact") == EXPECTED_LABEL_ARTIFACT
        and application.get("anchor_count") == 10
        and application.get("resolved_count") == 10
        and application.get("renamed_count") == 0
        and application.get("comments_added") == 9
        and application.get("failure_count") == 0
        and application.get("saved"),
        "sound anchor application did not pass",
    )
    require(
        verification.get("artifact") == "spectron_manual_anchor_reopen_verification"
        and verification.get("verified")
        and verification.get("expected_artifact") == EXPECTED_LABEL_ARTIFACT
        and verification.get("anchor_count") == 10
        and verification.get("verified_name_count") == 10
        and verification.get("failure_count") == 0,
        "sound anchor reopen verification did not pass",
    )
    require(
        name_audit.get("network_contacted") is False
        and name_audit.get("input_sha256") == EXPECTED_BINARY_SHA256
        and name_audit.get("function_count") == 11707
        and name_audit.get("default_name_count") == 0
        and name_audit.get("name_origins") == EXPECTED_NAME_ORIGINS,
        "v349 name audit changed",
    )
    require(
        boundary.get("network_contacted") is False
        and boundary.get("input_sha256") == EXPECTED_BINARY_SHA256
        and {
            "defined_function_symbol_count": boundary.get("defined_function_symbol_count"),
            "ida_exact_start_count": boundary.get("ida_exact_start_count"),
            "ida_missing_exact_start_count": boundary.get("ida_missing_exact_start_count"),
            "row_count": len(boundary.get("rows", [])),
        }
        == EXPECTED_BOUNDARY,
        "v349 dynamic boundary audit changed",
    )
    require(
        dynamic_coverage.get("network_contacted") is False
        and dynamic_coverage.get("input_sha256") == EXPECTED_BINARY_SHA256
        and dynamic_coverage.get("summary") == EXPECTED_DYNAMIC_SUMMARY,
        "v349 dynamic symbol coverage changed",
    )
    require(
        semantic_map.get("network_contacted") is False
        and semantic_map.get("summary") == EXPECTED_SEMANTIC_SUMMARY
        and semantic_map.get("carried_forward", {}).get("target_feature_count") == 11707
        and semantic_map.get("carried_forward", {}).get("manual_matches_added") == 10
        and semantic_map.get("carried_forward", {}).get("ambiguous_rows_resolved") == 10,
        "v349 semantic map changed",
    )
    require(
        feature_export.get("artifact") == "ida_function_features"
        and feature_export.get("network_contacted") is False
        and feature_export.get("function_count") == 11707,
        "v349 feature export changed",
    )
    require(args.database.is_file(), "database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == EXPECTED_DATABASE_SHA256, "v349 database hash changed")

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
        "v349_sounds_anchor_artifact": str(args.label_artifact),
        "v349_sounds_anchor_artifact_sha256": sha256_path(args.label_artifact),
        "v349_sounds_application_report": str(args.application_report),
        "v349_sounds_application_report_sha256": sha256_path(args.application_report),
        "v349_sounds_verification_report": str(args.verification_report),
        "v349_sounds_verification_report_sha256": sha256_path(args.verification_report),
        "v349_name_audit": str(args.name_audit),
        "v349_name_audit_sha256": sha256_path(args.name_audit),
        "v349_boundary_audit": str(args.boundary_audit),
        "v349_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v349_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v349_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        "v349_semantic_map": str(args.semantic_map),
        "v349_semantic_map_sha256": sha256_path(args.semantic_map),
        "v349_feature_export": str(args.feature_export),
        "v349_feature_export_sha256": sha256_path(args.feature_export),
    }
    result["sounds_translation_v349"] = {
        "anchor_artifact": str(args.label_artifact),
        "anchor_artifact_sha256": sha256_path(args.label_artifact),
        "application_report": str(args.application_report),
        "application_report_sha256": sha256_path(args.application_report),
        "anchor_count": labels["summary"]["anchor_count"],
        "high_confidence_count": labels["summary"]["high_confidence_count"],
        "exact_shape_anchor_count": labels["summary"]["exact_shape_anchor_count"],
        "layout_change_anchor_count": labels["summary"]["layout_change_anchor_count"],
        "new_context_anchor_count": labels["summary"]["new_context_anchor_count"],
        "target_default_name_count": labels["summary"]["target_default_name_count"],
        "source_counterpart_count": labels["summary"]["anchor_count"],
        "resolved_ambiguous_count": semantic_map["carried_forward"]["ambiguous_rows_resolved"],
        "reopen_verified": verification["verified"],
        "verification_report": str(args.verification_report),
        "verification_report_sha256": sha256_path(args.verification_report),
        "existing_target_alias_count": application["anchor_count"] - application["renamed_count"],
    }
    result["name_coverage_audit_v349"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["dynamic_function_boundary_audit_v349"] = {
        "artifact_path": str(args.boundary_audit),
        "artifact_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
    }
    result["dynamic_symbol_coverage_audit_v349"] = {
        "artifact_path": str(args.dynamic_symbol_coverage),
        "artifact_sha256": sha256_path(args.dynamic_symbol_coverage),
        "summary": dynamic_coverage["summary"],
    }
    result["semantic_function_translation_v349"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
        "carried_forward": semantic_map["carried_forward"],
        "source_backed_translation_change": True,
        "target_only_label_change": False,
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v349 pass resolves ten remaining TSounds and Java-audio wrapper ambiguities with high-confidence exact-shape source-backed aliases. The target already carried the v18_ names, so the IDA copy receives review comments and the semantic map gains explicit source-to-target rows."
    )
    result["interpretation"].append(
        "Five larger sound routines remain a separate layout-change group. Their direct pseudocode is strongly corresponding, but their target wrapper layout differs enough that this exact-shape checkpoint does not claim them."
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "database_sha256": database_sha256,
                "function_count": result["database"]["function_count"],
                "sounds_anchor_count": labels["summary"]["anchor_count"],
                "resolved_ambiguous_rows": semantic_map["carried_forward"]["ambiguous_rows_resolved"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
