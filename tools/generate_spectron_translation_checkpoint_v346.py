#!/usr/bin/env python3
"""Create the v346 checkpoint for the target-only resource path helper pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260829_v346"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v345"
EXPECTED_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
EXPECTED_PARENT_DATABASE_SHA256 = "0b455dfb6777c8ca571f86e19612d30a7dca6c3d9b9e47590e31a6bfcea4442f"
EXPECTED_DATABASE_SHA256 = "bfb7f36be1a572c5428192c90ee3288035805a2e34b7ead439437c4b1ccf2392"
EXPECTED_LABEL_ARTIFACT = "spectron_resource_path_helper_target_only_labels_20260829"
EXPECTED_LABEL_SUMMARY = {
    "defined_dynamic_symbol_count": 1,
    "exact_metric_match_count": 0,
    "high_confidence_count": 1,
    "label_count": 1,
    "normalized_10_match_count": 0,
    "normalized_11_match_count": 0,
    "source_counterpart_count": 0,
    "target_code_caller_count": 0,
    "target_default_name_count": 0,
    "target_only_count": 1,
}
EXPECTED_NAME_ORIGINS = {
    "ida_named_or_other": 4052,
    "target_jni_export": 7,
    "target_named_export": 788,
    "target_only_descriptive": 420,
    "translated_v18_alias": 6440,
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
        "item_name_match": 1676,
        "item_name_mismatch": 5094,
        "value_name_match": 1676,
        "value_name_mismatch": 5094,
    },
    "named_dynamic_symbol_count": 6770,
    "status_counts": {
        "exact_retained_dynamic_name": 1676,
        "linker_boundary_alias_mismatch": 7,
        "other_retained_target_name": 119,
        "source_backed_v18_alias": 4795,
        "target_only_descriptive": 3,
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
    "ambiguous_functions": 1015,
    "mapped_functions": 3721,
    "mapped_high_confidence": 3661,
    "mapped_medium_confidence": 60,
    "original_functions": 11308,
    "spectron_functions": 11707,
    "unique_spectron_targets": 3721,
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
    require(parent["database"]["sha256"] == EXPECTED_PARENT_DATABASE_SHA256, "parent database hash is not v345")
    require(labels.get("artifact") == EXPECTED_LABEL_ARTIFACT, "unexpected resource path helper label artifact")
    require(labels.get("network_contacted") is False, "resource path helper labels contacted the network")
    require(labels.get("summary") == EXPECTED_LABEL_SUMMARY, "resource path helper label summary changed")
    require(
        [row["proposed_name"] for row in labels["labels"]]
        == ["spectron_TResourceFunctions_resolveResourcePath_TString_const_bool"],
        "resource path helper label changed",
    )
    require(
        [row["target_ea"] for row in labels["labels"]] == ["0xefbcc"],
        "resource path helper target address changed",
    )
    require(
        application.get("apply")
        and application.get("expected_artifact") == EXPECTED_LABEL_ARTIFACT
        and application.get("label_count") == 1
        and application.get("resolved_count") == 1
        and application.get("renamed_count") == 1
        and application.get("comments_added") == 1
        and application.get("failure_count") == 0
        and application.get("saved"),
        "resource path helper label application did not pass",
    )
    require(
        verification.get("artifact") == "spectron_target_only_label_reopen_verification"
        and verification.get("verified")
        and verification.get("expected_artifact") == EXPECTED_LABEL_ARTIFACT
        and verification.get("label_count") == 1
        and verification.get("verified_name_count") == 1
        and verification.get("failure_count") == 0,
        "resource path helper label reopen verification did not pass",
    )
    require(
        name_audit.get("network_contacted") is False
        and name_audit.get("input_sha256") == EXPECTED_BINARY_SHA256
        and name_audit.get("function_count") == 11707
        and name_audit.get("default_name_count") == 0
        and name_audit.get("name_origins") == EXPECTED_NAME_ORIGINS,
        "v346 name audit changed",
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
        "v346 dynamic boundary audit changed",
    )
    require(
        dynamic_coverage.get("network_contacted") is False
        and dynamic_coverage.get("input_sha256") == EXPECTED_BINARY_SHA256
        and dynamic_coverage.get("summary") == EXPECTED_DYNAMIC_SUMMARY,
        "v346 dynamic symbol coverage changed",
    )
    require(
        semantic_map.get("network_contacted") is False
        and semantic_map.get("summary") == EXPECTED_SEMANTIC_SUMMARY
        and semantic_map.get("carried_forward", {}).get("target_feature_count") == 11707,
        "v346 semantic map changed",
    )
    require(
        feature_export.get("artifact") == "ida_function_features"
        and feature_export.get("network_contacted") is False
        and feature_export.get("function_count") == 11707,
        "v346 feature export changed",
    )
    require(args.database.is_file(), "database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == EXPECTED_DATABASE_SHA256, "v346 database hash changed")

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
        "v346_resource_path_helper_label_artifact": str(args.label_artifact),
        "v346_resource_path_helper_label_artifact_sha256": sha256_path(args.label_artifact),
        "v346_resource_path_helper_application_report": str(args.application_report),
        "v346_resource_path_helper_application_report_sha256": sha256_path(args.application_report),
        "v346_resource_path_helper_verification_report": str(args.verification_report),
        "v346_resource_path_helper_verification_report_sha256": sha256_path(args.verification_report),
        "v346_name_audit": str(args.name_audit),
        "v346_name_audit_sha256": sha256_path(args.name_audit),
        "v346_boundary_audit": str(args.boundary_audit),
        "v346_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v346_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v346_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        "v346_semantic_map": str(args.semantic_map),
        "v346_semantic_map_sha256": sha256_path(args.semantic_map),
        "v346_feature_export": str(args.feature_export),
        "v346_feature_export_sha256": sha256_path(args.feature_export),
    }
    result["resource_path_helper_target_only_v346"] = {
        "label_artifact": str(args.label_artifact),
        "label_artifact_sha256": sha256_path(args.label_artifact),
        "application_report": str(args.application_report),
        "application_report_sha256": sha256_path(args.application_report),
        "verification_report": str(args.verification_report),
        "verification_report_sha256": sha256_path(args.verification_report),
        "label_count": labels["summary"]["label_count"],
        "high_confidence_count": labels["summary"]["high_confidence_count"],
        "source_counterpart_count": labels["summary"]["source_counterpart_count"],
        "exact_metric_match_count": labels["summary"]["exact_metric_match_count"],
        "normalized_11_match_count": labels["summary"]["normalized_11_match_count"],
        "normalized_10_match_count": labels["summary"]["normalized_10_match_count"],
        "target_code_caller_count": labels["summary"]["target_code_caller_count"],
        "reopen_verified": verification["verified"],
    }
    result["name_coverage_audit_v346"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["dynamic_function_boundary_audit_v346"] = {
        "artifact_path": str(args.boundary_audit),
        "artifact_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
    }
    result["dynamic_symbol_coverage_audit_v346"] = {
        "artifact_path": str(args.dynamic_symbol_coverage),
        "artifact_sha256": sha256_path(args.dynamic_symbol_coverage),
        "summary": dynamic_coverage["summary"],
    }
    result["semantic_function_translation_v346"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
        "carried_forward": semantic_map["carried_forward"],
        "source_backed_translation_change": False,
        "target_only_label_change": True,
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v346 pass adds one high-confidence target-only descriptive label for the exported resource path, update, and download helper at 0xefbcc. It does not add a source-backed alias because the target already has a separate getGameFile correspondence at 0xefe78."
    )
    result["interpretation"].append(
        "The label changes one dynamic symbol from exact retained target naming to target-only descriptive naming. Function count, source-backed semantic coverage, and exact IDA dynamic boundaries remain unchanged."
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "database_sha256": database_sha256,
                "function_count": result["database"]["function_count"],
                "target_only_label_count": labels["summary"]["target_only_count"],
                "target_only_dynamic_symbols": dynamic_coverage["summary"]["status_counts"]["target_only_descriptive"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
