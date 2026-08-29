#!/usr/bin/env python3
"""Create the v329 checkpoint for the residual TScriptSpace pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260829_v329"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v328"
EXPECTED_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
EXPECTED_PARENT_DATABASE_SHA256 = "01e5dc66c7446c46101a09486f23c1a86822e9973b57b5897fa93a4d1f11526a"
EXPECTED_DATABASE_SHA256 = "c84c8bd4abe51302092c82db16003712e870b0ed8a541a9417f6c563f540b6ee"


def load(path: Path):
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
    parser.add_argument("--label-artifact", required=True, type=Path)
    parser.add_argument("--label-application-report", required=True, type=Path)
    parser.add_argument("--label-verification-report", required=True, type=Path)
    parser.add_argument("--name-audit", required=True, type=Path)
    parser.add_argument("--boundary-audit", required=True, type=Path)
    parser.add_argument("--dynamic-symbol-coverage", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--feature-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    anchors = load(args.anchor_artifact)
    application = load(args.application_report)
    verification = load(args.verification_report)
    labels = load(args.label_artifact)
    label_application = load(args.label_application_report)
    label_verification = load(args.label_verification_report)
    name_audit = load(args.name_audit)
    boundary = load(args.boundary_audit)
    dynamic_coverage = load(args.dynamic_symbol_coverage)
    semantic_map = load(args.semantic_map)
    feature_export = load(args.feature_export)

    require(parent.get("artifact") == PARENT_ARTIFACT, "unexpected parent checkpoint")
    require(parent["database"]["sha256"] == EXPECTED_PARENT_DATABASE_SHA256, "parent database hash is not v328")
    require(anchors.get("artifact") == "spectron_tscript_space_residual_manual_translation_anchors_20260829", "unexpected residual anchor artifact")
    require(anchors.get("network_contacted") is False, "residual anchors contacted the network")
    require(
        anchors.get("summary")
        == {
            "anchor_count": 2,
            "exact_metric_anchor_count": 1,
            "high_confidence_count": 2,
            "layout_change_anchor_count": 1,
            "new_context_anchor_count": 1,
            "semantic_promotion_count": 1,
            "source_pseudocode_count": 2,
            "target_pseudocode_count": 2,
        },
        "residual anchor summary changed",
    )
    require(
        [row["proposed_name"] for row in anchors["anchors"]]
        == [
            "v18_TScriptSpace_freeSuspendedStates_void",
            "v18_TScriptSpace_joinClass_TString_const_bool",
        ],
        "residual source alias order changed",
    )
    require(
        [row["spectron_ea"] for row in anchors["anchors"]]
        == ["0x230198", "0x233114"],
        "residual source target order changed",
    )
    require(
        application.get("apply")
        and application.get("expected_artifact") == anchors["artifact"]
        and application.get("anchor_count") == 2
        and application.get("resolved_count") == 2
        and application.get("renamed_count") == 2
        and application.get("comments_added") == 2
        and application.get("failure_count") == 0
        and application.get("saved")
        and application.get("verified")
        and application.get("verified_name_count") == 2,
        "residual source alias application did not pass",
    )
    require(
        verification.get("verified")
        and verification.get("expected_artifact") == anchors["artifact"]
        and verification.get("anchor_count") == 2
        and verification.get("verified_name_count") == 2
        and verification.get("failure_count") == 0
        and verification.get("function_count") == 11707,
        "residual source alias reopen verification did not pass",
    )
    require(labels.get("artifact") == "spectron_tscript_space_residual_labels_20260829", "unexpected residual label artifact")
    require(labels.get("network_contacted") is False, "residual labels contacted the network")
    require(
        labels.get("summary")
        == {
            "high_confidence_count": 2,
            "label_count": 2,
            "source_counterpart_count": 0,
            "target_default_name_count": 0,
            "target_only_count": 2,
        },
        "residual label summary changed",
    )
    require(
        [row["proposed_name"] for row in labels["labels"]]
        == [
            "spectron_TScriptSpace_receiveEvent_TString_const_CanTfaz6bZ_const_TGraalVar",
            "spectron_TScriptSpace_clearScheduledEventsAndCancelActions_void",
        ],
        "residual target-only label order changed",
    )
    require(
        label_application.get("apply")
        and label_application.get("expected_artifact") == labels["artifact"]
        and label_application.get("label_count") == 2
        and label_application.get("resolved_count") == 2
        and label_application.get("renamed_count") == 2
        and label_application.get("failure_count") == 0
        and label_application.get("saved"),
        "residual target-only label application did not pass",
    )
    require(
        label_verification.get("verified")
        and label_verification.get("expected_artifact") == labels["artifact"]
        and label_verification.get("label_count") == 2
        and label_verification.get("verified_name_count") == 2
        and label_verification.get("failure_count") == 0,
        "residual target-only label reopen verification did not pass",
    )
    require(
        name_audit.get("network_contacted") is False
        and name_audit.get("input_sha256") == EXPECTED_BINARY_SHA256
        and name_audit.get("function_count") == 11707
        and name_audit.get("default_name_count") == 0
        and name_audit.get("name_origins")
        == {
            "ida_named_or_other": 4053,
            "target_jni_export": 7,
            "target_named_export": 894,
            "target_only_descriptive": 419,
            "translated_v18_alias": 6334,
        },
        "v329 name audit changed",
    )
    require(
        boundary.get("network_contacted") is False
        and boundary.get("input_sha256") == EXPECTED_BINARY_SHA256
        and boundary.get("defined_function_symbol_count") == 5782
        and boundary.get("ida_exact_start_count") == 5782
        and boundary.get("ida_missing_exact_start_count") == 0
        and len(boundary.get("rows", [])) == 5782,
        "v329 dynamic boundary audit changed",
    )
    require(
        dynamic_coverage.get("network_contacted") is False
        and dynamic_coverage.get("input_sha256") == EXPECTED_BINARY_SHA256
        and dynamic_coverage.get("summary")
        == {
            "defined_named_symbol_count": 6600,
            "location_counts": {
                "ida_data_item": 482,
                "ida_function_exact": 5782,
                "ida_noncode_item": 336,
                "undefined_or_zero_value": 170,
            },
            "name_match_counts": {
                "item_name_match": 1782,
                "item_name_mismatch": 4988,
                "value_name_match": 1782,
                "value_name_mismatch": 4988,
            },
            "named_dynamic_symbol_count": 6770,
            "status_counts": {
                "exact_retained_dynamic_name": 1782,
                "linker_boundary_alias_mismatch": 7,
                "other_retained_target_name": 136,
                "source_backed_v18_alias": 4673,
                "target_only_descriptive": 2,
                "undefined_import_with_plt_stub": 169,
                "undefined_no_target_address": 1,
            },
        },
        "v329 dynamic symbol coverage changed",
    )
    require(
        semantic_map.get("network_contacted") is False
        and semantic_map.get("summary")
        == {
            "ambiguous_functions": 1020,
            "mapped_functions": 3716,
            "mapped_high_confidence": 3656,
            "mapped_medium_confidence": 60,
            "original_functions": 11308,
            "spectron_functions": 11707,
            "unique_spectron_targets": 3716,
            "unmatched_functions": 608,
        },
        "v329 semantic map changed",
    )
    require(feature_export.get("function_count") == 11707, "v329 feature export count changed")
    require(args.database.is_file(), "database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == EXPECTED_DATABASE_SHA256, "v329 database hash changed")

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
        "v329_tscript_space_residual_anchor_artifact": str(args.anchor_artifact),
        "v329_tscript_space_residual_anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "v329_tscript_space_residual_application_report": str(args.application_report),
        "v329_tscript_space_residual_application_report_sha256": sha256_path(args.application_report),
        "v329_tscript_space_residual_verification_report": str(args.verification_report),
        "v329_tscript_space_residual_verification_report_sha256": sha256_path(args.verification_report),
        "v329_tscript_space_residual_label_artifact": str(args.label_artifact),
        "v329_tscript_space_residual_label_artifact_sha256": sha256_path(args.label_artifact),
        "v329_tscript_space_residual_label_application_report": str(args.label_application_report),
        "v329_tscript_space_residual_label_application_report_sha256": sha256_path(args.label_application_report),
        "v329_tscript_space_residual_label_verification_report": str(args.label_verification_report),
        "v329_tscript_space_residual_label_verification_report_sha256": sha256_path(args.label_verification_report),
        "v329_name_audit": str(args.name_audit),
        "v329_name_audit_sha256": sha256_path(args.name_audit),
        "v329_boundary_audit": str(args.boundary_audit),
        "v329_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v329_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v329_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        "v329_semantic_map": str(args.semantic_map),
        "v329_semantic_map_sha256": sha256_path(args.semantic_map),
        "v329_feature_export": str(args.feature_export),
        "v329_feature_export_sha256": sha256_path(args.feature_export),
    }
    result["tscript_space_residual_translation_v329"] = {
        "anchor_artifact": str(args.anchor_artifact),
        "anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "application_report": str(args.application_report),
        "application_report_sha256": sha256_path(args.application_report),
        "verification_report": str(args.verification_report),
        "verification_report_sha256": sha256_path(args.verification_report),
        "anchor_count": anchors["summary"]["anchor_count"],
        "high_confidence_count": anchors["summary"]["high_confidence_count"],
        "exact_metric_anchor_count": anchors["summary"]["exact_metric_anchor_count"],
        "layout_change_anchor_count": anchors["summary"]["layout_change_anchor_count"],
        "semantic_promotion_count": anchors["summary"]["semantic_promotion_count"],
        "reopen_verified": verification["verified"],
    }
    result["tscript_space_residual_target_only_labels_v329"] = {
        "label_artifact": str(args.label_artifact),
        "label_artifact_sha256": sha256_path(args.label_artifact),
        "application_report": str(args.label_application_report),
        "application_report_sha256": sha256_path(args.label_application_report),
        "verification_report": str(args.label_verification_report),
        "verification_report_sha256": sha256_path(args.label_verification_report),
        "label_count": labels["summary"]["label_count"],
        "high_confidence_count": labels["summary"]["high_confidence_count"],
        "reopen_verified": label_verification["verified"],
    }
    result["name_coverage_audit_v329"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["dynamic_function_boundary_audit_v329"] = {
        "artifact_path": str(args.boundary_audit),
        "artifact_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
    }
    result["dynamic_symbol_coverage_audit_v329"] = {
        "artifact_path": str(args.dynamic_symbol_coverage),
        "artifact_sha256": sha256_path(args.dynamic_symbol_coverage),
        "summary": dynamic_coverage["summary"],
    }
    result["semantic_function_translation_v329"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v329 pass adds two reviewed TScriptSpace source aliases. ilmTfbBpbZ is an exact normalized match for freeSuspendedStates, while NIyWfarPS0 is a layout-change match for joinClass with a boolean argument."
    )
    result["interpretation"].append(
        "The same target class also exposes a receiveEvent overload taking a CanTfaz6bZ event name and a no-argument cleanup helper that clears scheduled events and marks pending actions canceled. Both receive descriptive spectron_ labels and remain outside the source mapping count because no distinct 1.8 source boundary was established."
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "database_sha256": database_sha256,
                "function_count": result["database"]["function_count"],
                "anchor_count": anchors["summary"]["anchor_count"],
                "target_only_label_count": labels["summary"]["label_count"],
                "source_backed_dynamic_symbols": dynamic_coverage["summary"]["status_counts"]["source_backed_v18_alias"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
