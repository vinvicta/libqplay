#!/usr/bin/env python3
"""Create the v332 checkpoint for the residual TPanelOperation pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260829_v332"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v331"
EXPECTED_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
EXPECTED_PARENT_DATABASE_SHA256 = "f6bb72c43b0022b372d6d98e4143aa920a7e3c43cd5a89ede10e7510cd00178c"
EXPECTED_DATABASE_SHA256 = "f77edbe5076211bd3bd5a18c549f0c3cbaeeb88d2da7bc9c52a2733c1d87cdc2"
EXPECTED_ANCHOR_ARTIFACT = "spectron_paneloperation_residual_manual_translation_anchors_20260829"
EXPECTED_ANCHOR_SUMMARY = {
    "anchor_count": 20,
    "exact_metric_anchor_count": 13,
    "high_confidence_count": 20,
    "layout_change_anchor_count": 7,
    "new_context_anchor_count": 17,
    "semantic_promotion_count": 3,
    "source_pseudocode_count": 20,
    "target_pseudocode_count": 20,
}
EXPECTED_ALIASES = [
    "v18_TPanelOperation_Clear_getBounds_void",
    "v18_TPanelOperation_DrawCurve_getBounds_void",
    "v18_TPanelOperation_DrawStretched_getBounds_void",
    "v18_TPanelOperation_DrawLine_getBounds_void",
    "v18_TPanelOperation_DrawText_getBounds_void",
    "v18_TPanelOperation_DrawLine_TPanelOperation_DrawLine",
    "v18_TPanelOperation_DrawCurve_TPanelOperation_DrawCurve",
    "v18_TPanelOperation_Clear_TPanelOperation_Clear",
    "v18_TPanelOperation_DrawLine_TPanelOperation_DrawLine__2",
    "v18_TPanelOperation_DrawCurve_TPanelOperation_DrawCurve__2",
    "v18_TPanelOperation_Clear_TPanelOperation_Clear__2",
    "v18_TDrawingPanelProperties_TDrawingPanelProperties",
    "v18_non_virtual_thunk_to_TDrawingPanelProperties_TDrawingPanelProperties",
    "v18_TDrawingPanelProperties_TDrawingPanelProperties__2",
    "v18_non_virtual_thunk_to_TDrawingPanelProperties_TDrawingPanelProperties__2",
    "v18_TPanelOperation_DrawRectangle_TPanelOperation_DrawRectangle",
    "v18_TPanelOperation_DrawRectangle_TPanelOperation_DrawRectangle__2",
    "v18_TPanelOperation_DrawStretched_TPanelOperation_DrawStretched",
    "v18_TPanelOperation_DrawStretched_TPanelOperation_DrawStretched__2",
    "v18_TPanelOperation_DrawImage_TPanelOperation_DrawImage__2",
]
EXPECTED_TARGETS = [
    "0x11d318",
    "0x11d344",
    "0x11d3d4",
    "0x11d400",
    "0x11d464",
    "0x11d47c",
    "0x11d480",
    "0x11d484",
    "0x11d530",
    "0x11d534",
    "0x11d538",
    "0x11d4cc",
    "0x11d4e8",
    "0x11d4f0",
    "0x11d528",
    "0x11d5ec",
    "0x11d600",
    "0x11d630",
    "0x11d644",
    "0x11d688",
]
EXPECTED_NAME_ORIGINS = {
    "ida_named_or_other": 4052,
    "target_jni_export": 7,
    "target_named_export": 847,
    "target_only_descriptive": 419,
    "translated_v18_alias": 6382,
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
        "item_name_match": 1735,
        "item_name_mismatch": 5035,
        "value_name_match": 1735,
        "value_name_mismatch": 5035,
    },
    "named_dynamic_symbol_count": 6770,
    "status_counts": {
        "exact_retained_dynamic_name": 1735,
        "linker_boundary_alias_mismatch": 7,
        "other_retained_target_name": 124,
        "source_backed_v18_alias": 4732,
        "target_only_descriptive": 2,
        "undefined_import_with_plt_stub": 169,
        "undefined_no_target_address": 1,
    },
}
EXPECTED_SEMANTIC_SUMMARY = {
    "ambiguous_functions": 1020,
    "mapped_functions": 3716,
    "mapped_high_confidence": 3656,
    "mapped_medium_confidence": 60,
    "original_functions": 11308,
    "spectron_functions": 11707,
    "unique_spectron_targets": 3716,
    "unmatched_functions": 608,
}


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
    name_audit = load(args.name_audit)
    boundary = load(args.boundary_audit)
    dynamic_coverage = load(args.dynamic_symbol_coverage)
    semantic_map = load(args.semantic_map)
    feature_export = load(args.feature_export)

    require(parent.get("artifact") == PARENT_ARTIFACT, "unexpected parent checkpoint")
    require(parent["database"]["sha256"] == EXPECTED_PARENT_DATABASE_SHA256, "parent database hash is not v331")
    require(anchors.get("artifact") == EXPECTED_ANCHOR_ARTIFACT, "unexpected TPanelOperation anchor artifact")
    require(anchors.get("network_contacted") is False, "TPanelOperation anchors contacted the network")
    require(anchors.get("summary") == EXPECTED_ANCHOR_SUMMARY, "TPanelOperation anchor summary changed")
    require([row["proposed_name"] for row in anchors["anchors"]] == EXPECTED_ALIASES, "TPanelOperation alias order changed")
    require([row["spectron_ea"] for row in anchors["anchors"]] == EXPECTED_TARGETS, "TPanelOperation target order changed")
    require(
        application.get("apply")
        and application.get("expected_artifact") == EXPECTED_ANCHOR_ARTIFACT
        and application.get("anchor_count") == 20
        and application.get("resolved_count") == 20
        and application.get("renamed_count") == 20
        and application.get("comments_added") == 20
        and application.get("failure_count") == 0
        and application.get("saved")
        and application.get("verified")
        and application.get("verified_name_count") == 20,
        "TPanelOperation alias application did not pass",
    )
    require(
        verification.get("verified")
        and verification.get("expected_artifact") == EXPECTED_ANCHOR_ARTIFACT
        and verification.get("anchor_count") == 20
        and verification.get("verified_name_count") == 20
        and verification.get("failure_count") == 0
        and verification.get("artifact") == "spectron_manual_anchor_reopen_verification"
        and verification.get("function_count") == 11707,
        "TPanelOperation alias reopen verification did not pass",
    )
    require(
        name_audit.get("network_contacted") is False
        and name_audit.get("input_sha256") == EXPECTED_BINARY_SHA256
        and name_audit.get("function_count") == 11707
        and name_audit.get("default_name_count") == 0
        and name_audit.get("name_origins") == EXPECTED_NAME_ORIGINS,
        "v332 name audit changed",
    )
    require(
        boundary.get("network_contacted") is False
        and boundary.get("input_sha256") == EXPECTED_BINARY_SHA256
        and boundary.get("defined_function_symbol_count") == 5782
        and boundary.get("ida_exact_start_count") == 5782
        and boundary.get("ida_missing_exact_start_count") == 0
        and len(boundary.get("rows", [])) == 5782,
        "v332 dynamic boundary audit changed",
    )
    require(
        dynamic_coverage.get("network_contacted") is False
        and dynamic_coverage.get("input_sha256") == EXPECTED_BINARY_SHA256
        and dynamic_coverage.get("summary") == EXPECTED_DYNAMIC_SUMMARY,
        "v332 dynamic symbol coverage changed",
    )
    require(
        semantic_map.get("network_contacted") is False
        and semantic_map.get("summary") == EXPECTED_SEMANTIC_SUMMARY
        and semantic_map.get("carried_forward", {}).get("target_feature_count") == 11707,
        "v332 semantic map changed",
    )
    require(feature_export.get("function_count") == 11707, "v332 feature export count changed")
    require(args.database.is_file(), "database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == EXPECTED_DATABASE_SHA256, "v332 database hash changed")

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
        "v332_paneloperation_anchor_artifact": str(args.anchor_artifact),
        "v332_paneloperation_anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "v332_paneloperation_application_report": str(args.application_report),
        "v332_paneloperation_application_report_sha256": sha256_path(args.application_report),
        "v332_paneloperation_verification_report": str(args.verification_report),
        "v332_paneloperation_verification_report_sha256": sha256_path(args.verification_report),
        "v332_name_audit": str(args.name_audit),
        "v332_name_audit_sha256": sha256_path(args.name_audit),
        "v332_boundary_audit": str(args.boundary_audit),
        "v332_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v332_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v332_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        "v332_semantic_map": str(args.semantic_map),
        "v332_semantic_map_sha256": sha256_path(args.semantic_map),
        "v332_feature_export": str(args.feature_export),
        "v332_feature_export_sha256": sha256_path(args.feature_export),
    }
    result["paneloperation_residual_translation_v332"] = {
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
        "new_context_anchor_count": anchors["summary"]["new_context_anchor_count"],
        "semantic_promotion_count": anchors["summary"]["semantic_promotion_count"],
        "reopen_verified": verification["verified"],
    }
    result["name_coverage_audit_v332"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["dynamic_function_boundary_audit_v332"] = {
        "artifact_path": str(args.boundary_audit),
        "artifact_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
    }
    result["dynamic_symbol_coverage_audit_v332"] = {
        "artifact_path": str(args.dynamic_symbol_coverage),
        "artifact_sha256": sha256_path(args.dynamic_symbol_coverage),
        "summary": dynamic_coverage["summary"],
    }
    result["semantic_function_translation_v332"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
        "carried_forward": semantic_map["carried_forward"],
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v332 pass adds 20 reviewed aliases for the residual TPanelOperation bounds methods, operation destructor boundaries, and TDrawingPanelProperties cleanup family."
    )
    result["interpretation"].append(
        "Thirteen rows are exact normalized feature matches, while seven differ only in register-detail allocation after obfuscation. Every row has direct source and target Hex-Rays pseudocode."
    )
    result["interpretation"].append(
        "The function-level semantic map is carried forward from v331 because the current IDALIB source export reports 11,297 functions instead of the reviewed 11,308-function source snapshot. v332 changes target names only, so the carry-forward avoids presenting exporter drift as a semantic regression."
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
                "source_backed_dynamic_symbols": dynamic_coverage["summary"]["status_counts"]["source_backed_v18_alias"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
