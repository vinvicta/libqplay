#!/usr/bin/env python3
"""Create the v328 checkpoint after the TScriptMachine static-tail pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260829_v328"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v327"
EXPECTED_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
EXPECTED_PARENT_DATABASE_SHA256 = "cc731360c7c08f825a7905c760897d3a7aede1dccdb4322d56d72f5c2e0c2f13"
EXPECTED_DATABASE_SHA256 = "01e5dc66c7446c46101a09486f23c1a86822e9973b57b5897fa93a4d1f11526a"


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
    require(parent["database"]["sha256"] == EXPECTED_PARENT_DATABASE_SHA256, "parent database hash is not v327")
    require(
        anchors.get("artifact") == "spectron_script_machine_static_tail_manual_translation_anchors_20260829",
        "unexpected static-tail anchor artifact",
    )
    require(anchors.get("network_contacted") is False, "static-tail anchors contacted the network")
    require(
        anchors.get("summary")
        == {
            "anchor_count": 2,
            "exact_metric_anchor_count": 1,
            "high_confidence_count": 2,
            "layout_change_anchor_count": 1,
            "new_context_anchor_count": 2,
            "source_pseudocode_count": 2,
            "target_pseudocode_count": 2,
        },
        "static-tail anchor summary changed",
    )
    require(
        [row["proposed_name"] for row in anchors["anchors"]]
        == [
            "v18_TScriptMachine_initStaticScriptVars_void",
            "v18_TCallStackEntry_TCallStackEntry__2",
        ],
        "static-tail alias order changed",
    )
    require(
        [row["spectron_ea"] for row in anchors["anchors"]]
        == ["0x227780", "0x227808"],
        "static-tail target order changed",
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
        and application.get("verified"),
        "static-tail application did not pass",
    )
    require(
        verification.get("verified")
        and verification.get("expected_artifact") == anchors["artifact"]
        and verification.get("anchor_count") == 2
        and verification.get("verified_name_count") == 2
        and verification.get("failure_count") == 0
        and verification.get("function_count") == 11707,
        "static-tail reopen verification did not pass",
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
            "target_named_export": 898,
            "target_only_descriptive": 417,
            "translated_v18_alias": 6332,
        },
        "v328 name audit changed",
    )
    require(
        boundary.get("network_contacted") is False
        and boundary.get("input_sha256") == EXPECTED_BINARY_SHA256
        and boundary.get("defined_function_symbol_count") == 5782
        and boundary.get("ida_exact_start_count") == 5782
        and boundary.get("ida_missing_exact_start_count") == 0
        and len(boundary.get("rows", [])) == 5782,
        "v328 dynamic boundary audit changed",
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
                "item_name_match": 1786,
                "item_name_mismatch": 4984,
                "value_name_match": 1786,
                "value_name_mismatch": 4984,
            },
            "named_dynamic_symbol_count": 6770,
            "status_counts": {
                "exact_retained_dynamic_name": 1786,
                "linker_boundary_alias_mismatch": 7,
                "other_retained_target_name": 136,
                "source_backed_v18_alias": 4671,
                "undefined_import_with_plt_stub": 169,
                "undefined_no_target_address": 1,
            },
        },
        "v328 dynamic coverage changed",
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
        "v328 semantic map changed",
    )
    require(feature_export.get("function_count") == 11707, "v328 feature export count changed")
    require(args.database.is_file(), "database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == EXPECTED_DATABASE_SHA256, "v328 database hash changed")

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
        "v328_script_machine_static_tail_anchor_artifact": str(args.anchor_artifact),
        "v328_script_machine_static_tail_anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "v328_script_machine_static_tail_application_report": str(args.application_report),
        "v328_script_machine_static_tail_application_report_sha256": sha256_path(args.application_report),
        "v328_script_machine_static_tail_verification_report": str(args.verification_report),
        "v328_script_machine_static_tail_verification_report_sha256": sha256_path(args.verification_report),
        "v328_name_audit": str(args.name_audit),
        "v328_name_audit_sha256": sha256_path(args.name_audit),
        "v328_boundary_audit": str(args.boundary_audit),
        "v328_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v328_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v328_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        "v328_semantic_map": str(args.semantic_map),
        "v328_semantic_map_sha256": sha256_path(args.semantic_map),
        "v328_feature_export": str(args.feature_export),
        "v328_feature_export_sha256": sha256_path(args.feature_export),
    }
    result["script_machine_static_tail_translation_v328"] = {
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
        "source_pseudocode_count": anchors["summary"]["source_pseudocode_count"],
        "target_pseudocode_count": anchors["summary"]["target_pseudocode_count"],
        "reopen_verified": verification["verified"],
    }
    result["name_coverage_audit_v328"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["dynamic_function_boundary_audit_v328"] = {
        "artifact_path": str(args.boundary_audit),
        "artifact_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
    }
    result["dynamic_symbol_coverage_audit_v328"] = {
        "artifact_path": str(args.dynamic_symbol_coverage),
        "artifact_sha256": sha256_path(args.dynamic_symbol_coverage),
        "summary": dynamic_coverage["summary"],
    }
    result["semantic_function_translation_v328"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v328 pass adds two high-confidence TScriptMachine static-tail aliases. The DgaM1aDf85 helper is a layout-change match for TScriptMachine_initStaticScriptVars_void because the target allocates a larger rebuilt property object, while the l8eTfaIl5Y deleting destructor is an exact normalized match for TCallStackEntry_TCallStackEntry__2."
    )
    result["interpretation"].append(
        "The nearby mTAogaaEip C8THgaTQxF overload at 0x221928 is a target string-wrapper adapter around the already translated CanTfaz6bZ resolver. It remains outside the source-backed alias count until a distinct 1.8 function boundary is established."
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
