#!/usr/bin/env python3
"""Create the v325 checkpoint after the remaining TScript destructor pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260829_v325"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260829_v324"
EXPECTED_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
EXPECTED_PARENT_DATABASE_SHA256 = "975367646c22c2f21d1c7ffc8380e0b48a6c259864a1f8b192e043c3e0992e06"
EXPECTED_DATABASE_SHA256 = "229e4729eed1be2759935c1604ac6e3987ffe6fbe91c2b5a0dca16ae344c0757"


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

    require(parent.get("artifact") == PARENT_ARTIFACT, "unexpected parent checkpoint")
    require(parent["database"]["sha256"] == EXPECTED_PARENT_DATABASE_SHA256, "parent database hash is not v324")
    require(
        anchors.get("artifact") == "spectron_tscript_destructor_manual_translation_anchors_20260829",
        "unexpected TScript destructor anchor artifact",
    )
    require(
        anchors.get("network_contacted") is False,
        "TScript destructor anchor artifact contacted the network",
    )
    require(
        anchors.get("summary")
        == {
            "anchor_count": 8,
            "exact_metric_anchor_count": 3,
            "high_confidence_count": 8,
            "layout_change_anchor_count": 5,
            "new_context_anchor_count": 8,
            "source_pseudocode_count": 8,
            "target_pseudocode_count": 8,
        },
        "TScript destructor anchor summary changed",
    )
    require(
        application.get("apply")
        and application.get("expected_artifact") == anchors["artifact"]
        and application.get("anchor_count") == 8
        and application.get("resolved_count") == 8
        and application.get("renamed_count") == 8
        and application.get("comments_added") == 8
        and application.get("failure_count") == 0
        and application.get("saved")
        and application.get("verified"),
        "TScript destructor application did not pass",
    )
    require(
        verification.get("verified")
        and verification.get("expected_artifact") == anchors["artifact"]
        and verification.get("anchor_count") == 8
        and verification.get("verified_name_count") == 8
        and verification.get("failure_count") == 0
        and verification.get("function_count") == 11707,
        "TScript destructor reopen verification did not pass",
    )
    require(
        name_audit.get("input_sha256") == EXPECTED_BINARY_SHA256
        and name_audit.get("function_count") == 11707
        and name_audit.get("default_name_count") == 0
        and name_audit.get("name_origins")
        == {
            "ida_named_or_other": 4053,
            "target_jni_export": 7,
            "target_named_export": 935,
            "target_only_descriptive": 417,
            "translated_v18_alias": 6295,
        },
        "v325 name audit changed",
    )
    require(
        boundary.get("input_sha256") == EXPECTED_BINARY_SHA256
        and boundary.get("defined_function_symbol_count") == 5782
        and boundary.get("ida_exact_start_count") == 5782
        and boundary.get("ida_missing_exact_start_count") == 0,
        "v325 dynamic boundary audit changed",
    )
    require(dynamic_coverage.get("input_sha256") == EXPECTED_BINARY_SHA256, "v325 dynamic coverage hash changed")
    require(
        dynamic_coverage["summary"]
        == {
            "defined_named_symbol_count": 6600,
            "location_counts": {
                "ida_data_item": 482,
                "ida_function_exact": 5782,
                "ida_noncode_item": 336,
                "undefined_or_zero_value": 170,
            },
            "name_match_counts": {
                "item_name_match": 1823,
                "item_name_mismatch": 4947,
                "value_name_match": 1823,
                "value_name_mismatch": 4947,
            },
            "named_dynamic_symbol_count": 6770,
            "status_counts": {
                "exact_retained_dynamic_name": 1823,
                "linker_boundary_alias_mismatch": 7,
                "other_retained_target_name": 146,
                "source_backed_v18_alias": 4624,
                "undefined_import_with_plt_stub": 169,
                "undefined_no_target_address": 1,
            },
        },
        "v325 dynamic coverage counts changed",
    )
    require(
        semantic_map.get("summary", {}).get("mapped_functions") == 3716
        and semantic_map.get("summary", {}).get("mapped_high_confidence") == 3656,
        "v320 semantic map count changed",
    )
    require(args.database.is_file(), "database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == EXPECTED_DATABASE_SHA256, "v325 database hash changed")

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
        "v325_tscript_destructor_anchor_artifact": str(args.anchor_artifact),
        "v325_tscript_destructor_anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "v325_tscript_destructor_application_report": str(args.application_report),
        "v325_tscript_destructor_application_report_sha256": sha256_path(args.application_report),
        "v325_tscript_destructor_verification_report": str(args.verification_report),
        "v325_tscript_destructor_verification_report_sha256": sha256_path(args.verification_report),
        "v325_name_audit": str(args.name_audit),
        "v325_name_audit_sha256": sha256_path(args.name_audit),
        "v325_boundary_audit": str(args.boundary_audit),
        "v325_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v325_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v325_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        "v325_semantic_map": str(args.semantic_map),
        "v325_semantic_map_sha256": sha256_path(args.semantic_map),
    }
    result["tscript_destructor_translation_v325"] = {
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
    result["name_coverage_audit_v325"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["dynamic_function_boundary_audit_v325"] = {
        "artifact_path": str(args.boundary_audit),
        "artifact_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
    }
    result["dynamic_symbol_coverage_audit_v325"] = {
        "artifact_path": str(args.dynamic_symbol_coverage),
        "artifact_sha256": sha256_path(args.dynamic_symbol_coverage),
        "summary": dynamic_coverage["summary"],
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v325 pass adds eight high-confidence TScript, TScriptFunctionProperties, and TFunctionProfile destructor-family aliases. Three rows retain exact normalized metrics, while five record rebuilt-string or register-detail changes."
    )
    result["interpretation"].append(
        "The v325 database contains 6,295 reviewed v18 aliases and no audited default function names. The target keeps the same 5,782 exact dynamic-function boundaries; the destructor aliases are semantic translations rather than claims that stripped debug metadata was restored."
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
