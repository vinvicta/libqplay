#!/usr/bin/env python3
"""Create the v321 checkpoint after the GUI boundary translation pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v321"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v320"
EXPECTED_ORIGINAL_BINARY_SHA256 = (
    "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
)
EXPECTED_SPECTRON_BINARY_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
)
EXPECTED_DATABASE_SHA256 = (
    "b7d17b9a5dbc34922cc40fe030cb539d69dcf89fe8a5f64bae83e962309263ab"
)


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
    parser.add_argument("--application-report", required=True, type=Path)
    parser.add_argument("--verification-report", required=True, type=Path)
    parser.add_argument("--anchor-artifact", required=True, type=Path)
    parser.add_argument("--name-audit", required=True, type=Path)
    parser.add_argument("--boundary-audit", required=True, type=Path)
    parser.add_argument("--dynamic-symbol-coverage", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--source-boundary-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    application = load(args.application_report)
    verification = load(args.verification_report)
    anchors = load(args.anchor_artifact)
    name_audit = load(args.name_audit)
    boundary = load(args.boundary_audit)
    dynamic_coverage = load(args.dynamic_symbol_coverage)
    semantic_map = load(args.semantic_map)
    source_boundary = load(args.source_boundary_report)

    require(parent.get("artifact") == PARENT_ARTIFACT, "unexpected parent checkpoint")
    require(parent["database"]["sha256"] ==
            "17015ba3140200199269ca94675e043e1e87cbefcdfa473680062a55ac96a0d6",
            "parent database hash is not v320")
    require(application.get("apply") and application.get("failure_count") == 0,
            "GUI alias application did not pass")
    require(application.get("anchor_count") == 11 and
            application.get("resolved_count") == 11 and
            application.get("renamed_count") == 11 and
            application.get("comments_added") == 11 and
            application.get("saved"),
            "GUI alias application count changed")
    require(verification.get("verified") and
            verification.get("anchor_count") == 11 and
            verification.get("verified_name_count") == 11 and
            verification.get("failure_count") == 0,
            "GUI alias reopen verification did not pass")
    require(anchors.get("artifact") ==
            "spectron_gui_missing_function_manual_translation_anchors_20260828",
            "unexpected GUI alias artifact")
    require(anchors["summary"]["anchor_count"] == 11 and
            anchors["summary"]["high_confidence_count"] == 10 and
            anchors["summary"]["medium_confidence_count"] == 1,
            "GUI alias summary changed")
    require(source_boundary.get("materialized_count") == 11 and
            source_boundary.get("failure_count") == 0,
            "source boundary repair did not pass")
    require(name_audit.get("input_sha256") == EXPECTED_SPECTRON_BINARY_SHA256 and
            name_audit.get("function_count") == 11707 and
            name_audit.get("default_name_count") == 0,
            "v321 name audit changed")
    require(name_audit.get("name_origins") == {
        "ida_named_or_other": 4053,
        "target_jni_export": 7,
        "target_named_export": 1002,
        "target_only_descriptive": 417,
        "translated_v18_alias": 6228,
    }, "v321 name-origin counts changed")
    require(boundary.get("input_sha256") == EXPECTED_SPECTRON_BINARY_SHA256 and
            boundary.get("defined_function_symbol_count") == 5782 and
            boundary.get("ida_exact_start_count") == 5782 and
            boundary.get("ida_missing_exact_start_count") == 0,
            "v321 dynamic boundary audit changed")
    require(dynamic_coverage.get("input_sha256") == EXPECTED_SPECTRON_BINARY_SHA256,
            "v321 dynamic symbol coverage hash changed")
    require(dynamic_coverage["summary"] == {
        "defined_named_symbol_count": 6600,
        "location_counts": {
            "ida_data_item": 482,
            "ida_function_exact": 5782,
            "ida_noncode_item": 336,
            "undefined_or_zero_value": 170,
        },
        "name_match_counts": {
            "item_name_match": 1890,
            "item_name_mismatch": 4880,
            "value_name_match": 1890,
            "value_name_mismatch": 4880,
        },
        "named_dynamic_symbol_count": 6770,
        "status_counts": {
            "exact_retained_dynamic_name": 1890,
            "linker_boundary_alias_mismatch": 7,
            "other_retained_target_name": 151,
            "source_backed_v18_alias": 4552,
            "undefined_import_with_plt_stub": 169,
            "undefined_no_target_address": 1,
        },
    }, "v321 dynamic symbol coverage counts changed")
    require(semantic_map.get("summary", {}).get("mapped_functions") == 3716,
            "v320 semantic map count changed")
    require(semantic_map.get("summary", {}).get("mapped_high_confidence") == 3656,
            "v320 semantic map high-confidence count changed")
    require(args.database.is_file(), "database path is not a regular file")
    database_sha256 = sha256_path(args.database)
    require(database_sha256 == EXPECTED_DATABASE_SHA256,
            "v321 database hash changed")

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
        "v321_source_boundary_report": str(args.source_boundary_report),
        "v321_source_boundary_report_sha256": sha256_path(args.source_boundary_report),
        "v321_semantic_map": str(args.semantic_map),
        "v321_semantic_map_sha256": sha256_path(args.semantic_map),
        "v321_gui_anchor_artifact": str(args.anchor_artifact),
        "v321_gui_anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "v321_gui_application_report": str(args.application_report),
        "v321_gui_application_report_sha256": sha256_path(args.application_report),
        "v321_gui_verification_report": str(args.verification_report),
        "v321_gui_verification_report_sha256": sha256_path(args.verification_report),
        "v321_name_audit": str(args.name_audit),
        "v321_name_audit_sha256": sha256_path(args.name_audit),
        "v321_boundary_audit": str(args.boundary_audit),
        "v321_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v321_dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
        "v321_dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
    }
    result["gui_missing_function_translation_v321"] = {
        "anchor_artifact": str(args.anchor_artifact),
        "anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "application_report": str(args.application_report),
        "application_report_sha256": sha256_path(args.application_report),
        "verification_report": str(args.verification_report),
        "verification_report_sha256": sha256_path(args.verification_report),
        "source_boundary_report": str(args.source_boundary_report),
        "source_boundary_report_sha256": sha256_path(args.source_boundary_report),
        "anchor_count": anchors["summary"]["anchor_count"],
        "high_confidence_count": anchors["summary"]["high_confidence_count"],
        "medium_confidence_count": anchors["summary"]["medium_confidence_count"],
        "source_materialized_count": source_boundary["materialized_count"],
        "reopen_verified": verification["verified"],
    }
    result["name_coverage_audit_v321"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["dynamic_function_boundary_audit_v321"] = {
        "artifact_path": str(args.boundary_audit),
        "artifact_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
    }
    result["dynamic_symbol_coverage_audit_v321"] = {
        "artifact_path": str(args.dynamic_symbol_coverage),
        "artifact_sha256": sha256_path(args.dynamic_symbol_coverage),
        "summary": dynamic_coverage["summary"],
    }
    result["semantic_function_translation_v320"] = {
        "artifact_path": str(args.semantic_map),
        "artifact_sha256": sha256_path(args.semantic_map),
        "summary": semantic_map["summary"],
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v321 pass restored eleven original GUI dynamic-function boundaries, matched ten of them exactly across builds, and recorded one class-slot match with an explicit eight-byte metric difference."
    )
    result["interpretation"].append(
        "The final v321 database contains 6,228 reviewed v18 aliases, including the eleven GUI methods restored from source-side ELF symbols that old IDA had treated as data."
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "artifact": result["artifact"],
        "database_sha256": database_sha256,
        "function_count": result["database"]["function_count"],
        "anchor_count": anchors["summary"]["anchor_count"],
        "source_backed_dynamic_symbols": dynamic_coverage["summary"]["status_counts"]["source_backed_v18_alias"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
