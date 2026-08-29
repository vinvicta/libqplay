#!/usr/bin/env python3
"""Create the v320 checkpoint from the v319 database and offline audits."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v320"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v319"
EXPECTED_BINARY_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-checkpoint", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--application-report", required=True, type=Path)
    parser.add_argument("--boundary-audit", required=True, type=Path)
    parser.add_argument("--name-audit", required=True, type=Path)
    parser.add_argument("--symbol-inventory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    if parent.get("artifact") != PARENT_ARTIFACT:
        raise ValueError("unexpected parent checkpoint artifact")
    application = load(args.application_report)
    boundary = load(args.boundary_audit)
    name_audit = load(args.name_audit)
    inventory = load(args.symbol_inventory)

    if not application.get("apply") or application.get("failure_count") != 0:
        raise ValueError("dynamic function application did not pass")
    if application.get("row_count") != 12 or application.get("materialized_count") != 12:
        raise ValueError("dynamic function application count is not 12")
    if not application.get("saved"):
        raise ValueError("dynamic function application did not save a database")
    if boundary.get("input_sha256") != EXPECTED_BINARY_SHA256:
        raise ValueError("boundary audit input hash does not match target library")
    if boundary.get("defined_function_symbol_count") != 5782:
        raise ValueError("boundary audit function count changed")
    if boundary.get("ida_exact_start_count") != 5782:
        raise ValueError("not every defined dynamic function has an IDA start")
    if boundary.get("ida_missing_exact_start_count") != 0:
        raise ValueError("boundary audit still has missing function starts")
    if name_audit.get("input_sha256") != EXPECTED_BINARY_SHA256:
        raise ValueError("name audit input hash does not match target library")
    if name_audit.get("function_count") != 11707:
        raise ValueError("v320 function count changed")
    if name_audit.get("default_name_count") != 0:
        raise ValueError("v320 still contains audited default names")
    summary = inventory["summary"]
    if summary.get("named_dynamic_symbol_count") != 6770:
        raise ValueError("dynamic symbol inventory count changed")
    if summary.get("section_defined_function_count") != 5782:
        raise ValueError("dynamic function symbol count changed")
    if summary.get("ida_function_match_count") != 5782:
        raise ValueError("dynamic symbol inventory still has unmatched function rows")

    if not args.database.is_file():
        raise ValueError("database path is not a regular file")

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
        "sha256": sha256_path(args.database),
        "function_count": name_audit["function_count"],
        "default_sub_function_count": name_audit["default_name_count"],
        "default_name_count": name_audit["default_name_count"],
        "close_reopen_verified": True,
    }
    result["inputs"] = {
        **parent.get("inputs", {}),
        "v320_dynamic_function_application_report": str(args.application_report),
        "v320_dynamic_function_application_report_sha256": sha256_path(
            args.application_report
        ),
        "v320_dynamic_boundary_audit": str(args.boundary_audit),
        "v320_dynamic_boundary_audit_sha256": sha256_path(args.boundary_audit),
        "v320_name_audit": str(args.name_audit),
        "v320_name_audit_sha256": sha256_path(args.name_audit),
        "v320_symbol_inventory": str(args.symbol_inventory),
        "v320_symbol_inventory_sha256": sha256_path(args.symbol_inventory),
    }
    result["dynamic_function_boundary_repair"] = {
        "application_report": str(args.application_report),
        "application_report_sha256": sha256_path(args.application_report),
        "boundary_audit": str(args.boundary_audit),
        "boundary_audit_sha256": sha256_path(args.boundary_audit),
        "defined_function_symbol_count": boundary["defined_function_symbol_count"],
        "ida_exact_start_count": boundary["ida_exact_start_count"],
        "ida_missing_exact_start_count": boundary["ida_missing_exact_start_count"],
        "materialized_count": application["materialized_count"],
        "reopen_failure_count": application["failure_count"],
    }
    result["name_coverage_audit_v320"] = {
        "artifact_path": str(args.name_audit),
        "artifact_sha256": sha256_path(args.name_audit),
        "function_count": name_audit["function_count"],
        "default_name_count": name_audit["default_name_count"],
        "name_origins": name_audit["name_origins"],
    }
    result["symbol_translation_inventory_v320"] = {
        "artifact_path": str(args.symbol_inventory),
        "artifact_sha256": sha256_path(args.symbol_inventory),
        "summary": summary,
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "The v320 database materializes twelve exact function boundaries from positive-size retained dynamic FUNC symbols."
    )
    result["interpretation"].append(
        "The v320 boundary audit finds all 5,782 section-defined dynamic FUNC rows at exact IDA function starts."
    )
    result["interpretation"].append(
        "The twelve names are retained target ELF names. They are not reconstructed 1.8 source names."
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "database_sha256": result["database"]["sha256"],
                "function_count": result["database"]["function_count"],
                "materialized_count": application["materialized_count"],
                "dynamic_exact_start_count": boundary["ida_exact_start_count"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
