#!/usr/bin/env python3
"""Create the v271 checkpoint from v270 and the reopened residual reports."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v271"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v270"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_report(path: Path, expected_count: int, kind: str) -> dict:
    report = load(path)
    if report.get("failure_count") != 0:
        raise ValueError("%s reopen report contains failures" % kind)
    actual_count = report.get("verified_name_count")
    if actual_count != expected_count:
        raise ValueError("%s reopen report count does not match artifact" % kind)
    if not report.get("verified", True):
        raise ValueError("%s reopen report is not marked verified" % kind)
    return report


def anchor_record(
    document: dict,
    path: Path,
    report_path: Path,
    report: dict,
    count_key: str,
) -> dict:
    return {
        "anchor_count": document["summary"][count_key],
        "anchor_path": str(path),
        "anchor_sha256": sha256_path(path),
        "reopen_failure_count": report["failure_count"],
        "reopen_verification": str(report_path),
        "verified_name_count": report["verified_name_count"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-checkpoint", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--runtime-anchor", required=True, type=Path)
    parser.add_argument("--runtime-verification", required=True, type=Path)
    parser.add_argument("--property-label", required=True, type=Path)
    parser.add_argument("--property-verification", required=True, type=Path)
    parser.add_argument("--translation-verification", required=True, type=Path)
    parser.add_argument("--feature-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    if parent.get("artifact") != PARENT_ARTIFACT:
        raise ValueError("unexpected parent checkpoint artifact")
    runtime = load(args.runtime_anchor)
    properties = load(args.property_label)
    runtime_report = checked_report(
        args.runtime_verification,
        runtime["summary"]["anchor_count"],
        "runtime callback",
    )
    property_report = checked_report(
        args.property_verification,
        properties["summary"]["label_count"],
        "TPlayer property",
    )
    translation_report = load(args.translation_verification)
    if translation_report.get("failure_count") != 0:
        raise ValueError("translation reopen report contains failures")
    if not translation_report.get("verified", True):
        raise ValueError("translation reopen report is not marked verified")

    result = copy.deepcopy(parent)
    result["artifact"] = ARTIFACT
    result["network_contacted"] = False
    result["parent_checkpoint"] = {
        "artifact": parent["artifact"],
        "path": str(args.parent_checkpoint),
        "sha256": sha256_path(args.parent_checkpoint),
    }
    result["database"] = {
        "close_reopen_verified": True,
        "default_sub_function_count": translation_report["default_sub_function_count"],
        "format": parent["database"].get("format", "packed IDA 9.3 database"),
        "function_count": translation_report["function_count"],
        "path": str(args.database),
        "sha256": sha256_path(args.database),
    }
    result["inputs"]["reopen_verification"] = str(args.translation_verification)
    result["inputs"]["v271_feature_export"] = str(args.feature_export)
    result["inputs"]["v271_feature_export_sha256"] = sha256_path(args.feature_export)
    result["runtime_callback_residual_anchors"] = anchor_record(
        runtime,
        args.runtime_anchor,
        args.runtime_verification,
        runtime_report,
        "anchor_count",
    )
    result["tplayer_quattro_zoom_property_labels"] = anchor_record(
        properties,
        args.property_label,
        args.property_verification,
        property_report,
        "label_count",
    )
    result["interpretation"].append(
        "The v271 database adds nine exact TStream, zlib, and YAJL callback-role anchors and preserves their installation-site evidence."
    )
    result["interpretation"].append(
        "The v271 database adds two target-only labels for the TPlayer Quattro zoom-culling getter and setter. The source inventory and source binary contain no matching property record or literal."
    )
    result["interpretation"].append(
        "The residual callback and target-only property artifacts were reopened with zero failures, and the default sub_ count is now %d."
        % translation_report["default_sub_function_count"]
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "database_sha256": result["database"]["sha256"],
                "default_sub_function_count": result["database"]["default_sub_function_count"],
                "function_count": result["database"]["function_count"],
                "property_label_count": properties["summary"]["label_count"],
                "runtime_anchor_count": runtime["summary"]["anchor_count"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
