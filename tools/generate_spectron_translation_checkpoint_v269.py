#!/usr/bin/env python3
"""Create the v269 checkpoint from the v268 record and reopen reports."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v269"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v268"


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
    if report.get("verified_name_count") != expected_count:
        raise ValueError("%s reopen report count does not match artifact" % kind)
    if not report.get("verified", True):
        raise ValueError("%s reopen report is not marked verified" % kind)
    return report


def anchor_record(
    document: dict,
    path: Path,
    report_path: Path,
    report: dict,
    count_key: str = "anchor_count",
) -> dict:
    expected_count = document["summary"][count_key]
    return {
        "anchor_count": expected_count,
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
    parser.add_argument("--cross-anchor", required=True, type=Path)
    parser.add_argument("--cross-verification", required=True, type=Path)
    parser.add_argument("--target-label", required=True, type=Path)
    parser.add_argument("--target-verification", required=True, type=Path)
    parser.add_argument("--translation-verification", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    if parent.get("artifact") != PARENT_ARTIFACT:
        raise ValueError("unexpected parent checkpoint artifact")
    cross = load(args.cross_anchor)
    target = load(args.target_label)
    cross_count = cross["summary"]["anchor_count"]
    target_count = target["summary"]["label_count"]
    cross_report = checked_report(args.cross_verification, cross_count, "cross-build")
    target_report = checked_report(args.target_verification, target_count, "target-only")
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
    result["tgraalvar_script_runtime_anchors"] = anchor_record(
        cross,
        args.cross_anchor,
        args.cross_verification,
        cross_report,
    )
    result["tgraalvar_target_only_labels"] = anchor_record(
        target,
        args.target_label,
        args.target_verification,
        target_report,
        count_key="label_count",
    )
    result["interpretation"].append(
        "The v269 database also contains the five reviewed TGraalVar script-runtime callback anchors and the target-only loadvarsfromarray label."
    )
    result["interpretation"].append(
        "The four short callback wrappers match the complete recorded source metrics. The addnamedstring wrapper is recorded as a layout-change match, and the loadvarsfromarray row remains explicitly target-only."
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
                "cross_anchor_count": cross_count,
                "target_only_label_count": target_count,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
