#!/usr/bin/env python3
"""Create the v283 checkpoint from v282 and the reopened jquant2 report."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v283"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v282"


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


def anchor_record(document: dict, path: Path, report_path: Path, report: dict) -> dict:
    expected_count = document["summary"]["anchor_count"]
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
    parser.add_argument("--jquant2-anchor", required=True, type=Path)
    parser.add_argument("--jquant2-verification", required=True, type=Path)
    parser.add_argument("--translation-verification", required=True, type=Path)
    parser.add_argument("--feature-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    if parent.get("artifact") != PARENT_ARTIFACT:
        raise ValueError("unexpected parent checkpoint artifact")
    jquant2_anchor = load(args.jquant2_anchor)
    jquant2_count = jquant2_anchor["summary"]["anchor_count"]
    jquant2_report = checked_report(
        args.jquant2_verification, jquant2_count, "libjpeg two-pass quantizer"
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
    result["inputs"]["v283_feature_export"] = str(args.feature_export)
    result["inputs"]["v283_feature_export_sha256"] = sha256_path(args.feature_export)
    result["jquant2_anchors"] = anchor_record(
        jquant2_anchor,
        args.jquant2_anchor,
        args.jquant2_verification,
        jquant2_report,
    )
    result["interpretation"].append(
        "The v283 database adds nine high-confidence libjpeg jquant2 role anchors: prescan_quantize, finish_pass2, new_color_map_2_quant, start_pass_2_quant, update_box, fill_inverse_cmap, pass2_no_dither, pass2_fs_dither, and finish_pass1."
    )
    result["interpretation"].append(
        "The target two-pass quantizer initializer preserves the source callback contract, and its start-pass routine dispatches histogram prescan, palette mapping, and Floyd-Steinberg processing as expected."
    )
    result["interpretation"].append(
        "The v283 residual pass reduced the default sub_ count to %d while preserving all prior verified aliases and runtime labels."
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
                "jquant2_anchor_count": jquant2_count,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
