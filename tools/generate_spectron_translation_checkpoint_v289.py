#!/usr/bin/env python3
"""Create the v289 checkpoint from v288 and the reopened jccolor report."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v289"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v288"


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
    return {
        "anchor_count": document["summary"]["anchor_count"],
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
    parser.add_argument("--jccolor-anchor", required=True, type=Path)
    parser.add_argument("--jccolor-verification", required=True, type=Path)
    parser.add_argument("--translation-verification", required=True, type=Path)
    parser.add_argument("--feature-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    if parent.get("artifact") != PARENT_ARTIFACT:
        raise ValueError("unexpected parent checkpoint artifact")
    jccolor_anchor = load(args.jccolor_anchor)
    jccolor_count = jccolor_anchor["summary"]["anchor_count"]
    jccolor_report = checked_report(
        args.jccolor_verification, jccolor_count, "libjpeg compressor color converter"
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
    result["inputs"]["v289_feature_export"] = str(args.feature_export)
    result["inputs"]["v289_feature_export_sha256"] = sha256_path(args.feature_export)
    result["jccolor_anchors"] = anchor_record(
        jccolor_anchor,
        args.jccolor_anchor,
        args.jccolor_verification,
        jccolor_report,
    )
    result["interpretation"].append(
        "The v289 database adds six high-confidence libjpeg jccolor role anchors: rgb_ycc_start, rgb_ycc_convert, rgb_gray_convert, cmyk_ycck_convert, compressor-side grayscale_convert, and compressor-side null_convert."
    )
    result["interpretation"].append(
        "The target compressor color-converter initializer installs the table initializer and conversion callbacks in the same RGB, grayscale, CMYK, YCbCr, and YCCK branches as the source."
    )
    result["interpretation"].append(
        "The compressor-side duplicate grayscale_convert and null_convert roles use c_ qualifiers so they remain distinct from the already translated decompressor-side jdcolor routines."
    )
    result["interpretation"].append(
        "The v289 residual pass reduced the default sub_ count to %d while preserving all prior verified aliases and runtime labels."
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
                "jccolor_anchor_count": jccolor_count,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
