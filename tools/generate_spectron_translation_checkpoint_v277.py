#!/usr/bin/env python3
"""Create the v277 checkpoint from v276 and the reopened jdphuff reports."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v277"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v276"


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
    parser.add_argument("--jdphuff-anchor", required=True, type=Path)
    parser.add_argument("--jdphuff-verification", required=True, type=Path)
    parser.add_argument("--translation-verification", required=True, type=Path)
    parser.add_argument("--feature-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    if parent.get("artifact") != PARENT_ARTIFACT:
        raise ValueError("unexpected parent checkpoint artifact")
    jdphuff_anchor = load(args.jdphuff_anchor)
    jdphuff_count = jdphuff_anchor["summary"]["anchor_count"]
    jdphuff_report = checked_report(
        args.jdphuff_verification, jdphuff_count, "libjpeg progressive Huffman"
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
    result["inputs"]["v277_feature_export"] = str(args.feature_export)
    result["inputs"]["v277_feature_export_sha256"] = sha256_path(args.feature_export)
    result["jdphuff_anchors"] = anchor_record(
        jdphuff_anchor,
        args.jdphuff_anchor,
        args.jdphuff_verification,
        jdphuff_report,
    )
    result["interpretation"].append(
        "The v277 database adds five high-confidence libjpeg jdphuff role anchors: start_pass_phuff_decoder, decode_mcu_AC_refine, decode_mcu_AC_first, decode_mcu_DC_refine, and decode_mcu_DC_first."
    )
    result["interpretation"].append(
        "The target progressive-Huffman start-pass dispatcher selects the four MCU decoders according to DC versus AC spectral mode and first versus successive-approximation scan state."
    )
    result["interpretation"].append(
        "The v277 residual pass reduced the default sub_ count to %d while preserving all prior verified aliases and runtime labels."
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
                "jdphuff_anchor_count": jdphuff_count,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
