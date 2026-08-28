#!/usr/bin/env python3
"""Create the v308 checkpoint from the v307 database and reopen reports."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v308"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v307"


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
    if not report.get("verified"):
        raise ValueError("%s reopen report is not marked verified" % kind)
    return report


def anchor_record(document: dict, path: Path, report_path: Path, report: dict) -> dict:
    return {
        "anchor_count": document["summary"].get("anchor_count", document["summary"].get("correction_count")),
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
    parser.add_argument("--runtime-tail-anchor", required=True, type=Path)
    parser.add_argument("--runtime-tail-verification", required=True, type=Path)
    parser.add_argument("--projection-correction", required=True, type=Path)
    parser.add_argument("--projection-verification", required=True, type=Path)
    parser.add_argument("--translation-verification", required=True, type=Path)
    parser.add_argument("--original-feature-export", required=True, type=Path)
    parser.add_argument("--spectron-feature-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    if parent.get("artifact") != PARENT_ARTIFACT:
        raise ValueError("unexpected parent checkpoint artifact")
    runtime_anchor = load(args.runtime_tail_anchor)
    runtime_count = runtime_anchor["summary"]["anchor_count"]
    runtime_report = checked_report(
        args.runtime_tail_verification, runtime_count, "TrueType runtime tail"
    )
    projection_correction = load(args.projection_correction)
    projection_count = projection_correction["summary"]["correction_count"]
    projection_report = checked_report(
        args.projection_verification, projection_count, "TrueType projection correction"
    )
    translation_report = load(args.translation_verification)
    if translation_report.get("failure_count") != 0:
        raise ValueError("translation reopen report contains failures")
    if not translation_report.get("verified"):
        raise ValueError("translation reopen report is not marked verified")
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
        "close_reopen_verified": True,
        "default_sub_function_count": translation_report["default_sub_function_count"],
        "format": parent["database"].get("format", "packed IDA 9.3 database"),
        "function_count": translation_report["function_count"],
        "path": str(args.database),
        "sha256": sha256_path(args.database),
    }
    result["inputs"]["reopen_verification"] = str(args.translation_verification)
    result["inputs"]["v308_original_feature_export"] = str(args.original_feature_export)
    result["inputs"]["v308_original_feature_export_sha256"] = sha256_path(args.original_feature_export)
    result["inputs"]["v308_spectron_feature_export"] = str(args.spectron_feature_export)
    result["inputs"]["v308_spectron_feature_export_sha256"] = sha256_path(args.spectron_feature_export)
    result["freetype_tt_runtime_tail_anchors"] = anchor_record(
        runtime_anchor,
        args.runtime_tail_anchor,
        args.runtime_tail_verification,
        runtime_report,
    )
    result["freetype_tt_projection_name_correction"] = {
        **anchor_record(
            projection_correction,
            args.projection_correction,
            args.projection_verification,
            projection_report,
        ),
        "correction_count": projection_count,
    }
    result["interpretation"].append(
        "The v308 database adds eleven high-confidence FreeType TrueType runtime-tail labels: ENDF, tt_size_done, Dual_Project, FDEF, IDEF, DELTAP, DELTAC, TT_Load_Context, SHC, SHP, and ISECT."
    )
    result["interpretation"].append(
        "The v308 pass corrects target 0x26bab0 from the earlier v18_TT_DotFix14 label to v18_Project. Compute_Funcs installs the corresponding source helper in the projection callback slot, while the helper's TT_DotFix14 arithmetic is an implementation detail."
    )
    result["interpretation"].append(
        "The v308 database has %d functions and %d remaining default sub_ names after close and reopen verification."
        % (
            translation_report["function_count"],
            translation_report["default_sub_function_count"],
        )
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "database_sha256": result["database"]["sha256"],
                "default_sub_function_count": result["database"]["default_sub_function_count"],
                "function_count": result["database"]["function_count"],
                "projection_correction_count": projection_count,
                "runtime_tail_anchor_count": runtime_count,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
