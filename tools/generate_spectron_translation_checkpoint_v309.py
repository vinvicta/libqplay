#!/usr/bin/env python3
"""Create the v309 checkpoint from the v308 database and reopen reports."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_translation_checkpoint_20260828_v309"
PARENT_ARTIFACT = "spectron_translation_checkpoint_20260828_v308"


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
    parser.add_argument("--glyph-loader-anchor", required=True, type=Path)
    parser.add_argument("--glyph-loader-verification", required=True, type=Path)
    parser.add_argument("--translation-verification", required=True, type=Path)
    parser.add_argument("--original-feature-export", required=True, type=Path)
    parser.add_argument("--spectron-feature-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_checkpoint)
    if parent.get("artifact") != PARENT_ARTIFACT:
        raise ValueError("unexpected parent checkpoint artifact")
    glyph_anchor = load(args.glyph_loader_anchor)
    glyph_count = glyph_anchor["summary"]["anchor_count"]
    glyph_report = checked_report(
        args.glyph_loader_verification, glyph_count, "TrueType glyph-loader block"
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
    result["inputs"]["v309_original_feature_export"] = str(args.original_feature_export)
    result["inputs"]["v309_original_feature_export_sha256"] = sha256_path(args.original_feature_export)
    result["inputs"]["v309_spectron_feature_export"] = str(args.spectron_feature_export)
    result["inputs"]["v309_spectron_feature_export_sha256"] = sha256_path(args.spectron_feature_export)
    result["freetype_tt_glyph_loader_anchors"] = anchor_record(
        glyph_anchor,
        args.glyph_loader_anchor,
        args.glyph_loader_verification,
        glyph_report,
    )
    result["interpretation"].append(
        "The v309 database adds seven high-confidence FreeType TrueType labels: load_truetype_glyph, TT_Load_Glyph, tt_glyph_load, Ins_SxVTL, Ins_CALL, Ins_LOOPCALL, and Ins_UNKNOWN."
    )
    result["interpretation"].append(
        "The v309 glyph-loader block has exact recorded ARM64 feature metrics for six rows. TT_Load_Glyph differs only in register-detail hash, which is treated as compiler allocation rather than behavior."
    )
    result["interpretation"].append(
        "The v309 database has %d functions and %d remaining default sub_ names after close and reopen verification."
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
                "glyph_loader_anchor_count": glyph_count,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
