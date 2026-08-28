#!/usr/bin/env python3
"""Record the reviewed correction from TT_DotFix14 to Project."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_EA = "0x25e640"
TARGET_EA = "0x26bab0"
TARGET_CURRENT_NAME = "v18_TT_DotFix14"
RESTORED_NAME = "v18_Project"
METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"].lower(): row for row in document["functions"]}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original_by_ea = by_ea(load(args.original_features))
    spectron_by_ea = by_ea(load(args.spectron_features))
    source = original_by_ea[SOURCE_EA]
    target = spectron_by_ea[TARGET_EA]
    if not source.get("is_default_name"):
        raise ValueError("the source helper must remain an original default name")
    if target.get("name") != TARGET_CURRENT_NAME:
        raise ValueError("the target does not contain the historical mistaken label")
    if target.get("is_default_name"):
        raise ValueError("the target correction expects the prior semantic label")
    source_metrics = metrics(source)
    target_metrics = metrics(target)
    differences = [
        field
        for field in METRIC_FIELDS
        if source_metrics[field] != target_metrics[field]
    ]
    if differences:
        raise ValueError("projection body metrics differ in %s" % differences)

    correction = {
        "target_ea": TARGET_EA,
        "current_name": TARGET_CURRENT_NAME,
        "restored_name": RESTORED_NAME,
        "source_ea": SOURCE_EA,
        "source_symbol": "Project",
        "source_current_name": source["name"],
        "source_metrics": source_metrics,
        "target_metrics": target_metrics,
        "metric_differences": differences,
        "source_file": "src/truetype/ttinterp.c",
        "source_reference": "https://android.googlesource.com/platform/external/freetype/+/f720f0dbcf012d6c984dbbefa0875ef9840458c6/src/truetype/ttinterp.c",
        "confidence": "high",
        "reason": "Compute_Funcs installs the source helper at 0x25e640 as the func_project callback at the projection slot. The body is the Project projection callback and inlines TT_DotFix14 arithmetic, so the earlier TT_DotFix14 label described the implementation detail rather than the callback role.",
        "topology": "Compute_Funcs stores the source helper in the func_project slot at offset 984; the neighboring Dual_Project helper is stored in the func_dualproj slot at offset 992",
        "name_action": "restore-reviewed-project-role",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_freetype_tt_projection_name_correction_20260828",
        "scope": "correct the earlier Spectron label for the non-axis projection callback",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "summary": {
            "correction_count": 1,
            "high_confidence_count": 1,
            "metric_exact_count": 1,
            "source_default_name_count": 1,
            "target_prior_semantic_label_count": 1,
        },
        "corrections": [correction],
        "interpretation": [
            "This artifact supersedes the mistaken v18_TT_DotFix14 label at target 0x26bab0 without changing the historical v307 artifact.",
            "Project and Dual_Project are separate callbacks selected by Compute_Funcs for the projection and dual-projection vectors.",
            "The target body has the exact same recorded ARM64 feature metrics as the source body, and the remaining TT_DotFix14 arithmetic is an implementation detail in Project.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
