#!/usr/bin/env python3
"""Carry the semantic map through the v352 existing-alias reconciliation."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


RECONCILIATION_ARTIFACT = "spectron_existing_v18_alias_reconciliation_20260829"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def refresh_row_names(value, target_names: dict[str, str]) -> int:
    if isinstance(value, list):
        return sum(refresh_row_names(item, target_names) for item in value)
    if not isinstance(value, dict):
        return 0
    changed = 0
    target_ea = value.get("spectron_ea")
    if target_ea in target_names and value.get("spectron_current_name") != target_names[target_ea]:
        value["spectron_current_name"] = target_names[target_ea]
        changed += 1
    for child in value.values():
        changed += refresh_row_names(child, target_names)
    return changed


def semantic_match(anchor: dict) -> dict:
    source_metrics = anchor["original_metrics"]
    shared_calls = anchor.get("shared_direct_call_names", [])
    shared_strings = anchor.get("shared_string_refs", [])
    return {
        "alias_name": anchor["proposed_name"],
        "basic_block_count": source_metrics.get("basic_block_count"),
        "changed_metric_fields": anchor.get("metric_differences", []),
        "confidence": anchor["confidence"],
        "instruction_count": source_metrics.get("instruction_count"),
        "layout_change": bool(anchor.get("layout_change", True)),
        "layout_metric_delta": {
            field: {
                "original": anchor["original_metrics"].get(field),
                "spectron": anchor["spectron_metrics"].get(field),
            }
            for field in anchor.get("metric_differences", [])
        },
        "method": anchor["match_kind"],
        "original_ea": anchor["original_ea"],
        "original_name": anchor["original_name"],
        "provenance_artifact": anchor["provenance_artifact"],
        "provenance_artifact_sha256": anchor["provenance_artifact_sha256"],
        "shared_direct_call_count": len(shared_calls),
        "shared_direct_call_names": shared_calls,
        "shared_string_ref_count": len(shared_strings),
        "shared_string_refs": shared_strings,
        "size": source_metrics.get("size"),
        "source_category": anchor["source_category"],
        "spectron_current_name": anchor["proposed_name"],
        "spectron_ea": anchor["spectron_ea"],
        "target_name_before_reconciliation": anchor["target_name_before_reconciliation"],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-map", required=True, type=Path)
    parser.add_argument("--target-features", required=True, type=Path)
    parser.add_argument("--reconciliation-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_map)
    target_features = load(args.target_features)
    reconciliation = load(args.reconciliation_artifact)
    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected parent semantic-map artifact")
    if parent.get("network_contacted") is not False:
        raise ValueError("parent semantic map is not offline")
    if reconciliation.get("artifact") != RECONCILIATION_ARTIFACT:
        raise ValueError("unexpected reconciliation artifact")
    if reconciliation.get("network_contacted") is not False:
        raise ValueError("reconciliation artifact is not offline")
    anchors = reconciliation.get("anchors", [])
    if reconciliation.get("summary", {}).get("anchor_count") != 509 or len(anchors) != 509:
        raise ValueError("existing alias reconciliation count changed")
    if target_features.get("function_count") != 11707:
        raise ValueError("target feature count changed")

    parent_match_sources = {row["original_ea"] for row in parent.get("matches", [])}
    parent_match_targets = {row["spectron_ea"] for row in parent.get("matches", [])}
    parent_unmatched = {row["original_ea"] for row in parent.get("unmatched", [])}
    target_by_ea = {row["ea"]: row for row in target_features.get("functions", [])}
    seen_sources: set[str] = set()
    seen_targets: set[str] = set()
    high_count = 0
    medium_count = 0
    for anchor in anchors:
        source_ea = anchor["original_ea"]
        target_ea = anchor["spectron_ea"]
        if source_ea in parent_match_sources or source_ea not in parent_unmatched:
            raise ValueError("reconciliation source is not a parent unmatched row: %s" % source_ea)
        if target_ea in parent_match_targets:
            raise ValueError("reconciliation target is already mapped: %s" % target_ea)
        if source_ea in seen_sources or target_ea in seen_targets:
            raise ValueError("duplicate reconciliation source or target")
        seen_sources.add(source_ea)
        seen_targets.add(target_ea)
        target = target_by_ea.get(target_ea)
        if target is None or target.get("name") != anchor["proposed_name"]:
            raise ValueError("target alias changed at %s" % target_ea)
        if anchor.get("confidence") == "high":
            high_count += 1
        elif anchor.get("confidence") == "medium":
            medium_count += 1
        else:
            raise ValueError("unexpected reconciliation confidence")

    if (high_count, medium_count) != (508, 1):
        raise ValueError("reconciliation confidence split changed")

    result = copy.deepcopy(parent)
    refreshed_rows = refresh_row_names(
        result,
        {anchor["spectron_ea"]: anchor["proposed_name"] for anchor in anchors},
    )
    result["matches"].extend(semantic_match(anchor) for anchor in anchors)
    result["matches"].sort(key=lambda row: int(row["original_ea"], 16))
    resolved_sources = {anchor["original_ea"] for anchor in anchors}
    result["unmatched"] = [
        row for row in result.get("unmatched", []) if row.get("original_ea") not in resolved_sources
    ]
    result["summary"] = dict(result["summary"])
    result["summary"]["mapped_functions"] += len(anchors)
    result["summary"]["mapped_high_confidence"] += high_count
    result["summary"]["mapped_medium_confidence"] += medium_count
    result["summary"]["unique_spectron_targets"] += len(anchors)
    result["summary"]["unmatched_functions"] -= len(anchors)
    result["scope"] = (
        "stable 1.8-to-Spectron semantic translation map carried from v351; "
        "v352 reconciles 509 pre-existing reviewed v18_ aliases"
    )
    result["inputs"] = dict(result.get("inputs", {}))
    result["inputs"]["spectron_features"] = str(args.target_features)
    result["inputs"]["spectron_features_sha256"] = sha256_path(args.target_features)
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["existing_alias_reconciliation_artifact"] = str(args.reconciliation_artifact)
    result["inputs"]["existing_alias_reconciliation_artifact_sha256"] = sha256_path(
        args.reconciliation_artifact
    )
    result["existing_alias_reconciliation_v352"] = {
        "artifact": str(args.reconciliation_artifact),
        "artifact_sha256": sha256_path(args.reconciliation_artifact),
        "reconciled_alias_count": len(anchors),
        "high_confidence_count": high_count,
        "medium_confidence_count": medium_count,
        "target_database_changed": False,
        "target_feature_count": target_features["function_count"],
        "remaining_unmatched_without_existing_alias": reconciliation["summary"][
            "remaining_unmatched_without_existing_alias"
        ],
        "provenance_artifact_count": reconciliation["summary"]["provenance_artifact_count"],
        "reason": (
            "The target already carried the exact v18_ alias and each selected pair is backed by one prior reviewed anchor artifact. The current feature export verifies the existing target name in the persisted build."
        ),
    }
    result["carried_forward"] = {
        "from_artifact": str(args.parent_map),
        "from_artifact_sha256": sha256_path(args.parent_map),
        "reason": (
            "The v352 pass reconciles existing target aliases into the semantic map without changing the target IDB."
        ),
        "target_name_rows_refreshed": refreshed_rows,
        "target_feature_count": target_features["function_count"],
        "target_feature_sha256": sha256_path(args.target_features),
        "manual_matches_added": len(anchors),
        "ambiguous_rows_resolved": 0,
        "unmatched_rows_promoted": len(anchors),
        "existing_alias_rows_reconciled": len(anchors),
    }
    result["network_contacted"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "summary": result["summary"],
                "existing_alias_rows_reconciled": len(anchors),
                "high_confidence_count": high_count,
                "medium_confidence_count": medium_count,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
