#!/usr/bin/env python3
"""Carry the semantic map onto the v351 hash-residual pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ANCHOR_ARTIFACT = "spectron_hash_residual_manual_translation_anchors_20260829"


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


def manual_match(anchor: dict) -> dict:
    shared_calls = sorted(
        set(anchor["original_direct_call_names"]).intersection(anchor["spectron_direct_call_names"])
    )
    shared_strings = sorted(
        set(anchor["original_string_refs"]).intersection(anchor["spectron_string_refs"])
    )
    return {
        "alias_name": anchor["proposed_name"],
        "basic_block_count": anchor["original_metrics"]["basic_block_count"],
        "changed_metric_fields": anchor["changed_metric_fields"],
        "confidence": anchor["confidence"],
        "instruction_count": anchor["original_metrics"]["instruction_count"],
        "layout_change": not anchor["shape_equal"],
        "layout_metric_delta": {
            field: {
                "original": anchor["original_metrics"].get(field),
                "spectron": anchor["spectron_metrics"].get(field),
            }
            for field in anchor["changed_metric_fields"]
        },
        "method": anchor["match_kind"],
        "original_ea": anchor["original_ea"],
        "original_name": anchor["original_name"],
        "shared_direct_call_count": len(shared_calls),
        "shared_direct_call_names": shared_calls,
        "shared_string_ref_count": len(shared_strings),
        "shared_string_refs": shared_strings,
        "size": anchor["original_metrics"]["size"],
        "source_category": anchor["source_category"],
        "spectron_current_name": anchor["proposed_name"],
        "spectron_ea": anchor["spectron_ea"],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-map", required=True, type=Path)
    parser.add_argument("--target-features", required=True, type=Path)
    parser.add_argument("--anchor-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_map)
    target_features = load(args.target_features)
    anchors = load(args.anchor_artifact)
    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected parent semantic-map artifact")
    if parent.get("network_contacted") is not False:
        raise ValueError("parent semantic map is not offline")
    if anchors.get("artifact") != ANCHOR_ARTIFACT:
        raise ValueError("unexpected hash residual artifact")
    anchor_rows = anchors.get("anchors", [])
    if anchors.get("summary", {}).get("anchor_count") != 8 or len(anchor_rows) != 8:
        raise ValueError("hash residual anchor count changed")
    if target_features.get("function_count") != 11707:
        raise ValueError("target feature count changed")

    source_eas = {row["original_ea"] for row in parent.get("matches", [])}
    target_eas = {row["spectron_ea"] for row in parent.get("matches", [])}
    ambiguous = {row["original_ea"]: row for row in parent.get("ambiguous", [])}
    unmatched = {row["original_ea"] for row in parent.get("unmatched", [])}
    expected_categories = {"ambiguous": 0, "unmatched": 0}
    for anchor in anchor_rows:
        source_ea = anchor["original_ea"]
        target_ea = anchor["spectron_ea"]
        if source_ea in source_eas or target_ea in target_eas:
            raise ValueError("hash residual anchor is already in the parent semantic map")
        category = anchor.get("source_category")
        if category not in expected_categories:
            raise ValueError("unexpected source category: %s" % category)
        if category == "ambiguous" and source_ea not in ambiguous:
            raise ValueError("expected ambiguous source row is missing: %s" % source_ea)
        if category == "unmatched" and source_ea not in unmatched:
            raise ValueError("expected unmatched source row is missing: %s" % source_ea)
        expected_categories[category] += 1

    if expected_categories != {"ambiguous": 2, "unmatched": 6}:
        raise ValueError("unexpected ambiguous/unmatched split")

    result = copy.deepcopy(parent)
    refreshed_rows = refresh_row_names(
        result,
        {anchor["spectron_ea"]: anchor["proposed_name"] for anchor in anchor_rows},
    )
    result["matches"].extend(manual_match(anchor) for anchor in anchor_rows)
    result["matches"].sort(key=lambda row: int(row["original_ea"], 16))
    resolved_sources = {anchor["original_ea"] for anchor in anchor_rows}
    result["ambiguous"] = [
        row for row in result.get("ambiguous", []) if row.get("original_ea") not in resolved_sources
    ]
    result["unmatched"] = [
        row for row in result.get("unmatched", []) if row.get("original_ea") not in resolved_sources
    ]
    result["summary"] = dict(result["summary"])
    result["summary"]["mapped_functions"] += len(anchor_rows)
    result["summary"]["mapped_high_confidence"] += len(anchor_rows)
    result["summary"]["unique_spectron_targets"] += len(anchor_rows)
    result["summary"]["ambiguous_functions"] -= expected_categories["ambiguous"]
    result["summary"]["unmatched_functions"] -= expected_categories["unmatched"]
    result["scope"] = (
        "stable 1.8-to-Spectron semantic translation map carried from v350; "
        "v351 adds eight reviewed THashList and THashStrings correspondences"
    )
    result["inputs"] = dict(result.get("inputs", {}))
    result["inputs"]["spectron_features"] = str(args.target_features)
    result["inputs"]["spectron_features_sha256"] = sha256_path(args.target_features)
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["hash_residual_anchor_artifact"] = str(args.anchor_artifact)
    result["inputs"]["hash_residual_anchor_artifact_sha256"] = sha256_path(args.anchor_artifact)
    result["hash_residual_translation_v351"] = {
        "anchor_artifact": str(args.anchor_artifact),
        "anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "manual_match_count": len(anchor_rows),
        "source_eas": [anchor["original_ea"] for anchor in anchor_rows],
        "target_eas": [anchor["spectron_ea"] for anchor in anchor_rows],
        "resolved_ambiguous_count": expected_categories["ambiguous"],
        "promoted_unmatched_count": expected_categories["unmatched"],
        "exact_shape_count": sum(anchor["shape_equal"] for anchor in anchor_rows),
        "layout_change_count": sum(not anchor["shape_equal"] for anchor in anchor_rows),
        "reason": (
            "The target preserves hash bucket lookup, overload delegation, value replacement and removal, and string serialization. "
            "The normal string add/remove wrappers are exact feature matches; encoded and THashStrings rows retain their roles through the target string and iterator wrappers."
        ),
    }
    result["carried_forward"] = {
        "from_artifact": str(args.parent_map),
        "from_artifact_sha256": sha256_path(args.parent_map),
        "reason": (
            "The v351 pass keeps the existing semantic map and promotes two explicit ambiguities plus six unmatched hash-family rows using direct source and target pseudocode evidence."
        ),
        "target_name_rows_refreshed": refreshed_rows,
        "target_feature_count": target_features["function_count"],
        "target_feature_sha256": sha256_path(args.target_features),
        "manual_matches_added": len(anchor_rows),
        "ambiguous_rows_resolved": expected_categories["ambiguous"],
        "unmatched_rows_promoted": expected_categories["unmatched"],
    }
    result["network_contacted"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "manual_matches_added": len(anchor_rows),
                "resolved_ambiguous_rows": expected_categories["ambiguous"],
                "promoted_unmatched_rows": expected_categories["unmatched"],
                "refreshed_target_name_rows": refreshed_rows,
                "summary": result["summary"],
                "target_feature_sha256": result["inputs"]["spectron_features_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
