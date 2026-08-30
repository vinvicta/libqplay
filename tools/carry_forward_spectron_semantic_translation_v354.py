#!/usr/bin/env python3
"""Carry the semantic map through the v354 compact core anchors."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ANCHOR_ARTIFACT = "spectron_compact_core_manual_translation_anchors_20260830"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def semantic_match(anchor: dict) -> dict:
    source_metrics = anchor["original_metrics"]
    source_strings = anchor.get("original_string_refs", [])
    target_strings = anchor.get("spectron_string_refs", [])
    shared_strings = sorted(set(source_strings) & set(target_strings))
    source_calls = anchor.get("original_direct_call_names", [])
    target_calls = anchor.get("spectron_direct_call_names", [])
    shared_calls = sorted(set(source_calls) & set(target_calls))
    return {
        "alias_name": anchor["proposed_name"],
        "basic_block_count": source_metrics.get("basic_block_count"),
        "changed_metric_fields": anchor["changed_metric_fields"],
        "confidence": anchor["confidence"],
        "instruction_count": source_metrics.get("instruction_count"),
        "layout_change": True,
        "layout_metric_delta": anchor["layout_metric_delta"],
        "method": anchor["match_kind"],
        "original_ea": anchor["original_ea"],
        "original_name": anchor["original_name"],
        "provenance_artifact": ANCHOR_ARTIFACT,
        "provenance_artifact_sha256": None,
        "shared_direct_call_count": len(shared_calls),
        "shared_direct_call_names": shared_calls,
        "shared_string_ref_count": len(shared_strings),
        "shared_string_refs": shared_strings,
        "size": source_metrics.get("size"),
        "source_category": anchor.get("source_category", "unmatched"),
        "spectron_current_name": anchor["proposed_name"],
        "spectron_ea": anchor["spectron_ea"],
        "target_name_before_translation": anchor["spectron_current_name"],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-map", required=True, type=Path)
    parser.add_argument("--anchor-artifact", required=True, type=Path)
    parser.add_argument("--target-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_map)
    anchors_document = load(args.anchor_artifact)
    target_features = load(args.target_features)
    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected parent semantic-map artifact")
    if parent.get("network_contacted") is not False:
        raise ValueError("parent semantic map is not offline")
    if anchors_document.get("artifact") != ANCHOR_ARTIFACT:
        raise ValueError("unexpected compact-core anchor artifact")
    if anchors_document.get("network_contacted") is not False:
        raise ValueError("compact-core anchor artifact is not offline")
    anchors = anchors_document.get("anchors", [])
    if len(anchors) != 9 or anchors_document.get("summary", {}).get("high_confidence_count") != 9:
        raise ValueError("compact-core anchor count changed")
    if target_features.get("function_count") != 11707:
        raise ValueError("target feature count changed")
    if target_features.get("network_contacted") is not False:
        raise ValueError("target feature export is not offline")

    parent_sources = {row["original_ea"] for row in parent.get("matches", [])}
    parent_targets = {row["spectron_ea"] for row in parent.get("matches", [])}
    parent_unmatched = {row["original_ea"] for row in parent.get("unmatched", [])}
    target_by_ea = {row["ea"]: row for row in target_features.get("functions", [])}
    seen_sources: set[str] = set()
    seen_targets: set[str] = set()
    for anchor in anchors:
        source_ea = anchor["original_ea"]
        target_ea = anchor["spectron_ea"]
        if source_ea in parent_sources or source_ea not in parent_unmatched:
            raise ValueError("anchor source is not a parent unmatched row: %s" % source_ea)
        if target_ea in parent_targets:
            raise ValueError("anchor target is already mapped: %s" % target_ea)
        if source_ea in seen_sources or target_ea in seen_targets:
            raise ValueError("duplicate compact-core source or target")
        target = target_by_ea.get(target_ea)
        if target is None or target.get("name") not in {
            anchor["spectron_current_name"],
            anchor["proposed_name"],
        }:
            raise ValueError("target name changed: %s" % target_ea)
        if target.get("is_default_name"):
            raise ValueError("target unexpectedly has a default name: %s" % target_ea)
        seen_sources.add(source_ea)
        seen_targets.add(target_ea)

    anchor_sha256 = sha256_path(args.anchor_artifact)
    result = copy.deepcopy(parent)
    matches = []
    for anchor in anchors:
        row = semantic_match(anchor)
        row["provenance_artifact_sha256"] = anchor_sha256
        matches.append(row)
    result["matches"].extend(matches)
    result["matches"].sort(key=lambda row: int(row["original_ea"], 16))
    result["unmatched"] = [
        row for row in result.get("unmatched", []) if row["original_ea"] not in seen_sources
    ]
    result["summary"] = dict(result["summary"])
    result["summary"]["mapped_functions"] += len(anchors)
    result["summary"]["mapped_high_confidence"] += len(anchors)
    result["summary"]["unique_spectron_targets"] += len(anchors)
    result["summary"]["unmatched_functions"] -= len(anchors)
    result["scope"] = (
        "stable 1.8-to-Spectron semantic translation map carried from v353; "
        "v354 adds nine reviewed compact filesystem, identity, logging, profiling, and input translations"
    )
    result["inputs"] = dict(result.get("inputs", {}))
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["compact_core_anchor_artifact"] = str(args.anchor_artifact)
    result["inputs"]["compact_core_anchor_artifact_sha256"] = anchor_sha256
    result["inputs"]["compact_core_target_features"] = str(args.target_features)
    result["inputs"]["compact_core_target_features_sha256"] = sha256_path(args.target_features)
    result["compact_core_translation_v354"] = {
        "artifact": str(args.anchor_artifact),
        "artifact_sha256": anchor_sha256,
        "anchor_count": len(anchors),
        "high_confidence_count": len(anchors),
        "target_database_changed": True,
        "renamed_count": sum(
            anchor["name_action"] == "rename-with-v18-prefix" for anchor in anchors
        ),
        "existing_alias_role_correction_count": sum(
            anchor["name_action"] == "retain-existing-v18-alias-and-add-reviewed-comment"
            for anchor in anchors
        ),
        "remaining_unmatched_functions": result["summary"]["unmatched_functions"],
        "folded_or_removed_rows_not_promoted": [
            "0xea9e0 THashList_containsEncoded_THashListObject",
            "0xebdfc THashStrings_listNames_TStringList_TString_const",
            "0xf7e44 TLog_echo_TString_const_double_double_double_char_const",
            "0x2468c4 TInitStatics_initVars_void",
        ],
    }
    result["carried_forward"] = {
        "from_artifact": str(args.parent_map),
        "from_artifact_sha256": sha256_path(args.parent_map),
        "reason": "The v354 pass adds only fresh, one-to-one compact-core anchors and leaves folded or removed source rows explicitly unresolved.",
        "target_feature_count": target_features["function_count"],
        "manual_matches_added": len(anchors),
        "ambiguous_rows_resolved": 0,
        "unmatched_rows_promoted": len(anchors),
    }
    result["network_contacted"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "summary": result["summary"],
                "anchor_count": len(anchors),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
