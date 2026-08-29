#!/usr/bin/env python3
"""Carry the semantic map onto the v349 exact sound-wrapper pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ANCHOR_ARTIFACT = "spectron_sounds_exact_manual_translation_anchors_20260829"


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
        "confidence": anchor["confidence"],
        "instruction_count": anchor["original_metrics"]["instruction_count"],
        "method": "manual-sounds-exact-anchor",
        "original_ea": anchor["original_ea"],
        "original_name": anchor["original_name"],
        "shared_direct_call_count": len(shared_calls),
        "shared_direct_call_names": shared_calls,
        "shared_string_ref_count": len(shared_strings),
        "shared_string_refs": shared_strings,
        "size": anchor["original_metrics"]["size"],
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
        raise ValueError("unexpected sound anchor artifact")
    anchor_rows = anchors.get("anchors", [])
    if anchors.get("summary", {}).get("anchor_count") != 10 or len(anchor_rows) != 10:
        raise ValueError("sound anchor count changed")
    if target_features.get("function_count") != 11707:
        raise ValueError("target feature count changed")

    source_eas = {row["original_ea"] for row in parent.get("matches", [])}
    target_eas = {row["spectron_ea"] for row in parent.get("matches", [])}
    ambiguous = {row["original_ea"]: row for row in parent.get("ambiguous", [])}
    for anchor in anchor_rows:
        source_ea = anchor["original_ea"]
        target_ea = anchor["spectron_ea"]
        if source_ea in source_eas or target_ea in target_eas:
            raise ValueError("sound anchor is already in the parent semantic map")
        row = ambiguous.get(source_ea)
        if row is None or target_ea not in row.get("candidate_spectron_eas", []):
            raise ValueError("sound anchor does not resolve the expected parent ambiguity: %s" % source_ea)

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
    result["summary"] = dict(result["summary"])
    result["summary"]["mapped_functions"] += len(anchor_rows)
    result["summary"]["mapped_high_confidence"] += len(anchor_rows)
    result["summary"]["unique_spectron_targets"] += len(anchor_rows)
    result["summary"]["ambiguous_functions"] -= len(anchor_rows)
    result["scope"] = (
        "stable 1.8-to-Spectron semantic translation map carried from v348; "
        "v349 adds ten reviewed exact-shape TSounds and Java-audio wrapper correspondences"
    )
    result["inputs"] = dict(result.get("inputs", {}))
    result["inputs"]["spectron_features"] = str(args.target_features)
    result["inputs"]["spectron_features_sha256"] = sha256_path(args.target_features)
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["sounds_anchor_artifact"] = str(args.anchor_artifact)
    result["inputs"]["sounds_anchor_artifact_sha256"] = sha256_path(args.anchor_artifact)
    result["sounds_translation_v349"] = {
        "anchor_artifact": str(args.anchor_artifact),
        "anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "manual_match_count": len(anchor_rows),
        "source_eas": [anchor["original_ea"] for anchor in anchor_rows],
        "target_eas": [anchor["spectron_ea"] for anchor in anchor_rows],
        "resolved_ambiguous_count": len(anchor_rows),
        "reason": (
            "The source and target TSounds, TSoundPlayerJava, and TSoundEffectJava rows have identical complete normalized ARM64 feature records. "
            "Direct wrapper behavior, vtable slots, class-local order, and the target sound-player clusters resolve the otherwise ambiguous shape matches."
        ),
    }
    result["carried_forward"] = {
        "from_artifact": str(args.parent_map),
        "from_artifact_sha256": sha256_path(args.parent_map),
        "reason": (
            "The v349 pass keeps the existing semantic map and adds ten exact sound-wrapper rows that were explicitly resolved from the parent ambiguity list."
        ),
        "target_name_rows_refreshed": refreshed_rows,
        "target_feature_count": target_features["function_count"],
        "target_feature_sha256": sha256_path(args.target_features),
        "manual_matches_added": len(anchor_rows),
        "ambiguous_rows_resolved": len(anchor_rows),
    }
    result["network_contacted"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "manual_matches_added": len(anchor_rows),
                "resolved_ambiguous_rows": len(anchor_rows),
                "refreshed_target_name_rows": refreshed_rows,
                "summary": result["summary"],
                "target_feature_sha256": result["inputs"]["spectron_features_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
