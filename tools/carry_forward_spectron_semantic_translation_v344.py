#!/usr/bin/env python3
"""Carry the semantic map onto the v344 resource-stream crypto pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


def load(path: Path):
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
    shared_strings = sorted(set(anchor["original_string_refs"]).intersection(anchor["spectron_string_refs"]))
    source_metrics = anchor["original_metrics"]
    return {
        "alias_name": anchor["proposed_name"],
        "basic_block_count": source_metrics["basic_block_count"],
        "confidence": anchor["confidence"],
        "instruction_count": source_metrics["instruction_count"],
        "method": "manual-resource-stream-crypto-call",
        "original_ea": anchor["original_ea"],
        "original_name": anchor["original_name"],
        "shared_direct_call_count": len(shared_calls),
        "shared_direct_call_names": shared_calls,
        "shared_string_ref_count": len(shared_strings),
        "shared_string_refs": shared_strings,
        "size": source_metrics["size"],
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
    if target_features.get("function_count") != 11707:
        raise ValueError("v344 target feature count changed")
    if anchors.get("artifact") != "spectron_resource_stream_residual_manual_translation_anchors_20260829":
        raise ValueError("unexpected v344 anchor artifact")

    result = copy.deepcopy(parent)
    target_names = {row["spectron_ea"]: row["proposed_name"] for row in anchors["anchors"]}
    refreshed_rows = refresh_row_names(result, target_names)

    source_eas = {row["original_ea"] for row in anchors["anchors"]}
    target_eas = {row["spectron_ea"] for row in anchors["anchors"]}
    removed_ambiguous = []
    remaining_ambiguous = []
    for row in result.get("ambiguous", []):
        if row.get("original_ea") in source_eas:
            if not target_eas.intersection(row.get("candidate_spectron_eas", [])):
                raise ValueError("resource anchor target is absent from its ambiguous candidates")
            removed_ambiguous.append(row)
        else:
            remaining_ambiguous.append(row)
    if len(removed_ambiguous) != len(anchors["anchors"]):
        raise ValueError("not every resource anchor resolved an existing ambiguous row")

    added_matches = [manual_match(anchor) for anchor in anchors["anchors"]]
    result["matches"].extend(added_matches)
    result["matches"].sort(key=lambda row: int(row["original_ea"], 16))
    result["ambiguous"] = remaining_ambiguous
    result["summary"] = dict(result["summary"])
    result["summary"]["mapped_functions"] += len(added_matches)
    result["summary"]["mapped_high_confidence"] += sum(
        row["confidence"] == "high" for row in added_matches
    )
    result["summary"]["unique_spectron_targets"] += len(added_matches)
    result["summary"]["ambiguous_functions"] -= len(removed_ambiguous)

    result["scope"] = (
        "stable 1.8-to-Spectron semantic translation map carried from v343; "
        "v344 adds the two manually resolved TResourceFunctions stream crypto matches"
    )
    result["inputs"]["spectron_features"] = str(args.target_features)
    result["inputs"]["spectron_features_sha256"] = sha256_path(args.target_features)
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["resource_stream_anchor_artifact"] = str(args.anchor_artifact)
    result["inputs"]["resource_stream_anchor_artifact_sha256"] = sha256_path(args.anchor_artifact)
    result["resource_stream_translation_v344"] = {
        "anchor_artifact": str(args.anchor_artifact),
        "anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "manual_match_count": len(added_matches),
        "source_eas": [row["original_ea"] for row in anchors["anchors"]],
        "target_eas": [row["spectron_ea"] for row in anchors["anchors"]],
        "resolved_ambiguous_count": len(removed_ambiguous),
        "reason": (
            "The automatic matcher left both methods ambiguous because their normalized "
            "bodies are identical. Distinct encrypt-memory and decrypt-memory calls, "
            "adjacent method order, and matching pseudocode resolve the pair manually."
        ),
    }
    result["carried_forward"] = {
        "from_artifact": str(args.parent_map),
        "from_artifact_sha256": sha256_path(args.parent_map),
        "reason": (
            "The v344 pass keeps the existing automatic map and adds two reviewed "
            "resource-stream rows that were explicitly resolved from the parent "
            "ambiguous set. Target feature provenance is updated explicitly."
        ),
        "target_name_rows_refreshed": refreshed_rows,
        "target_feature_count": target_features["function_count"],
        "target_feature_sha256": sha256_path(args.target_features),
        "manual_matches_added": len(added_matches),
        "ambiguous_rows_resolved": len(removed_ambiguous),
    }
    result["network_contacted"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "manual_matches_added": len(added_matches),
                "resolved_ambiguous_rows": len(removed_ambiguous),
                "refreshed_target_name_rows": refreshed_rows,
                "summary": result["summary"],
                "target_feature_sha256": result["inputs"]["spectron_features_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
