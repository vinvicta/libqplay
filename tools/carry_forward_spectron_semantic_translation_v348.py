#!/usr/bin/env python3
"""Carry the semantic map onto the v348 RSA public-encryption pass."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


SOURCE_EA = "0xf7218"
TARGET_EA = "0xf94ac"
ANCHOR_ARTIFACT = "spectron_rsa_encrypt_manual_translation_anchor_20260829"


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
        "method": "manual-encryption-rsa-public-exact-anchor",
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
        raise ValueError("unexpected RSA anchor artifact")
    if anchors.get("summary", {}).get("anchor_count") != 1:
        raise ValueError("RSA anchor count changed")
    if target_features.get("function_count") != 11707:
        raise ValueError("v348 target feature count changed")

    anchor = anchors["anchors"][0]
    if anchor.get("original_ea") != SOURCE_EA or anchor.get("spectron_ea") != TARGET_EA:
        raise ValueError("unexpected RSA anchor addresses")
    source_eas = {row["original_ea"] for row in parent.get("matches", [])}
    target_eas = {row["spectron_ea"] for row in parent.get("matches", [])}
    if SOURCE_EA in source_eas or TARGET_EA in target_eas:
        raise ValueError("RSA anchor is already in the parent semantic map")

    removed_ambiguous = [
        row
        for row in parent.get("ambiguous", [])
        if row.get("original_ea") == SOURCE_EA
    ]
    if len(removed_ambiguous) != 1 or TARGET_EA not in removed_ambiguous[0].get("candidate_spectron_eas", []):
        raise ValueError("RSA anchor does not resolve the expected ambiguity")

    result = copy.deepcopy(parent)
    refreshed_rows = refresh_row_names(result, {TARGET_EA: anchor["proposed_name"]})
    result["matches"].append(manual_match(anchor))
    result["matches"].sort(key=lambda row: int(row["original_ea"], 16))
    result["ambiguous"] = [
        row for row in result.get("ambiguous", []) if row.get("original_ea") != SOURCE_EA
    ]
    result["summary"] = dict(result["summary"])
    result["summary"]["mapped_functions"] += 1
    result["summary"]["mapped_high_confidence"] += 1
    result["summary"]["unique_spectron_targets"] += 1
    result["summary"]["ambiguous_functions"] -= 1
    result["scope"] = (
        "stable 1.8-to-Spectron semantic translation map carried from v345; "
        "v348 adds the manually resolved TEncryption RSA public-encryption wrapper"
    )
    result["inputs"] = dict(result.get("inputs", {}))
    result["inputs"]["spectron_features"] = str(args.target_features)
    result["inputs"]["spectron_features_sha256"] = sha256_path(args.target_features)
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["rsa_encrypt_anchor_artifact"] = str(args.anchor_artifact)
    result["inputs"]["rsa_encrypt_anchor_artifact_sha256"] = sha256_path(args.anchor_artifact)
    result["rsa_encrypt_translation_v348"] = {
        "anchor_artifact": str(args.anchor_artifact),
        "anchor_artifact_sha256": sha256_path(args.anchor_artifact),
        "manual_match_count": 1,
        "source_eas": [SOURCE_EA],
        "target_eas": [TARGET_EA],
        "resolved_ambiguous_count": 1,
        "reason": (
            "The source RSA public-encryption wrapper and target D855FaUMK1 method have identical normalized ARM64 shape. "
            "Direct public-key decode and encryption calls distinguish the target from the already reviewed private-signing sibling."
        ),
    }
    result["carried_forward"] = {
        "from_artifact": str(args.parent_map),
        "from_artifact_sha256": sha256_path(args.parent_map),
        "reason": (
            "The v348 pass keeps the existing semantic map and adds one reviewed RSA public-encryption row "
            "that was explicitly resolved from the parent ambiguity list."
        ),
        "target_name_rows_refreshed": refreshed_rows,
        "target_feature_count": target_features["function_count"],
        "target_feature_sha256": sha256_path(args.target_features),
        "manual_matches_added": 1,
        "ambiguous_rows_resolved": 1,
    }
    result["network_contacted"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "manual_matches_added": 1,
                "resolved_ambiguous_rows": 1,
                "refreshed_target_name_rows": refreshed_rows,
                "summary": result["summary"],
                "target_feature_sha256": result["inputs"]["spectron_features_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
