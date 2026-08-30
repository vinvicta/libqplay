#!/usr/bin/env python3
"""Carry the v352 semantic map through the v353 JNI callback anchors."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ANCHOR_ARTIFACT = "spectron_jni_callbacks_manual_translation_anchors_20260829"


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
    return {
        "alias_name": anchor["proposed_name"],
        "basic_block_count": source_metrics["basic_block_count"],
        "changed_metric_fields": anchor["changed_metric_fields"],
        "confidence": anchor["confidence"],
        "instruction_count": source_metrics["instruction_count"],
        "layout_change": anchor["layout_change"],
        "layout_metric_delta": anchor["layout_metric_delta"],
        "method": anchor["match_kind"],
        "original_ea": anchor["original_ea"],
        "original_name": anchor["original_name"],
        "shared_direct_call_count": 0,
        "shared_direct_call_names": [],
        "shared_string_ref_count": 0,
        "shared_string_refs": [],
        "size": source_metrics["size"],
        "spectron_current_name": anchor["proposed_name"],
        "spectron_ea": anchor["spectron_ea"],
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
        raise ValueError("unexpected parent semantic map")
    if anchors_document.get("artifact") != ANCHOR_ARTIFACT:
        raise ValueError("unexpected JNI anchor artifact")
    anchors = anchors_document.get("anchors", [])
    if len(anchors) != 5 or anchors_document.get("summary", {}).get("high_confidence_count") != 5:
        raise ValueError("JNI anchor count changed")
    if target_features.get("function_count") != 11707:
        raise ValueError("target feature count changed")

    parent_sources = {row["original_ea"] for row in parent.get("matches", [])}
    parent_targets = {row["spectron_ea"] for row in parent.get("matches", [])}
    unmatched = {row["original_ea"] for row in parent.get("unmatched", [])}
    target_by_ea = {row["ea"]: row for row in target_features.get("functions", [])}
    seen_sources: set[str] = set()
    seen_targets: set[str] = set()
    for anchor in anchors:
        source_ea = anchor["original_ea"]
        target_ea = anchor["spectron_ea"]
        if source_ea not in unmatched or source_ea in parent_sources:
            raise ValueError("anchor source is not parent-unmatched: %s" % source_ea)
        if target_ea in parent_targets or target_ea in seen_targets:
            raise ValueError("anchor target is already used: %s" % target_ea)
        if source_ea in seen_sources:
            raise ValueError("anchor source is duplicated: %s" % source_ea)
        target = target_by_ea.get(target_ea)
        if target is None or target.get("name") != anchor["spectron_current_name"]:
            raise ValueError("target evidence name changed: %s" % target_ea)
        seen_sources.add(source_ea)
        seen_targets.add(target_ea)

    result = copy.deepcopy(parent)
    result["matches"].extend(semantic_match(anchor) for anchor in anchors)
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
        "stable 1.8-to-Spectron semantic translation map carried from v352; "
        "v353 adds five reviewed retained-JNI callback translations"
    )
    result["inputs"] = dict(result.get("inputs", {}))
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["jni_callback_anchor_artifact"] = str(args.anchor_artifact)
    result["inputs"]["jni_callback_anchor_artifact_sha256"] = sha256_path(args.anchor_artifact)
    result["inputs"]["jni_callback_target_features"] = str(args.target_features)
    result["inputs"]["jni_callback_target_features_sha256"] = sha256_path(args.target_features)
    result["jni_callbacks_translation_v353"] = {
        "artifact": str(args.anchor_artifact),
        "artifact_sha256": sha256_path(args.anchor_artifact),
        "anchor_count": len(anchors),
        "high_confidence_count": len(anchors),
        "target_database_changed": True,
        "target_name_action": "five exact retained JNI names received the v18_ analysis prefix",
        "remaining_unmatched_functions": result["summary"]["unmatched_functions"],
    }
    result["network_contacted"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"summary": result["summary"], "anchor_count": len(anchors)}, sort_keys=True))


if __name__ == "__main__":
    main()
