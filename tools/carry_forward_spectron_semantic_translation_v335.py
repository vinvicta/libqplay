#!/usr/bin/env python3
"""Carry the stable semantic map onto the v335 Adventure residual pass."""

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
        raise ValueError("v335 target feature count changed")
    if anchors.get("artifact") != "spectron_adventure_static_residual_manual_translation_anchors_20260829":
        raise ValueError("unexpected v335 anchor artifact")

    target_names = {
        row["spectron_ea"]: row["proposed_name"]
        for row in anchors["anchors"]
    }
    result = copy.deepcopy(parent)
    refreshed_rows = refresh_row_names(result, target_names)
    result["scope"] = (
        "stable 1.8-to-Spectron semantic translation map carried from v334; "
        "v335 adds the reviewed GSFunctionsClient and TAdventure residual names without changing function bodies"
    )
    result["inputs"]["spectron_features"] = str(args.target_features)
    result["inputs"]["spectron_features_sha256"] = sha256_path(args.target_features)
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["adventure_static_residual_anchor_artifact"] = str(args.anchor_artifact)
    result["inputs"]["adventure_static_residual_anchor_artifact_sha256"] = sha256_path(args.anchor_artifact)
    result["carried_forward"] = {
        "from_artifact": str(args.parent_map),
        "from_artifact_sha256": sha256_path(args.parent_map),
        "reason": (
            "The v335 pass changes four target names and does not alter the function "
            "bodies or target function count. The reviewed semantic map therefore "
            "remains the v334 map, with target feature provenance updated explicitly."
        ),
        "target_name_rows_refreshed": refreshed_rows,
        "target_feature_count": target_features["function_count"],
        "target_feature_sha256": sha256_path(args.target_features),
    }
    result["network_contacted"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": result["artifact"],
                "carried_forward": True,
                "refreshed_target_name_rows": refreshed_rows,
                "summary": result["summary"],
                "target_feature_sha256": result["inputs"]["spectron_features_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
