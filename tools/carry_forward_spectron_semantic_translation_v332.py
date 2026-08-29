#!/usr/bin/env python3
"""Carry the stable v331 semantic map onto the v332 name-only database pass.

The v331 map was produced from a source feature snapshot with 11,308 functions.
The current IDALIB re-export of the preserved source databases reports 11,297
functions, so rerunning the matcher would turn an exporter-version difference
into an apparent loss of mappings. This pass keeps the reviewed function map,
updates the target feature provenance, and refreshes any target names covered by
the v332 aliases.
"""

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
    """Refresh target names in any semantic-map row that carries an EA."""

    changed = 0
    if isinstance(value, list):
        for item in value:
            changed += refresh_row_names(item, target_names)
        return changed
    if not isinstance(value, dict):
        return 0

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
        raise ValueError("v332 target feature count changed")
    if anchors.get("artifact") != "spectron_paneloperation_residual_manual_translation_anchors_20260829":
        raise ValueError("unexpected v332 anchor artifact")

    target_names = {
        row["spectron_ea"]: row["proposed_name"]
        for row in anchors["anchors"]
    }
    result = copy.deepcopy(parent)
    refreshed_rows = refresh_row_names(result, target_names)
    result["scope"] = (
        "stable 1.8-to-Spectron semantic translation map carried from v331; "
        "v332 adds reviewed TPanelOperation names without changing function bodies"
    )
    result["inputs"]["spectron_features"] = str(args.target_features)
    result["inputs"]["spectron_features_sha256"] = sha256_path(args.target_features)
    result["inputs"]["semantic_map_parent"] = str(args.parent_map)
    result["inputs"]["semantic_map_parent_sha256"] = sha256_path(args.parent_map)
    result["inputs"]["paneloperation_anchor_artifact"] = str(args.anchor_artifact)
    result["inputs"]["paneloperation_anchor_artifact_sha256"] = sha256_path(args.anchor_artifact)
    result["carried_forward"] = {
        "from_artifact": str(args.parent_map),
        "from_artifact_sha256": sha256_path(args.parent_map),
        "reason": (
            "The preserved source IDA databases currently export 11,297 functions, "
            "while the reviewed v331 source snapshot contains 11,308. Since v332 "
            "changes only target names and not function bodies, the v331 semantic "
            "map is retained instead of presenting exporter drift as a regression."
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
