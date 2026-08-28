#!/usr/bin/env python3
"""Create reviewed anchors for the two TPlayer findweapon callbacks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRICS = (
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
NORMALIZED_METRICS = ("opcode_shape_hash", "register_shape_hash", "shape_hash")


SPECS = (
    {
        "original_ea": "0x16ca18",
        "spectron_ea": "0x1705f0",
        "original_name": "TPlayerProperties_script_findweapon",
        "spectron_name": "sub_1705F0",
        "proposed_name": "v18_TPlayerProperties_script_findweapon",
        "source_record": "0x37bce8",
        "target_record": "0x38ed18",
        "source_table": "TPlayerProperties function table",
        "target_table": "Spectron TPlayer function table",
        "operation": "iterates the player's weapon list and returns the first weapon whose name equals the script argument",
        "context": "property callback receives the player object and the weapon-name argument",
    },
    {
        "original_ea": "0x16db28",
        "spectron_ea": "0x171728",
        "original_name": "TPlayer_script_findweapon",
        "spectron_name": "sub_171728",
        "proposed_name": "v18_TPlayer_script_findweapon",
        "source_record": "0x37bdd8",
        "target_record": "0x38ee38",
        "source_table": "TPlayer static function table",
        "target_table": "Spectron TPlayer static function table",
        "operation": "iterates the active player's weapon list and returns the first weapon whose name equals the script argument",
        "context": "static callback resolves the active player before searching",
    },
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
    return {field: row.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, spec: dict) -> dict:
    if source["name"] != spec["original_name"]:
        raise ValueError(f"unexpected source name at {spec['original_ea']}: {source['name']}")
    if target["name"] != spec["spectron_name"]:
        raise ValueError(f"unexpected target name at {spec['spectron_ea']}: {target['name']}")
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {spec['spectron_ea']}")
    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source[field] == target[field] for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    evidence = [
        f"The source registration is in the {spec['source_table']} at {spec['source_record']}.",
        f"The target registration is in the {spec['target_table']} at {spec['target_record']}.",
        f"Both pseudocodes preserve the same search operation: {spec['operation']}.",
        f"The calling context is preserved: {spec['context']}.",
        "The target callback remained a default sub name before this pass.",
    ]
    if normalized_equal and full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; remaining differences are recorded as target register detail."
        )
    else:
        evidence.append(
            "The target uses rebuilt string comparison and player-layout helpers, so the shape differences are retained explicitly rather than treated as byte identity."
        )
    return {
        "original_ea": spec["original_ea"],
        "original_name": spec["original_name"],
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": spec["spectron_ea"],
        "spectron_current_name": spec["spectron_name"],
        "spectron_default_name": True,
        "spectron_metrics": target_metrics,
        "spectron_function_end": target.get("end_ea"),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": spec["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-tplayer-findweapon-anchor",
        "source_component": spec["source_table"],
        "target_component": spec["target_table"],
        "source_basis": f"matching the findweapon callback in {spec['source_table']} and its decompiled search behavior",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": spec["source_record"],
        "target_script_table_record": spec["target_record"],
        "script_name": "findweapon",
        "property_role": "callback",
        "operation": spec["operation"],
        "context": spec["context"],
        "evidence": evidence,
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original = by_ea(load(args.original_features))
    spectron = by_ea(load(args.spectron_features))
    anchors = []
    for spec in SPECS:
        source = original.get(spec["original_ea"])
        target = spectron.get(spec["spectron_ea"])
        if source is None or target is None:
            raise ValueError(
                f"missing feature row for {spec['original_ea']} or {spec['spectron_ea']}"
            )
        anchors.append(make_anchor(source, target, spec))

    result = {
        "schema_version": 1,
        "artifact": "spectron_tplayer_findweapon_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TPlayer property and static findweapon callbacks",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "resolution": "matched both decoded findweapon registration rows, their distinct source callbacks, calling context, pseudocode, and ARM64 feature metrics",
            "target_behavior": "Spectron keeps separate callbacks for the player-object property path and the active-player static path",
            "source_property_record": "0x37bce8",
            "target_property_record": "0x38ed18",
            "source_static_record": "0x37bdd8",
            "target_static_record": "0x38ee38",
        },
        "summary": {
            "anchor_count": len(anchors),
            "registration_row_count": len(anchors),
            "unique_target_count": len({row["spectron_ea"] for row in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "normalized_shape_exact_count": sum(
                row["normalized_shape_equal"] for row in anchors
            ),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(
                not row["normalized_shape_equal"] for row in anchors
            ),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
            "callback_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The two source findweapon symbols remain separate because their 1.8 calling contexts differ, and Spectron also keeps two target callbacks.",
            "Both target bodies use the same rebuilt weapon-list and string-comparison helpers, which explains their larger target shapes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
