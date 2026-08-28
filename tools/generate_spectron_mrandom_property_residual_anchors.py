#!/usr/bin/env python3
"""Create reviewed anchors for residual MRandomGenerator properties."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x1e3220",
        "0x1e70f0",
        "MRandomGenerator_get_seed",
        "sub_1E70F0",
        "seed",
        "0x384228",
        "0x397288",
    ),
    (
        "0x1e3228",
        "0x1e70f8",
        "MRandomGenerator_set_seed",
        "sub_1E70F8",
        "seed setter",
        "0x384228",
        "0x397288",
    ),
    (
        "0x1e3248",
        "0x1e7118",
        "MRandomGenerator_script_randint",
        "sub_1E7118",
        "randint",
        "0x384288",
        "0x3972e8",
    ),
    (
        "0x1e3268",
        "0x1e7138",
        "MRandomGenerator_script_randfloat",
        "sub_1E7138",
        "randfloat",
        "0x384258",
        "0x3972b8",
    ),
)

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


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"]: row for row in document["functions"]}


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, spec: tuple[str, ...]) -> dict:
    source_ea, target_ea, source_name, target_name, table_name, source_table, target_table = spec
    if source["name"] != source_name:
        raise ValueError(f"unexpected source name at {source_ea}: {source['name']}")
    if target["name"] != target_name:
        raise ValueError(f"unexpected target name at {target_ea}: {target['name']}")
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    if source_metrics != target_metrics:
        raise ValueError(f"MRandom property feature mismatch at {source_ea}")
    return {
        "original_ea": source_ea,
        "original_name": source_name,
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target_ea,
        "spectron_current_name": target_name,
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source_name,
        "confidence": "high",
        "match_kind": "manual-mrandom-property-table-anchor",
        "source_component": "MRandomGenerator",
        "target_component": "o3AZxayNqc",
        "source_basis": f"script property-table entry {table_name}",
        "normalized_shape_equal": True,
        "full_metric_equal": True,
        "metric_differences": [],
        "source_property_table_record": source_table,
        "target_property_table_record": target_table,
        "evidence": [
            f"The source registration record for {table_name} is at {source_table}.",
            f"The target registration record for {table_name} is at {target_table}.",
            "The source and target pseudocode preserve the same receiver field or virtual dispatch slot.",
            "All recorded normalized and complete function metrics match exactly.",
        ],
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original = by_ea(load(args.original_features))
    spectron = by_ea(load(args.spectron_features))
    anchors = []
    for spec in SPECS:
        source = original.get(spec[0])
        target = spectron.get(spec[1])
        if source is None or target is None:
            raise ValueError(f"missing feature row for {spec[0]} or {spec[1]}")
        anchors.append(make_anchor(source, target, spec))

    result = {
        "schema_version": 1,
        "artifact": "spectron_mrandom_property_residual_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual MRandomGenerator property and script callbacks",
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
            "source_component": "MRandomGenerator",
            "target_component": "o3AZxayNqc",
            "resolution": "decoded property-table names, class-local random-generator block, decompiled bodies, and exact normalized metrics",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "normalized_shape_exact_count": len(anchors),
            "full_metric_exact_count": len(anchors),
            "layout_change_count": 0,
            "register_detail_difference_count": 0,
        },
        "anchors": anchors,
        "reviewed_target_only_rows": [],
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ labels preserve readable 1.8 roles while the target ABI names remain in each evidence row.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
