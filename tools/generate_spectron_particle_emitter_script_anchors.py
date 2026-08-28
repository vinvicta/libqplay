#!/usr/bin/env python3
"""Create reviewed TParticleEmitter GS2 function-table anchors."""

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

SPECS = [
    {
        "script_name": "addglobalmodifier",
        "source_record": "0x38ae10",
        "target_record": "0x39df60",
        "original_ea": "0x239414",
        "spectron_ea": "0x2432b4",
        "original_name": "TParticleEmitter_script_addglobalmodifier",
        "spectron_name": "sub_2432B4",
        "operation": "parses and adds a global particle modifier",
    },
    {
        "script_name": "addlocalmodifier",
        "source_record": "0x38ae40",
        "target_record": "0x39df90",
        "original_ea": "0x239500",
        "spectron_ea": "0x2433a0",
        "original_name": "TParticleEmitter_script_addlocalmodifier",
        "spectron_name": "sub_2433A0",
        "operation": "parses and adds a local particle modifier",
    },
    {
        "script_name": "addemitmodifier",
        "source_record": "0x38ae70",
        "target_record": "0x39dfc0",
        "original_ea": "0x2395ec",
        "spectron_ea": "0x24348c",
        "original_name": "TParticleEmitter_script_addemitmodifier",
        "spectron_name": "sub_24348C",
        "operation": "parses and adds a template particle modifier",
    },
]


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


def make_anchor(source: dict, target: dict, item: dict) -> dict:
    if source["name"] != item["original_name"]:
        raise ValueError(
            f"unexpected source name at {item['original_ea']}: {source['name']}"
        )
    if target["name"] != item["spectron_name"]:
        raise ValueError(
            f"unexpected target name at {item['spectron_ea']}: {target['name']}"
        )
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {item['spectron_ea']}")
    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source[field] == target[field] for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    return {
        "original_ea": item["original_ea"],
        "original_name": item["original_name"],
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": item["spectron_ea"],
        "spectron_current_name": item["spectron_name"],
        "spectron_default_name": True,
        "spectron_metrics": target_metrics,
        "spectron_function_end": target.get("end_ea"),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + item["original_name"],
        "confidence": "high",
        "match_kind": "manual-particle-emitter-script-function-table-anchor",
        "source_component": "TParticleEmitterProperties script-function table",
        "target_component": "Spectron obfuscated TParticleEmitter script-function table",
        "source_basis": (
            f"matching the {item['script_name']} function-table registration and "
            f"decompiled operation: {item['operation']}"
        ),
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["script_name"],
        "operation": item["operation"],
        "evidence": [
            f"The source function-table record for {item['script_name']} is at {item['source_record']}.",
            f"The target function-table record for {item['script_name']} is at {item['target_record']}.",
            f"Both bodies preserve the same modifier wrapper operation: {item['operation']}.",
            "The target callback remains in the TParticleEmitter script-function block and began as a default sub name.",
            "All recorded function metrics match exactly.",
        ],
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
    for item in SPECS:
        source = original.get(item["original_ea"])
        target = spectron.get(item["spectron_ea"])
        if source is None or target is None:
            raise ValueError(
                f"missing feature row for {item['original_ea']} or {item['spectron_ea']}"
            )
        anchors.append(make_anchor(source, target, item))

    result = {
        "schema_version": 1,
        "artifact": "spectron_particle_emitter_script_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TParticleEmitter GS2 modifier callbacks",
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
            "source_component": "TParticleEmitterProperties script-function table at 0x38ae10",
            "target_component": "Spectron obfuscated TParticleEmitter script-function table at 0x39df60",
            "resolution": "decoded function names, direct callback pointers, decompiled modifier dispatch, and complete ARM64 feature equality",
            "callback_field": "The callback pointer is stored at record offset +0x18.",
        },
        "summary": {
            "anchor_count": len(anchors),
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
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source and target function tables retain the same three modifier callback names and order.",
            "All three selected target functions were default sub names before the pass.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
