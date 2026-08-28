#!/usr/bin/env python3
"""Create reviewed TServerNPC showimg and showimg2 anchors."""

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
        "script_name": "showimg",
        "source_record": "0x37cb48",
        "target_record": "0x38fba8",
        "original_ea": "0x182f44",
        "spectron_ea": "0x1875a0",
        "original_name": "TServerNPC_script_showImg",
        "spectron_name": "sub_1875A0",
        "argument_shape": "image index, image string, X, Y",
        "operation": "looks up or creates a TShowImg entry, resets its image part, assigns the image and position, and refreshes the owning object",
    },
    {
        "script_name": "showimg2",
        "source_record": "0x37cb78",
        "target_record": "0x38fbd8",
        "original_ea": "0x182c84",
        "spectron_ea": "0x18742c",
        "original_name": "TServerNPC_script_showImg2",
        "spectron_name": "sub_18742C",
        "argument_shape": "image index, image string, X, Y, Z",
        "operation": "looks up or creates a TShowImg entry, resets its image part, assigns the image and three coordinates, and returns the entry",
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
    return {item["ea"].lower(): item for item in document["functions"]}


def metrics(item: dict) -> dict:
    return {field: item.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, item: dict) -> dict:
    if source["name"] != item["original_name"]:
        raise ValueError(f"unexpected source name at {item['original_ea']}: {source['name']}")
    if target["name"] != item["spectron_name"]:
        raise ValueError(f"unexpected target name at {item['spectron_ea']}: {target['name']}")
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {item['spectron_ea']}")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source_metrics[field] == target_metrics[field] for field in NORMALIZED_METRICS
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
        "match_kind": "manual-server-npc-showimg-function-table-anchor",
        "source_component": "TServerNPC script-function table",
        "target_component": "Spectron obfuscated TServerNPC script-function table",
        "source_basis": (
            f"matching the {item['script_name']} script-function registration, its "
            f"{item['argument_shape']} argument shape, and decompiled operation: {item['operation']}"
        ),
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["script_name"],
        "argument_shape": item["argument_shape"],
        "operation": item["operation"],
        "evidence": [
            f"The source callback is registered in the TServerNPC script table at {item['source_record']}.",
            f"The target callback is registered in the corresponding table at {item['target_record']}.",
            f"Both pseudocode bodies preserve the {item['argument_shape']} path and the same high-level operation.",
            "The target callback remained a default sub name before this pass.",
            "The target uses an explicit temporary string assignment and cleanup around the image argument, accounting for the body expansion.",
            "The metric and shape differences are retained explicitly rather than hidden by the alias.",
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
        "artifact": "spectron_server_npc_showimg_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TServerNPC showimg callbacks",
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
            "source_component": "TServerNPC script-function table at 0x37c308",
            "target_component": "Spectron obfuscated TServerNPC script-function table at 0x38f368",
            "resolution": "decoded function names, direct callback pointers, decompiled image-list behavior, and ARM64 feature metrics",
            "callback_field": "The callback pointer is stored at record offset +0x18.",
            "comparison_note": "The target rebuild makes the image-string temporary explicit, so normalized instruction shape and complete metrics differ while the registration and operation remain aligned.",
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
            "The source and target TServerNPC script-function tables retain the same showimg names and callback order for this pair.",
            "The target image-string wrapper is a target-version implementation detail, not evidence of a different script operation.",
            "The target functions were default sub names before the pass and are renamed with the original 1.8 symbol plus a v18 prefix.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
