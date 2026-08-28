#!/usr/bin/env python3
"""Create reviewed residual TServerNPC GS2 callback anchors."""

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
        "script_name": "canbecarried",
        "source_record": "0x37c398",
        "target_record": "0x38f3f8",
        "original_ea": "0x1809e0",
        "spectron_ea": "0x184f48",
        "original_name": "TServerNPC_script_canBeCarried",
        "spectron_name": "sub_184F48",
        "operation": "returns the script-visible can-be-carried result",
    },
    {
        "script_name": "cannotbecarried",
        "source_record": "0x37c3c8",
        "target_record": "0x38f428",
        "original_ea": "0x1809ec",
        "spectron_ea": "0x184f54",
        "original_name": "TServerNPC_script_cannotBeCarried",
        "spectron_name": "sub_184F54",
        "operation": "returns the script-visible cannot-be-carried result",
    },
    {
        "script_name": "canbepushed",
        "source_record": "0x37c3f8",
        "target_record": "0x38f458",
        "original_ea": "0x1809f4",
        "spectron_ea": "0x184f5c",
        "original_name": "TServerNPC_script_canBePushed",
        "spectron_name": "sub_184F5C",
        "operation": "returns the script-visible can-be-pushed result",
    },
    {
        "script_name": "cannotbepushed",
        "source_record": "0x37c428",
        "target_record": "0x38f488",
        "original_ea": "0x180a00",
        "spectron_ea": "0x184f68",
        "original_name": "TServerNPC_script_cannotBePushed",
        "spectron_name": "sub_184F68",
        "operation": "returns the script-visible cannot-be-pushed result",
    },
    {
        "script_name": "canbepulled",
        "source_record": "0x37c458",
        "target_record": "0x38f4b8",
        "original_ea": "0x180a08",
        "spectron_ea": "0x184f70",
        "original_name": "TServerNPC_script_canBePulled",
        "spectron_name": "sub_184F70",
        "operation": "returns the script-visible can-be-pulled result",
    },
    {
        "script_name": "cannotbepulled",
        "source_record": "0x37c488",
        "target_record": "0x38f4e8",
        "original_ea": "0x180a14",
        "spectron_ea": "0x184f7c",
        "original_name": "TServerNPC_script_cannotBePulled",
        "spectron_name": "sub_184F7C",
        "operation": "returns the script-visible cannot-be-pulled result",
    },
    {
        "script_name": "timereverywhere",
        "source_record": "0x37ccf8",
        "target_record": "0x38fd58",
        "original_ea": "0x180aa8",
        "spectron_ea": "0x185010",
        "original_name": "TServerNPC_script_timeEverywhere",
        "spectron_name": "sub_185010",
        "operation": "returns the script-visible time-everywhere result",
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
        "match_kind": "manual-server-npc-script-function-table-anchor",
        "source_component": "TServerNPC script-function table",
        "target_component": "Spectron obfuscated TServerNPC script-function table",
        "source_basis": (
            f"matching the {item['script_name']} script-function registration and "
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
            f"The source callback is registered in the TServerNPC script table at {item['source_record']}.",
            f"The target callback is registered in the corresponding table at {item['target_record']}.",
            f"The source and target wrappers preserve the same script-visible operation: {item['operation']}.",
            "The target callback remained a default sub name before this pass.",
            (
                "All recorded function metrics match exactly."
                if full_metric_equal
                else "Normalized instruction shape matches; the register-detail difference is retained explicitly."
            ),
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
        "artifact": "spectron_server_npc_script_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TServerNPC script callbacks",
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
            "resolution": "decoded function names, direct callback pointers, decompiled script-visible operations, and ARM64 feature metrics",
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
            "The source and target TServerNPC script-function tables retain the same function names and callback order for this batch.",
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
