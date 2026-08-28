#!/usr/bin/env python3
"""Create reviewed anchors for residual TClient script-property callbacks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x1eaff8",
        "0x1ef660",
        "TClient_setBigFileSizeAndContinue",
        "sub_1EF660",
        "tclient_downloadsetsize",
        "0x384b30",
        "0x397b90",
        "TClient",
        "w6qzgacqqy",
        "stores the big-file size and advances the download action",
    ),
    (
        "0x1eb4c0",
        "0x1efb64",
        "TGUIScriptLoader_finishServerListConnect",
        "sub_1EFB64",
        "tclient_setserverlisterconnect",
        "0x3847d0",
        "0x397830",
        "TGUIScriptLoader",
        "s_viIa9wbT",
        "hides the connecting window, invokes onServerListerConnect, and sets the reconnect state",
    ),
    (
        "0x1eb890",
        "0x1eff68",
        "TClient_setPlayerFlagValueNullName",
        "sub_1EFF68",
        "tclient_unsetflagdata",
        "0x384980",
        "0x3979e0",
        "TClient",
        "mTAogaaEip",
        "forwards a flag update with a null name argument",
    ),
    (
        "0x1eb898",
        "0x1eff70",
        "TClient_setPlayerFlagValueEmptyName",
        "sub_1EFF70",
        "tclient_setflagdata",
        "0x384950",
        "0x3979b0",
        "TClient",
        "mTAogaaEip",
        "forwards a flag update with the empty or dummy name argument",
    ),
    (
        "0x1eb8bc",
        "0x1eff94",
        "TClient_addWeaponForActivePlayer",
        "sub_1EFF94",
        "tclient_setweapon",
        "0x384890",
        "0x3978f0",
        "TClient",
        "W6NzgawMJy",
        "forwards two weapon strings to the active player when present",
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
    (
        source_ea,
        target_ea,
        source_name,
        target_name,
        script_name,
        source_table,
        target_table,
        source_component,
        target_component,
        operation,
    ) = spec
    if source["name"] != source_name:
        raise ValueError(f"unexpected source name at {source_ea}: {source['name']}")
    if target["name"] != target_name:
        raise ValueError(f"unexpected target name at {target_ea}: {target['name']}")
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    normalized_equal = all(
        source[field] == target[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    full_metric_equal = source_metrics == target_metrics
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
        "match_kind": "manual-tclient-script-property-anchor",
        "source_component": source_component,
        "target_component": target_component,
        "source_basis": f"script property-table entry {script_name}; {operation}",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ],
        "source_script_table_record": source_table,
        "target_script_table_record": target_table,
        "evidence": [
            f"The source registration record for {script_name} is at {source_table}.",
            f"The target registration record for {script_name} is at {target_table}.",
            f"The source and target pseudocode preserve the same operation: {operation}.",
            "The target remains in the same TClient script-property table block as the surrounding translated callbacks.",
            (
                "All recorded normalized and complete function metrics match exactly."
                if normalized_equal and full_metric_equal
                else "The semantic operation is preserved, while the metric record retains the target wrapper or register-layout difference."
            ),
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
        "artifact": "spectron_tclient_script_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TClient script-property callbacks",
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
            "source_component": "TClient script-property table",
            "target_component": "obfuscated TClient callback block",
            "resolution": "decoded registration names, source and target table records, class-local order, decompiled behavior, and explicit wrapper-change accounting",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "normalized_shape_exact_count": sum(row["normalized_shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(not row["normalized_shape_equal"] for row in anchors),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
        },
        "anchors": anchors,
        "reviewed_target_only_rows": [],
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ labels preserve readable 1.8 roles while the target ABI names remain in each row.",
            "The table names are retained as direct evidence because the target implementation uses rebuilt helper classes and obfuscated callback families.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
