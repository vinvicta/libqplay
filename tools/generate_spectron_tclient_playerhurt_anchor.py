#!/usr/bin/env python3
"""Create the reviewed boundary-recovery anchor for tclient_setplayerhurt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPEC = {
    "original_ea": "0x1ed158",
    "original_name": "TClient_script_tclient_setplayerhurt",
    "original_function_end": "0x1ed1e4",
    "spectron_ea": "0x1f1b08",
    "spectron_current_name": "loc_1F1B08",
    "spectron_function_end": "0x1f1b94",
    "proposed_name": "v18_TClient_script_tclient_setplayerhurt",
    "source_script_table_record": "0x384fb0",
    "target_script_table_record": "0x398010",
    "target_callback_xref": "0x398028",
}


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
    fields = (
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
    return {field: row.get(field) for field in fields}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original = by_ea(load(args.original_features))
    source = original.get(SPEC["original_ea"])
    if source is None:
        raise ValueError("missing source feature row for 0x1ed158")
    if source["name"] != SPEC["original_name"]:
        raise ValueError("unexpected source name at 0x1ed158")
    if source["end_ea"] != SPEC["original_function_end"]:
        raise ValueError("unexpected source boundary at 0x1ed158")

    anchor = {
        **SPEC,
        "original_metrics": metric_record(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_default_name": True,
        "confidence": "high",
        "match_kind": "manual-tclient-property-boundary-anchor",
        "source_component": "TClient script-property table",
        "target_component": "obfuscated TClient property callback",
        "source_basis": "matching tclient_setplayerhurt property registration, active-player guard, no-hurt check, and hurtPlayer tail call",
        "target_evidence": [
            "The target property-table record at 0x398010 names tclient_setplayerhurt and stores the callback pointer at 0x398028.",
            "The target raw entry at 0x1f1b08 checks the active-player singleton, object state, and the target no-hurt byte before returning or continuing.",
            "The continuation calls the target no-hurt virtual helper, preserves the script arguments, and tail-branches to v18_TClient_hurtPlayer at 0x1f1b90.",
            "The next known target function begins at 0x1f1b94, so 0x1f1b08-0x1f1b94 is the recovered callback boundary.",
        ],
        "operation": "guards a scripted player-hurt request and forwards eligible requests to the client hurtPlayer routine",
        "normalized_shape_equal": False,
        "full_metric_equal": False,
        "metric_comparison_status": "target boundary was absent from the v232 feature export, so target feature metrics will be captured after IDA materializes the reviewed range",
        "name_action": "add-reviewed-boundary-and-rename-with-v18-prefix",
    }

    result = {
        "schema_version": 1,
        "artifact": "spectron_tclient_playerhurt_property_manual_translation_anchor_20260828",
        "scope": "reviewed 1.8-to-Spectron anchor requiring target function-boundary recovery for tclient_setplayerhurt",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "source_component": "TClient script-property table",
            "target_component": "obfuscated TClient property callback",
            "target_boundary_reason": "IDA had no function boundary at the callback pointer, while the raw control flow and next known function identify the complete range",
            "resolution": "decoded property name, direct callback pointer, raw ARM64 control flow, source callback behavior, and recovered target boundary",
        },
        "summary": {
            "anchor_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": 1,
            "boundary_recovery_count": 1,
            "normalized_shape_exact_count": 0,
            "full_metric_exact_count": 0,
            "layout_change_count": 1,
        },
        "anchors": [anchor],
        "interpretation": [
            "The target callback is a reviewed 1.8-to-Spectron semantic anchor, not a byte-for-byte claim.",
            "The target boundary is intentionally materialized from direct property-table and control-flow evidence.",
            "Target layout changes are expected because the active-player singleton and no-hurt field moved in the rebuilt library.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
