#!/usr/bin/env python3
"""Create reviewed labels for Spectron callbacks with no proven 1.8 source pair.

These rows are deliberately kept out of the 1.8-to-Spectron mapping count. The
evidence comes from the target's decoded property-table names, callback
locations, and pseudocode rather than from a source address correspondence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x1f00f8",
        "sub_1F00F8",
        "0x1f01e0",
        "spectron_setdebugdatahandlers",
        "setdebugdatahandlers",
        "0x398670",
        "0x398688",
        "w6qzgacqqy::kr8GxaAIUX",
        "debug-handler table",
        "zeros the 1024-byte debug-handler table and copies at most 256 integer values from the array-like callback argument",
    ),
    (
        "0x1f0010",
        "sub_1F0010",
        "0x1f00f8",
        "spectron_adventure_setdebugdatahandlersauthorization",
        "adventure_setdebugdatahandlersauthorization",
        "0x3986a0",
        "0x3986b8",
        "w6qzgacqqy::nz6Gxas8SX",
        "debug-handler authorization table",
        "zeros the 1024-byte debug-handler authorization table and copies at most 256 integer values from the array-like callback argument",
    ),
    (
        "0x1f2160",
        "sub_1F2160",
        "0x1f2170",
        "spectron_tclient_setotherplayerprops_adapter",
        "tclient_setotherplayerprops",
        "0x398430",
        "0x398448",
        None,
        "TClient property ABI adapter",
        "checks that the result value is positive and then forwards the callback to the translated updateGlobalPlayer body",
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


def make_label(target: dict, spec: tuple[str, ...]) -> dict:
    (
        target_ea,
        current_name,
        function_end,
        proposed_name,
        script_name,
        table_record,
        callback_xref,
        target_global,
        target_role,
        operation,
    ) = spec
    if target["name"] != current_name:
        raise ValueError(f"unexpected target name at {target_ea}: {target['name']}")
    if target["end_ea"] != function_end:
        raise ValueError(
            f"unexpected target boundary at {target_ea}: {target['end_ea']}"
        )
    return {
        "target_ea": target_ea,
        "current_name": current_name,
        "function_end": function_end,
        "proposed_name": proposed_name,
        "target_default_name": target.get("is_default_name", False),
        "target_metrics": metric_record(target),
        "target_string_refs": target.get("string_refs", []),
        "target_direct_call_names": target.get("direct_call_names", []),
        "script_name": script_name,
        "target_property_table_record": table_record,
        "target_callback_xref": callback_xref,
        "target_global": target_global,
        "target_role": target_role,
        "operation": operation,
        "source_counterpart": None,
        "source_counterpart_status": "not-demonstrated",
        "confidence": "high",
        "match_kind": "reviewed-target-only-callback-label",
        "evidence": [
            f"The decoded target property-table record for {script_name} is at {table_record}.",
            f"The record points to this callback through the target xref at {callback_xref}.",
            f"Target pseudocode shows that it {operation}.",
            "No 1.8 source registration or source address is claimed for this row.",
        ],
        "name_action": "rename-with-spectron-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    spectron = by_ea(load(args.spectron_features))
    labels = []
    for spec in SPECS:
        target = spectron.get(spec[0])
        if target is None:
            raise ValueError(f"missing target feature row for {spec[0]}")
        labels.append(make_label(target, spec))

    result = {
        "schema_version": 1,
        "artifact": "spectron_target_only_callback_labels_20260828",
        "scope": "reviewed descriptive labels for three Spectron 2.2 property callbacks without a demonstrated 1.8 source counterpart",
        "network_contacted": False,
        "inputs": {
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "target_components": [
                "w6qzgacqqy property tables",
                "TClient property ABI",
            ],
            "resolution": "decoded target property names, direct table-record xrefs, function boundaries, target metrics, and reviewed pseudocode",
            "mapping_boundary": "These labels describe target behavior only. They are not 1.8-to-Spectron correspondences and are excluded from the source mapping count.",
        },
        "summary": {
            "label_count": len(labels),
            "high_confidence_count": sum(
                row["confidence"] == "high" for row in labels
            ),
            "target_default_name_count": sum(
                row["target_default_name"] for row in labels
            ),
            "source_counterpart_count": sum(
                row["source_counterpart"] is not None for row in labels
            ),
            "target_only_count": len(labels),
            "debug_handler_count": sum(
                row["target_role"] == "debug-handler table" or "debug-handler" in row["target_role"]
                for row in labels
            ),
            "adapter_count": sum(
                row["target_role"] == "TClient property ABI adapter" for row in labels
            ),
        },
        "labels": labels,
        "interpretation": [
            "The spectron_ prefix marks a target-specific descriptive label rather than a restored 1.8 symbol.",
            "The two debug-handler callbacks copy bounded integer arrays into separate target globals.",
            "The tclient_setotherplayerprops callback is an ABI adapter around the separately translated updateGlobalPlayer implementation.",
            "No source counterpart is counted for any row in this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
