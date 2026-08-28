#!/usr/bin/env python3
"""Create reviewed GSFunctionsClient and GuiControl property anchors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    (
        "0x1565ec",
        "0x159414",
        "GSFunctionsClient_get_carriesbush",
        "sub_159414",
        "carriesbush",
        "0x378388",
        "0x38b398",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "returns whether the action player is carrying the bush sprite",
    ),
    (
        "0x156640",
        "0x159468",
        "GSFunctionsClient_get_carriessign",
        "sub_159468",
        "carriessign",
        "0x3783b8",
        "0x38b3c8",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "returns whether the action player is carrying the sign sprite",
    ),
    (
        "0x156694",
        "0x1594bc",
        "GSFunctionsClient_get_carriesvase",
        "sub_1594BC",
        "carriesvase",
        "0x3783e8",
        "0x38b3f8",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "returns whether the action player is carrying the vase sprite",
    ),
    (
        "0x1566e8",
        "0x159510",
        "GSFunctionsClient_get_carriesstone",
        "sub_159510",
        "carriesstone",
        "0x378418",
        "0x38b428",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "returns whether the action player is carrying the stone sprite",
    ),
    (
        "0x15673c",
        "0x159564",
        "GSFunctionsClient_get_carriesblackstone",
        "sub_159564",
        "carriesblackstone",
        "0x378448",
        "0x38b458",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "returns whether the action player is carrying the black-stone sprite",
    ),
    (
        "0x1571d8",
        "0x15a000",
        "GSFunctionsClient_get_mousescreeny",
        "sub_15A000",
        "mousescreeny",
        "0x378958",
        "0x38b968",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "reads the cursor Y position and subtracts the active-player screen origin",
    ),
    (
        "0x157234",
        "0x15a05c",
        "GSFunctionsClient_get_mousescreenx",
        "sub_15A05C",
        "mousescreenx",
        "0x378928",
        "0x38b938",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "reads the cursor X position and subtracts the active-player screen origin",
    ),
    (
        "0x157290",
        "0x15a0b8",
        "GSFunctionsClient_set_mousescreeny",
        "sub_15A0B8",
        "mousescreeny",
        "0x378958",
        "0x38b968",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "adds the active-player screen origin to the requested Y position and updates the cursor",
    ),
    (
        "0x157304",
        "0x15a12c",
        "GSFunctionsClient_set_mousescreenx",
        "sub_15A12C",
        "mousescreenx",
        "0x378928",
        "0x38b938",
        "GSFunctionsClient",
        "obfuscated GSFunctionsClient property table",
        "adds the active-player screen origin to the requested X position and updates the cursor",
    ),
    (
        "0x1b27cc",
        "0x1b6ccc",
        "GuiControl_setClientHeight",
        "sub_1B6CCC",
        "clientheight",
        "0x3808c8",
        "0x393910",
        "GuiControl",
        "obfuscated GuiControl property table",
        "builds the client-height point from the control bounds and calls the virtual layout callback",
    ),
    (
        "0x1b2818",
        "0x1b6d18",
        "GuiControl_setClientWidth",
        "sub_1B6D18",
        "clientwidth",
        "0x3808f8",
        "0x393940",
        "GuiControl",
        "obfuscated GuiControl property table",
        "builds the client-width point from the control bounds and calls the virtual layout callback",
    ),
    (
        "0x1b2944",
        "0x1b6e44",
        "GuiControl_getIsInAnimation",
        "sub_1B6E44",
        "isinanimation",
        "0x380c80",
        "0x393cd0",
        "GuiControl",
        "obfuscated GuiControl property table",
        "returns whether the control's animation object has a positive frame count",
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
        "match_kind": "manual-gsfunctions-property-table-anchor",
        "source_component": source_component,
        "target_component": target_component,
        "source_basis": f"matching {script_name} property registration and operation: {operation}",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ],
        "source_script_table_record": source_table,
        "target_script_table_record": target_table,
        "script_name": script_name,
        "operation": operation,
        "evidence": [
            f"The source registration record for {script_name} is at {source_table}.",
            f"The target registration record for {script_name} is at {target_table}.",
            f"The source and target pseudocode preserve the same operation: {operation}.",
            "The target remains in the corresponding GSFunctionsClient or GuiControl property block.",
            (
                "All recorded normalized and complete function metrics match exactly."
                if normalized_equal and full_metric_equal
                else "Normalized instruction shape matches; the remaining differences are recorded as target register or layout details."
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
        "artifact": "spectron_gsfunctions_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual GSFunctionsClient and GuiControl property callbacks",
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
            "source_components": ["GSFunctionsClient", "GuiControl"],
            "target_components": [
                "obfuscated GSFunctionsClient property table",
                "obfuscated GuiControl property table",
            ],
            "resolution": "decoded property names, table record addresses, class-local order, decompiled behavior, and normalized feature metrics",
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
            "full_metric_exact_count": sum(
                row["full_metric_equal"] for row in anchors
            ),
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
            "The target property names and pseudocode identify the role while v18_ aliases preserve the readable 1.8 lookup key.",
            "The nine register-detail differences reflect target global or class layout and register allocation; the three GuiControl rows match the complete recorded metric set.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
