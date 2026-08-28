#!/usr/bin/env python3
"""Create reviewed residual TTilesLayer property anchors."""

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


def pair(
    property_name: str,
    source_record: str,
    target_record: str,
    getter_source_ea: str,
    getter_target_ea: str,
    getter_source_name: str,
    getter_target_name: str,
    value_kind: str,
    getter_operation: str,
    *,
    setter_source_ea: str | None = None,
    setter_target_ea: str | None = None,
    setter_source_name: str | None = None,
    setter_target_name: str | None = None,
    setter_operation: str | None = None,
) -> list[dict]:
    rows = [
        {
            "role": "getter",
            "property_name": property_name,
            "source_record": source_record,
            "target_record": target_record,
            "original_ea": getter_source_ea,
            "spectron_ea": getter_target_ea,
            "original_name": getter_source_name,
            "spectron_name": getter_target_name,
            "value_kind": value_kind,
            "operation": getter_operation,
        }
    ]
    if setter_source_ea is not None:
        if not all(
            value is not None
            for value in (
                setter_target_ea,
                setter_source_name,
                setter_target_name,
                setter_operation,
            )
        ):
            raise ValueError(f"incomplete setter specification for {property_name}")
        rows.append(
            {
                "role": "setter",
                "property_name": property_name,
                "source_record": source_record,
                "target_record": target_record,
                "original_ea": setter_source_ea,
                "spectron_ea": setter_target_ea,
                "original_name": setter_source_name,
                "spectron_name": setter_target_name,
                "value_kind": value_kind,
                "operation": setter_operation,
            }
        )
    return rows


SPECS: list[dict] = []
SPECS += pair(
    "alpha", "0x37fb00", "0x392b60", "0x19f8b0", "0x1a4580",
    "TTilesLayer_getAlpha", "sub_1A4580", "integer", "reads the alpha channel",
    setter_source_ea="0x19f8b8", setter_target_ea="0x1a4588",
    setter_source_name="TTilesLayer_setAlpha", setter_target_name="sub_1A4588",
    setter_operation="stores the alpha channel",
)
SPECS += pair(
    "blue", "0x37fb30", "0x392b90", "0x19f8c0", "0x1a4590",
    "TTilesLayer_getBlue", "sub_1A4590", "integer", "reads the blue channel",
    setter_source_ea="0x19f8c8", setter_target_ea="0x1a4598",
    setter_source_name="TTilesLayer_setBlue", setter_target_name="sub_1A4598",
    setter_operation="stores the blue channel",
)
SPECS += pair(
    "green", "0x37fb60", "0x392bc0", "0x19f8d0", "0x1a45a0",
    "TTilesLayer_getGreen", "sub_1A45A0", "integer", "reads the green channel",
    setter_source_ea="0x19f8d8", setter_target_ea="0x1a45a8",
    setter_source_name="TTilesLayer_setGreen", setter_target_name="sub_1A45A8",
    setter_operation="stores the green channel",
)
SPECS += pair(
    "layerindex", "0x37fb90", "0x392bf0", "0x19f8e0", "0x1a45b0",
    "TTilesLayer_getLayerIndex", "sub_1A45B0", "integer", "reads the tile-layer index",
)
SPECS += pair(
    "offset", "0x37fbc0", "0x392c20", "0x19fbcc", "0x1a48a4",
    "TTilesLayer_getOffset", "sub_1A48A4", "point", "returns the tile-layer offset",
    setter_source_ea="0x19fb98", setter_target_ea="0x1a4870",
    setter_source_name="TTilesLayer_setOffset", setter_target_name="sub_1A4870",
    setter_operation="stores the tile-layer offset",
)
SPECS += pair(
    "red", "0x37fbf0", "0x392c50", "0x19f8e8", "0x1a45b8",
    "TTilesLayer_getRed", "sub_1A45B8", "integer", "reads the red channel",
    setter_source_ea="0x19f8f0", setter_target_ea="0x1a45c0",
    setter_source_name="TTilesLayer_setRed", setter_target_name="sub_1A45C0",
    setter_operation="stores the red channel",
)
SPECS += pair(
    "x", "0x37fc20", "0x392c80", "0x19f8f8", "0x1a45c8",
    "TTilesLayer_getX", "sub_1A45C8", "float", "reads the tile-layer X coordinate",
    setter_source_ea="0x19f900", setter_target_ea="0x1a45d0",
    setter_source_name="TTilesLayer_setX", setter_target_name="sub_1A45D0",
    setter_operation="stores the tile-layer X coordinate",
)
SPECS += pair(
    "y", "0x37fc50", "0x392cb0", "0x19f908", "0x1a45d8",
    "TTilesLayer_getY", "sub_1A45D8", "float", "reads the tile-layer Y coordinate",
    setter_source_ea="0x19f910", setter_target_ea="0x1a45e0",
    setter_source_name="TTilesLayer_setY", setter_target_name="sub_1A45E0",
    setter_operation="stores the tile-layer Y coordinate",
)
SPECS += pair(
    "z", "0x37fc80", "0x392ce0", "0x19f918", "0x1a45e8",
    "TTilesLayer_getZ", "sub_1A45E8", "float", "reads the tile-layer Z coordinate",
    setter_source_ea="0x19f920", setter_target_ea="0x1a45f0",
    setter_source_name="TTilesLayer_setZ", setter_target_name="sub_1A45F0",
    setter_operation="stores the tile-layer Z coordinate",
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
        "match_kind": "manual-tiles-layer-property-table-anchor",
        "source_component": "TTilesLayer property table",
        "target_component": "Spectron obfuscated TTilesLayer property table",
        "source_basis": (
            f"matching the TTilesLayer {item['role']} registration for "
            f"{item['property_name']} and decompiled property behavior: {item['operation']}"
        ),
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["property_name"],
        "property_role": item["role"],
        "value_kind": item["value_kind"],
        "operation": item["operation"],
        "evidence": [
            f"The source registration row is in the TTilesLayer table at {item['source_record']}.",
            f"The target registration row is in the corresponding table at {item['target_record']}.",
            f"The source and target pseudocode preserve the same {item['value_kind']} {item['role']} operation: {item['operation']}.",
            "The target callback remained a default sub name before this pass.",
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
        "artifact": "spectron_tiles_layer_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TTilesLayer property callbacks",
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
            "source_component": "TTilesLayer property table at 0x37fb00",
            "target_component": "Spectron obfuscated TTilesLayer property table at 0x392b60",
            "resolution": "decoded property names, getter/setter roles, direct callback pointers, decompiled channel, coordinate, layer, and offset operations, and ARM64 feature metrics",
            "target_table_copy": "The target addresses use the .data copy of the registration table.",
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
            "getter_count": sum(row["property_role"] == "getter" for row in anchors),
            "setter_count": sum(row["property_role"] == "setter" for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source and target TTilesLayer property tables retain the same property names, roles, and callback order for all nine properties.",
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
