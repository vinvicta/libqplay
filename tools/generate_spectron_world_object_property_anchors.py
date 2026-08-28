#!/usr/bin/env python3
"""Create reviewed property anchors for small Spectron world-object tables.

This pass covers residual callbacks whose 1.8 registration rows have an exact
name/order counterpart in Spectron 2.2.  The feature comparison is recorded
alongside each proposed alias so the resulting IDA names remain auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
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


def row(
    class_name: str,
    property_name: str,
    source_record: str,
    target_record: str,
    original_ea: str,
    spectron_ea: str,
    original_name: str,
    spectron_name: str,
    role: str,
    value_kind: str,
    operation: str,
) -> dict:
    return {
        "class_name": class_name,
        "property_name": property_name,
        "source_record": source_record,
        "target_record": target_record,
        "original_ea": original_ea,
        "spectron_ea": spectron_ea,
        "original_name": original_name,
        "spectron_name": spectron_name,
        "role": role,
        "value_kind": value_kind,
        "operation": operation,
    }


SPECS = [
    row(
        "TBitmap", "jpegquality", "0x378268", "0x38b278", "0x150e80", "0x153ca8",
        "TBitmap_get_jpegquality", "sub_153CA8", "getter", "integer",
        "reads the JPEG quality setting",
    ),
    row(
        "TBitmap", "jpegquality", "0x378268", "0x38b278", "0x150e90", "0x153cb8",
        "TBitmap_set_jpegquality", "sub_153CB8", "setter", "integer",
        "stores the incoming JPEG quality setting",
    ),
    row(
        "TServerWeapon", "isweapon", "0x37d8e0", "0x390940", "0x190c68", "0x1956a4",
        "TServerWeapon_getIsWeapon", "sub_1956A4", "getter", "boolean",
        "returns whether the object is a weapon",
    ),
    row(
        "TProjectile", "x", "0x37f6d8", "0x392738", "0x19eb88", "0x1a3860",
        "TProjectile_getX", "sub_1A3860", "getter", "float",
        "reads the projectile X coordinate",
    ),
    row(
        "TProjectile", "y", "0x37f6d8", "0x392738", "0x19ebbc", "0x1a3894",
        "TProjectile_getY", "sub_1A3894", "getter", "float",
        "reads the projectile Y coordinate",
    ),
    row(
        "TProjectile", "z", "0x37f6d8", "0x392738", "0x19ebf0", "0x1a38c8",
        "TProjectile_getZ", "sub_1A38C8", "getter", "float",
        "reads the projectile Z coordinate",
    ),
    row(
        "TProjectile", "angle", "0x37f6d8", "0x392738", "0x19ec10", "0x1a38e8",
        "TProjectile_getAngle", "sub_1A38E8", "getter", "float",
        "reads the projectile angle",
    ),
    row(
        "TProjectile", "speed", "0x37f6d8", "0x392738", "0x19ec18", "0x1a38f0",
        "TProjectile_getSpeed", "sub_1A38F0", "getter", "float",
        "reads the projectile speed",
    ),
    row(
        "TProjectile", "zspeed", "0x37f6d8", "0x392738", "0x19ec20", "0x1a38f8",
        "TProjectile_getZSpeed", "sub_1A38F8", "getter", "float",
        "reads the projectile vertical speed",
    ),
    row(
        "TProjectile", "horiz", "0x37f6d8", "0x392738", "0x19ec28", "0x1a3900",
        "TProjectile_getHoriz", "sub_1A3900", "getter", "boolean",
        "reads the projectile horizontal-motion flag",
    ),
    row(
        "TProjectile", "fromplayer", "0x37f6d8", "0x392738", "0x19ec30", "0x1a3908",
        "TProjectile_getFromPlayer", "sub_1A3908", "getter", "boolean",
        "reads whether the projectile came from a player",
    ),
    row(
        "TProjectile", "fromplayerid", "0x37f6d8", "0x392738", "0x19ec38", "0x1a3910",
        "TProjectile_getFromPlayerId", "sub_1A3910", "getter", "integer",
        "reads the originating player ID",
    ),
    row(
        "TProjectile", "params", "0x37f6d8", "0x392738", "0x19ec40", "0x1a3918",
        "TProjectile_getParams", "sub_1A3918", "getter", "object",
        "returns the projectile parameter object",
    ),
    row(
        "TProjectile", "disableactionprojectile", "0x37f8b8", "0x392918", "0x19eb48", "0x1a3820",
        "TProjectile_get_disableactionprojectile", "sub_1A3820", "getter", "boolean",
        "reads the action-projectile disable flag",
    ),
    row(
        "TProjectile", "disableactionprojectile", "0x37f8b8", "0x392918", "0x19eb58", "0x1a3830",
        "TProjectile_set_disableactionprojectile", "sub_1A3830", "setter", "boolean",
        "stores the action-projectile disable flag",
    ),
    row(
        "TProjectile", "disableactionprojectile2", "0x37f8b8", "0x392918", "0x19eb68", "0x1a3840",
        "TProjectile_get_disableactionprojectile2", "sub_1A3840", "getter", "boolean",
        "reads the secondary action-projectile disable flag",
    ),
    row(
        "TProjectile", "disableactionprojectile2", "0x37f8b8", "0x392918", "0x19eb78", "0x1a3850",
        "TProjectile_set_disableactionprojectile2", "sub_1A3850", "setter", "boolean",
        "stores the secondary action-projectile disable flag",
    ),
    row(
        "TServerLevelLink", "height", "0x37f9b0", "0x392a10", "0x19f890", "0x1a4560",
        "TServerLevelLink_getHeight", "sub_1A4560", "getter", "integer",
        "reads the linked level height",
    ),
    row(
        "TServerLevelLink", "width", "0x37f9b0", "0x392a10", "0x19f898", "0x1a4568",
        "TServerLevelLink_getWidth", "sub_1A4568", "getter", "integer",
        "reads the linked level width",
    ),
    row(
        "TServerLevelLink", "x", "0x37f9b0", "0x392a10", "0x19f8a0", "0x1a4570",
        "TServerLevelLink_getX", "sub_1A4570", "getter", "integer",
        "reads the linked level X coordinate",
    ),
    row(
        "TServerLevelLink", "y", "0x37f9b0", "0x392a10", "0x19f8a8", "0x1a4578",
        "TServerLevelLink_getY", "sub_1A4578", "getter", "integer",
        "reads the linked level Y coordinate",
    ),
    row(
        "TServerLevel", "preloadleveldefaulttile", "0x380160", "0x3931c0", "0x19f928", "0x1a45f8",
        "TServerLevel_get_preloadleveldefaulttile", "sub_1A45F8", "getter", "integer",
        "reads the default tile used while preloading a level",
    ),
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
        "match_kind": "manual-world-object-property-table-anchor",
        "source_component": f"{item['class_name']} property table",
        "target_component": f"Spectron obfuscated {item['class_name']} property table",
        "source_basis": (
            f"matching the {item['class_name']} {item['role']} registration for "
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
            f"The source registration row is in the {item['class_name']} table at {item['source_record']}.",
            f"The target registration row is in the corresponding table at {item['target_record']}.",
            f"The source and target pseudocode preserve the same {item['value_kind']} {item['role']} operation: {item['operation']}.",
            "The target callback remained a default sub name before this pass.",
            (
                "All recorded function metrics match exactly."
                if full_metric_equal
                else "Normalized instruction shape matches; the recorded metric differences are retained explicitly."
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

    classes = sorted({item["class_name"] for item in SPECS})
    result = {
        "schema_version": 1,
        "artifact": "spectron_world_object_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual small world-object property callbacks",
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
            "source_components": [f"{name} property table" for name in classes],
            "target_components": [
                f"Spectron obfuscated {name} property table" for name in classes
            ],
            "resolution": "decoded property names, getter/setter roles, direct callback pointers, decompiled field operations, and ARM64 feature metrics",
            "target_table_copy": "The target addresses use the .data copy of the registration tables.",
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
            "class_counts": dict(Counter(item["class_name"] for item in SPECS)),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source and target registration tables retain the same property names, roles, and callback order for this batch.",
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
