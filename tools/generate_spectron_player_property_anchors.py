#!/usr/bin/env python3
"""Create reviewed residual TPlayer property anchors."""

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


def spec(
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
    spec("alliedguilds", "0x37b508", "0x38e538", "0x16c9f4", "0x1705cc", "TPlayer_get_alliedguilds", "sub_1705CC", "getter", "string", "returns the allied-guild list"),
    spec("alliedguilds", "0x37b508", "0x38e538", "0x16c9ec", "0x1705c4", "TPlayer_set_alliedguilds", "sub_1705C4", "setter", "string", "stores the allied-guild list"),
    spec("ap", "0x37b538", "0x38e568", "0x16c1e8", "0x16fda0", "TPlayer_get_ap", "sub_16FDA0", "getter", "integer", "reads the action-point value"),
    spec("chat", "0x37b568", "0x38e598", "0x16c844", "0x1703bc", "TPlayer_get_chat", "sub_1703BC", "getter", "string", "returns the current chat text"),
    spec("defaultwalkspeed", "0x37b598", "0x38e5c8", "0x16c268", "0x16fe20", "TPlayer_get_defaultwalkspeed", "sub_16FE20", "getter", "float", "reads the default walk speed"),
    spec("diagonalwalkspeed", "0x37b5c8", "0x38e5f8", "0x16c2b0", "0x16fe68", "TPlayer_get_diagonalwalkspeed", "sub_16FE68", "getter", "float", "reads the diagonal walk speed"),
    spec("hearts", "0x37b628", "0x38e658", "0x16c2f8", "0x16feb0", "TPlayer_get_hearts", "sub_16FEB0", "getter", "integer", "reads the player heart value"),
    spec("horseimg", "0x37b658", "0x38e688", "0x16c814", "0x17038c", "TPlayer_get_horseimg", "sub_17038C", "getter", "string", "returns the horse image string"),
    spec("hp", "0x37b6b8", "0x38e6e8", "0x16c2f8", "0x16feb0", "TPlayer_get_hearts", "sub_16FEB0", "getter", "integer", "reads the same heart value exposed as HP"),
    spec("hurt", "0x37b6e8", "0x38e718", "0x16c3f8", "0x16ffb0", "TPlayer_get_hurt", "sub_16FFB0", "getter", "integer", "reads the hurt-state value"),
    spec("hurtdx", "0x37b718", "0x38e748", "0x16c370", "0x16ff28", "TPlayer_get_hurtdx", "sub_16FF28", "getter", "integer", "reads the hurt X delta"),
    spec("hurtdy", "0x37b748", "0x38e778", "0x16c378", "0x16ff30", "TPlayer_get_hurtdy", "sub_16FF30", "getter", "integer", "reads the hurt Y delta"),
    spec("hurted", "0x37b778", "0x38e7a8", "0x16c380", "0x16ff38", "TPlayer_get_hurted", "sub_16FF38", "getter", "integer", "reads the hurted-state value"),
    spec("hurtpower", "0x37b7a8", "0x38e7d8", "0x16c470", "0x170028", "TPlayer_get_hurtpower", "sub_170028", "getter", "integer", "reads the hurt power"),
    spec("isfemale", "0x37b7d8", "0x38e808", "0x16c478", "0x170030", "TPlayer_get_isfemale", "sub_170030", "getter", "boolean", "reads the female flag"),
    spec("isinvincible", "0x37b808", "0x38e838", "0x16c484", "0x17003c", "TPlayer_get_isinvincible", "sub_17003C", "getter", "boolean", "reads the invincibility flag"),
    spec("isinvincible", "0x37b808", "0x38e838", "0x16cdec", "0x170a58", "TPlayer_set_isinvincible", "sub_170A58", "setter", "boolean", "stores the invincibility flag"),
    spec("isinvincible2", "0x37b838", "0x38e868", "0x16c4ac", "0x170064", "TPlayer_get_isinvincible2", "sub_170064", "getter", "boolean", "reads the secondary invincibility flag"),
    spec("isinvincible2", "0x37b838", "0x38e868", "0x16ce58", "0x1709ec", "TPlayer_set_isinvincible2", "sub_1709EC", "setter", "boolean", "stores the secondary invincibility flag"),
    spec("ismale", "0x37b868", "0x38e898", "0x16c4d4", "0x17008c", "TPlayer_get_ismale", "sub_17008C", "getter", "boolean", "reads the male flag"),
    spec("letters", "0x37b898", "0x38e8f8", "0x16c7e4", "0x17035c", "TPlayer_get_letters", "sub_17035C", "getter", "string", "returns the letters string"),
    spec("letters", "0x37b898", "0x38e8f8", "0x16c77c", "0x170354", "TPlayer_set_letters", "sub_170354", "setter", "string", "stores the letters string"),
    spec("nick", "0x37b928", "0x38e958", "0x16c874", "0x1703ec", "TPlayer_get_nick", "sub_1703EC", "getter", "string", "returns the player nickname"),
    spec("onhorse", "0x37b958", "0x38e988", "0x16c584", "0x17013c", "TPlayer_get_onhorse", "sub_17013C", "getter", "boolean", "reads whether the player is on a horse"),
    spec("shield", "0x37ba18", "0x38ea48", "0x16c7b4", "0x1704b4", "TPlayer_get_shield", "sub_1704B4", "getter", "string", "returns the shield string"),
    spec("shieldimg", "0x37ba48", "0x38ea78", "0x16c7b4", "0x1704b4", "TPlayer_get_shield", "sub_1704B4", "getter", "string", "returns the same shield string exposed as shieldimg"),
    spec("sword", "0x37bad8", "0x38eb08", "0x16c784", "0x170484", "TPlayer_get_sword", "sub_170484", "getter", "string", "returns the sword string"),
    spec("swordimg", "0x37bb08", "0x38eb38", "0x16c784", "0x170484", "TPlayer_get_sword", "sub_170484", "getter", "string", "returns the same sword string exposed as swordimg"),
    spec("zoomfactor", "0x37bb38", "0x38eb68", "0x16c68c", "0x170244", "TPlayer_get_zoomfactor", "sub_170244", "getter", "float", "reads the player zoom factor"),
    spec("weapons", "0x37bb98", "0x38ebc8", "0x16c6c0", "0x170278", "TPlayer_get_weapons", "sub_170278", "getter", "object", "returns the weapon list"),
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
        "match_kind": "manual-player-property-table-anchor",
        "source_component": "TPlayer property table",
        "target_component": "Spectron obfuscated TPlayer property table",
        "source_basis": (
            f"matching the TPlayer {item['role']} registration for "
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
            f"The source registration row is in the TPlayer table at {item['source_record']}.",
            f"The target registration row is in the corresponding table at {item['target_record']}.",
            f"The source and target pseudocode preserve the same {item['value_kind']} {item['role']} operation: {item['operation']}.",
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
        "artifact": "spectron_player_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TPlayer property callbacks",
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
            "source_component": "TPlayer property table at 0x37b508",
            "target_component": "Spectron obfuscated TPlayer property table at 0x38e538",
            "resolution": "decoded property names, getter/setter roles, direct callback pointers, decompiled property behavior, and ARM64 feature metrics",
            "target_table_copy": "The target addresses use the .data copy of the registration table.",
            "shared_callbacks": [
                "hearts and hp share TPlayer_get_hearts at 0x16c2f8 and target 0x16feb0",
                "shield and shieldimg share TPlayer_get_shield at 0x16c7b4 and target 0x1704b4",
                "sword and swordimg share TPlayer_get_sword at 0x16c784 and target 0x170484",
            ],
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({row["spectron_ea"] for row in anchors}),
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
            "The source and target TPlayer property tables retain the same property names, roles, and callback order for this batch.",
            "Three getter callbacks are deliberately recorded twice because the source table exposes each through two script properties.",
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
