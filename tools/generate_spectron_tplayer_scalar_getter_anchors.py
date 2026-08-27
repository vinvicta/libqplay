#!/usr/bin/env python3
"""Create reviewed anchors for the contiguous TPlayer scalar getters."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_SPECS = [
    ("0x17afd8", "TPlayer_getlocalx_void", 1488, 1496),
    ("0x17b020", "TPlayer_getlocaly_void", 1504, 1512),
    ("0x17b068", "TPlayer_getHP_void", 1120, 1128),
    ("0x17b0b0", "TPlayer_getMaxHP_void", 1136, 1144),
    ("0x17b100", "TPlayer_getGralats_void", 1152, 1160),
    ("0x17b150", "TPlayer_getBombsCount_void", 1168, 1176),
    ("0x17b1a0", "TPlayer_getArrows_void", 1184, 1192),
    ("0x17b1f0", "TPlayer_getGlovePower_void", 1200, 1208),
    ("0x17b240", "TPlayer_getSwordPower_void", 1216, 1224),
    ("0x17b290", "TPlayer_getShieldPower_void", 1232, 1240),
    ("0x17b2e0", "TPlayer_getAlignment_void", 1248, 1256),
    ("0x17b330", "TPlayer_getMagicPoints_void", 1264, 1272),
    ("0x17b380", "TPlayer_getCarrySprite_void", 1280, 1288),
    ("0x17b3d0", "TPlayer_getWeaponsEnabled_void", 1296, 1304),
    ("0x17b3f8", "TPlayer_getDefaultMovement_void", 1312, 1320),
    ("0x17b420", "TPlayer_getEnabledFeatures_void", 1328, 1336),
    ("0x17b470", "TPlayer_getPaused_void", 1344, 1352),
    ("0x17b498", "TPlayer_getDead_void", 1352, 1360),
    ("0x17b4c0", "TPlayer_getIsHurt_void", 1360, 1368),
    ("0x17b4e8", "TPlayer_getHidden_void", 1376, 1384),
    ("0x17b510", "TPlayer_getSwordHidden_void", 1408, 1416),
]

TARGET_EAS = [
    "0x17f37c",
    "0x17f3c4",
    "0x17f40c",
    "0x17f454",
    "0x17f4a4",
    "0x17f4f4",
    "0x17f544",
    "0x17f594",
    "0x17f5e4",
    "0x17f634",
    "0x17f684",
    "0x17f6d4",
    "0x17f724",
    "0x17f774",
    "0x17f79c",
    "0x17f7c4",
    "0x17f814",
    "0x17f83c",
    "0x17f864",
    "0x17f88c",
    "0x17f8b4",
]

METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)

EVIDENCE = [
    "The source rows form one contiguous 21-function TPlayer getter block from 0x17afd8 through 0x17b510. The target has a matching 21-function block from 0x17f37c through 0x17f8b4 in W6NzgawMJy.",
    "The getter order is preserved across local coordinates, health, inventory, combat power, movement flags, and visibility state. Every pair has identical complete normalized feature metrics.",
    "Hex-Rays checks show the same guarded decode operation in each sampled scalar family. The target reads the corresponding encoded pointer and mask storage at source offset plus 24 bytes, including the byte-valued flags at the end of the block.",
    "The constant +0x43a4 address relocation, the exact fingerprints, the class-local sequence, and the independently visible next-class boundary jointly identify the roles.",
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(functions: list[dict]) -> dict[int, dict]:
    return {int(function["ea"], 16): function for function in functions}


def metrics(function: dict) -> dict:
    return {field: function.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for index, (source_text, source_name, source_storage_offset, source_mask_offset) in enumerate(SOURCE_SPECS):
        target_text = TARGET_EAS[index]
        source_ea = int(source_text, 16)
        target_ea = int(target_text, 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % source_text)
        if source.get("name") != source_name:
            raise ValueError("unexpected source name at %s" % source_text)
        target_name = target.get("name", "")
        if not target_name.startswith("_ZN") or "W6NzgawMJy" not in target_name:
            raise ValueError("unexpected target class name at %s" % target_text)
        if source_ea in semantic_source_eas or target_ea in semantic_target_eas:
            raise ValueError("getter row is already in the semantic map at %s" % source_text)
        if target_ea - source_ea != 0x43A4:
            raise ValueError("unexpected TPlayer getter relocation at %s" % source_text)
        if metrics(source) != metrics(target):
            raise ValueError("TPlayer getter feature mismatch at %s" % source_text)
        target_storage_offset = source_storage_offset + 24
        target_mask_offset = source_mask_offset + 24
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "source_storage_pointer_offset": source_storage_offset,
                "source_mask_offset": source_mask_offset,
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target_name,
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "target_storage_pointer_offset": target_storage_offset,
                "target_mask_offset": target_mask_offset,
                "field_offset_delta": 24,
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-tplayer-scalar-getter-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TPlayer contiguous scalar getter %s" % source["name"],
                "context_group": "TPlayer contiguous scalar getter block",
                "context_order": index + 1,
                "target_delta": "+0x43a4",
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tplayer_scalar_getter_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the contiguous TPlayer scalar getter block",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "constant_target_delta": "+0x43a4",
            "constant_storage_offset_delta": 24,
            "constant_mask_offset_delta": 24,
        },
        "context": {
            "source_class": "TPlayer",
            "target_class": "W6NzgawMJy",
            "source_range": "0x17afd8 through 0x17b510",
            "target_range": "0x17f37c through 0x17f8b4",
            "source_function_count": 21,
            "target_function_count": 21,
            "address_relocation": "+0x43a4",
            "storage_pointer_relocation": "+24",
            "mask_relocation": "+24",
            "source_next_boundary": "0x17b538 TPlayerProperties_TPlayerProperties",
            "target_next_boundary": "0x17f8dc _ZN20W6NzgawMJyPropertiesD2Ev",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ aliases preserve the readable 1.8 getter roles while the artifact records the obfuscated target names.",
            "The target encoded storage and mask offsets are source plus 24 bytes throughout this accessor block. That relationship is local to this block and is not assumed for unrelated TPlayer methods.",
            "The +0x43a4 address delta is specific to this contiguous TPlayer getter block.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
