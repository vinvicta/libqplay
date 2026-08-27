#!/usr/bin/env python3
"""Create reviewed anchors for the contiguous TServerPlayer accessors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_SPECS = [
    ("0x18a1a4", "TServerPlayer_getHP_void", 680),
    ("0x18a1ac", "TServerPlayer_setHP_double", 680),
    ("0x18a1b4", "TServerPlayer_getMaxHP_void", 688),
    ("0x18a1bc", "TServerPlayer_setMaxHP_int", 688),
    ("0x18a1c4", "TServerPlayer_getGralats_void", 692),
    ("0x18a1cc", "TServerPlayer_setGralats_int", 692),
    ("0x18a1d4", "TServerPlayer_getBombsCount_void", 696),
    ("0x18a1dc", "TServerPlayer_setBombsCount_int", 696),
    ("0x18a1e4", "TServerPlayer_getArrows_void", 700),
    ("0x18a1ec", "TServerPlayer_setArrows_int", 700),
    ("0x18a1f4", "TServerPlayer_getGlovePower_void", 704),
    ("0x18a1fc", "TServerPlayer_setGlovePower_int", 704),
    ("0x18a204", "TServerPlayer_getSwordPower_void", 708),
    ("0x18a20c", "TServerPlayer_setSwordPower_int", 708),
    ("0x18a214", "TServerPlayer_getShieldPower_void", 712),
    ("0x18a21c", "TServerPlayer_setShieldPower_int", 712),
    ("0x18a224", "TServerPlayer_getAlignment_void", 716),
    ("0x18a22c", "TServerPlayer_setAlignment_int", 716),
    ("0x18a234", "TServerPlayer_getMagicPoints_void", 720),
    ("0x18a23c", "TServerPlayer_setMagicPoints_int", 720),
    ("0x18a244", "TServerPlayer_getCarrySprite_void", 724),
    ("0x18a24c", "TServerPlayer_setCarrySprite_int", 724),
    ("0x18a254", "TServerPlayer_getWeaponsEnabled_void", 728),
    ("0x18a25c", "TServerPlayer_setWeaponsEnabled_bool", 728),
    ("0x18a264", "TServerPlayer_getDefaultMovement_void", 729),
    ("0x18a26c", "TServerPlayer_setDefaultMovement_bool", 729),
    ("0x18a274", "TServerPlayer_getEnabledFeatures_void", 732),
    ("0x18a27c", "TServerPlayer_setEnabledFeatures_int", 732),
    ("0x18a284", "TServerPlayer_getPaused_void", 736),
    ("0x18a28c", "TServerPlayer_getDead_void", 737),
    ("0x18a294", "TServerPlayer_setDead_bool", 737),
    ("0x18a29c", "TServerPlayer_getIsHurt_void", 738),
    ("0x18a2a4", "TServerPlayer_setIsHurt_bool", 738),
    ("0x18a2ac", "TServerPlayer_getHidden_void", 739),
    ("0x18a2b4", "TServerPlayer_setHidden_bool", 739),
    ("0x18a2bc", "TServerPlayer_getSwordHidden_void", 740),
    ("0x18a2c4", "TServerPlayer_setSwordHidden_bool", 740),
]

TARGET_BASE = 0x18E98C
TARGET_NAME_PREFIX = "_ZN10MpGzgariDy10"
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
    "The source rows form one contiguous 37-function getter/setter block from 0x18a1a4 through 0x18a2c4. The target has a matching 37-function block from 0x18e98c through 0x18eaac.",
    "Every pair is an 8-byte, 2-instruction, 1-basic-block wrapper with identical complete normalized feature metrics. The alternating getter and setter order is preserved across the whole block.",
    "Direct Hex-Rays checks show the same field sequence. The target expands the player object by 24 bytes in this region, so each target field offset is the source offset plus 24, while the getter and setter operation remains the same.",
    "Every target symbol retains the obfuscated MpGzgariDy class name and a distinct C++ method name. The class-local name, contiguous order, field sequence, and exact fingerprints jointly identify the roles.",
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
    for index, (source_text, source_name, source_field_offset) in enumerate(SOURCE_SPECS):
        source_ea = int(source_text, 16)
        target_ea = TARGET_BASE + index * 8
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % source_text)
        if source.get("name") != source_name:
            raise ValueError("unexpected source name at %s" % source_text)
        if not target.get("name", "").startswith(TARGET_NAME_PREFIX):
            raise ValueError("unexpected target class name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas or target_ea in semantic_target_eas:
            raise ValueError("accessor row is already in the semantic map at %s" % source_text)
        if target_ea - source_ea != 0x47E8:
            raise ValueError("unexpected TServerPlayer accessor relocation at %s" % source_text)
        shape_equal = metrics(source) == metrics(target)
        if not shape_equal:
            raise ValueError("TServerPlayer accessor feature mismatch at %s" % source_text)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "source_field_offset": source_field_offset,
                "spectron_ea": target["ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "target_field_offset": source_field_offset + 24,
                "field_offset_delta": 24,
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-tserverplayer-accessor-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": "server-player property accessor %s" % source["name"],
                "context_group": "TServerPlayer contiguous getter and setter block",
                "context_order": index + 1,
                "target_delta": "+0x47e8",
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tserverplayer_accessor_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the contiguous TServerPlayer scalar getter and setter block",
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
            "constant_target_delta": "+0x47e8",
            "constant_field_offset_delta": 24,
        },
        "context": {
            "source_class": "TServerPlayer",
            "target_class": "MpGzgariDy",
            "source_range": "0x18a1a4 through 0x18a2c4",
            "target_range": "0x18e98c through 0x18eaac",
            "source_function_count": 37,
            "target_function_count": 37,
            "address_relocation": "+0x47e8",
            "field_offset_relocation": "+24",
            "source_next_boundary": "0x18a2cc TNumberArrayVar_double_getArraySize_void",
            "target_next_boundary": "0x18eab4 _ZN10LBgVgaqANQ10HTp1IavoOuEv",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ aliases preserve the readable 1.8 getter and setter roles while the artifact records the obfuscated target names.",
            "The target object has a 24-byte field-layout expansion in this block. The code operation and accessor order remain exact, so this is recorded as field relocation rather than a behavioral change.",
            "The address delta is specific to this contiguous TServerPlayer accessor block and is not a general rule for the rest of the class.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
