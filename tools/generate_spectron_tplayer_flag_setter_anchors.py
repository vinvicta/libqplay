#!/usr/bin/env python3
"""Create reviewed anchors for the remaining TPlayer flag setters."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_SPECS = [
    ("0x17b59c", "TPlayer_setWeaponsEnabled_bool", "0x17f940"),
    ("0x17b608", "TPlayer_setSwordHidden_bool", "0x17f9ac"),
    ("0x17b674", "TPlayer_setDefaultMovement_bool", "0x17fa18"),
    ("0x17b6e0", "TPlayer_setIsHurt_bool", "0x17fa84"),
    ("0x17b74c", "TPlayer_setHidden_bool", "0x17faf0"),
    ("0x17b7b8", "TPlayer_setDead_bool", "0x17fb5c"),
    ("0x17b8a0", "TPlayer_setEnabledFeatures_int", "0x17fc44"),
]

INTERSTITIAL_SOURCE = ("0x17b824", "TPlayer_setPaused_bool")
INTERSTITIAL_TARGET = ("0x17fbc8", "v18_TPlayer_setPaused_bool")

TARGET_NAME_CLASS = "W6NzgawMJy"
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
    "Six new rows form one contiguous TPlayer flag-setter block from 0x17b59c through 0x17b7b8. A seventh exact row follows the already translated setPaused method at 0x17b8a0.",
    "Every new source and target pair has identical complete normalized feature metrics. The six boolean setters are 108 bytes with 26 instructions, three basic blocks, four branches, and one call. The enabled-features setter is 168 bytes with 41 instructions, three basic blocks, four branches, and one call.",
    "Hex-Rays shows the same encoded byte or integer setter operation and lazy allocation behavior. The target uses relocated storage constants, so this pass intentionally records a class-local semantic block rather than a global object-layout rule.",
    "The target address is source plus 0x43a4 for all seven new rows. The existing v18_TPlayer_setPaused_bool row between the two groups supplies an independently translated interstitial boundary.",
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

    interstitial_source_ea = int(INTERSTITIAL_SOURCE[0], 16)
    interstitial_target_ea = int(INTERSTITIAL_TARGET[0], 16)
    interstitial_source = original.get(interstitial_source_ea)
    interstitial_target = spectron.get(interstitial_target_ea)
    if interstitial_source is None or interstitial_target is None:
        raise ValueError("the expected translated setPaused interstitial is missing")
    if interstitial_source.get("name") != INTERSTITIAL_SOURCE[1]:
        raise ValueError("unexpected setPaused source interstitial")
    if interstitial_target.get("name") != INTERSTITIAL_TARGET[1]:
        raise ValueError("unexpected setPaused target interstitial")
    if interstitial_source_ea not in semantic_source_eas or interstitial_target_ea not in semantic_target_eas:
        raise ValueError("the setPaused interstitial is not present in the semantic map")

    anchors = []
    for index, (source_text, source_name, target_text) in enumerate(SOURCE_SPECS):
        source_ea = int(source_text, 16)
        target_ea = int(target_text, 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % source_text)
        if source.get("name") != source_name:
            raise ValueError("unexpected source name at %s" % source_text)
        target_name = target.get("name", "")
        if not target_name.startswith("_ZN") or TARGET_NAME_CLASS not in target_name:
            raise ValueError("unexpected target class name at %s" % target_text)
        if source_ea in semantic_source_eas or target_ea in semantic_target_eas:
            raise ValueError("flag setter row is already in the semantic map at %s" % source_text)
        if target_ea - source_ea != 0x43A4:
            raise ValueError("unexpected TPlayer flag-setter relocation at %s" % source_text)
        if metrics(source) != metrics(target):
            raise ValueError("TPlayer flag-setter feature mismatch at %s" % source_text)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target_name,
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-tplayer-flag-setter-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TPlayer contiguous flag setter %s" % source["name"],
                "context_group": "TPlayer flag setter block",
                "context_order": index + 1,
                "target_delta": "+0x43a4",
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tplayer_flag_setter_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining TPlayer boolean and feature setters",
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
            "contiguous_boolean_setter_count": 6,
            "post_interstitial_setter_count": 1,
            "existing_interstitial_count": 1,
        },
        "context": {
            "source_class": "TPlayer",
            "target_class": TARGET_NAME_CLASS,
            "source_boolean_range": "0x17b59c through 0x17b7b8",
            "target_boolean_range": "0x17f940 through 0x17fb5c",
            "source_post_interstitial": "0x17b8a0 TPlayer_setEnabledFeatures_int",
            "target_post_interstitial": "0x17fc44 _ZN10W6NzgawMJy10K2iswaYDqVEi",
            "source_function_count": 7,
            "target_function_count": 7,
            "address_relocation": "+0x43a4",
            "existing_interstitial_source": "0x17b824 TPlayer_setPaused_bool",
            "existing_interstitial_target": "0x17fbc8 v18_TPlayer_setPaused_bool",
            "source_next_boundary": "0x17b948 TPlayerProperties_TPlayerProperties",
            "target_next_boundary": "0x17fcf0 v18_ObjectsYCompare_void_const_void_const",
        },
        "interstitial": {
            "original_ea": INTERSTITIAL_SOURCE[0],
            "original_name": INTERSTITIAL_SOURCE[1],
            "spectron_ea": INTERSTITIAL_TARGET[0],
            "spectron_name": INTERSTITIAL_TARGET[1],
            "semantic_match_already_present": True,
            "role": "existing translated boundary, not a new anchor",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ aliases preserve the readable 1.8 setter roles while the artifact records the obfuscated target names.",
            "The existing setPaused translation is retained as an interstitial boundary and is not counted twice.",
            "The +0x43a4 address delta is specific to this TPlayer flag-setter region. The target storage layout is not assumed to follow one global offset rule.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
