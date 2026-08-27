#!/usr/bin/env python3
"""Create reviewed anchors for the TServerPlayer property block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_SPECS = [
    ("0x18a55c", "TServerPlayer_setPaused_bool", "0x18edbc"),
    ("0x18a568", "TServerPlayer_getAP", "0x18edc8"),
    ("0x18a5bc", "TServerPlayer_getDarts", "0x18ee1c"),
    ("0x18a604", "TServerPlayer_getAttachedToObject", "0x18ee64"),
    ("0x18a60c", "TServerPlayer_getBombs", "0x18ee6c"),
    ("0x18a650", "TServerPlayer_getGlovePower", "0x18eeb0"),
    ("0x18a670", "TServerPlayer_setGlovePower", "0x18eed0"),
    ("0x18a698", "TServerPlayer_getGralatsRupees", "0x18eef8"),
    ("0x18a6b8", "TServerPlayer_setHeadOrHeadImg", "0x18ef18"),
    ("0x18a6d8", "TServerPlayer_getHeartsOrHP", "0x18ef38"),
    ("0x18a6f8", "TServerPlayer_getID", "0x18ef58"),
    ("0x18a700", "TServerPlayer_getIsAdmin", "0x18ef60"),
    ("0x18a708", "TServerPlayer_getIsBlocking", "0x18ef68"),
    ("0x18a714", "TServerPlayer_setIsBlocking", "0x18ef74"),
    ("0x18a720", "TServerPlayer_getIsBuddy", "0x18ef80"),
    ("0x18a728", "TServerPlayer_setIsBuddy", "0x18ef88"),
    ("0x18a730", "TServerPlayer_getIsChannel", "0x18ef90"),
    ("0x18a738", "TServerPlayer_getIsChannelOpen", "0x18ef98"),
    ("0x18a740", "TServerPlayer_getIsChannelUser", "0x18efa0"),
    ("0x18a748", "TServerPlayer_getIsExternal", "0x18efa8"),
    ("0x18a750", "TServerPlayer_getIsFemale", "0x18efb0"),
    ("0x18a75c", "TServerPlayer_getIsIgnored", "0x18efbc"),
    ("0x18a764", "TServerPlayer_setIsIgnored", "0x18efc4"),
    ("0x18a76c", "TServerPlayer_getIsIgnoring", "0x18efcc"),
    ("0x18a774", "TServerPlayer_getIsLoggedIn", "0x18efd4"),
    ("0x18a77c", "TServerPlayer_getIsMale", "0x18efdc"),
    ("0x18a784", "TServerPlayer_getFullHeartsMaxHP", "0x18efe4"),
    ("0x18a7a4", "TServerPlayer_getMP", "0x18f004"),
    ("0x18a7f8", "TServerPlayer_getPaused", "0x18f058"),
    ("0x18a818", "TServerPlayer_setPaused", "0x18f078"),
    ("0x18a838", "TServerPlayer_getPlayerListIcon", "0x18f098"),
    ("0x18a840", "TServerPlayer_getRating", "0x18f0a0"),
    ("0x18a84c", "TServerPlayer_getRatingD", "0x18f0ac"),
    ("0x18a858", "TServerPlayer_getShieldPower", "0x18f0b8"),
    ("0x18a878", "TServerPlayer_getSwordPower", "0x18f0d8"),
    ("0x18a898", "TServerPlayer_getX", "0x18f0f8"),
    ("0x18a8cc", "TServerPlayer_setX", "0x18f12c"),
    ("0x18a980", "TServerPlayer_getY", "0x18f1e0"),
    ("0x18a9b4", "TServerPlayer_setY", "0x18f214"),
]

EXISTING_CONTEXT = [
    ("0x18a588", "TServerPlayer_setAP", "0x18ede8", "v18_TServerPlayer_setAP"),
    ("0x18a5dc", "TServerPlayer_getAttached", "0x18ee3c", "v18_TServerPlayer_getAttached"),
    ("0x18a62c", "TServerPlayer_setChat", "0x18ee8c", "v18_TServerPlayer_setChat"),
    ("0x18a7c4", "TServerPlayer_setMP", "0x18f024", "v18_TServerPlayer_setMP"),
]

TARGET_NAME_CLASS = "MpGzgariDy"
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
    "The selected rows preserve the source order across the TServerPlayer property implementation. Four already translated rows remain as internal checkpoints: setAP, getAttached, setChat, and setMP.",
    "All 39 new source and target rows have identical complete normalized feature metrics. The block includes compact scalar getters and setters, boolean properties, two coordinate getters, and the two larger coordinate setters.",
    "The target rows sit in the corresponding MpGzgariDy implementation range. Most target rows still have default sub_ names, but their exact class-local order and the four existing v18 checkpoints make the sequence independently anchored.",
    "The source and target blocks include the same small boundary gaps around setX and setY. The target address relocation is +0x4860 for every new row and every interstitial checkpoint.",
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

    existing_context = []
    for source_text, source_name, target_text, target_name in EXISTING_CONTEXT:
        source = original.get(int(source_text, 16))
        target = spectron.get(int(target_text, 16))
        if source is None or target is None:
            raise ValueError("missing existing context row at %s" % source_text)
        if source.get("name") != source_name or target.get("name") != target_name:
            raise ValueError("unexpected existing context row at %s" % source_text)
        if int(source_text, 16) not in semantic_source_eas or int(target_text, 16) not in semantic_target_eas:
            raise ValueError("existing context row is not in the semantic map at %s" % source_text)
        if int(target_text, 16) - int(source_text, 16) != 0x4860:
            raise ValueError("unexpected existing context relocation at %s" % source_text)
        existing_context.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "spectron_ea": target["ea"],
                "spectron_name": target["name"],
                "semantic_match_already_present": True,
                "target_delta": "+0x4860",
                "role": "existing sequence checkpoint",
            }
        )

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
        if source_ea in semantic_source_eas or target_ea in semantic_target_eas:
            raise ValueError("property row is already in the semantic map at %s" % source_text)
        if target_ea - source_ea != 0x4860:
            raise ValueError("unexpected TServerPlayer property relocation at %s" % source_text)
        if metrics(source) != metrics(target):
            raise ValueError("TServerPlayer property feature mismatch at %s" % source_text)
        if index == 0:
            if not target_name.startswith("_ZN10MpGzgariDy"):
                raise ValueError("unexpected named target at the start of the property block")
        elif not target.get("is_default_name", False):
            raise ValueError("expected an unlabelled target at %s" % target_text)
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
                "match_kind": "manual-tserverplayer-property-block-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TServerPlayer property sequence: %s" % source["name"],
                "context_group": "TServerPlayer property block",
                "context_order": index + 1,
                "target_delta": "+0x4860",
                "role": source["name"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tserverplayer_property_block_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TServerPlayer property implementation block",
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
            "constant_target_delta": "+0x4860",
            "existing_context_count": len(existing_context),
            "source_block_function_count_including_context": len(anchors) + len(existing_context),
        },
        "context": {
            "source_class": "TServerPlayer",
            "target_class": TARGET_NAME_CLASS,
            "source_range": "0x18a55c through 0x18aa5c",
            "target_range": "0x18edbc through 0x18f2bc",
            "source_function_count_new": len(anchors),
            "target_function_count_new": len(anchors),
            "existing_context_count": len(existing_context),
            "address_relocation": "+0x4860",
            "source_boundary_after_setY": "0x18aa68 TServerPlayer_script_PMsWaiting",
            "target_boundary_after_setY": "0x18f2e8 sub_18F2E8",
            "source_setX_gap": "0x18a974 through 0x18a980",
            "target_setX_gap": "0x18f1d4 through 0x18f1e0",
            "source_setY_gap": "0x18aa5c through 0x18aa68",
            "target_setY_gap": "0x18f2bc through 0x18f2e8",
        },
        "existing_context": existing_context,
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ aliases preserve the readable 1.8 property roles while the artifact records the obfuscated or default target names.",
            "Four already translated rows are retained as sequence checkpoints and are not renamed again.",
            "The +0x4860 relocation is specific to this property block and is not a general rule for every TServerPlayer method.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
