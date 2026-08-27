#!/usr/bin/env python3
"""Create reviewed anchors for the contiguous TPlayer scalar setters."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_SPECS = [
    ("0x16cec4", "TPlayer_setGralats_int"),
    ("0x16cf6c", "TPlayer_setAlignment_int"),
    ("0x16d038", "TPlayer_setSwordPower_int"),
    ("0x16d104", "TPlayer_setMagicPoints_int"),
    ("0x16d1d0", "TPlayer_setMaxHP_int"),
    ("0x16d29c", "TPlayer_setShieldPower_int"),
    ("0x16d368", "TPlayer_setBombsCount_int"),
    ("0x16d434", "TPlayer_setArrows_int"),
    ("0x16d500", "TPlayer_setGlovePower_int"),
    ("0x16d5cc", "TPlayer_setCarrySprite_int"),
]

TARGET_EAS = [
    "0x170ac4",
    "0x170b6c",
    "0x170c38",
    "0x170d04",
    "0x170dd0",
    "0x170e9c",
    "0x170f68",
    "0x171034",
    "0x171100",
    "0x1711cc",
]

TARGET_NAME_PREFIX = "_ZN10W6NzgawMJy10"
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
    "The source rows form one contiguous ten-function TPlayer scalar setter block from 0x16cec4 through 0x16d5cc. The target has the same ten-function order from 0x170ac4 through 0x1711cc.",
    "Each source and target pair has identical complete normalized feature metrics. The first setter is a 168-byte, 41-instruction body, and the remaining nine setters are 204-byte, 51-instruction bodies with the same branch and call structure in both builds.",
    "The source and target Hex-Rays bodies perform the same encoded integer setter operation. The target uses the obfuscated W6NzgawMJy class and relocated object storage constants, but preserves the setter order and normalized instruction shape.",
    "The class-local sequence is stronger than a single address delta here. The target relocation is +0x3c00 for every row, while the target object-layout constants are not a uniform field offset translation across the whole block.",
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
    for index, (source_text, source_name) in enumerate(SOURCE_SPECS):
        target_text = TARGET_EAS[index]
        source_ea = int(source_text, 16)
        target_ea = int(target_text, 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % source_text)
        if source.get("name") != source_name:
            raise ValueError("unexpected source name at %s" % source_text)
        if not target.get("name", "").startswith(TARGET_NAME_PREFIX):
            raise ValueError("unexpected target class name at %s" % target_text)
        if source_ea in semantic_source_eas or target_ea in semantic_target_eas:
            raise ValueError("setter row is already in the semantic map at %s" % source_text)
        if target_ea - source_ea != 0x3C00:
            raise ValueError("unexpected TPlayer setter relocation at %s" % source_text)
        if metrics(source) != metrics(target):
            raise ValueError("TPlayer setter feature mismatch at %s" % source_text)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-tplayer-scalar-setter-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TPlayer contiguous scalar setter %s" % source["name"],
                "context_group": "TPlayer contiguous scalar setter block",
                "context_order": index + 1,
                "target_delta": "+0x3c00",
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tplayer_scalar_setter_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the contiguous TPlayer scalar setter block",
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
            "constant_target_delta": "+0x3c00",
        },
        "context": {
            "source_class": "TPlayer",
            "target_class": "W6NzgawMJy",
            "source_range": "0x16cec4 through 0x16d5cc",
            "target_range": "0x170ac4 through 0x1711cc",
            "source_function_count": 10,
            "target_function_count": 10,
            "address_relocation": "+0x3c00",
            "source_next_boundary": "0x16d698 TPlayer_set_defaultwalkspeed",
            "target_next_boundary": "0x171298 v18_TPlayer_set_defaultwalkspeed",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ aliases preserve the readable 1.8 setter roles while the artifact records the obfuscated target names.",
            "The target setter bodies preserve the source operation and normalized shape. Relocated storage constants are expected because the target class layout changed.",
            "The +0x3c00 address delta is specific to this contiguous TPlayer setter block and is not a general rule for the rest of the class.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
