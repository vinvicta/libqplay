#!/usr/bin/env python3
"""Create reviewed anchors for the compact Spectron NPC accessors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1807b0",
        "original_name": "TServerNPC_getHeartsOrHP",
        "spectron_ea": "0x184d18",
        "target_name_fragment": "sub_184D18",
        "source_basis": "NPC hearts or HP getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both are one-block virtual getters for the same hearts or HP property; the vtable coordinate shifts from 560 to 568 bytes in the rebuilt target.",
            "The source callback records at 0x37be58 and 0x37bee8 decode to hearts and hp and share this getter. The target has the matching two callback-table references at 0x38eec8 and 0x38ef58.",
            "The target keeps the same compact 32-byte body and class-local position at the start of the server-NPC accessor cluster.",
        ],
    },
    {
        "original_ea": "0x1807d0",
        "original_name": "TServerNPC_getHurtDX",
        "spectron_ea": "0x184d38",
        "target_name_fragment": "sub_184D38",
        "source_basis": "NPC horizontal hurt displacement getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both read one double from the horizontal hurt-displacement field, shifting the logical field from offset 1208 to 1256 bytes.",
            "The source callback record at 0x37bf18 decodes to hurtdx and points to this getter; the target remains the next eight-byte accessor in the same cluster.",
            "The source and target preserve the one-block, eight-byte body and the adjacent setter relationship.",
        ],
    },
    {
        "original_ea": "0x1807d8",
        "original_name": "TServerNPC_setHurtDX",
        "spectron_ea": "0x184d40",
        "target_name_fragment": "sub_184D40",
        "source_basis": "NPC horizontal hurt displacement setter",
        "source_basic_block_count": 4,
        "spectron_basic_block_count": 4,
        "required_string_refs": [],
        "evidence": [
            "Both clamp the incoming horizontal hurt displacement to the inclusive range -1.0 through 1.0 and store it in the same logical field.",
            "The source hurtdx callback record at 0x37bf18 stores this address in its setter slot, directly pairing it with the reviewed getter.",
            "The target preserves the four-block, 36-byte setter body with only the rebuilt field offset changing from 1208 to 1256 bytes.",
        ],
    },
    {
        "original_ea": "0x1807fc",
        "original_name": "TServerNPC_getHurtDY",
        "spectron_ea": "0x184d64",
        "target_name_fragment": "sub_184D64",
        "source_basis": "NPC vertical hurt displacement getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both read one double from the vertical hurt-displacement field, shifting the logical field from offset 1216 to 1264 bytes.",
            "The source callback record at 0x37bf48 decodes to hurtdy and points to this getter; the target keeps the matching accessor order after getHurtDX and setHurtDX.",
            "The source and target preserve the one-block, eight-byte body and the adjacent setter relationship.",
        ],
    },
    {
        "original_ea": "0x180804",
        "original_name": "TServerNPC_setHurtDY",
        "spectron_ea": "0x184d6c",
        "target_name_fragment": "sub_184D6C",
        "source_basis": "NPC vertical hurt displacement setter",
        "source_basic_block_count": 4,
        "spectron_basic_block_count": 4,
        "required_string_refs": [],
        "evidence": [
            "Both clamp the incoming vertical hurt displacement to the inclusive range -1.0 through 1.0 and store it in the same logical field.",
            "The source hurtdy callback record at 0x37bf48 stores this address in its setter slot, directly pairing it with the reviewed getter.",
            "The target preserves the four-block, 36-byte setter body with only the rebuilt field offset changing from 1216 to 1264 bytes.",
        ],
    },
    {
        "original_ea": "0x180828",
        "original_name": "TServerNPC_getIsBlocking",
        "spectron_ea": "0x184d90",
        "target_name_fragment": "sub_184D90",
        "source_basis": "NPC blocking-state getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both return the inverse of the blocking byte, shifting the primary byte from offset 741 to 765 and preserving the one-block body.",
            "The source callback record at 0x37bfa8 decodes to isblocking and stores this address in its getter slot.",
            "The target follows the reviewed blocking setter at 0x184d9c in the same callback and accessor neighborhood.",
        ],
    },
    {
        "original_ea": "0x18084c",
        "original_name": "TServerNPC_getIsBlockingProjectiles",
        "spectron_ea": "0x184db4",
        "target_name_fragment": "sub_184DB4",
        "source_basis": "NPC projectile-blocking getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both read the projectile-blocking byte directly, shifting its logical field from offset 1060 to 1108 bytes.",
            "The source callback record at 0x37bfd8 decodes to isblockingprojectiles and stores this address in its getter slot.",
            "The target keeps the adjacent getter and setter order around the previously reviewed blocking-state helper.",
        ],
    },
    {
        "original_ea": "0x180854",
        "original_name": "TServerNPC_setIsBlockingProjectiles",
        "spectron_ea": "0x184dbc",
        "target_name_fragment": "sub_184DBC",
        "source_basis": "NPC projectile-blocking setter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both store the boolean argument directly in the projectile-blocking byte, shifting the logical field from offset 1060 to 1108 bytes.",
            "The source is the setter slot of the isblockingprojectiles callback record at 0x37bfd8.",
            "The source and target preserve the one-block, eight-byte body and the getter-setter adjacency.",
        ],
    },
    {
        "original_ea": "0x18085c",
        "original_name": "TServerNPC_getLayer",
        "spectron_ea": "0x184dc4",
        "target_name_fragment": "sub_184DC4",
        "source_basis": "NPC layer normalization getter",
        "source_basic_block_count": 3,
        "spectron_basic_block_count": 3,
        "required_string_refs": [],
        "evidence": [
            "Both normalize the same stored layer value, returning 3 for layer 8, layer plus 1 below 10, and layer minus 6 otherwise.",
            "The source callback record at 0x37c008 decodes to layer and stores this address in its getter slot.",
            "The target preserves the exact three-block, 32-byte body and the same class-local position immediately before setLayer.",
        ],
    },
    {
        "original_ea": "0x1808b0",
        "original_name": "TServerNPC_getSave",
        "spectron_ea": "0x184e18",
        "target_name_fragment": "sub_184E18",
        "source_basis": "NPC save-variable getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both return the NPC save-variable pointer, shifting the logical field from offset 1152 to 1200 bytes.",
            "The source callback record at 0x37c188 decodes to save and stores this address in its getter slot.",
            "The target remains the one-block, eight-byte getter immediately before the shield-power pair.",
        ],
    },
    {
        "original_ea": "0x1808b8",
        "original_name": "TServerNPC_getShieldPower",
        "spectron_ea": "0x184e20",
        "target_name_fragment": "sub_184E20",
        "source_basis": "NPC shield-power virtual getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both forward the shield-power getter through the NPC vtable, shifting the virtual coordinate from 672 to 680 bytes.",
            "The source callback record at 0x37c1b8 decodes to shieldpower and stores this address in its getter slot.",
            "The target is the matching one-block, 32-byte virtual wrapper followed by the clamping setter.",
        ],
    },
    {
        "original_ea": "0x1808d8",
        "original_name": "TServerNPC_setShieldPower",
        "spectron_ea": "0x184e40",
        "target_name_fragment": "sub_184E40",
        "source_basis": "NPC shield-power virtual setter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both clamp negative shield power to zero, truncate nonnegative input to an unsigned integer, and forward through the shield-power setter slot.",
            "The source shieldpower callback record at 0x37c1b8 stores this address in its setter slot.",
            "The target shifts the setter virtual coordinate from 680 to 688 bytes while preserving the one-block, 40-byte wrapper.",
        ],
    },
    {
        "original_ea": "0x180900",
        "original_name": "TServerNPC_getSwordPower",
        "spectron_ea": "0x184e68",
        "target_name_fragment": "sub_184E68",
        "source_basis": "NPC sword-power virtual getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both forward the sword-power getter through the NPC vtable, shifting the virtual coordinate from 656 to 664 bytes.",
            "The source callback record at 0x37c218 decodes to swordpower and stores this address in its getter slot.",
            "The target is the matching one-block, 32-byte virtual wrapper followed by the clamping setter.",
        ],
    },
    {
        "original_ea": "0x180920",
        "original_name": "TServerNPC_setSwordPower",
        "spectron_ea": "0x184e88",
        "target_name_fragment": "sub_184E88",
        "source_basis": "NPC sword-power virtual setter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both clamp negative sword power to zero, truncate nonnegative input to an unsigned integer, and forward through the sword-power setter slot.",
            "The source swordpower callback record at 0x37c218 stores this address in its setter slot.",
            "The target shifts the setter virtual coordinate from 664 to 672 bytes while preserving the one-block, 40-byte wrapper.",
        ],
    },
    {
        "original_ea": "0x180948",
        "original_name": "TServerNPC_getX",
        "spectron_ea": "0x184eb0",
        "target_name_fragment": "sub_184EB0",
        "source_basis": "NPC global X coordinate getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both call the inherited local-X getter and add the same map-cell contribution from the NPC tile coordinate shifted left by six bits.",
            "The source callback record at 0x37c2a8 decodes to x and stores this address in its getter slot.",
            "The target preserves the one-block, 52-byte body and the exact X accessor position before getY.",
        ],
    },
    {
        "original_ea": "0x18097c",
        "original_name": "TServerNPC_getY",
        "spectron_ea": "0x184ee4",
        "target_name_fragment": "sub_184EE4",
        "source_basis": "NPC global Y coordinate getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both call the inherited local-Y getter and add the same map-cell contribution from the NPC tile coordinate shifted left by six bits.",
            "The source callback record at 0x37c2d8 decodes to y and stores this address in its getter slot.",
            "The target preserves the one-block, 52-byte body and the exact Y accessor position between getX and getVisible.",
        ],
    },
    {
        "original_ea": "0x1809b0",
        "original_name": "TServerNPC_getVisible",
        "spectron_ea": "0x184f18",
        "target_name_fragment": "sub_184F18",
        "source_basis": "NPC visibility getter",
        "source_basic_block_count": 1,
        "spectron_basic_block_count": 1,
        "required_string_refs": [],
        "evidence": [
            "Both read the NPC visibility byte directly, shifting the logical field from offset 1008 to 1032 bytes.",
            "The source callback record at 0x37c248 decodes to visible and stores this address in its getter slot.",
            "The target preserves the one-block, eight-byte body and the end position of the compact accessor cluster before the script helpers.",
        ],
    },
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
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "mnemonic_hash",
            "register_shape_hash",
            "shape_hash",
        )
    }


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
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        target_name = target.get("name", "")
        if spec["target_name_fragment"] not in target_name:
            raise ValueError(
                "target %s does not retain expected signature fragment: %s"
                % (spec["spectron_ea"], spec["target_name_fragment"])
            )
        if source.get("basic_block_count") != spec["source_basic_block_count"]:
            raise ValueError(
                "unexpected source basic-block count at %s" % spec["original_ea"]
            )
        if target.get("basic_block_count") != spec["spectron_basic_block_count"]:
            raise ValueError(
                "unexpected target basic-block count at %s" % spec["spectron_ea"]
            )
        for literal in spec["required_string_refs"]:
            if literal not in source.get("string_refs", []):
                raise ValueError(
                    "source %s lacks required string reference %s"
                    % (spec["original_ea"], literal)
                )
            if literal not in target.get("string_refs", []):
                raise ValueError(
                    "target %s lacks required string reference %s"
                    % (spec["spectron_ea"], literal)
                )
        if spectron_ea in semantic_targets:
            raise ValueError(
                "target %s is already present in the semantic map" % spec["spectron_ea"]
            )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target_name,
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-npc-accessor-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in NPC accessor anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_npc_accessor_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact server-NPC property accessors",
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
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": sum(
                row["semantic_match_already_present"] for row in anchors
            ),
            "new_context_anchor_count": sum(
                not row["semantic_match_already_present"] for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated 2.2 name in the evidence row.",
            "The correspondence relies on callback-table records, exact accessor order, matching local behavior, field and vtable-coordinate shifts, and compact body shapes rather than target names alone.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
