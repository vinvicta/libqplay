#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for TServerNPC helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x180834",
        "original_name": "TServerNPC_setIsBlocking",
        "spectron_ea": "0x184d9c",
        "target_name": "sub_184D9C",
        "source_basis": "NPC blocking-state setter",
        "evidence": [
            "Both bodies clear the transient blocking field, invert the boolean argument, and store it in the same two blocking-state fields.",
            "The source callback record is the setisblocking entry in the TServerNPC script-function table.",
        ],
    },
    {
        "original_ea": "0x1809b8",
        "original_name": "TServerNPC_script_blockAgain",
        "spectron_ea": "0x184f20",
        "target_name": "sub_184F20",
        "source_basis": "NPC block-again script helper",
        "evidence": [
            "Both bodies clear the same block mode and local-block flags.",
            "The source callback record decodes to blockagain and points into the TServerNPC script-function table.",
        ],
    },
    {
        "original_ea": "0x1809cc",
        "original_name": "TServerNPC_script_blockAgainLocal",
        "spectron_ea": "0x184f34",
        "target_name": "sub_184F34",
        "source_basis": "NPC local block-again script helper",
        "evidence": [
            "Both bodies clear the same block mode and local-block flag, then set the local-only marker.",
            "The source callback record decodes to blockagainlocal and occupies the matching script table slot.",
        ],
    },
    {
        "original_ea": "0x180a1c",
        "original_name": "TServerNPC_script_dontBlock",
        "spectron_ea": "0x184f84",
        "target_name": "sub_184F84",
        "source_basis": "NPC dont-block script helper",
        "evidence": [
            "Both bodies set the no-block mode and clear the local marker with the same three stores.",
            "The source callback record decodes to dontblock in the same TServerNPC script-function table.",
        ],
    },
    {
        "original_ea": "0x180a30",
        "original_name": "TServerNPC_script_dontBlockLocal",
        "spectron_ea": "0x184f98",
        "target_name": "sub_184F98",
        "source_basis": "NPC local dont-block script helper",
        "evidence": [
            "Both bodies set the no-block and local-only fields with the same two stores.",
            "The source callback record decodes to dontblocklocal and occupies the matching script table slot.",
        ],
    },
    {
        "original_ea": "0x180a40",
        "original_name": "TServerNPC_script_drawAsLight",
        "spectron_ea": "0x184fa8",
        "target_name": "sub_184FA8",
        "source_basis": "NPC draw-mode script helper",
        "evidence": [
            "Both bodies store draw mode eight in the same object field and return the object.",
            "The source callback record decodes to drawaslight.",
        ],
    },
    {
        "original_ea": "0x180a4c",
        "original_name": "TServerNPC_script_drawOverPlayer",
        "spectron_ea": "0x184fb4",
        "target_name": "sub_184FB4",
        "source_basis": "NPC draw-over-player script helper",
        "evidence": [
            "Both bodies store draw mode one in the same object field and return the object.",
            "The source callback record decodes to drawoverplayer.",
        ],
    },
    {
        "original_ea": "0x180a58",
        "original_name": "TServerNPC_script_drawUnderPlayer",
        "spectron_ea": "0x184fc0",
        "target_name": "sub_184FC0",
        "source_basis": "NPC draw-under-player script helper",
        "evidence": [
            "Both bodies store draw mode negative one in the same object field and return the object.",
            "The source callback record decodes to drawunderplayer.",
        ],
    },
    {
        "original_ea": "0x180ac0",
        "original_name": "TServerNPC_getLevelVisible_void",
        "spectron_ea": "0x185028",
        "target_name": "_ZN10LBgVgaqANQ10ex97IaxDtAEv",
        "source_basis": "NPC level-visibility accessor",
        "evidence": [
            "Both bodies read the level-visibility override byte and return either the object visibility byte or the override value.",
            "The same three-call target context and identical normalized body hashes distinguish this accessor from generic byte getters.",
        ],
    },
    {
        "original_ea": "0x180adc",
        "original_name": "TServerNPC_script_setBow",
        "spectron_ea": "0x185044",
        "target_name": "sub_185044",
        "source_basis": "NPC bow-image script setter",
        "evidence": [
            "Both bodies gate the assignment on the same Graal 2002 mode flag and copy the string into the bow-image field.",
            "The source callback record decodes to setbow.",
        ],
    },
    {
        "original_ea": "0x180c1c",
        "original_name": "TServerNPC_getPeltWithBlackStone",
        "spectron_ea": "0x185184",
        "target_name": "sub_185184",
        "source_basis": "NPC pelt-with-black-stone predicate",
        "evidence": [
            "Both bodies compare the pelt string field at the same logical object offset with the black-stone literal.",
            "The source callback record decodes to peltwithblackstone and is a read-only property getter.",
        ],
    },
    {
        "original_ea": "0x180c30",
        "original_name": "TServerNPC_getPeltWithStone",
        "spectron_ea": "0x185198",
        "target_name": "sub_185198",
        "source_basis": "NPC pelt-with-stone predicate",
        "evidence": [
            "Both bodies compare the pelt string field at the same logical object offset with the stone literal.",
            "The source callback record decodes to peltwithstone and is a read-only property getter.",
        ],
    },
    {
        "original_ea": "0x180c44",
        "original_name": "TServerNPC_getPeltWithVase",
        "spectron_ea": "0x1851ac",
        "target_name": "sub_1851AC",
        "source_basis": "NPC pelt-with-vase predicate",
        "evidence": [
            "Both bodies compare the pelt string field at the same logical object offset with the vase literal.",
            "The source callback record decodes to peltwithvase after accounting for the encoded terminator byte.",
        ],
    },
    {
        "original_ea": "0x180c58",
        "original_name": "TServerNPC_getPeltWithSign",
        "spectron_ea": "0x1851c0",
        "target_name": "sub_1851C0",
        "source_basis": "NPC pelt-with-sign predicate",
        "evidence": [
            "Both bodies compare the pelt string field at the same logical object offset with the sign literal.",
            "The source callback record decodes to peltwithsign after accounting for the encoded terminator byte.",
        ],
    },
    {
        "original_ea": "0x180c6c",
        "original_name": "TServerNPC_getPeltWithBush",
        "spectron_ea": "0x1851d4",
        "target_name": "sub_1851D4",
        "source_basis": "NPC pelt-with-bush predicate",
        "evidence": [
            "Both bodies compare the pelt string field at the same logical object offset with the bush literal.",
            "The source callback record decodes to peltwithbush after accounting for the encoded terminator byte.",
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
            raise ValueError("unexpected original name at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("unexpected Spectron name at %s" % spec["spectron_ea"])
        for field in ("size", "instruction_count", "basic_block_count"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
                )
        for field in ("mnemonic_hash", "register_shape_hash", "shape_hash"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
                )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_size": source["size"],
                "original_instruction_count": source["instruction_count"],
                "original_basic_block_count": source["basic_block_count"],
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_size": target["size"],
                "spectron_instruction_count": target["instruction_count"],
                "spectron_basic_block_count": target["basic_block_count"],
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-npc-helper-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in NPC helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_npc_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TServerNPC blocking, draw-mode, bow, visibility, and pelt helpers",
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
            "already_in_semantic_map": sum(row["semantic_match_already_present"] for row in anchors),
            "new_context_anchor_count": sum(not row["semantic_match_already_present"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The target bodies preserve the original NPC blocking, draw-mode, visibility, bow, and pelt helper behavior with exact normalized function hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
