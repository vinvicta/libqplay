#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron server-NPC state cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x180f1c",
        "original_name": "TServerNPC_script_setShape2",
        "spectron_ea": "0x185484",
        "target_name_fragment": "sub_185484",
        "source_basis": "server-NPC script shape callback",
        "source_basic_block_count": 10,
        "spectron_basic_block_count": 10,
        "required_string_refs": ["shape"],
        "evidence": [
            "Both update the NPC shape width and height, create or clear the shape script variable, accept the array only when it contains at least width times height entries, and mark the object changed.",
            "The source IDA comment identifies the callback record at 0x37c908 as setshape2 and places it in the TServerNPC script-function table installed at 0x183c18.",
            "The target was default-named sub_185484 in the feature export, but its pseudocode preserves the same ten-block callback behavior and the distinctive shape literal.",
        ],
    },
    {
        "original_ea": "0x183cc8",
        "original_name": "TServerNPC_TServerNPC_int",
        "spectron_ea": "0x188340",
        "target_name_fragment": "LBgVgaqANQC2Ei",
        "source_basis": "server-NPC constructor and save variable initialization",
        "source_basic_block_count": 4,
        "spectron_basic_block_count": 4,
        "required_string_refs": ["save"],
        "evidence": [
            "Both call the server-player constructor, install the NPC vtables, initialize the same dimensions and state flags, allocate the same small helper object, and create the save variable.",
            "The target exposes both C1 and C2 constructor entry names at the same function body, while the source has the readable TServerNPC constructor name.",
            "The exact four-block constructor shape and save literal identify the corresponding target despite shifted fields and rebuilt wrappers.",
        ],
    },
    {
        "original_ea": "0x181458",
        "original_name": "TServerNPC_getLogName_void",
        "spectron_ea": "0x1859ec",
        "target_name_fragment": "LBgVgaqANQ10XmPXfa5PW1Ev",
        "source_basis": "role-aware server-NPC log name construction",
        "source_basic_block_count": 62,
        "spectron_basic_block_count": 63,
        "required_string_refs": [
            " (in level ",
            " at pos (",
            " attr[",
            "))",
            ", ",
            "Gani",
            "Gani ",
            "Projectile",
            "Weapon ",
            "]",
            "head0",
            "unknown",
        ],
        "evidence": [
            "Both construct a descriptive name for attached NPCs, weapons, projectiles, GANI objects, and unknown objects before appending level, cell, and coordinate context.",
            "The source and target preserve the same role-specific labels, including Gani, Projectile, Weapon, head0, and unknown, plus the same level and position formatting fragments.",
            "The target adds one block for rebuilt wrapper handling but retains the same class-local role and the complete distinctive string set.",
        ],
    },
    {
        "original_ea": "0x185fd0",
        "original_name": "TServerNPC_setDefaultImageNames_void",
        "spectron_ea": "0x18a678",
        "target_name_fragment": "LBgVgaqANQ10Lkz7IadlZzEv",
        "source_basis": "server-NPC default image names and colors",
        "source_basic_block_count": 12,
        "spectron_basic_block_count": 12,
        "required_string_refs": ["body.png", "head26.png", "shield1.png", "sword1.png"],
        "evidence": [
            "Both choose defaults based on water state, select the corresponding animation, assign sword, shield, head, and body images, and write the same five color defaults with color 5 set to 18.",
            "The four default image literals are preserved exactly in both functions and occur in the same class-local initialization role.",
            "The target retains the exact twelve-block shape even though its string wrappers and field offsets were rebuilt for the 2.2 object layout.",
        ],
    },
    {
        "original_ea": "0x186c38",
        "original_name": "TServerNPC_serverMovedNPC_bool",
        "spectron_ea": "0x18b3b0",
        "target_name_fragment": "LBgVgaqANQ10W9g1Ia82GuEb",
        "source_basis": "server-NPC movement update and animation reset",
        "source_basic_block_count": 10,
        "spectron_basic_block_count": 10,
        "required_string_refs": ["def"],
        "evidence": [
            "Both remove the NPC from the movement list, reject the legacy server path, check the action level, test the default gani and water state, reset animation when needed, and play movement sound when the flag is set.",
            "The def literal and exact ten-block control-flow shape are preserved in the target.",
            "The correspondence is supported by the adjacent server-NPC movement methods and the same class-local state fields, not by an obfuscated name alone.",
        ],
    },
    {
        "original_ea": "0x186d48",
        "original_name": "TServerNPC_setProperties_TString_const",
        "spectron_ea": "0x18b4ec",
        "target_name_fragment": "LBgVgaqANQ10Q3v7IaUAWzERK10C8THgaTQxF",
        "source_basis": "encoded server-NPC property parser",
        "source_basic_block_count": 180,
        "spectron_basic_block_count": 181,
        "required_string_refs": ["#c#", ".gif", ".png", "def", "head", "head0.png", "sparringzone"],
        "evidence": [
            "Both parse the compact encoded NPC property stream with the same branches for images, head and body, weapon, GANI, movement, attachments, map and position, status, and event or hit-detection state.",
            "The target retains the distinctive #c#, image-extension, def, head0.png, and sparringzone literals and calls the same adjacent NPC state paths.",
            "The one-block difference from 180 to 181 is consistent with rebuilt string, list, and event wrappers in the target; the large parser role and branch sequence remain aligned.",
        ],
    },
    {
        "original_ea": "0x188260",
        "original_name": "TServerNPC_doNPCMove_void",
        "spectron_ea": "0x18ca28",
        "target_name_fragment": "LBgVgaqANQ10aQS6IasKozEv",
        "source_basis": "server-NPC movement queue and completion event",
        "source_basic_block_count": 91,
        "spectron_basic_block_count": 91,
        "required_string_refs": ["bomy_", "bomy_idle", "bomy_kick", "bomy_walk", "movementfinished"],
        "evidence": [
            "Both consume the queued NPC movement state, calculate the current step, update positions, select bomy idle, kick, and walk animations, and finish the movement sequence.",
            "Both invoke the movementfinished event when the queue reaches its terminal state and preserve all five distinctive movement literals.",
            "The exact 91-block shape and adjacent server-NPC movement context make this a stable role correspondence despite target wrapper changes.",
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
                "match_kind": "manual-server-npc-state-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in server-NPC-state anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_npc_state_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for server-NPC construction, shape callbacks, log naming, defaults, movement, and properties",
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
            "The correspondence relies on preserved server-NPC state machines, callback-table context, distinctive literals, compatible block counts, and reviewed pseudocode rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
