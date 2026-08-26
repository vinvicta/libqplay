#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for compact client state helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1e9560",
        "original_name": "TClient_callVirtual320",
        "spectron_ea": "0x1eda20",
        "target_name": "sub_1EDA20",
        "source_basis": "client virtual method forwarding at vtable offset 320",
        "evidence": [
            "Both bodies call the receiver virtual method at vtable offset 320 with no additional argument.",
            "The source and target retain the same 32-byte, eight-instruction, single-block wrapper shape in the state-helper run.",
        ],
    },
    {
        "original_ea": "0x1e95a0",
        "original_name": "TClient_setServerOptionsRaw",
        "spectron_ea": "0x1eda60",
        "target_name": "sub_1EDA60",
        "source_basis": "raw server-options static setter",
        "evidence": [
            "Both bodies assign the incoming value directly to the client server-options static.",
            "The target keeps the same 16-byte, four-instruction setter position between the virtual wrappers and the mode flag setter.",
        ],
    },
    {
        "original_ea": "0x1e95b0",
        "original_name": "TClient_enableGraal2002ServerMode",
        "spectron_ea": "0x1eda70",
        "target_name": "sub_1EDA70",
        "source_basis": "Graal 2002 server-mode flag setter",
        "evidence": [
            "Both bodies write one to the client Graal 2002 mode static and return its address.",
            "The source and target retain the same 20-byte, five-instruction, single-block helper shape.",
        ],
    },
    {
        "original_ea": "0x1e95c4",
        "original_name": "TClient_setTimeVarRaw",
        "spectron_ea": "0x1eda84",
        "target_name": "sub_1EDA84",
        "source_basis": "raw time-variable static setter",
        "evidence": [
            "Both bodies assign the incoming value directly to the time-variable static.",
            "The target keeps the same 16-byte, four-instruction setter immediately before the preserved active-player state helpers.",
        ],
    },
    {
        "original_ea": "0x1e9678",
        "original_name": "TClient_setPlayerStateFlag1680",
        "spectron_ea": "0x1edb38",
        "target_name": "sub_1EDB38",
        "source_basis": "active-player state flag at offset 1680",
        "evidence": [
            "Both bodies check for an active player and store byte one at the corresponding state field.",
            "The source and target retain the same 28-byte, seven-instruction, three-block shape after the level-state field setter.",
        ],
    },
    {
        "original_ea": "0x1e9694",
        "original_name": "TClient_setGhostModeValue",
        "spectron_ea": "0x1edb54",
        "target_name": "sub_1EDB54",
        "source_basis": "ghost-mode static setter",
        "evidence": [
            "Both bodies assign the incoming value directly to the ghost-mode static.",
            "The target retains the same 16-byte, four-instruction setter between the two active-player flag helpers.",
        ],
    },
    {
        "original_ea": "0x1e96a4",
        "original_name": "TClient_setPlayerStateFlag2328",
        "spectron_ea": "0x1edb64",
        "target_name": "sub_1EDB64",
        "source_basis": "active-player state flag at offset 2328",
        "evidence": [
            "Both bodies normalize the bool argument, check for an active player, and store it in the corresponding state byte.",
            "The source and target retain the same 28-byte, seven-instruction, three-block shape immediately before the event helpers.",
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
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: expected %s, got %s"
                % (spec["spectron_ea"], spec["target_name"], target.get("name"))
            )
        for field in ("size", "instruction_count", "basic_block_count"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s: %s versus %s"
                    % (
                        field,
                        spec["original_ea"],
                        spec["spectron_ea"],
                        source.get(field),
                        target.get(field),
                    )
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
                "match_kind": "manual-client-state-helper-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in client state helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_state_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact client state and forwarding helpers",
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
            "The compact wrappers preserve their forwarding, static assignment, and active-player field behavior across the two builds.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
