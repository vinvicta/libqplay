#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for small machine helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x218bd0",
        "original_name": "TScriptMachine_restoreExecutionVariables_void",
        "spectron_ea": "0x2202fc",
        "target_name_fragment": "mTAogaaEip10vlUlPaO01OEv",
        "source_basis": "execution-variable restoration",
        "evidence": [
            "Both clear the saved execution-object field and return the machine pointer.",
            "Both are exact normalized two-instruction, one-block helpers; the target field offset moves from 144 to 152 with the changed machine layout.",
        ],
    },
    {
        "original_ea": "0x21ca00",
        "original_name": "TScriptMachine_charAt_void",
        "spectron_ea": "0x224af0",
        "target_name_fragment": "mTAogaaEip10nVJygaSeQxEv",
        "source_basis": "script string character extraction",
        "evidence": [
            "Both consume the next indexed input value, convert it to an integer position, and return an empty string for a negative or out-of-range index.",
            "Both load one character from the source string, assign it to the result string, and decrement the remaining input count. The target preserves the same nine-block body and only changes wrapper offsets and calls.",
        ],
    },
    {
        "original_ea": "0x21df18",
        "original_name": "TScriptMachine_findActionPlayer_void",
        "spectron_ea": "0x2261fc",
        "target_name_fragment": "mTAogaaEip10Q80oPa6zFREv",
        "source_basis": "action player lookup",
        "evidence": [
            "Both scan the action variable list backwards, dynamic-cast each non-null value to the server-player property type, and stop at the first match.",
            "Both initialize the global action-player slot from the executing player and replace it with the matched value while preserving the exact 8-block loop shape and normalized hashes.",
        ],
    },
    {
        "original_ea": "0x21dfc0",
        "original_name": "TScriptMachine_findActionNPC_void",
        "spectron_ea": "0x2262a4",
        "target_name_fragment": "mTAogaaEip10HvBoPapajREv",
        "source_basis": "action NPC lookup",
        "evidence": [
            "Both scan the action variable list backwards, dynamic-cast each non-null value to the server-NPC property type, and stop at the first match.",
            "Both initialize the global action-NPC slot from the executing NPC and replace it with the matched value while preserving the exact 8-block loop shape and normalized hashes.",
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
                "match_kind": "manual-machine-helper-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in machine-helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_machine_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for execution restoration, character extraction, and action-context lookup",
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
            "The changed-size character helper relies on its input-count and string-index behavior, while the action lookups are exact normalized matches with preserved global-slot roles.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
