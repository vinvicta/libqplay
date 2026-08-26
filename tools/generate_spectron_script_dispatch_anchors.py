#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for top-level script dispatch."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x22919c",
        "original_name": "TScriptSpace_executeScript_TString_const_TString_const_TGraalVar",
        "spectron_ea": "0x232160",
        "target_name_fragment": "N67CMatrxw10uSMgPasJJKERK10C8THgaTQxFS2_P10G0gxgajWBw",
        "source_basis": "script-state execution entry",
        "evidence": [
            "Both check the current script and busy flag, look up or create the event state, borrow the universe free machine, and prepare either the event state or the script's main function.",
            "Both supply NPC comma-text arguments when needed, execute the machine, detect an updated called script, wake a suspended caller, restore execution variables, return the machine to the free list, and restore the previous universe machine.",
            "The target retains the same event-state and script-function branches. Its body grows from 844 to 960 bytes because target string and variable wrappers are materialized explicitly.",
        ],
    },
    {
        "original_ea": "0x2294e8",
        "original_name": "TScriptSpace_executeAction_TScriptAction",
        "spectron_ea": "0x232520",
        "target_name_fragment": "N67CMatrxw10cLiSfbhoiYEP10FOb5fbmyZ8",
        "source_basis": "top-level action dispatcher",
        "evidence": [
            "Both reject busy actions and scripts, update classes, resolve the action's target object or universe object, and update the executing NPC's global-player state.",
            "Both route an existing event state through executeScript, dispatch local and caught actions, select whole-script or function events, execute the fallback script, and process pending class leaves.",
            "The target preserves the same action-state branches and helper calls in the N67CMatrxw class. Its body grows from 820 to 1060 bytes around target string and object wrappers.",
        ],
    },
    {
        "original_ea": "0x229898",
        "original_name": "TScriptSpace_receiveEvent_TString_const_TString_const_TGraalVar",
        "spectron_ea": "0x2329c0",
        "target_name_fragment": "N67CMatrxw10rVjVga1mQQERK10C8THgaTQxFS2_P10G0gxgajWBw",
        "source_basis": "incoming event queue insertion",
        "evidence": [
            "Both reject events on inactive objects, enforce the 999-event limit with the onAllRCChat exception, and report overruns through addScriptError.",
            "Both suppress duplicate onshow and onhide events in the small queue, construct a TScriptAction with the same object, event, and argument fields, and prioritize timeout, created, and initialized actions at the front.",
            "The target preserves duplicate detection, optional argument comparison for larger queues, activation of the script, and return of the new action. Its body grows from 988 to 1156 bytes due to target wrappers and guarded constants.",
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
                "match_kind": "manual-script-dispatch-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-dispatch anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_dispatch_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for GS2 script execution, action dispatch, and incoming event queueing",
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
            "The changed-size rows rely on class-local order, pseudocode behavior, target signatures, and caller context rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
