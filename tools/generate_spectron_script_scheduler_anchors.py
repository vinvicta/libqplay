#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for script scheduling and cleanup."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x22a204",
        "original_name": "TScriptSpace_cancelEvents_TString_const",
        "spectron_ea": "0x233a68",
        "target_name_fragment": "N67CMatrxw10hH2bMa5SK9ERK10C8THgaTQxF",
        "source_basis": "scheduled-event cancellation",
        "evidence": [
            "Both walk the scheduled-event list backwards, compare event names case-insensitively, destroy matching events, and remove them from the list.",
            "Both then mark matching pending actions as canceled when they have no argument object, preserving the same two-list cancellation policy.",
            "The target retains the source method signature and class-local position. Its body grows from 272 to 328 bytes around the rebuilt string wrapper.",
        ],
    },
    {
        "original_ea": "0x22a354",
        "original_name": "TScriptSpace_checkScheduledEvents_void",
        "spectron_ea": "0x233bf0",
        "target_name_fragment": "N67CMatrxw10Gr_GMaW8MzEv",
        "source_basis": "scheduled-event polling",
        "evidence": [
            "Both decrement the active timeout against universe time, enqueue the timeout event when it expires, and retain the remaining time otherwise.",
            "Both walk scheduled events, unlink dead object references, enqueue due events, reschedule repeating events, and process delayed event states from the second list.",
            "The target preserves the same loop nesting and receiveEvent calls while growing from 640 to 732 bytes for changed event and string wrappers.",
        ],
    },
    {
        "original_ea": "0x22a5e0",
        "original_name": "TScriptSpace_runScript_void",
        "spectron_ea": "0x233ed8",
        "target_name_fragment": "N67CMatrxw10_xWAgaiSGzEv",
        "source_basis": "script-space action loop",
        "evidence": [
            "Both reject inactive scripts, update classes and scheduled events, defer while waiting for downloads, and install event catchers after downloads complete.",
            "Both set executing player and NPC context, profile action execution time, iterate active actions, stop on a script error state, free actions, and restore global execution state.",
            "The target preserves the same action-loop structure and profiling table update, with 892 bytes versus 844 bytes in the source.",
        ],
    },
    {
        "original_ea": "0x22ac2c",
        "original_name": "TScriptSpace_unlinkEventObject_void",
        "spectron_ea": "0x234554",
        "target_name_fragment": "N67CMatrxw10jpuKOaZbJiEv",
        "source_basis": "event-object unlinking",
        "evidence": [
            "Both remove the script-space catcher from the event object, decide whether the object is still globally referenced, and either retain or unregister and destroy it.",
            "Both preserve the unknown-object guard, universe event-object hash lookup, and nulling of the script-space event-object pointer when ownership is released.",
            "The target grows from 380 to 416 bytes because its event-object, hash, and string wrappers changed, but the ownership branches remain explicit.",
        ],
    },
    {
        "original_ea": "0x22ada8",
        "original_name": "TScriptSpace_ignoreEvents_TString_const",
        "spectron_ea": "0x2346f4",
        "target_name_fragment": "N67CMatrxw10qFYqMasEimERK10C8THgaTQxF",
        "source_basis": "event ignore helper",
        "evidence": [
            "Both find the named event object, remove this script space as a catcher when present, and remove the event name from the locally tracked event list.",
            "The target retains the same short two-helper behavior and target string signature, with wrapper cleanup added around the list key.",
        ],
    },
    {
        "original_ea": "0x22b07c",
        "original_name": "TScriptSpace_setClasses_TString_const",
        "spectron_ea": "0x234a34",
        "target_name_fragment": "N67CMatrxw10HsHbZaTas5ERK10C8THgaTQxF",
        "source_basis": "script class-list replacement",
        "evidence": [
            "Both leave all current classes, create the empty base script when needed, split the supplied class list, and join each class with the update flag set.",
            "Both reinstall event catchers, trigger classUpdateAction(true), and destroy the temporary class-name list.",
            "The target preserves the same helper order and grows only from 224 to 228 bytes around wrapper construction.",
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
                "match_kind": "manual-script-scheduler-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-scheduler anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_scheduler_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for GS2 scheduling, action loops, event-object cleanup, and class-list replacement",
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
