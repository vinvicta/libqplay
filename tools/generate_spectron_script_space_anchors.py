#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for TScriptSpace event state."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x2274d0",
        "original_name": "TScriptSpace_freeScriptErrors_void",
        "spectron_ea": "0x230214",
        "target_name_fragment": "N67CMatrxw10flS_fbykv4Ev",
        "source_basis": "script-error list cleanup",
        "evidence": [
            "Both inspect the script-error list at object offset 112, release it through the same virtual clear path, and write the field back to null.",
            "The source and target bodies preserve the same 52-byte, 13-instruction, three-block shape in the N67CMatrxw class sequence.",
        ],
    },
    {
        "original_ea": "0x227558",
        "original_name": "TScriptSpace_addScriptError_TString_const",
        "spectron_ea": "0x23029c",
        "target_name_fragment": "N67CMatrxw10vZIuMasssp",
        "source_basis": "script-error hook",
        "evidence": [
            "IDA shows both functions as the same empty one-instruction hook with the TScriptSpace receiver and one string argument.",
            "The target sits directly after the target free-script and free-error-list helpers, preserving the source class-local order.",
        ],
    },
    {
        "original_ea": "0x22755c",
        "original_name": "TScriptSpace_catchEvent_TString_const_TString_const_TString_const",
        "spectron_ea": "0x2302a0",
        "target_name_fragment": "N67CMatrxw10vcTVfae3i0ERK10C8THgaTQxFS2_S2_",
        "source_basis": "named event catcher registration",
        "evidence": [
            "Both resolve or create the universe event object, enforce the TClient class-depth rule, create the script space when needed, and register the event catcher.",
            "Both maintain the unknown-object exclusion list and return success after adding the event object name, with the same source class-local position.",
            "The target expands from 648 to 720 bytes because the obfuscated build uses new string and hash wrappers, but the pseudocode retains the same universe, client, event-object, and catcher operations.",
        ],
    },
    {
        "original_ea": "0x2277e4",
        "original_name": "TScriptSpace_catchEvent_TGraalVar_TString_const_TString_const",
        "spectron_ea": "0x230570",
        "target_name_fragment": "N67CMatrxw10vcTVfae3i0EP10G0gxgajWBw",
        "source_basis": "object event catcher registration",
        "evidence": [
            "Both reject a null object or script space, apply the same TClient class-depth rule, create the object's event space when absent, and register the catcher against that object.",
            "Both avoid adding the local event object to the unknown-object list and otherwise append it to the script-space list only once.",
            "The target is 464 bytes versus 360 bytes in the source, with the changed size attributable to target string wrappers while the control flow and event-object behavior remain recognizable.",
        ],
    },
    {
        "original_ea": "0x227ee8",
        "original_name": "TScriptSpace_leaveClass_TScript",
        "spectron_ea": "0x230cdc",
        "target_name_fragment": "N67CMatrxw10fssWfaryN0EP10zW2NgaU4IK",
        "source_basis": "script class leave dispatch",
        "evidence": [
            "Both require the class in the active script list, iterate its event objects, skip onInitFrame when the class flag is set, and invoke the matching event object's leave callback.",
            "Both then remove the class from the owning script and destroy the iterator. The target retains the same iterator and virtual callback sequence.",
            "The target grows from 308 to 320 bytes because the string and list wrappers changed, while the class-local method order remains exact.",
        ],
    },
    {
        "original_ea": "0x2280ac",
        "original_name": "TScriptSpace_checkLeaveClasses_void",
        "spectron_ea": "0x230eac",
        "target_name_fragment": "N67CMatrxw10JFyTfbLMlZEv",
        "source_basis": "pending class leave processing",
        "evidence": [
            "Both walk the pending leave-name list, search the active class list by name, call the TScriptSpace leave-class helper for each match, and clear the pending list.",
            "Both trigger classUpdateAction(true) when a class was actually removed and otherwise return after clearing the list.",
            "The target preserves the source loop and callback roles in the same class-local slot, with a 312-byte body versus 276 bytes after wrapper changes.",
        ],
    },
    {
        "original_ea": "0x22835c",
        "original_name": "TScriptSpace_getEventState_TString_const_TString_const_bool",
        "spectron_ea": "0x231180",
        "target_name_fragment": "N67CMatrxw10mtG7fbil4aERK10CanTfaz6bZS2_b",
        "source_basis": "event-state lookup",
        "evidence": [
            "Both normalize the event name, map istimeout to timeout, strip an on prefix, and search the saved machine-state list by event name and object name.",
            "Both fall back to the current script object when the supplied object name is empty and optionally delete the matched state when the boolean flag is set.",
            "The target retains the same loop, timeout normalization, fallback, and optional-delete semantics. Its body grows from 436 to 656 bytes because of guarded target string constants and wrapper calls.",
        ],
    },
    {
        "original_ea": "0x228510",
        "original_name": "TScriptSpace_setTimeout_double",
        "spectron_ea": "0x231410",
        "target_name_fragment": "N67CMatrxw10CodpMarTPkEd",
        "source_basis": "script timeout scheduling",
        "evidence": [
            "Both store the timeout value, clear the timeout state for non-positive values, and look up the timeout event state with the same timeout and on names.",
            "Both destroy an existing machine state, update the universe player or active object pointer, and activate the script when a positive timeout remains.",
            "The target preserves the same double-taking signature and call order while expanding from 236 to 352 bytes for guarded string constants.",
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
                "match_kind": "manual-script-space-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-space anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_space_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TScriptSpace event registration, class transitions, event state, and timeout scheduling",
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
