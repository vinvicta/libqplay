#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for GS2 script-runtime helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x20d28c",
        "original_name": "TGraalVar_getArraySize_void",
        "spectron_ea": "0x21364c",
        "target_name": "_ZN10G0gxgajWBw10zYM_faGOq4Ev",
        "source_basis": "GS2 array-size accessor",
        "evidence": [
            "Both bodies read the array pointer at the same logical variable offset and return its element count, or zero when no array is present.",
            "The source and target preserve the same compact normalized function shape and field offsets.",
        ],
    },
    {
        "original_ea": "0x20d8b4",
        "original_name": "TGraalVar_setPaused_bool",
        "spectron_ea": "0x213d5c",
        "target_name": "_ZN10G0gxgajWBw10Gd3lMafkaiEb",
        "source_basis": "GS2 script pause setter",
        "evidence": [
            "Both bodies store the pause byte and, when pausing, follow the script-space pointer to clear pending actions.",
            "The source and target preserve the same compact normalized function shape and action-clearing call path.",
        ],
    },
    {
        "original_ea": "0x20eae0",
        "original_name": "TGraalVar_script_scheduleevent",
        "spectron_ea": "0x214fb4",
        "target_name": "sub_214FB4",
        "source_basis": "GS2 scheduled-event wrapper",
        "evidence": [
            "Both wrappers forward the event delay, event name, and variable payload to the same schedule-event helper.",
            "The source and target preserve the same argument-forwarding sequence and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x20edd8",
        "original_name": "TGraalVar_getTimeout_void",
        "spectron_ea": "0x2152a4",
        "target_name": "_ZN10G0gxgajWBw10nBwpMa214kEv",
        "source_basis": "GS2 timeout accessor",
        "evidence": [
            "Both bodies follow the variable's script-space pointer, return zero for a missing script space, and otherwise call the script-space timeout accessor.",
            "The source and target preserve the same null guard, forwarding path, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x20ee38",
        "original_name": "TGraalVar_script_settimer",
        "spectron_ea": "0x215304",
        "target_name": "sub_215304",
        "source_basis": "GS2 timer wrapper",
        "evidence": [
            "Both wrappers forward the timer delay to the same variable timeout setter.",
            "The source and target preserve the same compact argument-forwarding sequence and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x20eec8",
        "original_name": "TGraalVar_setScriptLogMissingFunctions_bool",
        "spectron_ea": "0x215394",
        "target_name": "_ZN10G0gxgajWBw10GXtpMaRO2kEb",
        "source_basis": "GS2 missing-function logging setter",
        "evidence": [
            "Both bodies follow the script-space pointer and store the logging flag at the same logical script-space field.",
            "The source and target preserve the same null guard, field store, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x20f878",
        "original_name": "TGraalVar_setArrayWasUpdated_void",
        "spectron_ea": "0x215e40",
        "target_name": "_ZN10G0gxgajWBw10tpNgMa2aKdEv",
        "source_basis": "GS2 linked-array update propagation",
        "evidence": [
            "Both bodies walk the linked variable list, clear the updated byte in each entry, and follow the same next-link field.",
            "The source and target preserve the same loop structure, field offsets, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x214e8c",
        "original_name": "TScript_copyAccessRights_TGraalVar",
        "spectron_ea": "0x21ba9c",
        "target_name": "_ZN10zW2NgaU4IK10Dy0WfaM4f1EP10G0gxgajWBw",
        "source_basis": "GS2 access-right propagation",
        "evidence": [
            "Both bodies test the variable pointer and copy its access-right byte into the same script field.",
            "The source and target preserve the same null guard, byte load, destination store, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x227b94",
        "original_name": "TScriptSpace_getTimeout_void",
        "spectron_ea": "0x230988",
        "target_name": "_ZN10N67CMatrxw10nBwpMa214kEv",
        "source_basis": "script-space timeout field accessor",
        "evidence": [
            "Both bodies return the double stored in the same script-space timeout field.",
            "The source and target preserve the same direct field access and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x227eb8",
        "original_name": "TScriptSpace_needWholeScriptEvent_script_event",
        "spectron_ea": "0x230cac",
        "target_name": "_ZN10N67CMatrxw10B0GWfbeOZ0E10RiQ7IaxCcA",
        "source_basis": "whole-script event mask predicate",
        "evidence": [
            "Both bodies test the requested event bit against the same whole-script event mask field.",
            "The source and target preserve the same shift, mask load, and boolean result shape.",
        ],
    },
    {
        "original_ea": "0x227ed0",
        "original_name": "TScriptSpace_needFunctionEvent_script_event",
        "spectron_ea": "0x230cc4",
        "target_name": "_ZN10N67CMatrxw10vZjWfbmqG0E10RiQ7IaxCcA",
        "source_basis": "function event mask predicate",
        "evidence": [
            "Both bodies test the requested event bit against the same function event mask field beside the whole-script mask.",
            "The source and target preserve the same shift, mask load, and boolean result shape.",
        ],
    },
    {
        "original_ea": "0x22b600",
        "original_name": "TScriptUniverse_clearVars_void",
        "spectron_ea": "0x234fec",
        "target_name": "_ZN10e4ZYfa8PV210I75gMaeM_dEv",
        "source_basis": "GS2 universe variable cleanup",
        "evidence": [
            "Both bodies test the universe variable container, then invoke non-protected variable cleanup with the same mode argument.",
            "The source and target preserve the same conditional cleanup call and normalized function shape.",
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
                "match_kind": "manual-script-runtime-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-runtime anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_runtime_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact GS2-facing script-runtime helpers",
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
            "The target script-runtime helpers preserve the local GS2-facing array, timer, event, access-right, and variable-cleanup behavior with exact normalized function hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
