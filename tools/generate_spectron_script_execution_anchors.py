#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for script execution dispatch."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x22871c",
        "original_name": "TScriptSpace_executeFunction_TScriptFunction_TGraalVar_bool_TScriptMachine",
        "spectron_ea": "0x23168c",
        "target_name_fragment": "N67CMatrxw10PADGMaKVtzEP10AICTfaebpZP10G0gxgajWBwbP10mTAogaaEip",
        "source_basis": "script function execution",
        "evidence": [
            "Both reject invalid or busy script spaces, borrow the universe free machine, set its executing object and script name, prepare the function, push the argument variable, and execute the machine.",
            "Both preserve the status-two suspended path, status-three return-value extraction when requested, execution-variable restoration, free-machine return, and restoration of the previous universe machine.",
            "The target keeps the five-argument signature and the same call sequence. Its body is 500 bytes versus 532 bytes in the source because the target wrappers and inlining changed the code shape.",
        ],
    },
    {
        "original_ea": "0x228930",
        "original_name": "TScriptSpace_executeActionSelfCatch_TString_const_TScriptAction",
        "spectron_ea": "0x231880",
        "target_name_fragment": "N67CMatrxw10A2WRfbUh_XERK10C8THgaTQxFP10FOb5fbmyZ8",
        "source_basis": "self-caught action dispatch",
        "evidence": [
            "Both normalize an on-prefixed action name, handle the created, initialized, and initframe event set, and execute matching event functions while avoiding duplicate function calls.",
            "Both fall back to the script and class property lookup path when no direct event function is found, then execute the resolved function with the action argument array.",
            "The target preserves the same 41-block dispatch structure and grows only from 952 to 956 bytes, with target string and list wrappers visible in pseudocode.",
        ],
    },
    {
        "original_ea": "0x228ce8",
        "original_name": "TScriptSpace_executeActionNamedObject_TScriptAction",
        "spectron_ea": "0x231c3c",
        "target_name_fragment": "N67CMatrxw10wI3Rfb4J5XEP10FOb5fbmyZ8",
        "source_basis": "named-object action dispatch",
        "evidence": [
            "Both scan the current script's function list and then the active class list for an action name and case-insensitive function name match.",
            "Both invoke the shared script-function executor with the action's argument array and release each returned variable before continuing.",
            "The target retains the same nested scan and loop roles in the N67CMatrxw sequence, with a 472-byte body versus 456 bytes in the source.",
        ],
    },
    {
        "original_ea": "0x228eb0",
        "original_name": "TScriptSpace_executeActionCatch_TGraalVar_TScriptAction",
        "spectron_ea": "0x231e14",
        "target_name_fragment": "N67CMatrxw10hvRRfb_CVXEP10G0gxgajWBwP10FOb5fbmyZ8",
        "source_basis": "caught action dispatch",
        "evidence": [
            "Both require an object and action, skip the current executing object, resolve the catching function by event and object name, and lazily create the action argument array.",
            "Both insert a link variable for the caught object, execute the function, and release the returned value when present.",
            "The target keeps the same compact role and expands from 188 to 256 bytes for target string and variable wrappers.",
        ],
    },
    {
        "original_ea": "0x228f6c",
        "original_name": "TScriptSpace_checkCallerSuspenseWakeUp_TGraalVar_TString_const_double_int",
        "spectron_ea": "0x231f14",
        "target_name_fragment": "N67CMatrxw10FIvRfbdiDXEP10G0gxgajWBwRK10C8THgaTQxFdi",
        "source_basis": "suspended caller wake-up",
        "evidence": [
            "Both first update an existing saved state when found, otherwise read the object's script space and locate the matching event state using the supplied delay and event name.",
            "Both mark the state active, create or update its stack entry, copy the current machine value when the execution status requires it, and call the object's event callback.",
            "The target retains the same five-argument signature and wake-up sequence, with 588 bytes versus 560 bytes in the source.",
        ],
    },
    {
        "original_ea": "0x22981c",
        "original_name": "TScriptSpace_freeActions_void",
        "spectron_ea": "0x232944",
        "target_name_fragment": "N67CMatrxw10oaqhMalDgeEv",
        "source_basis": "script action list cleanup",
        "evidence": [
            "Both walk the action list at object offset 64, destroy each non-null TScriptAction object, and clear the list afterward.",
            "The source and target bodies preserve the same 124-byte, 31-instruction, nine-block shape in the N67CMatrxw class sequence.",
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
                "match_kind": "manual-script-execution-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-execution anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_execution_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for GS2 function invocation, action dispatch, caller wake-up, and action cleanup",
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
