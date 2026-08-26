#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for GS2 execution-machine code."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x21886c",
        "original_name": "TScriptMachine_TScriptMachine",
        "spectron_ea": "0x21ff78",
        "target_name_fragment": "mTAogaaEipD1Ev",
        "source_basis": "script-machine destructor",
        "evidence": [
            "IDA identifies the source body as the TScriptMachine destructor through its alternative D2 name; it clears the call stack, releases machine-owned lists and variables, decrements the machine count, and clears the string fields.",
            "Spectron's target is the matching mTAogaaEip D1/D2 destructor body. It preserves the same owned-list cleanup order and machine-count decrement, with one additional target string wrapper clear.",
            "The source and target retain the same 22-block control-flow shape and sit immediately before their respective reset-stack methods.",
        ],
    },
    {
        "original_ea": "0x218a3c",
        "original_name": "TScriptMachine_TScriptMachine_void",
        "spectron_ea": "0x220150",
        "target_name_fragment": "mTAogaaEipC1Ev",
        "source_basis": "script-machine constructor",
        "evidence": [
            "Both constructors initialize the machine counters and stack-owned lists, create the parameter variable, set its type markers, and allocate its child list.",
            "The source and target constructor bodies preserve the same one-block initialization structure and the same field offsets. Spectron's target carries the matching C1/C2 constructor signature.",
        ],
    },
    {
        "original_ea": "0x218b8c",
        "original_name": "TScriptMachine_setExecutingObject_TGraalVar_TString_const_TScriptMachine",
        "spectron_ea": "0x2202a4",
        "target_name_fragment": "mTAogaaEip10RGsmPaPKvPEP10G0gxgajWBw",
        "source_basis": "executing-object and script-name setup",
        "evidence": [
            "Both helpers copy the current script name into the machine's string field, set the executing and active object pointers to the supplied variable, and save the parent machine pointer.",
            "The target remains a short one-block method in the mTAogaaEip execution-machine class and preserves the same three state assignments.",
        ],
    },
    {
        "original_ea": "0x218e98",
        "original_name": "TScriptMachine_resolveObjectMember_TGraalVar_TString_const_TScriptProperty_TGraalVar_bool",
        "spectron_ea": "0x2205c4",
        "target_name_fragment": "mTAogaaEip10xxpwPaW5SXEP10G0gxgajWBw",
        "source_basis": "script object-member resolution",
        "evidence": [
            "Both resolve a property or variable through an object, then search object fields, temporary and parameter variables, this and player aliases, class objects, joined classes, event objects, and the active or universe fallback paths.",
            "The target preserves the same special names including temp, params, this, thiso, player, playero, level, join, leave, serverr, client, and clientr, with the same property and variable output parameters.",
            "The target is the large mTAogaaEip resolver immediately before the target stack-entry helpers. Its added size comes from target string and hash wrappers, not a different role.",
        ],
    },
    {
        "original_ea": "0x21a3b0",
        "original_name": "TScriptMachine_assign_void",
        "spectron_ea": "0x221ef8",
        "target_name_fragment": "mTAogaaEip6assignEv",
        "source_basis": "script value assignment",
        "evidence": [
            "Both pop the assignment frame, resolve the destination and value stack entries, and dispatch string, float, integer, or object writes through either a property or a variable virtual method.",
            "The target retains the same 29-block control-flow shape and the same value-type branches. Its additional instructions materialize target string temporaries for string assignment.",
        ],
    },
    {
        "original_ea": "0x21a6a8",
        "original_name": "TScriptMachine_compare_void",
        "spectron_ea": "0x222218",
        "target_name_fragment": "mTAogaaEip7compareEv",
        "source_basis": "script value comparison",
        "evidence": [
            "Both resolve and pop the two comparison operands, then handle string, numeric, and object-backed values with the same tolerance for float comparison and the same three-way return convention.",
            "The target preserves the 36-block comparison structure and the source's type-pair dispatch, while target string wrappers expand the body.",
        ],
    },
    {
        "original_ea": "0x21a8b0",
        "original_name": "TScriptMachine_compareFloat_double",
        "spectron_ea": "0x2224e0",
        "target_name_fragment": "mTAogaaEip10Z9kTPa5pagEd",
        "source_basis": "script value versus float comparison",
        "evidence": [
            "Both resolve the current stack value, convert a string value when needed, compare it with the supplied double using the same tolerance, and return -1, 0, or 1 semantics.",
            "The target is the adjacent mTAogaaEip double-taking comparison helper and retains the same nested type branches.",
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
                "match_kind": "manual-script-machine-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-machine anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_machine_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for GS2 script-machine construction, resolution, assignment, and comparison",
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
            "The source destructor's alternative D2 name and the target D1/D2 pair are treated as one compiler-generated destructor body.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
