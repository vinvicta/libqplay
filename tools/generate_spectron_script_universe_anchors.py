#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for the script universe layer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x22b254",
        "original_name": "TScriptUniverse_writeString_TString_const",
        "spectron_ea": "0x234c1c",
        "target_name_fragment": "e4ZYfa8PV210m6pngaXzjoERK10CanTfaz6bZ",
        "source_basis": "universe string value write",
        "evidence": [
            "Both mark the universe variable as a string, copy the incoming text into the value field, parse the same text as a floating-point cache, and unlink the old value links.",
            "The target adds the expected temporary string wrapper and cleanup but preserves the two-block setter structure and its position beside the other universe variable accessors. The body grows from 68 to 96 bytes.",
        ],
    },
    {
        "original_ea": "0x22b3ec",
        "original_name": "TScriptExecutionStats_TScriptExecutionStats_TGraalVar",
        "spectron_ea": "0x234dd0",
        "target_name_fragment": "R94BFa3XECC2EP10G0gxgajWBw",
        "source_basis": "script execution statistics construction",
        "evidence": [
            "Both initialize the statistics object from an optional Graal variable, copy the source name, allocate and link the nested value object, and clear all temporary strings.",
            "Both finish with zeroed counters and a null secondary pointer. The target constructor remains a three-block body and grows from 224 to 232 bytes.",
        ],
    },
    {
        "original_ea": "0x22b624",
        "original_name": "TScriptUniverse_addStaticObject_TGraalVar",
        "spectron_ea": "0x235010",
        "target_name_fragment": "e4ZYfa8PV210qBXhIa5KISEP10G0gxgajWBw",
        "source_basis": "universe static-object registration",
        "evidence": [
            "Both reject null objects, exclude the unknown_object name from replacement lookup, initialize links, remove an existing object with the same name, and lazily create the static-object hash list.",
            "Both add the object through the universe-owned list and preserve the same 11-block registration flow. The target grows from 196 to 204 bytes and retains the unknown_object diagnostic string.",
        ],
    },
    {
        "original_ea": "0x22b6e8",
        "original_name": "TScriptUniverse_TScriptUniverse_void",
        "spectron_ea": "0x2350dc",
        "target_name_fragment": "e4ZYfa8PV2C1Ev",
        "source_basis": "script universe construction",
        "evidence": [
            "Both initialize the universe Graal variable, register the universe globally, allocate the same collection and machine-state lists, and initialize the same counters and object tables.",
            "Both create the players, npcs, and allplayers static variables, assign their list backing stores, and register them through addStaticObject. The target body remains three IDA chunks with the same 848 versus 864 byte construction footprint and the same distinctive strings.",
        ],
    },
    {
        "original_ea": "0x22c260",
        "original_name": "TScriptUniverse_getClassAndCreate_TString_const_bool",
        "spectron_ea": "0x235c48",
        "target_name_fragment": "e4ZYfa8PV210_d5_faz0G4ERK10C8THgaTQxFb",
        "source_basis": "universe class lookup and creation",
        "evidence": [
            "Both hash and look up the requested class, reload a requested class when necessary, create a new script object when absent, and store server privileges on the class.",
            "Both clear privileges for the gani:: prefix, register the new class in the universe table, and optionally start the encrypted class load. The target grows from 364 to 388 bytes while retaining the same 11-block flow and gani:: string.",
        ],
    },
    {
        "original_ea": "0x22cc88",
        "original_name": "TScriptUniverse_addClassScript_TString_const_TString_const",
        "spectron_ea": "0x2366ec",
        "target_name_fragment": "e4ZYfa8PV210aUFLuaVRIuERK10C8THgaTQxFS2_",
        "source_basis": "universe class script installation",
        "evidence": [
            "Both add a class name to the requested-class list, obtain or create the class with loading enabled, install the script stream when privileges allow, and clear the pending-load flag.",
            "Both invoke onClassLoaded on the universe and on the class itself, passing the class name through the same string argument path. The target grows from 272 to 404 bytes while preserving the source ten-block role.",
        ],
    },
    {
        "original_ea": "0x22cf78",
        "original_name": "TScriptUniverse_compileZippedScripts_TString_const",
        "spectron_ea": "0x236a60",
        "target_name_fragment": "e4ZYfa8PV210fNjKua0fAtERK10C8THgaTQxF",
        "source_basis": "zipped script package compiler",
        "evidence": [
            "Both parse the same package header and length fields, verify the package with the embedded RSA and SHA-256 material, decrypt the archive payload, and iterate the zip entries with the same 10000-entry and 0x40000000-byte limits.",
            "Both branch on .rk, .t, NPCS/, and CLASSES/ entries, update NPC scripts or class streams, invoke onClassLoaded, and preserve the same split IDA entry boundary immediately before addZippedScripts. The large body is represented as a 32-byte entry range with 563 source instructions and 587 target instructions, so the artifact records the boundary and pseudocode evidence rather than treating the displayed range as the full body size.",
        ],
    },
    {
        "original_ea": "0x22cf98",
        "original_name": "TScriptUniverse_addZippedScripts_TString_const_TSocketConnection",
        "spectron_ea": "0x236a80",
        "target_name_fragment": "e4ZYfa8PV210PoZKuaEg8tERK10C8THgaTQxFP10u3cBgayBVz",
        "source_basis": "zipped script package installation",
        "evidence": [
            "Both compile the zipped script payload, locate StartScript_Connector or StartScript_Fail, report the same networking error when neither exists, and require onCreated before continuing.",
            "Both copy scriptip, scriptsslcipher, scriptsslsubject, and scriptsslissuer from the socket connection before enabling the connector object. The target body is 644 bytes versus 680 in the source, with the same 11-block package-install role and distinctive strings.",
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
                "match_kind": "manual-script-universe-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-universe anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_universe_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for universe variables, classes, and zipped scripts",
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
            "The changed-size rows rely on class-local order, package strings, archive and class state transitions, target signatures, and pseudocode behavior rather than byte identity.",
            "The compileZippedScripts row is a split IDA function with a short displayed entry range and a large set of associated function chunks. Its evidence records that boundary explicitly.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
