#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for the script property layer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x224ac0",
        "original_name": "TScriptProperty_readString_TGraalVar",
        "spectron_ea": "0x22d168",
        "target_name_fragment": "cWWYfaxbT210VkenganG9nEP10G0gxgajWBw",
        "source_basis": "script property string read conversion",
        "evidence": [
            "Both dispatch on the same property type letters b, c, d, f, i, o, s, and u, with a separate universe-object calling convention.",
            "Both convert boolean, numeric, object, and string results into the supplied string object, preserve the true and false literals, and return an empty string for unsupported or missing accessors. The target grows from 516 to 552 bytes while retaining 29 basic blocks.",
        ],
    },
    {
        "original_ea": "0x224cc4",
        "original_name": "TScriptProperty_writeFloat_TGraalVar_double",
        "spectron_ea": "0x22d390",
        "target_name_fragment": "cWWYfaxbT210JGEjIaHQ8TEP10G0gxgajWBwd",
        "source_basis": "script property floating-point write conversion",
        "evidence": [
            "Both dispatch the incoming floating-point value through the same property type table, including boolean, string, double, float, integer, object, and unsigned-integer cases.",
            "Both handle the universe object separately, normalize small values to the string '0', and report writes to read-only properties through the script-space error path. The target grows from 1252 to 1320 bytes while retaining 61 basic blocks.",
        ],
    },
    {
        "original_ea": "0x2251b0",
        "original_name": "TScriptProperty_writeString_TGraalVar_TString_const",
        "spectron_ea": "0x22d8c0",
        "target_name_fragment": "cWWYfaxbT210m6pngaXzjoEP10G0gxgajWBwRK10C8THgaTQxF",
        "source_basis": "script property string write conversion",
        "evidence": [
            "Both parse a string input according to the same property type letters, including boolean text, numeric conversion, object forwarding, and direct string assignment.",
            "Both preserve the universe-object and ordinary-object branches, forward read-only writes to the owning object when available, and otherwise build the same diagnostic. The target grows from 1092 to 1196 bytes while retaining 43 basic blocks.",
        ],
    },
    {
        "original_ea": "0x2255f4",
        "original_name": "TScriptProperty_writeObject_TGraalVar_TGraalVar",
        "spectron_ea": "0x22dd6c",
        "target_name_fragment": "cWWYfaxbT210Cu3DMaoyjxEP10G0gxgajWBwS1_",
        "source_basis": "script property object write conversion",
        "evidence": [
            "Both dispatch an incoming Graal variable through the same typed property cases, using float, object, string, and scalar conversion helpers as appropriate.",
            "Both create a temporary property object for unresolved access, forward read-only writes to the owning object when possible, and use the same script-space diagnostic fallback. The target grows from 1344 to 1620 bytes while retaining 61 basic blocks.",
        ],
    },
    {
        "original_ea": "0x225f68",
        "original_name": "TScriptProperty_TScriptProperty_TString_const_bool",
        "spectron_ea": "0x22e86c",
        "target_name_fragment": "cWWYfaxbT2C2ERK10C8THgaTQxFb",
        "source_basis": "script property construction",
        "evidence": [
            "Both construct the property base object from a string name and encoded-name flag, initialize the same accessor and ownership fields, and install the property vtable.",
            "Both normalize the name through the encoded or lowercase path before storing it, with four basic blocks in each decompilation. The target expands from 160 to 224 bytes because its string and hash helpers are inlined differently.",
        ],
    },
    {
        "original_ea": "0x226008",
        "original_name": "TScriptProperty_clone_void",
        "spectron_ea": "0x22e94c",
        "target_name_fragment": "cWWYfaxbT25cloneEv",
        "source_basis": "script property clone",
        "evidence": [
            "Both allocate a new property object, copy the base name and all accessor fields, and preserve the type, flags, owning properties object, and function metadata.",
            "The clone remains a single straight-line block in both builds and changes only from 152 to 148 bytes, with the target retaining the expected clone symbol fragment.",
        ],
    },
    {
        "original_ea": "0x2260dc",
        "original_name": "TScriptProperty_addProps_TProperties_TPropertyPropDef_int",
        "spectron_ea": "0x22ea1c",
        "target_name_fragment": "cWWYfaxbT210hFWn2apYKCEP10c76BgaJBGAP10C7do2a8u_Ci",
        "source_basis": "script property definition registration",
        "evidence": [
            "Both iterate property definitions, select encoded or case-insensitive lookup, replace typed property subclasses, create the universe property table when needed, and update inherited property metadata.",
            "Both lower unresolved names before creating the base property and then call the property setter with the supplied read accessor and metadata. The target grows from 948 to 1336 bytes while preserving the two registration paths.",
        ],
    },
    {
        "original_ea": "0x2264b4",
        "original_name": "TScriptProperty_setFunction_TProperties_char_TString_const_void_TString_const_bool",
        "spectron_ea": "0x22ef54",
        "target_name_fragment": "cWWYfaxbT210mVBJ2aXvZUEP10c76BgaJBGAcRK10C8THgaTQxFPvS4_b",
        "source_basis": "script property function metadata registration",
        "evidence": [
            "Both initialize the owning properties object, function type, setter and getter pointers, encoded-name flag, and the same adventure_ and tclient_ prefix guards.",
            "Both derive the real property name, classify the property as client or adventure scoped, and enable the same readonly behavior when the caller did not force it. The source and target each have 28 basic blocks and 500 bytes of function body.",
        ],
    },
    {
        "original_ea": "0x2266a8",
        "original_name": "TScriptProperty_addFuncs_TProperties_TPropertyFuncDef_int",
        "spectron_ea": "0x22f148",
        "target_name_fragment": "cWWYfaxbT210DpbOGacdQCEP10c76BgaJBGAP10sXw2GaJkKPi",
        "source_basis": "script property function definition registration",
        "evidence": [
            "Both iterate function definitions, choose encoded or case-insensitive lookup, create a base property when absent, and attach the function metadata through the shared setter.",
            "Both lower unresolved names, register the resulting property in the universe table when needed, and propagate the highest property scope. The target grows from 660 to 1016 bytes while retaining the same registration loop structure.",
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
                "match_kind": "manual-script-property-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-property anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_property_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for typed script properties and registration",
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
            "The changed-size rows rely on typed dispatch, conversion behavior, registration loops, matching diagnostics, control-flow shape, and pseudocode behavior rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
