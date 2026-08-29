#!/usr/bin/env python3
"""Create reviewed residual anchors for the Spectron static-variable block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)


ANCHOR_SPECS = (
    {
        "original_ea": "0x22d240",
        "original_name": "TScriptUniverse_initStaticScriptVars_void",
        "spectron_ea": "0x236d04",
        "spectron_name": "_Z10NJLNuahMtwv",
        "operation": "registers the universe static script properties",
        "basis": "Hex-Rays pseudocode, same one-call initializer shape, exact normalized size and control-flow metrics, and class-local placement",
        "evidence": [
            "Both functions make one property-registration call with a null receiver, one static table address, and the integer 1.",
            "The target NJLNuahMtw body is the same 20-byte initializer shape; only register-detail normalization differs.",
        ],
    },
    {
        "original_ea": "0x22d254",
        "original_name": "TScriptUniverseProperties_TScriptUniverseProperties",
        "spectron_ea": "0x236d18",
        "spectron_name": "_ZN20e4ZYfa8PV2PropertiesD1Ev",
        "operation": "runs the complete TScriptUniverseProperties destructor",
        "basis": "Hex-Rays pseudocode, D1 destructor spelling, exact normalized destructor metrics, and adjacent target thunk and D0 entries",
        "evidence": [
            "Both functions reset the primary and secondary vtable pointers and call the base TProperties destructor.",
            "The target e4ZYfa8PV2Properties D1 body is a 28-byte normalized counterpart of the source complete destructor and is followed by the matching non-virtual thunk and deleting destructor.",
        ],
    },
    {
        "original_ea": "0x22d270",
        "original_name": "non_virtual_thunk_to_TScriptUniverseProperties_TScriptUniverseProperties",
        "spectron_ea": "0x236d34",
        "spectron_name": "_ZThn16_N20e4ZYfa8PV2PropertiesD1Ev",
        "operation": "adjusts the secondary TScriptUniverseProperties destructor receiver",
        "basis": "Hex-Rays pseudocode, exact normalized thunk metrics, and adjacency to the matching D1 destructor",
        "evidence": [
            "Both thunks subtract 16 bytes from the receiver and tail-call the corresponding complete destructor.",
            "The source and target are exact 8-byte, one-block thunk matches in the same destructor quartet.",
        ],
    },
    {
        "original_ea": "0x22d278",
        "original_name": "TScriptUniverseProperties_TScriptUniverseProperties__2",
        "spectron_ea": "0x236d3c",
        "spectron_name": "_ZN20e4ZYfa8PV2PropertiesD0Ev",
        "operation": "runs the deleting TScriptUniverseProperties destructor",
        "basis": "Hex-Rays pseudocode, D0 destructor spelling, exact normalized destructor metrics, and adjacent target D1 and thunk entries",
        "evidence": [
            "Both functions reset the two vtable pointers, invoke the base destructor, and then release the receiver with operator delete.",
            "The target e4ZYfa8PV2Properties D0 body is a 56-byte normalized counterpart of the source deleting destructor.",
        ],
    },
    {
        "original_ea": "0x22d2b0",
        "original_name": "non_virtual_thunk_to_TScriptUniverseProperties_TScriptUniverseProperties__2",
        "spectron_ea": "0x236d74",
        "spectron_name": "_ZThn16_N20e4ZYfa8PV2PropertiesD0Ev",
        "operation": "adjusts the secondary deleting TScriptUniverseProperties destructor receiver",
        "basis": "Hex-Rays pseudocode, exact normalized thunk metrics, and adjacency to the matching D0 destructor",
        "evidence": [
            "Both thunks subtract 16 bytes from the receiver and call the corresponding deleting destructor.",
            "The source and target are exact 8-byte thunk matches in the same class-local destructor sequence.",
        ],
    },
    {
        "original_ea": "0x22d2d4",
        "original_name": "TGraalPlayersArrayVar_TGraalPlayersArrayVar",
        "spectron_ea": "0x236d98",
        "spectron_name": "_ZN10JE42uaVwcKD1Ev",
        "operation": "runs the complete TGraalPlayersArrayVar destructor",
        "basis": "Hex-Rays pseudocode, D1 destructor spelling, exact normalized destructor metrics, and the translated array-cell method immediately before it",
        "evidence": [
            "Both functions install the class vtable and invoke the TGraalVar base destructor.",
            "The target JE42uaVwcK D1 body is a 20-byte normalized counterpart of the source complete destructor and directly follows the already translated getArrayCellObject method.",
        ],
    },
    {
        "original_ea": "0x22d2e8",
        "original_name": "TGraalPlayersArrayVar_TGraalPlayersArrayVar__2",
        "spectron_ea": "0x236dac",
        "spectron_name": "_ZN10JE42uaVwcKD0Ev",
        "operation": "runs the deleting TGraalPlayersArrayVar destructor",
        "basis": "Hex-Rays pseudocode, D0 destructor spelling, exact normalized destructor metrics, and adjacency to the target D1 body",
        "evidence": [
            "Both functions install the class vtable, invoke the TGraalVar base destructor, and then call operator delete.",
            "The target JE42uaVwcK D0 body is a 48-byte normalized counterpart of the source deleting destructor.",
        ],
    },
    {
        "original_ea": "0x22d318",
        "original_name": "jump_TScriptEnvironment_destroyScriptVariable_TGraalVar__2",
        "spectron_ea": "0x236ddc",
        "spectron_name": "j_._ZN10D6TlgajP1m10R8CcIadyeOEP10G0gxgajWBw_0",
        "operation": "forwards script-variable destruction to the environment helper",
        "basis": "Hex-Rays pseudocode, exact normalized jump-wrapper metrics, and placement between the players-array destructor and TStaticVar methods",
        "evidence": [
            "Both four-byte wrappers are thunks that forward the same two-argument destruction operation to the target-specific implementation.",
            "The source and target are exact one-instruction jump-wrapper matches; the target linker prefix is retained in its raw name.",
        ],
    },
    {
        "original_ea": "0x22d490",
        "original_name": "TStaticVar_create_TString_const",
        "spectron_ea": "0x236f80",
        "spectron_name": "_Z20NgNBgaN3oAE7Bm2aaHDBRK10C8THgaTQxF",
        "operation": "allocates and constructs a TStaticVar from a string",
        "basis": "Hex-Rays pseudocode, exact normalized allocator and constructor call sequence, and adjacency to the translated TStaticVar constructor",
        "evidence": [
            "Both factories allocate 0x88 bytes and immediately invoke the matching static-variable constructor with the string argument.",
            "The source and target are exact 48-byte normalized matches and the target factory sits directly after the translated constructor.",
        ],
    },
    {
        "original_ea": "0x22d53c",
        "original_name": "TStaticVar_TStaticVar",
        "spectron_ea": "0x23702c",
        "spectron_name": "_ZN10NgNBgaN3oAD2Ev",
        "operation": "runs the complete TStaticVar destructor",
        "basis": "Hex-Rays pseudocode, D2 destructor spelling, same vtable and base-destructor sequence, and adjacency to the TStaticVar deleting destructor",
        "evidence": [
            "Both functions install the TStaticVar vtable, remove the object from the garbage collector, and invoke the TGraalVar base destructor.",
            "The target NgNBgaN3oA D2 body is the 48-byte class-local counterpart of the source complete destructor; only register-detail normalization differs.",
        ],
    },
    {
        "original_ea": "0x22d56c",
        "original_name": "TStaticVar_TStaticVar__2",
        "spectron_ea": "0x23705c",
        "spectron_name": "_ZN10NgNBgaN3oAD0Ev",
        "operation": "runs the deleting TStaticVar destructor",
        "basis": "Hex-Rays pseudocode, D0 destructor spelling, exact normalized destructor metrics, and adjacency to the complete destructor",
        "evidence": [
            "Both functions call the complete TStaticVar destructor and then release the receiver with operator delete.",
            "The target NgNBgaN3oA D0 body is an exact 32-byte normalized counterpart of the source deleting destructor.",
        ],
    },
    {
        "original_ea": "0x22d7d4",
        "original_name": "TActionScriptVar_create_TString_const",
        "spectron_ea": "0x2372c4",
        "spectron_name": "_Z20mH33wa4I1qE7Bm2aaHDBRK10C8THgaTQxF",
        "operation": "allocates and constructs a TActionScriptVar from a string",
        "basis": "Hex-Rays pseudocode, exact normalized allocator and constructor call sequence, and adjacency to the translated action-variable constructor",
        "evidence": [
            "Both factories allocate 0x88 bytes and immediately invoke the matching action-variable constructor with the string argument.",
            "The source and target are exact 48-byte normalized matches in the same static-variable lifecycle block.",
        ],
    },
    {
        "original_ea": "0x22d8e4",
        "original_name": "TStaticVarProperties_TStaticVarProperties",
        "spectron_ea": "0x2373d4",
        "spectron_name": "_ZN20NgNBgaN3oAPropertiesD2Ev",
        "operation": "runs the complete TStaticVarProperties destructor",
        "basis": "Hex-Rays pseudocode, D2 destructor spelling, same vtable and base-destructor sequence, and the following property-thunk quartet",
        "evidence": [
            "Both functions install the two TStaticVarProperties vtable pointers and invoke the base TProperties destructor.",
            "The target NgNBgaN3oAProperties D2 body is a 28-byte class-local counterpart of the source complete destructor; only register-detail normalization differs.",
        ],
    },
    {
        "original_ea": "0x22d900",
        "original_name": "non_virtual_thunk_to_TStaticVarProperties_TStaticVarProperties",
        "spectron_ea": "0x2373f0",
        "spectron_name": "_ZThn16_N20NgNBgaN3oAPropertiesD1Ev",
        "operation": "adjusts the secondary TStaticVarProperties destructor receiver",
        "basis": "Hex-Rays pseudocode, exact normalized thunk metrics, and adjacency to the matching TStaticVarProperties D2 body",
        "evidence": [
            "Both thunks subtract 16 bytes from the receiver and call the complete property destructor.",
            "The source and target are exact 8-byte thunk matches in the same property destructor sequence.",
        ],
    },
    {
        "original_ea": "0x22d908",
        "original_name": "TActionScriptVarProperties_TActionScriptVarProperties",
        "spectron_ea": "0x2373f8",
        "spectron_name": "_ZN20mH33wa4I1qPropertiesD1Ev",
        "operation": "runs the complete TActionScriptVarProperties destructor",
        "basis": "Hex-Rays pseudocode, D1 destructor spelling, same vtable and base-destructor sequence, and the following property-thunk quartet",
        "evidence": [
            "Both functions install the two TActionScriptVarProperties vtable pointers and invoke the base TProperties destructor.",
            "The target mH33wa4I1qProperties D1 body is a 28-byte class-local counterpart of the source complete destructor; only register-detail normalization differs.",
        ],
    },
    {
        "original_ea": "0x22d924",
        "original_name": "non_virtual_thunk_to_TActionScriptVarProperties_TActionScriptVarProperties",
        "spectron_ea": "0x237414",
        "spectron_name": "_ZThn16_N20mH33wa4I1qPropertiesD1Ev",
        "operation": "adjusts the secondary TActionScriptVarProperties destructor receiver",
        "basis": "Hex-Rays pseudocode, exact normalized thunk metrics, and adjacency to the matching TActionScriptVarProperties D1 body",
        "evidence": [
            "Both thunks subtract 16 bytes from the receiver and call the complete action-property destructor.",
            "The source and target are exact 8-byte thunk matches in the same property destructor sequence.",
        ],
    },
    {
        "original_ea": "0x22d92c",
        "original_name": "TStaticVarProperties_TStaticVarProperties__2",
        "spectron_ea": "0x23741c",
        "spectron_name": "_ZN20NgNBgaN3oAPropertiesD0Ev",
        "operation": "runs the deleting TStaticVarProperties destructor",
        "basis": "Hex-Rays pseudocode, D0 destructor spelling, same vtable and base-destructor sequence, and exact normalized metrics",
        "evidence": [
            "Both functions install the property vtables, invoke the base TProperties destructor, and call operator delete.",
            "The target NgNBgaN3oAProperties D0 body is a 56-byte normalized counterpart of the source deleting property destructor.",
        ],
    },
    {
        "original_ea": "0x22d964",
        "original_name": "non_virtual_thunk_to_TStaticVarProperties_TStaticVarProperties__2",
        "spectron_ea": "0x237454",
        "spectron_name": "_ZThn16_N20NgNBgaN3oAPropertiesD0Ev",
        "operation": "adjusts the secondary deleting TStaticVarProperties destructor receiver",
        "basis": "Hex-Rays pseudocode, exact normalized thunk metrics, and adjacency to the matching property D0 body",
        "evidence": [
            "Both thunks subtract 16 bytes from the receiver and call the deleting property destructor.",
            "The source and target are exact 8-byte thunk matches in the same class-local destructor sequence.",
        ],
    },
    {
        "original_ea": "0x22d96c",
        "original_name": "TActionScriptVarProperties_TActionScriptVarProperties__2",
        "spectron_ea": "0x23745c",
        "spectron_name": "_ZN20mH33wa4I1qPropertiesD0Ev",
        "operation": "runs the deleting TActionScriptVarProperties destructor",
        "basis": "Hex-Rays pseudocode, D0 destructor spelling, same vtable and base-destructor sequence, and exact normalized metrics",
        "evidence": [
            "Both functions install the property vtables, invoke the base TProperties destructor, and call operator delete.",
            "The target mH33wa4I1qProperties D0 body is a 56-byte normalized counterpart of the source deleting property destructor.",
        ],
    },
    {
        "original_ea": "0x22d9a4",
        "original_name": "non_virtual_thunk_to_TActionScriptVarProperties_TActionScriptVarProperties__2",
        "spectron_ea": "0x237494",
        "spectron_name": "_ZThn16_N20mH33wa4I1qPropertiesD0Ev",
        "operation": "adjusts the secondary deleting TActionScriptVarProperties destructor receiver",
        "basis": "Hex-Rays pseudocode, exact normalized thunk metrics, and adjacency to the matching action-property D0 body",
        "evidence": [
            "Both thunks subtract 16 bytes from the receiver and call the deleting action-property destructor.",
            "The source and target are exact 8-byte thunk matches in the same property destructor sequence.",
        ],
    },
    {
        "original_ea": "0x22d9ac",
        "original_name": "TActionScriptVar_TActionScriptVar",
        "spectron_ea": "0x23749c",
        "spectron_name": "_ZN10mH33wa4I1qD1Ev",
        "operation": "runs the complete TActionScriptVar destructor",
        "basis": "Hex-Rays pseudocode, D1 destructor spelling, exact class-local destructor order, and the translated action-variable constructor above",
        "evidence": [
            "Both functions install the action-variable vtable and invoke the complete TStaticVar destructor.",
            "The target mH33wa4I1q D1 body is the 20-byte class-local counterpart of the source complete destructor; only register-detail normalization differs.",
        ],
    },
    {
        "original_ea": "0x22d9c0",
        "original_name": "TActionScriptVar_TActionScriptVar__2",
        "spectron_ea": "0x2374b0",
        "spectron_name": "_ZN10mH33wa4I1qD0Ev",
        "operation": "runs the deleting TActionScriptVar destructor",
        "basis": "Hex-Rays pseudocode, D0 destructor spelling, exact normalized destructor metrics, and adjacency to the complete destructor",
        "evidence": [
            "Both functions install the action-variable vtable, invoke the complete TStaticVar destructor, and call operator delete.",
            "The target mH33wa4I1q D0 body is an exact 48-byte normalized counterpart of the source deleting destructor.",
        ],
    },
)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(rows):
    return {int(row["ea"], 16): row for row in rows}


def metrics(row):
    return {field: row.get(field) for field in METRIC_FIELDS}


def evidence_by_ea(paths):
    rows = {}
    inputs = []
    for path in paths:
        document = load(path)
        inputs.append({"path": str(path), "sha256": sha256_path(path)})
        for row in document.get("targets", []):
            ea = int(row["ea"], 16)
            previous = rows.get(ea)
            if previous is not None:
                if previous.get("name") != row.get("name") or previous.get("pseudocode") != row.get("pseudocode"):
                    raise ValueError("conflicting evidence row at %s" % row["ea"])
                continue
            rows[ea] = row
    return rows, inputs


def pseudocode_sha256(row):
    pseudocode = row.get("pseudocode")
    if pseudocode is None:
        return None
    return hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()


def semantic_rows(document):
    return {
        (int(row["original_ea"], 16), int(row["spectron_ea"], 16)): row
        for row in document.get("matches", [])
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path, action="append")
    parser.add_argument("--target-evidence", required=True, type=Path, action="append")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    source_evidence, source_inputs = evidence_by_ea(args.source_evidence)
    target_evidence, target_inputs = evidence_by_ea(args.target_evidence)
    semantic = semantic_rows(semantic_document)

    anchors = []
    for reviewed in ANCHOR_SPECS:
        original_ea = int(reviewed["original_ea"], 16)
        spectron_ea = int(reviewed["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        source_trace = source_evidence.get(original_ea)
        target_trace = target_evidence.get(spectron_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % reviewed["original_ea"])
        if source.get("name") != reviewed["original_name"]:
            raise ValueError("source name mismatch at %s" % reviewed["original_ea"])
        if target.get("name") != reviewed["spectron_name"]:
            raise ValueError("target name mismatch at %s" % reviewed["spectron_ea"])
        if target.get("is_default_name"):
            raise ValueError("target unexpectedly has a default IDA name at %s" % reviewed["spectron_ea"])
        if source_trace is None or target_trace is None:
            raise ValueError("missing pseudocode evidence at %s" % reviewed["original_ea"])
        if source_trace.get("pseudocode") is None or target_trace.get("pseudocode") is None:
            raise ValueError("pseudocode was unavailable at %s" % reviewed["original_ea"])

        semantic_row = semantic.get((original_ea, spectron_ea))
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differences = [
            field
            for field in METRIC_FIELDS
            if source_metrics.get(field) != target_metrics.get(field)
        ]
        anchors.append(
            {
                "original_ea": reviewed["original_ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_string_refs": source.get("string_refs", []),
                "source_pseudocode_sha256": pseudocode_sha256(source_trace),
                "source_evidence_name": source_trace.get("name"),
                "spectron_ea": reviewed["spectron_ea"],
                "spectron_name": target["name"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_metrics": target_metrics,
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_string_refs": target.get("string_refs", []),
                "target_pseudocode_sha256": pseudocode_sha256(target_trace),
                "target_evidence_name": target_trace.get("name"),
                "source_component": "TScriptUniverse, TStaticVar, and TActionScriptVar residual runtime",
                "target_component": "obfuscated Spectron static-variable runtime",
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-tscript-var-residual-exact-anchor"
                if not differences
                else "manual-tscript-var-residual-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": semantic_row is not None,
                "semantic_match_confidence": None if semantic_row is None else semantic_row.get("confidence"),
                "semantic_match_method": None if semantic_row is None else semantic_row.get("method"),
                "source_basis": reviewed["basis"],
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in TScriptVar residual anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tscript_var_residual_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TScriptUniverse initialization, player-array destruction, static-variable factories, and static/action-variable destructor families",
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
            "source_evidence": source_inputs,
            "target_evidence": target_inputs,
        },
        "summary": {
            "anchor_count": len(anchors),
            "exact_metric_anchor_count": sum(row["exact_metric_match"] for row in anchors),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "layout_change_anchor_count": sum(not row["exact_metric_match"] for row in anchors),
            "source_pseudocode_count": sum(row["source_pseudocode_sha256"] is not None for row in anchors),
            "target_pseudocode_count": sum(row["target_pseudocode_sha256"] is not None for row in anchors),
            "semantic_promotion_count": sum(row["semantic_match_already_present"] for row in anchors),
            "new_context_anchor_count": sum(not row["semantic_match_already_present"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "The target NJLNuahMtw initializer begins the same static-property registration sequence as TScriptUniverse_initStaticScriptVars_void.",
            "The e4ZYfa8PV2Properties and JE42uaVwcK destructor families are identified by direct pseudocode, ABI destructor form, exact normalized shapes, and their class-local position next to already translated methods.",
            "The NgNBgaN3oA and mH33wa4I1q bodies preserve the TStaticVar and TActionScriptVar factories, complete destructors, deleting destructors, and secondary-base thunks from the 1.8 build.",
            "The reviewed aliases are high-confidence manual anchors. Twelve retain the same normalized metrics except for register-detail naming caused by the obfuscated target build.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
