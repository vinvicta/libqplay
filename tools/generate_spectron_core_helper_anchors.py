#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for compact core helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x16a180",
        "original_name": "TLevelObject_getOrderPoint_void",
        "spectron_ea": "0x16dbd8",
        "target_name": "_ZN10FY2VgaG6rR10JhjWgazQFREv",
        "source_basis": "level-object order-point result",
        "evidence": [
            "Both bodies return a zeroed two-coordinate result structure.",
            "The target belongs to the same contiguous FY2VgaG6rR level-object helper cluster as the local-coordinate and depth setters.",
        ],
    },
    {
        "original_ea": "0x16a19c",
        "original_name": "TLevelObject_setlocalx_double_bool",
        "spectron_ea": "0x16dbf4",
        "target_name": "_ZN10FY2VgaG6rR10yizVgakj2QEdb",
        "source_basis": "level-object local-x setter",
        "evidence": [
            "Both bodies conditionally store the double at the local-x field at offset 112, with the same force-update boolean.",
            "The matching target is distinguished from the adjacent local-y setter by its field offset and preserves the same normalized shape.",
        ],
    },
    {
        "original_ea": "0x16a1b8",
        "original_name": "TLevelObject_setlocaly_double_bool",
        "spectron_ea": "0x16dc10",
        "target_name": "_ZN10FY2VgaG6rR10rysVgaGDXQEdb",
        "source_basis": "level-object local-y setter",
        "evidence": [
            "Both bodies conditionally store the double at the local-y field at offset 120, with the same force-update boolean.",
            "The matching target is distinguished from the adjacent local-x setter by its field offset and preserves the same normalized shape.",
        ],
    },
    {
        "original_ea": "0x16a1d4",
        "original_name": "TLevelObject_setz_double",
        "spectron_ea": "0x16dc2c",
        "target_name": "_ZN10FY2VgaG6rR10iZDhga9esjEd",
        "source_basis": "level-object depth setter",
        "evidence": [
            "Both bodies compare and conditionally store the depth double at offset 128.",
            "The target is adjacent to the confirmed local-x and local-y setters in the same level-object class context.",
        ],
    },
    {
        "original_ea": "0x16a1e8",
        "original_name": "TLevelObject_getVisibleRectangle_void",
        "spectron_ea": "0x16dc40",
        "target_name": "_ZN10FY2VgaG6rR10U0VggaxqRiEv",
        "source_basis": "level-object visible-rectangle result",
        "evidence": [
            "Both bodies return a zeroed four-coordinate rectangle result structure.",
            "The target belongs to the same FY2VgaG6rR level-object cluster, while the other shape-equivalent target is in an unrelated class context.",
        ],
    },
    {
        "original_ea": "0x18a2fc",
        "original_name": "TNumberArrayVar_double_setArrayCellFloat_int_double",
        "spectron_ea": "0x18eaec",
        "target_name": "_ZN10PfQXva4zXuIdE10IS1sMaMb2nEid",
        "source_basis": "numeric array cell setter",
        "evidence": [
            "Both bodies reject negative or out-of-range indices, then store the double through the array data pointer.",
            "The source and target preserve the same bounds check, element stride, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x19fcbc",
        "original_name": "TServerLevel_isOnNPCPredicate",
        "spectron_ea": "0x1a4994",
        "target_name": "sub_1A4994",
        "source_basis": "server-level NPC predicate callback",
        "evidence": [
            "Both callbacks load the shared level-query coordinates and flag, then forward them to the NPC is-on predicate.",
            "The source callback comment identifies the predicate role and the target preserves the same argument-forwarding shape.",
        ],
    },
    {
        "original_ea": "0x1a193c",
        "original_name": "TServerLevel_getNPCList_void",
        "spectron_ea": "0x1a65ec",
        "target_name": "_ZN10zF9VgaBKxR10jOmXmbVNyVEv",
        "source_basis": "server-level NPC-list accessor",
        "evidence": [
            "Both bodies return the primary NPC-list pointer and fall back to the secondary list pointer when it is absent.",
            "The source and target preserve the same two-field fallback logic and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x1eba10",
        "original_name": "TGUIScriptLoader_runFailedsafeConnectorIfNoClient",
        "spectron_ea": "0x1f02b8",
        "target_name": "sub_1F02B8",
        "source_basis": "safe-connector failure fallback",
        "evidence": [
            "Both bodies test the global client pointer and invoke the failed-safe-connector path only when no client exists.",
            "The target preserves the same global guard, null call argument, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x204d94",
        "original_name": "TSocket_checkAllowConnect_TString_const_int",
        "spectron_ea": "0x20ac64",
        "target_name": "_ZN10XJLBgarMnA10EQfBga1WXzERK10C8THgaTQxFi",
        "source_basis": "socket host and port allow-list check",
        "evidence": [
            "Both wrappers pass the allowed-socket list, host string, and integer port to the same host-and-port membership helper.",
            "The source and target preserve the same three-argument forwarding shape and normalized function hash.",
        ],
    },
    {
        "original_ea": "0x20a888",
        "original_name": "TUpdatePackage_script_getupdatepackage",
        "spectron_ea": "0x210a84",
        "target_name": "sub_210A84",
        "source_basis": "update-package script lookup wrapper",
        "evidence": [
            "Both wrappers pass a null package context, the requested package string, and a zero boolean to the update-package lookup.",
            "The target preserves the same argument order and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x20d578",
        "original_name": "TGraalVar_script_isinclass",
        "spectron_ea": "0x2139a4",
        "target_name": "sub_2139A4",
        "source_basis": "GS2 class-membership predicate",
        "evidence": [
            "Both bodies follow the script-space pointer, return zero for a missing script space, and forward the class string to the script-space class predicate.",
            "The target takes the string argument and sits in the same TGraalVar helper cluster as the confirmed script-space wrappers.",
        ],
    },
    {
        "original_ea": "0x20d6e4",
        "original_name": "TGraalVar_clearVars_void",
        "spectron_ea": "0x213b8c",
        "target_name": "_ZN10G0gxgajWBw10I75gMaeM_dEv",
        "source_basis": "GS2 variable-container cleanup",
        "evidence": [
            "Both bodies read the variable container at the same logical field and clear it with the protected-entry mode argument one.",
            "The target is in the same G0gxgajWBw TGraalVar cluster and preserves the same conditional cleanup call.",
        ],
    },
    {
        "original_ea": "0x20edc4",
        "original_name": "TGraalVar_needEvent_script_event",
        "spectron_ea": "0x215290",
        "target_name": "_ZN10G0gxgajWBw10FDFHMa6DlAE10RiQ7IaxCcA",
        "source_basis": "GS2 event-needed predicate",
        "evidence": [
            "Both bodies use the script-space pointer as a null guard and forward the event query to the script-space predicate.",
            "The target is distinguished from the class-membership wrapper by its no-string signature and matching normalized shape.",
        ],
    },
    {
        "original_ea": "0x20ee40",
        "original_name": "TGraalVar_getShowTimer_void",
        "spectron_ea": "0x21530c",
        "target_name": "_ZN10G0gxgajWBw10AGqGMay3izEv",
        "source_basis": "GS2 show-timer accessor",
        "evidence": [
            "Both bodies read the show-timer byte at the script-space offset 73 and return zero for a missing script space.",
            "The target field offset separates it from the adjacent missing-function logging getter.",
        ],
    },
    {
        "original_ea": "0x20eeac",
        "original_name": "TGraalVar_getScriptLogMissingFunctions_void",
        "spectron_ea": "0x215378",
        "target_name": "_ZN10G0gxgajWBw10wCKpMa1PglEv",
        "source_basis": "GS2 missing-function logging accessor",
        "evidence": [
            "Both bodies read the script-space logging byte at offset 88 and return zero for a missing script space.",
            "The target field offset separates it from the adjacent show-timer getter.",
        ],
    },
    {
        "original_ea": "0x20eee0",
        "original_name": "TGraalVar_getMaxLoopLimit_void",
        "spectron_ea": "0x2153ac",
        "target_name": "_ZN10G0gxgajWBw10QKRlMaaQ_hEv",
        "source_basis": "GS2 loop-limit accessor",
        "evidence": [
            "Both bodies read the script-space loop limit at offset 92 and return 10000 when no script space is present.",
            "The target preserves the same default constant, field offset, and TGraalVar class context.",
        ],
    },
    {
        "original_ea": "0x2147f8",
        "original_name": "TScriptCom_TScriptCom_uchar",
        "spectron_ea": "0x21b3ac",
        "target_name": "_ZN10PRPTfaXeAZC1Eh",
        "source_basis": "script command record constructor",
        "evidence": [
            "Both constructors clear the two pointer fields, store the command byte, and preserve the same compact layout initialization.",
            "The target constructor has the matching one-byte signature and the same normalized function shape.",
        ],
    },
    {
        "original_ea": "0x21480c",
        "original_name": "TScriptCom_TScriptCom_uchar_double",
        "spectron_ea": "0x21b3c0",
        "target_name": "_ZN10PRPTfaXeAZC1Ehd",
        "source_basis": "script command record timed constructor",
        "evidence": [
            "Both constructors store the double payload, clear the pointer field, and store the command byte in the same record layout.",
            "The target constructor has the matching byte-and-double signature and is adjacent to the one-byte constructor.",
        ],
    },
    {
        "original_ea": "0x216b98",
        "original_name": "TScript_getClassFilename_TString_const",
        "spectron_ea": "0x21d918",
        "target_name": "_ZN10zW2NgaU4IK10IXGXfaTKP1ERK10C8THgaTQxF",
        "source_basis": "script class-filename result",
        "evidence": [
            "Both bodies return an empty string result structure.",
            "The target belongs to the zW2NgaU4IK script class context that also contains the confirmed access-right helper, separating it from the unrelated empty-result target.",
        ],
    },
    {
        "original_ea": "0x219cac",
        "original_name": "TScriptStackEntry_switchTypeProperty_TScriptMachine_bool",
        "spectron_ea": "0x221788",
        "target_name": "_ZN10ToQnQaIHFG10PofxPaEzAYEP10mTAogaaEipb",
        "source_basis": "script-stack property type switch",
        "evidence": [
            "Both bodies keep an existing property entry when its type is five and otherwise call the property-construction helper.",
            "The source and target preserve the same type test, forwarding call, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x22d2b8",
        "original_name": "TGraalPlayersArrayVar_getArrayCellObject_int",
        "spectron_ea": "0x236d7c",
        "target_name": "_ZN10JE42uaVwcK10c7E_faDck4Ei",
        "source_basis": "GS2 players-array object lookup",
        "evidence": [
            "Both bodies return the current action NPC for index negative one and otherwise forward to the base variable object lookup.",
            "The target preserves the same special index behavior and base-call branch.",
        ],
    },
    {
        "original_ea": "0x22d31c",
        "original_name": "TStaticVar_markAsNonGarbage_bool",
        "spectron_ea": "0x236de0",
        "target_name": "_ZN10NgNBgaN3oA10YYTtMa4HLoEb",
        "source_basis": "GS2 static-variable garbage marking",
        "evidence": [
            "Both bodies clear the non-garbage marker and, when requested, recurse through subvariables using the same helper.",
            "The target preserves the same marker offset, conditional recursion, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x22f314",
        "original_name": "TTempTile_TTempTile_void",
        "spectron_ea": "0x238f30",
        "target_name": "_ZN10yB4QvadugpC2Ev",
        "source_basis": "temporary tile record constructor",
        "evidence": [
            "Both constructors clear the pointer and initialize the same five integer fields to zero.",
            "The target preserves the matching six-field record initialization and constructor signature shape.",
        ],
    },
    {
        "original_ea": "0x230b48",
        "original_name": "TTilesBlock_isTransparent_void",
        "spectron_ea": "0x23aac0",
        "target_name": "_ZN10w7keKa2nGv10yXNcKaPDnuEv",
        "source_basis": "tile-block transparency predicate",
        "evidence": [
            "Both bodies compare the third 16-bit tile-block field with 0xFFFF.",
            "The source and target preserve the same field index, constant, and boolean result shape.",
        ],
    },
    {
        "original_ea": "0x230c08",
        "original_name": "TTilesBlock_isBlack_void",
        "spectron_ea": "0x23ab80",
        "target_name": "_ZN10w7keKa2nGv10rvAYJa3jAhEv",
        "source_basis": "tile-block black predicate",
        "evidence": [
            "Both bodies compare the first 16-bit tile-block field with 0xFFFF.",
            "The source and target preserve the same field index, constant, and boolean result shape beside the transparency predicate.",
        ],
    },
    {
        "original_ea": "0x23899c",
        "original_name": "TParticleModifier_script_addmod",
        "spectron_ea": "0x24283c",
        "target_name": "sub_24283C",
        "source_basis": "particle modifier script wrapper",
        "evidence": [
            "Both wrappers load two double inputs as floats and forward the two strings and float values to the modifier helper.",
            "The target preserves the same conversion sequence, argument order, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x23c86c",
        "original_name": "TExplosion_getDir",
        "spectron_ea": "0x24671c",
        "target_name": "sub_24671C",
        "source_basis": "explosion direction accessor",
        "evidence": [
            "Both bodies index the direction table with the integer field at offset 252.",
            "The target preserves the same table-index expression and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x23ce88",
        "original_name": "TServerBomb_setPower",
        "spectron_ea": "0x246da0",
        "target_name": "sub_246DA0",
        "source_basis": "server-bomb power setter",
        "evidence": [
            "Both bodies accept only power values one through three and store the accepted value at offset 248.",
            "The target preserves the same inclusive range check, field offset, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x244758",
        "original_name": "Java_com_quattroplay_GraalClassic_Natives_onReloadTextures",
        "spectron_ea": "0x2518a4",
        "target_name": "Java_com_quattroplay_GraalClassic_Natives_onReloadTextures",
        "source_basis": "native texture-reload callback",
        "evidence": [
            "Both JNI callbacks set the texture-reload flag and return the address of the native renderer state object.",
            "The exported target name, callback role, and normalized function shape are preserved across the two builds.",
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
                "match_kind": "manual-core-helper-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in core helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_core_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact level, script, network, tile, particle, and native callback helpers",
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
            "The target core helpers preserve local level, script, network-policy, tile, particle, and native callback behavior with exact normalized function hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
