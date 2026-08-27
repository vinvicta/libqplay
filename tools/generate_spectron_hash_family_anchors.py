#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's hash-list and hash-string methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target KKhLga4xoI and yL3_IaDMFt methods remain in the same local order as the source THashList and THashStrings families, surrounded by already translated constructors, iterators, add/remove methods, and file helpers.",
    "The three THashList lookup targets preserve bucket selection, chain traversal, hash comparison, and the case-sensitive, case-insensitive, or encoded character comparison used by their source roles.",
    "THashStrings getObject and setValue preserve hash lookup, value comparison, insertion of missing nonempty values, replacement of existing values, and removal for empty values. Spectron makes temporary C8THgaTQxF copies explicit.",
    "THashList assignment and sorted-list construction preserve iterator traversal, clearing, object insertion, ordered comparison, and list insertion. The target assignment signature has one bool and retains only the normal add path, while the source has a second bool for encoded insertion.",
    "THashStrings listStrings and GetCommaText2 preserve iterator traversal, name/value assembly, empty-value handling, comma joining, and double-quote escaping. Target literal references and wrapper calls differ because of the rebuilt string representation.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0xea674",
        "original_name": "THashList_getObject_uint_TString_const",
        "spectron_ea": "0xeb260",
        "target_name": "_ZN10KKhLga4xoI10TBCvgay5cvEjRK10C8THgaTQxF",
        "proposed_name": "v18_THashList_getObject_uint_TString_const",
        "source_metrics": (140, 35, 9),
        "target_metrics": (180, 45, 9),
        "source_call_count": 1,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_operator_assign_TString_const_TString_const",),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZeqRK10C8THgaTQxFS1_",
        ),
        "source_basis": "hash-list bucket lookup by string",
    },
    {
        "original_ea": "0xea700",
        "original_name": "THashList_getObjectIgnoreCase_uint_TString_const",
        "spectron_ea": "0xeb3a0",
        "target_name": "_ZN10KKhLga4xoI10sZ8vgajaFvEjRK10C8THgaTQxF",
        "proposed_name": "v18_THashList_getObjectIgnoreCase_uint_TString_const",
        "source_metrics": (252, 63, 24),
        "target_metrics": (364, 91, 31),
        "source_call_count": 0,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
        ),
        "source_basis": "hash-list case-insensitive bucket lookup",
    },
    {
        "original_ea": "0xea7fc",
        "original_name": "THashList_getObjectEncoded_uint_TString_const",
        "spectron_ea": "0xeb50c",
        "target_name": "_ZN10KKhLga4xoI10sZ8vgajaFvEjRK10CanTfaz6bZ",
        "proposed_name": "v18_THashList_getObjectEncoded_uint_TString_const",
        "source_metrics": (284, 71, 24),
        "target_metrics": (320, 80, 25),
        "source_call_count": 0,
        "target_call_count": 2,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": ("._ZNK10CanTfaz6bZixEi",),
        "source_basis": "hash-list encoded bucket lookup",
    },
    {
        "original_ea": "0xeade4",
        "original_name": "THashStrings_getObject_TString_const",
        "spectron_ea": "0xeba30",
        "target_name": "_ZN10yL3_IaDMFt10TBCvgay5cvERK10C8THgaTQxF",
        "proposed_name": "v18_THashStrings_getObject_TString_const",
        "source_metrics": (136, 34, 7),
        "target_metrics": (176, 44, 7),
        "source_call_count": 2,
        "target_call_count": 4,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashList_getHashcode_TString_const",
            "plt_operator_assign_TString_const_TString_const",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10KKhLga4xoI10g4ouMaaIbpERK10C8THgaTQxF",
            "._ZeqRK10C8THgaTQxFS1_",
        ),
        "source_basis": "hash-strings key lookup",
    },
    {
        "original_ea": "0xeb358",
        "original_name": "THashStrings_setValue_TString_const_TString_const",
        "spectron_ea": "0xebfcc",
        "target_name": "_ZN10yL3_IaDMFt10juVsfa5YWCERK10C8THgaTQxFS2_",
        "proposed_name": "v18_THashStrings_setValue_TString_const_TString_const",
        "source_metrics": (280, 70, 11),
        "target_metrics": (308, 77, 11),
        "source_call_count": 7,
        "target_call_count": 9,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashString_THashString_TString_const_TString_const",
            "plt_THashString_setValue_TString_const",
            "plt_THashStrings_addObject_THashString",
            "plt_THashStrings_getObject_TString_const",
            "plt_THashStrings_removeObject_THashString",
            "plt_operator_ne_TString_const_TString_const",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10NYF9TaOVKR10juVsfa5YWCERK10C8THgaTQxF",
            "._ZN10NYF9TaOVKRC1ERK10C8THgaTQxFS2_",
            "._ZN10yL3_IaDMFt10TBCvgay5cvERK10C8THgaTQxF",
            "._ZN10yL3_IaDMFt10g6yvgaX89uEP10NYF9TaOVKR",
            "._ZN10yL3_IaDMFt9addObjectEP10NYF9TaOVKR",
            "._ZneRK10C8THgaTQxFS1_",
            "._Znwm",
        ),
        "source_basis": "hash-strings key/value update",
    },
    {
        "original_ea": "0xebaa4",
        "original_name": "THashList_Assign_THashList_bool_bool",
        "spectron_ea": "0xec840",
        "target_name": "_ZN10KKhLga4xoI6AssignEPS_b",
        "proposed_name": "v18_THashList_Assign_THashList_bool_bool",
        "source_metrics": (160, 40, 6),
        "target_metrics": (104, 26, 4),
        "source_call_count": 9,
        "target_call_count": 6,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashListIterator_THashListIterator",
            "plt_THashListIterator_THashListIterator_THashList",
            "plt_THashListIterator_getNextObject_void",
            "plt_THashListIterator_objectsLeft_void",
            "plt_THashList_Clear_bool",
            "plt_THashList_addObjectEncoded_THashListObject",
            "plt_THashList_addObject_THashListObject",
        ),
        "required_target_calls": (
            "._ZN10KKhLga4xoI5ClearEb",
            "._ZN10R_MvgaEQlv10OGNvgaMpmvEv",
            "._ZN10R_MvgaEQlv10svNvga4fmvEv",
            "._ZN10R_MvgaEQlvC2EP10KKhLga4xoI",
            "._ZN10R_MvgaEQlvD1Ev",
            "._ZN10KKhLga4xoI9addObjectEP10J7zOgaf09K",
        ),
        "source_basis": "hash-list assignment and iterator copy",
    },
    {
        "original_ea": "0xebba8",
        "original_name": "THashList_getListSorted_void",
        "spectron_ea": "0xec90c",
        "target_name": "_ZN10KKhLga4xoI10AotaUajlqSEv",
        "proposed_name": "v18_THashList_getListSorted_void",
        "source_metrics": (260, 65, 9),
        "target_metrics": (324, 81, 9),
        "source_call_count": 10,
        "target_call_count": 14,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashListIterator_THashListIterator",
            "plt_THashListIterator_THashListIterator_THashList",
            "plt_THashListIterator_getNextObject_void",
            "plt_THashListIterator_objectsLeft_void",
            "plt_TList_Add_void",
            "plt_TList_Insert_int_void",
            "plt_TList_operator_index_int",
            "plt_operator_gt_TString_const_TString_const",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10CanTfaz6bZ10gwFWfaPxY0Ev",
            "._ZN10R_MvgaEQlv10OGNvgaMpmvEv",
            "._ZN10R_MvgaEQlv10svNvga4fmvEv",
            "._ZN10R_MvgaEQlvC2EP10KKhLga4xoI",
            "._ZN10R_MvgaEQlvD1Ev",
            "._ZN10vy1JgaKVkH3AddEPv",
            "._ZN10vy1JgaKVkH6InsertEiPv",
            "._ZNK10vy1JgaKVkHixEi",
            "._ZgtRK10C8THgaTQxFS1_",
            "._Znwm",
        ),
        "source_basis": "sorted hash-list object list",
    },
    {
        "original_ea": "0xebea0",
        "original_name": "THashStrings_listStrings_void",
        "spectron_ea": "0xecc58",
        "target_name": "_ZN10yL3_IaDMFt10SpbdUardIUEv",
        "proposed_name": "v18_THashStrings_listStrings_void",
        "source_metrics": (272, 68, 7),
        "target_metrics": (336, 84, 7),
        "source_call_count": 14,
        "target_call_count": 18,
        "source_string_refs": ("=",),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashStringsIterator_THashStringsIterator_THashStrings",
            "plt_THashStringsIterator_getNextObject_void",
            "plt_THashStringsIterator_objectsLeft_void",
            "plt_TStringList_Add_TString_const",
            "plt_TStringList_TStringList_void",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10C8THgaTQxFlsERKS_",
            "._ZN10Zb7cUaSFEU10OGNvgaMpmvEv",
            "._ZN10Zb7cUaSFEU10svNvga4fmvEv",
            "._ZN10Zb7cUaSFEUC2EP10yL3_IaDMFt",
            "._ZN10vuuHgangcF3AddERK10C8THgaTQxF",
            "._ZN10vuuHgangcF3AddERK10CanTfaz6bZ",
            "._ZN10vuuHgangcFC2Ev",
            "._Znwm",
        ),
        "source_basis": "hash-strings list of name/value strings",
    },
    {
        "original_ea": "0xebff0",
        "original_name": "THashStrings_GetCommaText2_void",
        "spectron_ea": "0xecde8",
        "target_name": "_ZN10yL3_IaDMFt10glvHgatZcFEv",
        "proposed_name": "v18_THashStrings_GetCommaText2_void",
        "source_metrics": (360, 90, 9),
        "target_metrics": (440, 110, 9),
        "source_call_count": 17,
        "target_call_count": 23,
        "source_string_refs": ("=",),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashStringsIterator_THashStringsIterator_THashStrings",
            "plt_THashStringsIterator_getNextObject_void",
            "plt_THashStringsIterator_objectsLeft_void",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_escaped34_TString_const",
        ),
        "required_target_calls": (
            "._Z10Z1ceJasAzFRK10C8THgaTQxF",
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10C8THgaTQxFlsERKS_",
            "._ZN10Zb7cUaSFEU10OGNvgaMpmvEv",
            "._ZN10Zb7cUaSFEU10svNvga4fmvEv",
            "._ZN10Zb7cUaSFEUC2EP10yL3_IaDMFt",
        ),
        "source_basis": "hash-strings comma serialization",
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
        source = original.get(int(spec["original_ea"], 16))
        target = spectron.get(int(spec["spectron_ea"], 16))
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        for side, function in (("source", source), ("target", target)):
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            expected_metrics = spec["%s_metrics" % side]
            ea = spec["original_ea" if side == "source" else "spectron_ea"]
            if actual_metrics != expected_metrics:
                raise ValueError(
                    "unexpected %s metrics at %s: %s" % (side, ea, actual_metrics)
                )
            if function.get("call_count") != spec["%s_call_count" % side]:
                raise ValueError(
                    "unexpected %s call count at %s: %s"
                    % (side, ea, function.get("call_count"))
                )
            expected_strings = list(spec["%s_string_refs" % side])
            if function.get("string_refs", []) != expected_strings:
                raise ValueError(
                    "unexpected %s string references at %s: %s"
                    % (side, ea, function.get("string_refs", []))
                )
            for required_call in spec["required_%s_calls" % side]:
                if required_call not in function.get("direct_call_names", []):
                    raise ValueError(
                        "missing %s call %s at %s" % (side, required_call, ea)
                    )
        if int(spec["spectron_ea"], 16) in semantic_targets:
            raise ValueError("target is already present in the semantic map")
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-hash-family-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in hash-family set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in hash-family set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_hash_family_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for THashList lookup, assignment, sorting, and THashStrings value and serialization methods",
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
            "high_confidence_count": sum(
                row["confidence"] == "high" for row in anchors
            ),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the obfuscated target names and wrapper differences in the evidence rows.",
            "The hash-list assignment target has a narrower one-bool signature and omits the source's explicit encoded-add branch, so that behavior change is preserved in the record.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
