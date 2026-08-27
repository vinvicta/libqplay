#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's extended TStringList methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target functions remain in the same vuuHgangcF method sequence as the translated TStringList comma-text family, load/save methods, and sort routine.",
    "Assign and AddList preserve the source count checks, capacity calculation, source indexing, per-item allocation, and destination placement. The target adds explicit CanTfaz6bZ copy construction and cleanup.",
    "getValue and setValue preserve the source equals-key construction, starts-with lookup, substring result, add-or-replace behavior, and deletion of an empty replacement.",
    "toString and SaveToFile preserve newline-separated list serialization, empty-string handling, file mode selection, fwrite and fclose behavior, extension filtering, and the existing log message path.",
    "Tokenize preserves both lazy delimiter tables, quoted-field scanning, backslash handling, newline trimming, delimiter checks, trailing empty-field behavior, and list insertion. The target makes the C8THgaTQxF trim and temporary-string wrappers explicit.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0xf5e50",
        "original_name": "TStringList_Assign_TStringList",
        "spectron_ea": "0xf76c8",
        "target_name": "_ZN10vuuHgangcF6AssignEPS_",
        "proposed_name": "v18_TStringList_Assign_TStringList",
        "source_metrics": (168, 42, 8),
        "target_metrics": (200, 50, 9),
        "source_call_count": 4,
        "target_call_count": 6,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TStringList_Clear_void",
            "plt_TStringList_operator_index_int",
            "plt_TStringList_setCapacity_int",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10vuuHgangcF10oP8REaQ19ZEi",
            "._ZN10vuuHgangcF5ClearEv",
            "._ZNK10vuuHgangcFixEi",
            "._Znwm",
        ),
        "source_basis": "TStringList full assignment",
    },
    {
        "original_ea": "0xf5ef8",
        "original_name": "TStringList_AddList_TStringList_int_int",
        "spectron_ea": "0xf7790",
        "target_name": "_ZN10vuuHgangcF10TF9BgaVKIAEPS_ii",
        "proposed_name": "v18_TStringList_AddList_TStringList_int_int",
        "source_metrics": (216, 54, 8),
        "target_metrics": (244, 61, 8),
        "source_call_count": 3,
        "target_call_count": 5,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TStringList_operator_index_int",
            "plt_TStringList_setCapacity_int",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10vuuHgangcF10oP8REaQ19ZEi",
            "._ZNK10vuuHgangcFixEi",
            "._Znwm",
        ),
        "source_basis": "TStringList range append",
    },
    {
        "original_ea": "0xf5ff8",
        "original_name": "TStringList_getValue_TString_const",
        "spectron_ea": "0xf7904",
        "target_name": "_ZNK10vuuHgangcF10iVjofaNm4yERK10C8THgaTQxF",
        "proposed_name": "v18_TStringList_getValue_TString_const",
        "source_metrics": (228, 57, 9),
        "target_metrics": (236, 59, 10),
        "source_call_count": 6,
        "target_call_count": 8,
        "source_string_refs": ("=",),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_TString_starts_TString_const",
            "plt_TString_subString_int",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10CanTfaz6bZ10gwFWfaPxY0Ev",
            "._ZNK10C8THgaTQxF10QgaLgaQfiIEi",
            "._ZNK10C8THgaTQxF10fEtHgarybFERKS_",
        ),
        "source_basis": "TStringList key lookup",
    },
    {
        "original_ea": "0xf60dc",
        "original_name": "TStringList_setValue_TString_const_TString_const",
        "spectron_ea": "0xf79f0",
        "target_name": "_ZN10vuuHgangcF10juVsfa5YWCERK10C8THgaTQxFS2_",
        "proposed_name": "v18_TStringList_setValue_TString_const_TString_const",
        "source_metrics": (372, 93, 12),
        "target_metrics": (408, 102, 12),
        "source_call_count": 15,
        "target_call_count": 17,
        "source_string_refs": ("=",),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TStringList_Add_TString_const",
            "plt_TStringList_Delete_int",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_TString_starts_TString_const",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10C8THgaTQxFlsERKS_",
            "._ZN10CanTfaz6bZ10gwFWfaPxY0Ev",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10vuuHgangcF3AddERK10C8THgaTQxF",
            "._ZN10vuuHgangcF6DeleteEi",
            "._ZNK10C8THgaTQxF10fEtHgarybFERKS_",
        ),
        "source_basis": "TStringList key assignment",
    },
    {
        "original_ea": "0xf6408",
        "original_name": "TStringList_toString_void",
        "spectron_ea": "0xf7d40",
        "target_name": "_ZNK10vuuHgangcF10bwoY2aKeq6Ev",
        "proposed_name": "v18_TStringList_toString_void",
        "source_metrics": (376, 94, 17),
        "target_metrics": (436, 109, 19),
        "source_call_count": 3,
        "target_call_count": 6,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            ".memcpy",
            "plt_TString_setSize_int_bool",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF10PHFwgaxH5vEib",
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10CanTfaz6bZ10gwFWfaPxY0Ev",
            ".memcpy",
        ),
        "source_basis": "TStringList newline serialization",
    },
    {
        "original_ea": "0xf6580",
        "original_name": "TStringList_SaveToFile_TString_const_uint",
        "spectron_ea": "0xf7ef4",
        "target_name": "_ZNK10vuuHgangcF10IA7WHax_lAERK10C8THgaTQxFj",
        "proposed_name": "v18_TStringList_SaveToFile_TString_const_uint",
        "source_metrics": (472, 116, 16),
        "target_metrics": (524, 129, 18),
        "source_call_count": 16,
        "target_call_count": 18,
        "source_string_refs": (" for writing!", ".log", "Couldn't open ", "ab", "files"),
        "target_string_refs": (" for writing!", ".log", "Couldn't open ", "ab", "files"),
        "required_source_calls": (
            ".fclose",
            ".fopen",
            ".fwrite",
            "plt_TFiles_extractFileExt_TString_const",
            "plt_TLog_echo_TString_const_double_double_double_char_const",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_operator_ne_TString_const_char_const",
        ),
        "required_target_calls": (
            ".fclose",
            ".fopen",
            ".fwrite",
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10C8THgaTQxFlsERKS_",
            "._ZN10CanTfaz6bZ10gwFWfaPxY0Ev",
            "._ZN10qjQMgaXCHJ10cWQMgaD8HJERK10C8THgaTQxFdddPKc",
            "._ZN10wiULgacZUI10Rr3vga6vAvERK10C8THgaTQxF",
            "._ZneRK10C8THgaTQxFPKc",
        ),
        "source_basis": "TStringList newline file output",
    },
    {
        "original_ea": "0xf6950",
        "original_name": "TStringList_Tokenize_TString_const_TString_const",
        "spectron_ea": "0xf82f8",
        "target_name": "_ZN10vuuHgangcF10q316gaulx0ERK10C8THgaTQxFS2_",
        "proposed_name": "v18_TStringList_Tokenize_TString_const_TString_const",
        "source_metrics": (1020, 253, 49),
        "target_metrics": (972, 241, 49),
        "source_call_count": 37,
        "target_call_count": 33,
        "source_string_refs": ("\n:,", "\\\"'"),
        "target_string_refs": ("\n:,",),
        "required_source_calls": (
            ".__cxa_guard_acquire",
            ".__cxa_guard_release",
            ".atexit",
            "plt_TStringList_Add_TString_const",
            "plt_TString_addbuffer_char_const_int",
            "plt_TString_clear_void",
            "plt_TString_indexOf_char",
            "plt_TString_operator_lshift_char",
            "plt_TString_operator_lshift_char_const",
            "plt_TString_subString_int_int",
            "plt_TString_trim_void",
        ),
        "required_target_calls": (
            ".__cxa_guard_acquire",
            ".__cxa_guard_release",
            ".atexit",
            "._ZN10C8THgaTQxF10f7_SgaGITOEPKci",
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10C8THgaTQxFlsEc",
            "._ZN10vuuHgangcF3AddEPKc",
            "._ZN10vuuHgangcF3AddERK10C8THgaTQxF",
            "._ZNK10C8THgaTQxF10JtTLgaLhUIEc",
            "._ZNK10C8THgaTQxF10QgaLgaQfiIEii",
            "._ZNK10C8THgaTQxF10_xFPgaiz4LEv",
        ),
        "source_basis": "TStringList delimiter-aware tokenizer",
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
                "match_kind": "manual-tstringlist-extended-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in extended TStringList set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in extended TStringList set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tstringlist_extended_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TStringList assignment, key/value access, serialization, file output, and tokenization",
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
            "The target's explicit C8THgaTQxF and CanTfaz6bZ operations, plus its missing standalone quote-table references, are recorded as build or decompiler differences.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
