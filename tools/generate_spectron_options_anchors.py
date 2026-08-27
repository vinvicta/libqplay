#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's TOptions methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target K7FLgag3II methods remain in the same options-class order as the translated filename, load, save, password-load, and nickname setters.",
    "The external and default GUI-style setters preserve change suppression, global value assignment, universe-event dispatch, and temporary event-name cleanup. Their target bodies differ only through rebuilt string operations and target-specific globals and literals.",
    "The nickname, account-name, and password getters preserve null-global handling and decode the corresponding stored hash-list slot. The target makes the temporary C8THgaTQxF copy and cleanup explicit.",
    "The account-name setter preserves lowercasing, guest and guest_ filtering, cookie handling, recent-account list removal and insertion, five-entry trimming, and registry persistence. The target replaces the source accountname literal with accountname_new.",
    "The options timer preserves the three stored-value refreshes and uniqueness operations. The target uses explicit CanTfaz6bZ conversion and assignment wrappers.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x16a4f0",
        "original_name": "TOptions_set_pref__video__externalguistyle",
        "spectron_ea": "0x16df48",
        "target_name": "sub_16DF48",
        "proposed_name": "v18_TOptions_set_pref__video__externalguistyle",
        "source_metrics": (184, 46, 7),
        "target_metrics": (244, 60, 7),
        "source_call_count": 5,
        "target_call_count": 9,
        "source_string_refs": ("onExternalStyleChanges",),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TGraalVar_invokeEvent_TString_const_char_const",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_operator_assign_TString_const_TString_const",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10G0gxgajWBw10BRcLgaJqkIERK10C8THgaTQxFPKcz",
            "._ZN10KKhLga4xoI10kEiLgawipIERK10C8THgaTQxF",
            "._ZN10KKhLga4xoI10tJOiUaYhrZERK10C8THgaTQxF",
            "._ZeqRK10C8THgaTQxFS1_",
        ),
        "source_basis": "options external GUI style setter",
    },
    {
        "original_ea": "0x16a5a8",
        "original_name": "TOptions_set_pref__video__defaultguistyle",
        "spectron_ea": "0x16e03c",
        "target_name": "sub_16E03C",
        "proposed_name": "v18_TOptions_set_pref__video__defaultguistyle",
        "source_metrics": (184, 46, 7),
        "target_metrics": (244, 60, 7),
        "source_call_count": 5,
        "target_call_count": 9,
        "source_string_refs": ("onDefaultStyleChanges",),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TGraalVar_invokeEvent_TString_const_char_const",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_operator_assign_TString_const_TString_const",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10G0gxgajWBw10BRcLgaJqkIERK10C8THgaTQxFPKcz",
            "._ZN10KKhLga4xoI10kEiLgawipIERK10C8THgaTQxF",
            "._ZN10KKhLga4xoI10tJOiUaYhrZERK10C8THgaTQxF",
            "._ZeqRK10C8THgaTQxFS1_",
        ),
        "source_basis": "options default GUI style setter",
    },
    {
        "original_ea": "0x16b8ec",
        "original_name": "TOptions_getGraalNickName_void",
        "spectron_ea": "0x16f3bc",
        "target_name": "_ZN10K7FLgag3II10M2jjMa_tSfEv",
        "proposed_name": "v18_TOptions_getGraalNickName_void",
        "source_metrics": (64, 16, 3),
        "target_metrics": (108, 27, 3),
        "source_call_count": 1,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_THashList_decodesimple_TString_const",),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10KKhLga4xoI10kEiLgawipIERK10C8THgaTQxF",
        ),
        "source_basis": "options decoded nickname getter",
    },
    {
        "original_ea": "0x16bc24",
        "original_name": "TOptions_getGraalAccountName_void",
        "spectron_ea": "0x16f720",
        "target_name": "_ZN10K7FLgag3II10rq3iMaRuEfEv",
        "proposed_name": "v18_TOptions_getGraalAccountName_void",
        "source_metrics": (68, 17, 3),
        "target_metrics": (112, 28, 3),
        "source_call_count": 1,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_THashList_decodesimple_TString_const",),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10KKhLga4xoI10kEiLgawipIERK10C8THgaTQxF",
        ),
        "source_basis": "options decoded account-name getter",
    },
    {
        "original_ea": "0x16bcd8",
        "original_name": "TOptions_setGraalAccountName_TString_const",
        "spectron_ea": "0x16f800",
        "target_name": "_ZN10K7FLgag3II10Ij0iMakTBfERK10C8THgaTQxF",
        "proposed_name": "v18_TOptions_setGraalAccountName_TString_const",
        "source_metrics": (408, 101, 10),
        "target_metrics": (480, 119, 10),
        "source_call_count": 20,
        "target_call_count": 24,
        "source_string_refs": ("accountname", "cookie", "guest", "guest_"),
        "target_string_refs": ("accountname_new", "cookie", "guest", "guest_"),
        "required_source_calls": (
            "plt_TFiles_setRegistryValue_TString_const_TString_const",
            "plt_TOptions_setGraalAccountNameSimple_TString_const",
            "plt_TStringList_Delete_int",
            "plt_TStringList_GetCommaText_void",
            "plt_TStringList_Insert_int_TString_const",
            "plt_TStringList_Remove_TString_const",
            "plt_TString_clear_void",
            "plt_TString_lower_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_TString_starts_TString_const",
            "plt_operator_ne_TString_const_char_const",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10CanTfaz6bZ5clearEv",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10K7FLgag3II10RofLgaAzmIERK10C8THgaTQxF",
            "._ZN10vuuHgangcF6DeleteEi",
            "._ZN10vuuHgangcF6InsertEiRK10CanTfaz6bZ",
            "._ZN10vuuHgangcF6RemoveERK10CanTfaz6bZ",
            "._ZN10wiULgacZUI10uBXwKafLkLERK10C8THgaTQxFS2_",
            "._ZNK10C8THgaTQxF10fEtHgarybFERKS_",
            "._ZNK10C8THgaTQxF5lowerEv",
            "._ZNK10vuuHgangcF10LzrhKaQOhyEv",
            "._ZneRK10C8THgaTQxFPKc",
        ),
        "source_basis": "options account-name persistence and recent-account list",
    },
    {
        "original_ea": "0x16be70",
        "original_name": "TOptions_getGraalPassWord_void",
        "spectron_ea": "0x16f9e0",
        "target_name": "_ZN10K7FLgag3II10rWDnMaMcvjEv",
        "proposed_name": "v18_TOptions_getGraalPassWord_void",
        "source_metrics": (68, 17, 3),
        "target_metrics": (112, 28, 3),
        "source_call_count": 1,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_THashList_decodesimple_TString_const",),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10KKhLga4xoI10kEiLgawipIERK10C8THgaTQxF",
        ),
        "source_basis": "options decoded password getter",
    },
    {
        "original_ea": "0x16bf24",
        "original_name": "TOptions_runOptionsTimer_void",
        "spectron_ea": "0x16fac0",
        "target_name": "_ZN10K7FLgag3II10odHnMaSYxjEv",
        "proposed_name": "v18_TOptions_runOptionsTimer_void",
        "source_metrics": (132, 33, 3),
        "target_metrics": (156, 39, 3),
        "source_call_count": 7,
        "target_call_count": 9,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TString_clear_void",
            "plt_TString_makeUnique_void",
            "plt_TString_operator_assign_TString_const",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10CanTfaz6bZ10gwFWfaPxY0Ev",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
        ),
        "source_basis": "options stored-value refresh timer",
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
                "match_kind": "manual-options-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in options anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in options anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_options_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TOptions style setters, decoded account getters, account persistence, and timer refresh",
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
            "The target's accountname_new literal, explicit string wrappers, and default-style sub_ targets are recorded as target-version differences.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
