#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's TStringList comma-text methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target functions occupy the same TStringList method sequence as the source family, immediately around the translated constructor, Clear, Add, and load/save methods.",
    "SetCommaText2 preserves the source parser's clear-first behavior, comma splitting, quoted-field handling, escaped quote handling, trailing empty-field behavior, and the 60000 and 65000 length guards.",
    "GetCommaText preserves the source escaped-field loop, comma insertion, length guards, and overflow fallback. The target adds an explicit temporary-string copy and assignment because C8THgaTQxF uses a different decompiler-visible representation.",
    "GetCommaText2 preserves the source quote-escaping loop and comma insertion. The target's Z1ceJasAzF helper is the obfuscated counterpart of escaped34_TString_const, while R3jeJaVuFF is the counterpart of escaped39_TString_const.",
    "The constructor keeps the source initialization order and calls the translated SetCommaText2 role. Spectron adds a third byte flag to the constructor, which is recorded as a target-side compatibility difference rather than hidden.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0xf5938",
        "original_name": "TStringList_SetCommaText2_TString_const",
        "spectron_ea": "0xf71a8",
        "target_name": "_ZN10vuuHgangcF10gzgLgalynIERK10C8THgaTQxF",
        "proposed_name": "v18_TStringList_SetCommaText2_TString_const",
        "source_metrics": (736, 182, 35),
        "target_metrics": (676, 168, 35),
        "source_call_count": 23,
        "target_call_count": 19,
        "source_string_refs": ("\\\"'",),
        "target_string_refs": (),
        "required_source_calls": (
            ".__cxa_guard_acquire",
            ".__cxa_guard_release",
            ".atexit",
            "plt_TStringList_Add_TString_const",
            "plt_TStringList_Clear_void",
            "plt_TString_addbuffer_char_const_int",
            "plt_TString_clear_void",
            "plt_TString_indexOf_char",
            "plt_TString_operator_lshift_char",
            "plt_TString_operator_lshift_char_const",
            "plt_TString_subString_int_int",
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
            "._ZN10vuuHgangcF5ClearEv",
            "._ZNK10C8THgaTQxF10JtTLgaLhUIEc",
            "._ZNK10C8THgaTQxF10QgaLgaQfiIEii",
        ),
        "source_basis": "TStringList comma parser with quoted fields",
    },
    {
        "original_ea": "0xf5c18",
        "original_name": "TStringList_TStringList_TString_const",
        "spectron_ea": "0xf744c",
        "target_name": "_ZN10vuuHgangcFC2ERK10C8THgaTQxFb",
        "proposed_name": "v18_TStringList_TStringList_TString_const",
        "source_metrics": (52, 13, 2),
        "target_metrics": (56, 14, 2),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "TStringList string constructor",
    },
    {
        "original_ea": "0xf5c4c",
        "original_name": "TStringList_GetCommaText_void",
        "spectron_ea": "0xf7484",
        "target_name": "_ZNK10vuuHgangcF10LzrhKaQOhyEv",
        "proposed_name": "v18_TStringList_GetCommaText_void",
        "source_metrics": (256, 64, 12),
        "target_metrics": (292, 73, 12),
        "source_call_count": 7,
        "target_call_count": 9,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_escaped39_TString_const",
        ),
        "required_target_calls": (
            "._Z10R3jeJaVuFFRK10C8THgaTQxF",
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10C8THgaTQxFlsERKS_",
        ),
        "source_basis": "TStringList comma serializer with single-quote escaping",
    },
    {
        "original_ea": "0xf5d4c",
        "original_name": "TStringList_GetCommaText2_void",
        "spectron_ea": "0xf75a8",
        "target_name": "_ZNK10vuuHgangcF10glvHgatZcFEv",
        "proposed_name": "v18_TStringList_GetCommaText2_void",
        "source_metrics": (172, 43, 6),
        "target_metrics": (200, 50, 6),
        "source_call_count": 4,
        "target_call_count": 6,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TString_clear_void",
            "plt_TString_operator_lshift_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_escaped34_TString_const",
        ),
        "required_target_calls": (
            "._Z10Z1ceJasAzFRK10C8THgaTQxF",
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10C8THgaTQxFlsERKS_",
        ),
        "source_basis": "TStringList comma serializer with double-quote escaping",
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
                "match_kind": "manual-tstringlist-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in TStringList anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in TStringList anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tstringlist_comma_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TStringList comma parsing, construction, and serialization",
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
            "The target's C8THgaTQxF wrappers, obfuscated escaping helpers, and constructor flag are recorded as implementation differences rather than treated as mismatches.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
