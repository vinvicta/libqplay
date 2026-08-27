#!/usr/bin/env python3
"""Create reviewed anchors for residual window, font-option, and font-data methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source TScreenPanelOpenGL destructor pair and native-mode predicate occur in one small virtual-method block. The target SU3JfaCUmR class keeps the same order and destructor forms, with the same normalized bodies.",
    "The six TFontOptions accessors sit immediately before the already translated UTF-8 methods in both builds. Their pseudocode reads or writes the corresponding default-font size, UTF-8 flag, default-font string, and UTF-8 font-file string globals.",
    "The source TFontData deleting destructor, filename lookup helper, and static initializer match the target fUWH_a_9zm class-local sequence. The lookup still lowercases the filename, computes the hash, queries the hash list, and clears its temporary string. The initializer still allocates and constructs the hash list.",
    "The source TWindowProperties destructor pair and both non-virtual thunks match the target LJyzga9PwyProperties destructor entries by local order, body shape, and adjusted-this thunk behavior.",
    "Every reviewed source and target pair has matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. The rows are not already present in the semantic translation map.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x10cbc4",
        "original_name": "TScreenPanelOpenGL_isNative_void",
        "spectron_ea": "0x10f514",
        "target_name": "_ZN10SU3JfaCUmR10aZ9nIa7_WXEv",
        "target_prefix": "_ZN10SU3JfaCUmR",
        "proposed_name": "v18_TScreenPanelOpenGL_isNative_void",
        "metrics": (8, 2, 1),
        "call_count": 0,
        "source_basis": "screen-panel native-mode predicate",
        "context_group": "TScreenPanelOpenGL residual lifecycle block",
        "context_order": 1,
    },
    {
        "original_ea": "0x10cbcc",
        "original_name": "TScreenPanelOpenGL_TScreenPanelOpenGL",
        "spectron_ea": "0x10f51c",
        "target_name": "_ZN10SU3JfaCUmRD1Ev",
        "target_prefix": "_ZN10SU3JfaCUmR",
        "proposed_name": "v18_TScreenPanelOpenGL_TScreenPanelOpenGL",
        "metrics": (20, 5, 2),
        "call_count": 0,
        "source_basis": "screen-panel complete destructor",
        "context_group": "TScreenPanelOpenGL residual lifecycle block",
        "context_order": 2,
    },
    {
        "original_ea": "0x10cbe0",
        "original_name": "TScreenPanelOpenGL_TScreenPanelOpenGL__2",
        "spectron_ea": "0x10f530",
        "target_name": "_ZN10SU3JfaCUmRD0Ev",
        "target_prefix": "_ZN10SU3JfaCUmR",
        "proposed_name": "v18_TScreenPanelOpenGL_TScreenPanelOpenGL__2",
        "metrics": (48, 12, 2),
        "call_count": 1,
        "source_basis": "screen-panel deleting destructor",
        "context_group": "TScreenPanelOpenGL residual lifecycle block",
        "context_order": 3,
    },
    {
        "original_ea": "0x10f6d4",
        "original_name": "TFontOptions_get_pref__graal__defaultfontsize",
        "spectron_ea": "0x111f70",
        "target_name": "sub_111F70",
        "target_prefix": "sub_",
        "proposed_name": "v18_TFontOptions_get_pref__graal__defaultfontsize",
        "metrics": (16, 4, 1),
        "call_count": 0,
        "source_basis": "default-font-size property getter",
        "context_group": "TFontOptions residual property accessors",
        "context_order": 1,
    },
    {
        "original_ea": "0x10f6e4",
        "original_name": "TFontOptions_set_pref__graal__defaultfontsize",
        "spectron_ea": "0x111f80",
        "target_name": "sub_111F80",
        "target_prefix": "sub_",
        "proposed_name": "v18_TFontOptions_set_pref__graal__defaultfontsize",
        "metrics": (16, 4, 1),
        "call_count": 0,
        "source_basis": "default-font-size property setter",
        "context_group": "TFontOptions residual property accessors",
        "context_order": 2,
    },
    {
        "original_ea": "0x10f6f4",
        "original_name": "TFontOptions_get_enableutf8",
        "spectron_ea": "0x111f90",
        "target_name": "sub_111F90",
        "target_prefix": "sub_",
        "proposed_name": "v18_TFontOptions_get_enableutf8",
        "metrics": (16, 4, 1),
        "call_count": 0,
        "source_basis": "UTF-8 option getter",
        "context_group": "TFontOptions residual property accessors",
        "context_order": 3,
    },
    {
        "original_ea": "0x10f704",
        "original_name": "TFontOptions_set_pref__graal__defaultfontname",
        "spectron_ea": "0x111fa0",
        "target_name": "sub_111FA0",
        "target_prefix": "sub_",
        "proposed_name": "v18_TFontOptions_set_pref__graal__defaultfontname",
        "metrics": (20, 5, 2),
        "call_count": 0,
        "source_basis": "default-font-name property setter",
        "context_group": "TFontOptions residual property accessors",
        "context_order": 4,
    },
    {
        "original_ea": "0x10f718",
        "original_name": "TFontOptions_get_pref__graal__utf8fontfile",
        "spectron_ea": "0x111fb4",
        "target_name": "sub_111FB4",
        "target_prefix": "sub_",
        "proposed_name": "v18_TFontOptions_get_pref__graal__utf8fontfile",
        "metrics": (56, 14, 1),
        "call_count": 1,
        "source_basis": "UTF-8 font-file property getter",
        "context_group": "TFontOptions residual property accessors",
        "context_order": 5,
    },
    {
        "original_ea": "0x10f750",
        "original_name": "TFontOptions_get_pref__graal__defaultfontname",
        "spectron_ea": "0x111fec",
        "target_name": "sub_111FEC",
        "target_prefix": "sub_",
        "proposed_name": "v18_TFontOptions_get_pref__graal__defaultfontname",
        "metrics": (56, 14, 1),
        "call_count": 1,
        "source_basis": "default-font-name property getter",
        "context_group": "TFontOptions residual property accessors",
        "context_order": 6,
    },
    {
        "original_ea": "0x110ad8",
        "original_name": "TFontData_TFontData__2",
        "spectron_ea": "0x113354",
        "target_name": "_ZN10fUWH_a_9zmD0Ev",
        "target_prefix": "_ZN10fUWH_a_9zm",
        "proposed_name": "v18_TFontData_TFontData__2",
        "metrics": (32, 8, 2),
        "call_count": 1,
        "source_basis": "font-data deleting destructor",
        "context_group": "TFontData residual lifecycle and lookup block",
        "context_order": 1,
    },
    {
        "original_ea": "0x110af8",
        "original_name": "TFontData_findFontData_TString_const",
        "spectron_ea": "0x113374",
        "target_name": "_ZN10fUWH_a_9zm10mzcH_arbYlERK10C8THgaTQxF",
        "target_prefix": "_ZN10fUWH_a_9zm",
        "proposed_name": "v18_TFontData_findFontData_TString_const",
        "metrics": (92, 23, 1),
        "call_count": 4,
        "source_basis": "font-data filename hash lookup",
        "context_group": "TFontData residual lifecycle and lookup block",
        "context_order": 2,
    },
    {
        "original_ea": "0x111218",
        "original_name": "TFontData_initStaticVars_void",
        "spectron_ea": "0x1139f8",
        "target_name": "_Z10RoMN2aAkuYv",
        "target_prefix": "_Z10RoMN2aAkuYv",
        "proposed_name": "v18_TFontData_initStaticVars_void",
        "metrics": (48, 12, 1),
        "call_count": 2,
        "source_basis": "font-data static hash-list initializer",
        "context_group": "TFontData residual lifecycle and lookup block",
        "context_order": 3,
    },
    {
        "original_ea": "0x108280",
        "original_name": "TWindowProperties_TWindowProperties",
        "spectron_ea": "0x10abd4",
        "target_name": "_ZN20LJyzga9PwyPropertiesD2Ev",
        "target_prefix": "_ZN20LJyzga9PwyProperties",
        "proposed_name": "v18_TWindowProperties_TWindowProperties",
        "metrics": (28, 7, 2),
        "call_count": 0,
        "source_basis": "window-properties base destructor",
        "context_group": "TWindowProperties residual destructor block",
        "context_order": 1,
    },
    {
        "original_ea": "0x10829c",
        "original_name": "non_virtual_thunk_to_TWindowProperties_TWindowProperties",
        "spectron_ea": "0x10abf0",
        "target_name": "_ZThn16_N20LJyzga9PwyPropertiesD1Ev",
        "target_prefix": "_ZThn16_N20LJyzga9PwyProperties",
        "proposed_name": "v18_non_virtual_thunk_to_TWindowProperties_TWindowProperties",
        "metrics": (8, 2, 2),
        "call_count": 0,
        "source_basis": "window-properties adjusted-this destructor thunk",
        "context_group": "TWindowProperties residual destructor block",
        "context_order": 2,
    },
    {
        "original_ea": "0x1082a4",
        "original_name": "TWindowProperties_TWindowProperties__2",
        "spectron_ea": "0x10abf8",
        "target_name": "_ZN20LJyzga9PwyPropertiesD0Ev",
        "target_prefix": "_ZN20LJyzga9PwyProperties",
        "proposed_name": "v18_TWindowProperties_TWindowProperties__2",
        "metrics": (56, 14, 2),
        "call_count": 1,
        "source_basis": "window-properties deleting destructor",
        "context_group": "TWindowProperties residual destructor block",
        "context_order": 3,
    },
    {
        "original_ea": "0x1082dc",
        "original_name": "non_virtual_thunk_to_TWindowProperties_TWindowProperties__2",
        "spectron_ea": "0x10ac30",
        "target_name": "_ZThn16_N20LJyzga9PwyPropertiesD0Ev",
        "target_prefix": "_ZThn16_N20LJyzga9PwyProperties",
        "proposed_name": "v18_non_virtual_thunk_to_TWindowProperties_TWindowProperties__2",
        "metrics": (8, 2, 2),
        "call_count": 0,
        "source_basis": "window-properties adjusted-this deleting-destructor thunk",
        "context_group": "TWindowProperties residual destructor block",
        "context_order": 4,
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
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
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
        if source is None or target is None:
            raise ValueError("missing source or target feature for %s" % spec["original_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("original name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
        if not target["name"].startswith(spec["target_prefix"]):
            raise ValueError("target context mismatch at %s" % spec["spectron_ea"])
        for side, function in (("source", source), ("target", target)):
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual_metrics != spec["metrics"]:
                raise ValueError(
                    "unexpected %s metrics at %s: %s"
                    % (
                        side,
                        spec["original_ea" if side == "source" else "spectron_ea"],
                        actual_metrics,
                    )
                )
            if function.get("call_count") != spec["call_count"]:
                raise ValueError(
                    "unexpected %s call count at %s"
                    % (side, spec["original_ea" if side == "source" else "spectron_ea"])
                )
            if function.get("string_refs", []):
                raise ValueError("unexpected string references at %s" % spec["original_ea"])
        if any(
            source.get(field) != target.get(field)
            for field in (
                "branch_count",
                "mnemonic_hash",
                "opcode_shape_hash",
                "register_shape_hash",
                "shape_hash",
            )
        ):
            raise ValueError("source and target shape mismatch at %s" % spec["original_ea"])
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
                "match_kind": "manual-font-options-font-data-window-residual-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "context_group": spec["context_group"],
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_font_options_font_data_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TScreenPanelOpenGL, TFontOptions, TFontData, and TWindowProperties methods",
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
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "target_classes": {
                "SU3JfaCUmR": "screen-panel native-mode predicate and destructor pair at 0x10f514 through 0x10f560",
                "KcKRganuPN": "font-option property accessors at 0x111f70 through 0x112024",
                "fUWH_a_9zm": "font-data destructor, filename lookup, and static initializer at 0x113354 through 0x113a28",
                "LJyzga9PwyProperties": "window-properties destructor pair and adjusted-this thunks at 0x10abd4 through 0x10ac38",
            },
            "source_sequence": "The source rows are the residual boundaries around already translated screen-panel, font-option, font-data, and window-properties methods.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable source roles while retaining the obfuscated target names and changed target class names in the evidence rows.",
            "The six font-option target functions were default IDA names, so this batch removes six more residual sub_ entries after verification.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
