#!/usr/bin/env python3
"""Create reviewed anchors for the remaining Spectron font/resource methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target TZf6gaQ3S_, Kv6ugas5Mu, KcKRganuPN, and fUWH_a_9zm methods remain in the same local class order as the source TFont, TFontManager, TFontOptions, and TFontData methods.",
    "The TFont constructor preserves the hash-list base, 256-character-info initialization loop, vtable installation, and field defaults. The target adds an explicit CanTfaz6bZ conversion around its rebuilt string wrapper.",
    "The font-texture method preserves the generate-bitmap guard, Font-name construction, texture creation, texture flags, upload call, and timestamp update. The target uses the already translated font bitmap and texture helpers.",
    "The font-file resolver preserves the .ttf and it.ttf fallback order, system-font lookup, resource lookup, and empty-result behavior. Its smaller target body reflects changed string and resource wrappers rather than a different role.",
    "The font-manager initializer preserves publication of the font hash list and missing-font list. The target initializes the system-font path in a different startup path, so that version difference is recorded instead of hidden.",
    "The UTF-8 range helper preserves validation, path normalization, range allocation, and list insertion. The font-data constructor preserves lower-case name construction, base initialization, source-name storage, and its 0x18-byte data list.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x10d348",
        "original_name": "TFont_TFont_TString_const",
        "spectron_ea": "0x10fcb4",
        "target_name": "_ZN10TZf6gaQ3S_C1ERK10C8THgaTQxF",
        "proposed_name": "v18_TFont_TFont_TString_const",
        "source_metrics": (156, 39, 3),
        "target_metrics": (188, 47, 3),
        "source_call_count": 2,
        "target_call_count": 4,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashListObject_THashListObject_TString_const",
            "plt_TFontCharInfo_TFontCharInfo_void",
        ),
        "required_target_calls": (
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10J7zOgaf09KC2ERK10CanTfaz6bZ",
            "._ZN10DFeOfaFXSUC2Ev",
        ),
        "source_basis": "font object construction and glyph-cache initialization",
    },
    {
        "original_ea": "0x10d8c4",
        "original_name": "TFont_makeFontTexture_void",
        "spectron_ea": "0x110274",
        "target_name": "_ZN10TZf6gaQ3S_10MdTr4al43lEv",
        "proposed_name": "v18_TFont_makeFontTexture_void",
        "source_metrics": (212, 52, 3),
        "target_metrics": (240, 59, 3),
        "source_call_count": 8,
        "target_call_count": 10,
        "source_string_refs": ("Font ",),
        "target_string_refs": ("Font ",),
        "required_source_calls": (
            "plt_TFont_generateFontBitmap_void",
            "plt_TTexture_createGraalTexture_TString_const",
        ),
        "required_target_calls": (
            "._ZN10TZf6gaQ3S_10fl7q4asNqlEv",
            "._ZN10_WevgakbUu10vDdFEaX4hPERK10C8THgaTQxF",
        ),
        "source_basis": "font bitmap generation and texture upload",
    },
    {
        "original_ea": "0x10e998",
        "original_name": "TFontManager_findFontFile_TString_const_TString_const",
        "spectron_ea": "0x111368",
        "target_name": "_ZN10Kv6ugas5Mu10aDqxfbC0JGERK10C8THgaTQxFS2_",
        "proposed_name": "v18_TFontManager_findFontFile_TString_const_TString_const",
        "source_metrics": (828, 207, 15),
        "target_metrics": (560, 140, 10),
        "source_call_count": 52,
        "target_call_count": 34,
        "source_string_refs": (".ttf", "it.ttf"),
        "target_string_refs": (".ttf", "it.ttf"),
        "required_source_calls": (
            "plt_TFontManager_getFontBaseName_TString_const",
            "plt_TFontManager_getStyleFileAddition_TString_const",
            "plt_TFiles_fileExists_TString_const",
            "plt_TResourceFunctions_getGameFile_TString_const_bool",
        ),
        "required_target_calls": (
            "._ZN10Kv6ugas5Mu10R9Hyfb3LOHERK10C8THgaTQxF",
            "._ZN10Kv6ugas5Mu10F_uyfbmHDHERK10C8THgaTQxF",
            "._ZN10f6WHgaQkAF10r3WHgaBiAFERK10C8THgaTQxFb",
        ),
        "source_basis": "font file search and resource fallback",
    },
    {
        "original_ea": "0x10f660",
        "original_name": "TFontManager_initStaticVars_void",
        "spectron_ea": "0x111f24",
        "target_name": "_Z10vVWN2a5aDYv",
        "proposed_name": "v18_TFontManager_initStaticVars_void",
        "source_metrics": (116, 29, 1),
        "target_metrics": (76, 19, 1),
        "source_call_count": 6,
        "target_call_count": 4,
        "source_string_refs": ("/system/fonts/",),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_operator_new_ulong__2",
            "plt_THashList_THashList_void__2",
            "plt_TStringList_TStringList_void",
        ),
        "required_target_calls": (
            "._Znwm",
            "._ZN10KKhLga4xoIC1Ev",
            "._ZN10vuuHgangcFC2Ev",
        ),
        "source_basis": "font manager static registry initialization",
    },
    {
        "original_ea": "0x10f81c",
        "original_name": "TFontOptions_script_addutf8fontrange",
        "spectron_ea": "0x1120b8",
        "target_name": "sub_1120B8",
        "proposed_name": "v18_TFontOptions_script_addutf8fontrange",
        "source_metrics": (232, 58, 6),
        "target_metrics": (200, 50, 4),
        "source_call_count": 9,
        "target_call_count": 8,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TFiles_extractFilename_TString_const",
            "plt_TList_Add_void",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10wiULgacZUI10_RVvga7htvERK10C8THgaTQxF",
            "._ZN10vy1JgaKVkH3AddEPv",
            "._Znwm",
        ),
        "source_basis": "UTF-8 font range validation and registration",
    },
    {
        "original_ea": "0x110c00",
        "original_name": "TFontData_TFontData_TString_const",
        "spectron_ea": "0x11347c",
        "target_name": "_ZN10fUWH_a_9zmC2ERK10C8THgaTQxF",
        "proposed_name": "v18_TFontData_TFontData_TString_const",
        "source_metrics": (160, 40, 1),
        "target_metrics": (196, 49, 1),
        "source_call_count": 5,
        "target_call_count": 7,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TFiles_lowerCaseFilename_TString_const",
            "plt_THashListObject_THashListObject_TString_const",
            "plt_TString_operator_assign_TString_const",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10wiULgacZUI10RUnvgavJ0uERK10C8THgaTQxF",
            "._ZN10J7zOgaf09KC2ERK10CanTfaz6bZ",
            "._ZN10C8THgaTQxFaSERKS_",
            "._Znwm",
        ),
        "source_basis": "font data object and glyph-data list construction",
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
                    "unexpected %s call count at %s"
                    % (side, ea)
                )
            expected_strings = list(spec["%s_string_refs" % side])
            if function.get("string_refs", []) != expected_strings:
                raise ValueError(
                    "unexpected %s string references at %s: %s"
                    % (side, ea, function.get("string_refs", []))
                )
            for required_call in spec["required_%s_calls" % side]:
                if required_call not in function.get("direct_call_names", []):
                    raise ValueError("missing %s call %s at %s" % (side, required_call, ea))
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
                "match_kind": "manual-font-runtime-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in font-runtime anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in font-runtime anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_font_runtime_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TFont, TFontManager, TFontOptions, and TFontData residual methods",
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
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable 1.8 font and resource roles while keeping the obfuscated target names and wrapper differences in the evidence rows.",
            "The target keeps the same font search, texture construction, UTF-8 range, and font-data ownership roles, with version-specific wrapper and initialization differences recorded explicitly.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
