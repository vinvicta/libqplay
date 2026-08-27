#!/usr/bin/env python3
"""Create reviewed anchors for the remaining Spectron drawing-panel methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target V8fxgahcBw methods remain in the same local order as the source TDrawingPanel methods, between the translated initialization, primitive drawing, operation, and image-save helpers.",
    "Both target constructors preserve the TGraalVar base construction, derived-vtable installation, and panel initialization path. The bool overload keeps the same second constructor control.",
    "The image implementation methods preserve the tiles special case, texture-size query, drawImageRectangle2 forwarding, and outside-rectangle fill used by the source wrappers.",
    "The filter method preserves refresh checking, lower-case filter-name matching, the six named image filters, and temporary TStringList cleanup. The target uses rebuilt image-filter and string-list wrappers.",
    "The palette method preserves palette-name parsing, color lookup, indexed palette storage, and the same temporary list lifetime. Target string and list wrappers account for the small size change.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x117bec",
        "original_name": "TDrawingPanel_TDrawingPanel_TString_const",
        "spectron_ea": "0x11a64c",
        "target_name": "_ZN10V8fxgahcBwC2ERK10C8THgaTQxF",
        "proposed_name": "v18_TDrawingPanel_TDrawingPanel_TString_const",
        "source_metrics": (60, 15, 2),
        "target_metrics": (104, 26, 1),
        "source_call_count": 1,
        "target_call_count": 4,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TGraalVar_TGraalVar_TString_const",),
        "required_target_calls": (
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10G0gxgajWBwC1ERK10CanTfaz6bZ_0",
            "._ZN10V8fxgahcBw10j9gLgaw2nIEv",
        ),
        "source_basis": "drawing-panel string constructor",
    },
    {
        "original_ea": "0x117c28",
        "original_name": "TDrawingPanel_TDrawingPanel_TString_const_bool",
        "spectron_ea": "0x11a6b4",
        "target_name": "_ZN10V8fxgahcBwC1ERK10C8THgaTQxFb",
        "proposed_name": "v18_TDrawingPanel_TDrawingPanel_TString_const_bool",
        "source_metrics": (68, 17, 2),
        "target_metrics": (104, 26, 1),
        "source_call_count": 1,
        "target_call_count": 4,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TGraalVar_TGraalVar_TString_const",),
        "required_target_calls": (
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10G0gxgajWBwC1ERK10CanTfaz6bZ_0",
            "._ZN10V8fxgahcBw10j9gLgaw2nIEv",
        ),
        "source_basis": "drawing-panel bool constructor overload",
    },
    {
        "original_ea": "0x1191d4",
        "original_name": "TDrawingPanel_drawImage_Impl_int_int_TString_const",
        "spectron_ea": "0x11bc84",
        "target_name": "_ZN10V8fxgahcBw10qm0S2azVT1EiiRK10C8THgaTQxF",
        "proposed_name": "v18_TDrawingPanel_drawImage_Impl_int_int_TString_const",
        "source_metrics": (184, 46, 4),
        "target_metrics": (236, 59, 4),
        "source_call_count": 4,
        "target_call_count": 6,
        "source_string_refs": ("tiles",),
        "target_string_refs": ("tiles",),
        "required_source_calls": (
            "plt_TDrawingPanel_drawImageRectangle2_int_int_TString_const_int_int_int_int_int_int",
            "plt_TTexture_getTextureSize_TString_const",
        ),
        "required_target_calls": (
            "._ZN10V8fxgahcBw10eDPU2aA2p3EiiRK10C8THgaTQxFiiiiii",
            "._ZN10_WevgakbUu10HP8Cga81xBERK10C8THgaTQxF",
        ),
        "source_basis": "drawing-panel image implementation wrapper",
    },
    {
        "original_ea": "0x1192f0",
        "original_name": "TDrawingPanel_drawImageRectangle_Impl_int_int_TString_const_int_int_int_int",
        "spectron_ea": "0x11bdd4",
        "target_name": "_ZN10V8fxgahcBw10LlAS2aYbx1EiiRK10C8THgaTQxFiiii",
        "proposed_name": "v18_TDrawingPanel_drawImageRectangle_Impl_int_int_TString_const_int_int_int_int",
        "source_metrics": (252, 63, 4),
        "target_metrics": (284, 71, 4),
        "source_call_count": 5,
        "target_call_count": 7,
        "source_string_refs": ("tiles",),
        "target_string_refs": ("tiles",),
        "required_source_calls": (
            "plt_TDrawingPanel_drawImageRectangle2_int_int_TString_const_int_int_int_int_int_int",
            "plt_TDrawingPanel_fillOutsideRectangle_int_int_int_int_int_int_int_int",
            "plt_TTexture_getTextureSize_TString_const",
        ),
        "required_target_calls": (
            "._ZN10V8fxgahcBw10VlzU2admc3Eiiiiiiii",
            "._ZN10V8fxgahcBw10eDPU2aA2p3EiiRK10C8THgaTQxFiiiiii",
            "._ZN10_WevgakbUu10HP8Cga81xBERK10C8THgaTQxF",
        ),
        "source_basis": "drawing-panel image-rectangle implementation wrapper",
    },
    {
        "original_ea": "0x11a48c",
        "original_name": "TDrawingPanel_filterRectangle_Impl_int_int_int_int_TString_const",
        "spectron_ea": "0x11cf8c",
        "target_name": "_ZN10V8fxgahcBw10guGxDa8lXSEiiiiRK10C8THgaTQxF",
        "proposed_name": "v18_TDrawingPanel_filterRectangle_Impl_int_int_int_int_TString_const",
        "source_metrics": (536, 133, 19),
        "target_metrics": (540, 134, 19),
        "source_call_count": 17,
        "target_call_count": 17,
        "source_string_refs": ("gray,nightgoggle,negative,updown,blackwhite,lesscolors",),
        "target_string_refs": ("gray,nightgoggle,negative,updown,blackwhite,lesscolors",),
        "required_source_calls": (
            "plt_TDrawingPanel_checkRefresh_void",
            "plt_TImageFilter_gray_uchar_int_int_int",
            "plt_TImageFilter_negative_uchar_int_int_int",
            "plt_TImageFilter_nightGoggle_uchar_int_int_int",
            "plt_TImageFilter_reducedcolors_uchar_int_int_int",
            "plt_TImageFilter_twocolor_uchar_int_int_int",
            "plt_TImageFilter_updown_uchar_int_int_int",
        ),
        "required_target_calls": (
            "._ZN10V8fxgahcBw10aTwwDa4gZREv",
            "._ZN10EYMwkbFObT10BVRwkbbZfTEPhiii",
            "._ZN10EYMwkbFObT10CD4vkb3vBSEPhiii",
            "._ZN10EYMwkbFObT10GgGAkbGatWEPhiii",
            "._ZN10EYMwkbFObT10IfDwkbSD3SEPhiii",
            "._ZN10EYMwkbFObT10SXUAkb8wFWEPhiii",
            "._ZN10EYMwkbFObT10x_PAkbemBWEPhiii",
        ),
        "source_basis": "drawing-panel image filter selection and application",
    },
    {
        "original_ea": "0x11a6a8",
        "original_name": "TDrawingPanel_setDrawPaletteNamed_TString_const_int",
        "spectron_ea": "0x11d1ac",
        "target_name": "_ZN10V8fxgahcBw10VV_wDapynSERK10C8THgaTQxFi",
        "proposed_name": "v18_TDrawingPanel_setDrawPaletteNamed_TString_const_int",
        "source_metrics": (204, 51, 5),
        "target_metrics": (208, 52, 5),
        "source_call_count": 8,
        "target_call_count": 8,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TStringList_TStringList_TString_const",
            "plt_TStringList_operator_index_int",
            "plt_getStringColor_TString_const",
        ),
        "required_target_calls": (
            "._ZN10vuuHgangcFC2ERK10C8THgaTQxFb",
            "._ZNK10vuuHgangcFixEi",
            "._Z10Q9LCGaX7dtRK10C8THgaTQxF",
        ),
        "source_basis": "drawing-panel named palette selection",
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
        if source is None or target is None:
            raise ValueError("missing feature for %s" % spec["original_name"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("original name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
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
                raise ValueError("unexpected %s call count at %s" % (side, ea))
            if function.get("string_refs", []) != list(spec["%s_string_refs" % side]):
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
                "match_kind": "manual-drawing-panel-residual-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in drawing-panel residual anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in drawing-panel residual anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_drawing_panel_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TDrawingPanel constructors, image wrappers, filters, and palettes",
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
            "The proposed v18_ labels preserve readable 1.8 drawing-panel roles while keeping the obfuscated target names and wrapper differences in the evidence rows.",
            "The target retains the same panel construction, image wrapper, filter selection, and palette behavior, with explicit target wrappers and changed helper bodies recorded.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
