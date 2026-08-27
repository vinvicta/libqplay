#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's TBitmapArrayHolder methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target r1dvgaPpTu methods remain in the same local order as the source TBitmapArrayHolder methods, with the translated rectangle clear, constructor, list accessor, and file-update neighbors providing class context.",
    "The string constructor preserves hash-list-object base construction, null rectangle-list initialization, and derived-vtable installation. The target makes its CanTfaz6bZ temporary conversion explicit.",
    "The deleting destructor preserves the source complete-destructor and operator-delete sequence, with the target D0 ABI spelling and obfuscated D2 helper.",
    "The rectangle calculator preserves the bitmap lookup, top-left color test, rectangle-list reset, color-run scanning, four-edge rectangle detection, and list insertion loops. Spectron changes only through typed string and list wrappers and the target bitmap accessor.",
    "The rectangle lookup preserves normalized filename derivation, hash lookup, lazy holder allocation, registry insertion, rectangle calculation access, and temporary cleanup. Static initialization preserves creation and publication of the bitmap-array hash list.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0xfd524",
        "original_name": "TBitmapArrayHolder_TBitmapArrayHolder_TString_const",
        "spectron_ea": "0xffb40",
        "target_name": "_ZN10r1dvgaPpTuC2ERK10C8THgaTQxF",
        "proposed_name": "v18_TBitmapArrayHolder_TBitmapArrayHolder_TString_const",
        "source_metrics": (48, 12, 1),
        "target_metrics": (88, 22, 1),
        "source_call_count": 1,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_THashListObject_THashListObject_TString_const",),
        "required_target_calls": (
            "._ZN10CanTfaz6bZ5clearEv",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10J7zOgaf09KC2ERK10CanTfaz6bZ",
        ),
        "source_basis": "bitmap-array holder string constructor",
    },
    {
        "original_ea": "0xfd600",
        "original_name": "TBitmapArrayHolder_TBitmapArrayHolder__2",
        "spectron_ea": "0xffc44",
        "target_name": "_ZN10r1dvgaPpTuD0Ev",
        "proposed_name": "v18_TBitmapArrayHolder_TBitmapArrayHolder__2",
        "source_metrics": (32, 8, 2),
        "target_metrics": (32, 8, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TBitmapArrayHolder_TBitmapArrayHolder",),
        "required_target_calls": ("._ZN10r1dvgaPpTuD2Ev",),
        "source_basis": "deleting bitmap-array holder destructor",
    },
    {
        "original_ea": "0xfd620",
        "original_name": "TBitmapArrayHolder_calcRects_void",
        "spectron_ea": "0xffc64",
        "target_name": "_ZN10r1dvgaPpTu10wq9rfa1xiCEv",
        "proposed_name": "v18_TBitmapArrayHolder_calcRects_void",
        "source_metrics": (804, 201, 38),
        "target_metrics": (832, 208, 38),
        "source_call_count": 11,
        "target_call_count": 13,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TBitmapArrayHolder_clearRects_void",
            "plt_TBitmap_getColor_uint_uint_ColorI",
            "plt_TList_Add_void",
            "plt_TTexture_getGraalBitmap_TString_const_bool_bool",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10_WevgakbUu10pgy_gapreVERK10C8THgaTQxFbb",
            "._ZN10r1dvgaPpTu10Py4rfa3reCEv",
            "._ZN10vy1JgaKVkH3AddEPv",
            "._ZNK10Fcx_gaoydV10dp9wIaTwv4EjjR10dVIHgaIooF",
            "._Znwm",
        ),
        "source_basis": "bitmap-array rectangle discovery",
    },
    {
        "original_ea": "0xfd9d4",
        "original_name": "TBitmapArrayHolder_getBitmapArrayRects_TString_const",
        "spectron_ea": "0x100034",
        "target_name": "_ZN10r1dvgaPpTu10qwJrfaTUWBERK10CanTfaz6bZ",
        "proposed_name": "v18_TBitmapArrayHolder_getBitmapArrayRects_TString_const",
        "source_metrics": (200, 50, 7),
        "target_metrics": (208, 52, 7),
        "source_call_count": 9,
        "target_call_count": 8,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TBitmapArrayHolder_TBitmapArrayHolder_TString_const",
            "plt_TBitmapArrayHolder_getRects_void",
            "plt_THashList_addObject_THashListObject",
            "plt_THashList_getHashcode_TString_const",
            "plt_THashList_getObject_uint_TString_const",
            "plt_TString_clear_void",
            "plt_TTexture_stripGraphicsFileName_TString_const",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10CanTfaz6bZ10wsWEEaIN2OERKS_",
            "._ZN10KKhLga4xoI10TBCvgay5cvEjRK10CanTfaz6bZ",
            "._ZN10KKhLga4xoI10g4ouMaaIbpERK10CanTfaz6bZ",
            "._ZN10KKhLga4xoI9addObjectEP10J7zOgaf09K",
            "._ZN10r1dvgaPpTu10L06rfaiwgCEv",
            "._ZN10r1dvgaPpTuC2ERK10C8THgaTQxF",
            "._Znwm",
        ),
        "source_basis": "bitmap-array rectangle registry lookup",
    },
    {
        "original_ea": "0xfda9c",
        "original_name": "TBitmapArrayHolder_initStaticVars_void",
        "spectron_ea": "0x100104",
        "target_name": "_Z10L9BrfaYIQBv",
        "proposed_name": "v18_TBitmapArrayHolder_initStaticVars_void",
        "source_metrics": (48, 12, 1),
        "target_metrics": (48, 12, 1),
        "source_call_count": 2,
        "target_call_count": 2,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashList_THashList_void__2",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10KKhLga4xoIC1Ev",
            "._Znwm",
        ),
        "source_basis": "bitmap-array registry initialization",
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
                "match_kind": "manual-bitmap-array-holder-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in bitmap-array holder anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in bitmap-array holder anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_bitmap_array_holder_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TBitmapArrayHolder construction, rectangle discovery, lookup, and static registry setup",
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
            "The target constructor and rectangle calculator use explicit typed string and list wrappers, and the target deleting destructor uses the D0 ABI spelling.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
