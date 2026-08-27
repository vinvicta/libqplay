#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's TTexture method cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target _WevgakbUu methods remain in the same local order as the source TTexture methods, between the already translated bitmap helpers and the TDrawTexture class.",
    "The width and height accessors preserve the same lazy-load decision, bitmap dimension offsets, fallback dimensions, and zero result when loading still produces no bitmap.",
    "The texture allocation and texture-dimension methods preserve the same GPU allocation, mipmap update, lazy texture load, and width or height field reads. Spectron makes temporary string conversion and cleanup explicit in the allocator.",
    "The target deleting destructor and window constructor preserve the source ownership and object initialization roles. The target uses the C8THgaTQxF and CanTfaz6bZ wrapper types and an explicit C1 constructor alias.",
    "The Graal bitmap accessor preserves lookup, optional reload flags, the guest or missing-resource guard, virtual load, and texture return. Spectron adds a typed lookup helper and also contains a separate overload that is not a 1.8 source counterpart.",
    "The static resource cleanup and initialization helpers preserve hash-list clearing and creation of the image and allowed-animation registries, with only obfuscated target class names and wrapper calls changed.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x10540c",
        "original_name": "TTexture_getWidth_void",
        "spectron_ea": "0x107a94",
        "target_name": "_ZN10_WevgakbUu10Ek0Mfa6TQTEv",
        "proposed_name": "v18_TTexture_getWidth_void",
        "source_metrics": (104, 26, 8),
        "target_metrics": (104, 26, 8),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "texture bitmap width accessor",
    },
    {
        "original_ea": "0x105474",
        "original_name": "TTexture_getHeight_void",
        "spectron_ea": "0x107afc",
        "target_name": "_ZN10_WevgakbUu10Jw2MfabKSTEv",
        "proposed_name": "v18_TTexture_getHeight_void",
        "source_metrics": (104, 26, 8),
        "target_metrics": (104, 26, 8),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "texture bitmap height accessor",
    },
    {
        "original_ea": "0x10566c",
        "original_name": "TTexture_createTexture_void",
        "spectron_ea": "0x107cf4",
        "target_name": "_ZN10_WevgakbUu10ZWKYgaj6ITEv",
        "proposed_name": "v18_TTexture_createTexture_void",
        "source_metrics": (152, 38, 10),
        "target_metrics": (176, 44, 10),
        "source_call_count": 1,
        "target_call_count": 4,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10_WevgakbUu10dplYgaNCnTEb",
        ),
        "source_basis": "GPU texture allocation and upload entry point",
    },
    {
        "original_ea": "0x105794",
        "original_name": "TTexture_getTextureWidth_void",
        "spectron_ea": "0x107e34",
        "target_name": "_ZN10_WevgakbUu10LMNKfaGuZREv",
        "proposed_name": "v18_TTexture_getTextureWidth_void",
        "source_metrics": (56, 14, 3),
        "target_metrics": (56, 14, 3),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TTexture_loadTexture_void",),
        "required_target_calls": ("._ZN10_WevgakbUu10mBzFEa1yAPEv",),
        "source_basis": "loaded GPU texture width accessor",
    },
    {
        "original_ea": "0x1057cc",
        "original_name": "TTexture_getTextureHeight_void",
        "spectron_ea": "0x107e6c",
        "target_name": "_ZN10_WevgakbUu10LwlPfajJOVEv",
        "proposed_name": "v18_TTexture_getTextureHeight_void",
        "source_metrics": (56, 14, 3),
        "target_metrics": (56, 14, 3),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TTexture_loadTexture_void",),
        "required_target_calls": ("._ZN10_WevgakbUu10mBzFEa1yAPEv",),
        "source_basis": "loaded GPU texture height accessor",
    },
    {
        "original_ea": "0x1058e0",
        "original_name": "TTexture_TTexture__2",
        "spectron_ea": "0x107f80",
        "target_name": "_ZN10_WevgakbUuD0Ev",
        "proposed_name": "v18_TTexture_TTexture__2",
        "source_metrics": (32, 8, 2),
        "target_metrics": (32, 8, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TTexture_TTexture",),
        "required_target_calls": ("._ZN10_WevgakbUuD1Ev",),
        "source_basis": "deleting destructor and object release",
    },
    {
        "original_ea": "0x105ad0",
        "original_name": "TTexture_TTexture_TWindow_TString_const",
        "spectron_ea": "0x108170",
        "target_name": "_ZN10_WevgakbUuC1EP10LJyzga9PwyRK10C8THgaTQxF",
        "proposed_name": "v18_TTexture_TTexture_TWindow_TString_const",
        "source_metrics": (252, 63, 1),
        "target_metrics": (280, 70, 1),
        "source_call_count": 5,
        "target_call_count": 7,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashListObject_THashListObject_TString_const",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TTexture_stripGraphicsFileName_TString_const",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSER10CanTfaz6bZ",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10CanTfaz6bZ5clearEv",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10J7zOgaf09KC2ERK10CanTfaz6bZ",
            "._ZN10_WevgakbUu10KVUIGaevoyERK10C8THgaTQxF",
        ),
        "source_basis": "window-backed texture constructor",
    },
    {
        "original_ea": "0x105d5c",
        "original_name": "TTexture_getGraalBitmap_TString_const_bool_bool",
        "spectron_ea": "0x1084cc",
        "target_name": "_ZN10_WevgakbUu10b8REEas9ZOERK10CanTfaz6bZbb",
        "proposed_name": "v18_TTexture_getGraalBitmap_TString_const_bool_bool",
        "source_metrics": (128, 32, 9),
        "target_metrics": (128, 32, 9),
        "source_call_count": 3,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TTexture_findGraalTexture_TString_const",),
        "required_target_calls": (
            "._ZN10_WevgakbUu10retFEaLcvPERK10CanTfaz6bZ",
        ),
        "source_basis": "Graal texture lookup and bitmap load",
    },
    {
        "original_ea": "0x105e54",
        "original_name": "TTexture_freeResources_void",
        "spectron_ea": "0x108644",
        "target_name": "_ZN10_WevgakbUu10wgSQgaCg5MEv",
        "proposed_name": "v18_TTexture_freeResources_void",
        "source_metrics": (20, 5, 2),
        "target_metrics": (20, 5, 2),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "global texture registry cleanup",
    },
    {
        "original_ea": "0x1065e4",
        "original_name": "TTexture_initStaticVars_void",
        "spectron_ea": "0x108dd4",
        "target_name": "_Z10DLwDEaIaSNv",
        "proposed_name": "v18_TTexture_initStaticVars_void",
        "source_metrics": (76, 19, 1),
        "target_metrics": (76, 19, 1),
        "source_call_count": 4,
        "target_call_count": 4,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashList_THashList_void__2",
            "plt_TStringList_TStringList_void",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10KKhLga4xoIC1Ev",
            "._ZN10vuuHgangcFC2Ev",
            "._Znwm",
        ),
        "source_basis": "image and animation registry initialization",
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
                "match_kind": "manual-texture-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in texture anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in texture anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_texture_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TTexture bitmap access, GPU texture lifecycle, Graal lookup, and static registries",
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
            "The target's typed string wrappers, extra Graal lookup helper, and C1 or D0 ABI spellings are recorded as target-version implementation differences.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
