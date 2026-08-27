#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's drawing-panel texture methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target BP3Kfa2PcS methods remain in the same local order as the source TDrawingPanelTexture methods, surrounded by the corresponding panel and OpenGL texture helpers.",
    "The source and target destructors preserve the two AArch64 C++ ABI roles: the complete destructor releases the panel texture and calls the base panel-port destructor, while the deleting destructor calls the complete destructor and operator delete.",
    "The window-backed constructors preserve base panel-port construction, vtable installation, and the null texture handle. The target exposes the C1 spelling and uses its obfuscated OYYKfaPU7R base class.",
    "The width and height accessors preserve the virtual texture update call, the target texture object field, and the width or height offsets. Only the target vtable slot and obfuscated method names differ.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x1082e8",
        "original_name": "TDrawingPanelTexture_TDrawingPanelTexture",
        "spectron_ea": "0x10ac38",
        "target_name": "_ZN10BP3Kfa2PcSD1Ev",
        "proposed_name": "v18_TDrawingPanelTexture_TDrawingPanelTexture",
        "source_metrics": (68, 17, 4),
        "target_metrics": (68, 17, 4),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "complete drawing-panel texture destructor",
    },
    {
        "original_ea": "0x10832c",
        "original_name": "TDrawingPanelTexture_TDrawingPanelTexture__2",
        "spectron_ea": "0x10ac7c",
        "target_name": "_ZN10BP3Kfa2PcSD0Ev",
        "proposed_name": "v18_TDrawingPanelTexture_TDrawingPanelTexture__2",
        "source_metrics": (32, 8, 2),
        "target_metrics": (32, 8, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TDrawingPanelTexture_TDrawingPanelTexture",),
        "required_target_calls": ("._ZN10BP3Kfa2PcSD1Ev",),
        "source_basis": "deleting drawing-panel texture destructor",
    },
    {
        "original_ea": "0x1084d0",
        "original_name": "TDrawingPanelTexture_TDrawingPanelTexture_TWindow_int_int_int_int",
        "spectron_ea": "0x10ae20",
        "target_name": "_ZN10BP3Kfa2PcSC1EP10LJyzga9Pwyiiii",
        "proposed_name": "v18_TDrawingPanelTexture_TDrawingPanelTexture_TWindow_int_int_int_int",
        "source_metrics": (48, 12, 1),
        "target_metrics": (48, 12, 1),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TDrawingPanelPort_TDrawingPanelPort_TWindow_int_int_int_int",
        ),
        "required_target_calls": (
            "._ZN10OYYKfaPU7RC2EP10LJyzga9Pwyiiii",
        ),
        "source_basis": "window-backed drawing-panel texture constructor",
    },
    {
        "original_ea": "0x108500",
        "original_name": "TDrawingPanelTexture_getTextureWidth_void",
        "spectron_ea": "0x10ae50",
        "target_name": "_ZN10BP3Kfa2PcS10LMNKfaGuZREv",
        "proposed_name": "v18_TDrawingPanelTexture_getTextureWidth_void",
        "source_metrics": (64, 16, 3),
        "target_metrics": (64, 16, 3),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "drawing-panel GPU texture width accessor",
    },
    {
        "original_ea": "0x108540",
        "original_name": "TDrawingPanelTexture_getTextureHeight_void",
        "spectron_ea": "0x10ae90",
        "target_name": "_ZN10BP3Kfa2PcS10LwlPfajJOVEv",
        "proposed_name": "v18_TDrawingPanelTexture_getTextureHeight_void",
        "source_metrics": (64, 16, 3),
        "target_metrics": (64, 16, 3),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "drawing-panel GPU texture height accessor",
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
                "match_kind": "manual-drawing-panel-texture-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in drawing-panel texture anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in drawing-panel texture anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_drawing_panel_texture_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TDrawingPanelTexture destructors, construction, and texture dimensions",
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
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the obfuscated target names and ABI or base-class differences in the evidence rows.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
