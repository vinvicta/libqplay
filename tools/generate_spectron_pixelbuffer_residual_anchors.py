#!/usr/bin/env python3
"""Create reviewed anchors for residual TPixelBuffer methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target uSjUgask_P methods sit in the same local pixel-buffer class cluster as the already translated setPixels, window-backed constructor, pitch, destroyPixels, compatible-bitmap, keep-bitmap, and createPixels methods.",
    "The setPixelsNoDestroy, setPalette, unsetPixels, and setFormat bodies preserve the source field roles. The target offsets differ because its class layout contains additional fields, but the pointer, dimensions, palette, and format operations remain explicit.",
    "The target getPixels method calls the target pixel-allocation helper and returns the pixel pointer, matching the source getPixels to createPixels relationship.",
    "The target hasTexture method returns zero, while the createTexture, updateTexture, and bindTexture base hooks remain empty just like the source base implementation. The overloaded updateTexture method keeps the same indirect vtable dispatch.",
    "The rows are not already present in the semantic translation map. They are recorded as manual context anchors for the exact hashed Spectron library.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x104c90",
        "original_name": "TPixelBuffer_setPixelsNoDestroy_uchar_int_int",
        "spectron_ea": "0x107318",
        "target_name": "_ZN10uSjUgask_P10P1yYgac5yTEPhii",
        "proposed_name": "v18_TPixelBuffer_setPixelsNoDestroy_uchar_int_int",
        "source_metrics": (24, 6, 1),
        "target_metrics": (24, 6, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "pixel pointer and dimension assignment",
    },
    {
        "original_ea": "0x104ca8",
        "original_name": "TPixelBuffer_setPalette_TPalette_const",
        "spectron_ea": "0x107330",
        "target_name": "_ZN10uSjUgask_P10hS36BafSyGEPK10NLT0HaSwmE",
        "proposed_name": "v18_TPixelBuffer_setPalette_TPalette_const",
        "source_metrics": (8, 2, 1),
        "target_metrics": (8, 2, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "palette pointer assignment",
    },
    {
        "original_ea": "0x104eac",
        "original_name": "TPixelBuffer_unsetPixels_void",
        "spectron_ea": "0x107534",
        "target_name": "_ZN10uSjUgask_P10cZhFEa3JlPEv",
        "proposed_name": "v18_TPixelBuffer_unsetPixels_void",
        "source_metrics": (12, 3, 1),
        "target_metrics": (12, 3, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "pixel and palette pointer clearing",
    },
    {
        "original_ea": "0x104eb8",
        "original_name": "TPixelBuffer_setFormat_int",
        "spectron_ea": "0x107540",
        "target_name": "_ZN10uSjUgask_P10SzGlKaXqRBEi",
        "proposed_name": "v18_TPixelBuffer_setFormat_int",
        "source_metrics": (8, 2, 1),
        "target_metrics": (8, 2, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "pixel format assignment",
    },
    {
        "original_ea": "0x105084",
        "original_name": "TPixelBuffer_getPixels_void",
        "spectron_ea": "0x10770c",
        "target_name": "_ZN10uSjUgask_P10KQm_ga7P4UEv",
        "proposed_name": "v18_TPixelBuffer_getPixels_void",
        "source_metrics": (32, 8, 1),
        "target_metrics": (32, 8, 1),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TPixelBuffer_createPixels_void",),
        "required_target_calls": ("._ZN10uSjUgask_P10gnoUnb962IEv",),
        "source_basis": "lazy pixel allocation and pointer return",
    },
    {
        "original_ea": "0x1050a4",
        "original_name": "TPixelBuffer_hasTexture_void",
        "spectron_ea": "0x10772c",
        "target_name": "_ZN10uSjUgask_P10gDNYgaImLTEv",
        "proposed_name": "v18_TPixelBuffer_hasTexture_void",
        "source_metrics": (8, 2, 1),
        "target_metrics": (8, 2, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "base texture-presence predicate",
    },
    {
        "original_ea": "0x1050ac",
        "original_name": "TPixelBuffer_createTexture_void",
        "spectron_ea": "0x107734",
        "target_name": "_ZN10uSjUgask_P10ZWKYgaj6ITEv",
        "proposed_name": "v18_TPixelBuffer_createTexture_void",
        "source_metrics": (4, 1, 1),
        "target_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "base texture-creation hook",
    },
    {
        "original_ea": "0x1050b0",
        "original_name": "TPixelBuffer_updateTexture_void",
        "spectron_ea": "0x107738",
        "target_name": "_ZN10uSjUgask_P10dplYgaNCnTEv",
        "proposed_name": "v18_TPixelBuffer_updateTexture_void",
        "source_metrics": (4, 1, 1),
        "target_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "base texture-update hook",
    },
    {
        "original_ea": "0x1050b4",
        "original_name": "TPixelBuffer_updateTexture_int_int_int_int",
        "spectron_ea": "0x10773c",
        "target_name": "_ZN10uSjUgask_P10dplYgaNCnTEiiii",
        "proposed_name": "v18_TPixelBuffer_updateTexture_int_int_int_int",
        "source_metrics": (32, 8, 1),
        "target_metrics": (32, 8, 1),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "rectangle texture-update vtable dispatch",
    },
    {
        "original_ea": "0x1050d4",
        "original_name": "TPixelBuffer_bindTexture_int",
        "spectron_ea": "0x10775c",
        "target_name": "_ZN10uSjUgask_P10AJfYga4QiTEi",
        "proposed_name": "v18_TPixelBuffer_bindTexture_int",
        "source_metrics": (4, 1, 1),
        "target_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "base texture-binding hook",
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
                raise ValueError("unexpected %s metrics at %s: %s" % (side, ea, actual_metrics))
            if function.get("call_count") != spec["%s_call_count" % side]:
                raise ValueError("unexpected %s call count at %s" % (side, ea))
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
                "match_kind": "manual-pixelbuffer-residual-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_pixelbuffer_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TPixelBuffer field and texture hooks",
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
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable source roles while keeping the obfuscated target names and the target class-layout offsets in the evidence rows.",
            "The three empty texture hooks are retained as base-class hooks, and the rectangle overload is retained as an indirect vtable dispatch rather than assigned a stronger implementation claim.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
