#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's TDrawTexture method cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target NVxhJah9mI methods remain in the same local order as the source TDrawTexture methods, with the already translated load, constructor, delete, destructor, repeat, and draw methods surrounding this batch.",
    "The static initializer allocates the same 0x18-byte list object, clears its count and storage fields, installs the list vtable, and publishes the class texture-list global. The only changes are the obfuscated target global and operator-new spelling.",
    "The resource cleanup and reload methods preserve the same indexed traversal of the global texture list. Cleanup calls the target deleting texture method for every entry, while reload calls the target load method for every entry.",
    "The bind helper is an exact OpenGL wrapper that binds texture target 3553 using the same object field. The target changes only the class and method spelling.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0xe0770",
        "original_name": "TDrawTexture_initializeTexturesList",
        "spectron_ea": "0xe0754",
        "target_name": "sub_E0754",
        "proposed_name": "v18_TDrawTexture_initializeTexturesList",
        "source_metrics": (68, 17, 1),
        "target_metrics": (68, 17, 1),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_operator_new_ulong__2",),
        "required_target_calls": ("._Znwm",),
        "source_basis": "global draw-texture list initialization",
    },
    {
        "original_ea": "0x108d1c",
        "original_name": "TDrawTexture_freeResources_void",
        "spectron_ea": "0x10b66c",
        "target_name": "_ZN10NVxhJah9mI10wgSQgaCg5MEv",
        "proposed_name": "v18_TDrawTexture_freeResources_void",
        "source_metrics": (96, 24, 3),
        "target_metrics": (96, 24, 3),
        "source_call_count": 2,
        "target_call_count": 2,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TDrawTexture_deleteTexture_void",
            "plt_TList_operator_index_int",
        ),
        "required_target_calls": (
            "._ZN10NVxhJah9mI10GzohJaFhfIEv",
            "._ZNK10vy1JgaKVkHixEi",
        ),
        "source_basis": "draw-texture registry cleanup",
    },
    {
        "original_ea": "0x108d7c",
        "original_name": "TDrawTexture_reloadTextures_void",
        "spectron_ea": "0x10b6cc",
        "target_name": "_ZN10NVxhJah9mI10WDrhJanShIEv",
        "proposed_name": "v18_TDrawTexture_reloadTextures_void",
        "source_metrics": (96, 24, 3),
        "target_metrics": (96, 24, 3),
        "source_call_count": 2,
        "target_call_count": 2,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TDrawTexture_load_void",
            "plt_TList_operator_index_int",
        ),
        "required_target_calls": (
            "._ZN10NVxhJah9mI4loadEv",
            "._ZNK10vy1JgaKVkHixEi",
        ),
        "source_basis": "draw-texture registry reload",
    },
    {
        "original_ea": "0x108e60",
        "original_name": "TDrawTexture_bindTexture_void",
        "spectron_ea": "0x10b7b0",
        "target_name": "_ZN10NVxhJah9mI10AJfYga4QiTEv",
        "proposed_name": "v18_TDrawTexture_bindTexture_void",
        "source_metrics": (12, 3, 2),
        "target_metrics": (12, 3, 2),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (),
        "required_target_calls": (),
        "source_basis": "OpenGL 2D texture bind wrapper",
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
                "match_kind": "manual-draw-texture-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in draw-texture anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in draw-texture anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_draw_texture_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TDrawTexture static initialization, registry cleanup, reload, and binding",
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
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the obfuscated target names and target global differences in the evidence rows.",
            "The static initializer target was a default sub_ name and is recorded as such.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
