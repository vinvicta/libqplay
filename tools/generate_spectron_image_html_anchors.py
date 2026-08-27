#!/usr/bin/env python3
"""Create reviewed anchors for HTML colors and image-animation methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target nDIHgaJ9nF initializer keeps the source HTML color-list construction order, including the hash list, string list, color object allocation, and insertion into both containers.",
    "The target HTML color initializer uses rebuilt C8THgaTQxF, CanTfaz6bZ, J7zOgaf09K, KKhLga4xoI, and vy1JgaKVkH wrappers. Those wrapper changes explain the additional calls without changing the role of the function.",
    "The target n_rGfa49jO constructor preserves the source image-animation field defaults, two palette constructions, bitmap-list allocation, and vtable setup. The target stores the same state at shifted offsets because its rebuilt helper objects have different sizes.",
    "The target n_rGfa49jO D1 and D0 functions preserve the source destructor pair: release the optional bitmap buffer, destroy both palettes, clear the backing string, then route the deleting destructor through the complete destructor.",
    "The source and target rows are not already present in the semantic translation map. They are recorded as manual context anchors and remain tied to the exact hashed Spectron library.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x11b1f0",
        "original_name": "THTMLColors_initHTMLColorList_void",
        "spectron_ea": "0x11dcf8",
        "target_name": "_ZN10nDIHgaJ9nF10JCdjIae4MTEv",
        "proposed_name": "v18_THTMLColors_initHTMLColorList_void",
        "source_metrics": (272, 67, 3),
        "target_metrics": (304, 76, 3),
        "source_call_count": 9,
        "target_call_count": 11,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_THashListObject_THashListObject_TString_const",
            "plt_THashList_THashList_void__2",
            "plt_THashList_addObject_THashListObject",
            "plt_TList_Add_void",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10J7zOgaf09KC2ERK10CanTfaz6bZ",
            "._ZN10KKhLga4xoI9addObjectEP10J7zOgaf09K",
            "._ZN10vy1JgaKVkH3AddEPv",
            "._Znwm",
        ),
        "source_basis": "HTML color registry initialization",
    },
    {
        "original_ea": "0x11b508",
        "original_name": "TImageAnimation_TImageAnimation_void",
        "spectron_ea": "0x11e030",
        "target_name": "_ZN10n_rGfa49jOC2Ev",
        "proposed_name": "v18_TImageAnimation_TImageAnimation_void",
        "source_metrics": (140, 35, 1),
        "target_metrics": (148, 37, 1),
        "source_call_count": 3,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TPalette_TPalette_void",
            "plt_operator_new_ulong__2",
        ),
        "required_target_calls": (
            "._ZN10NLT0HaSwmEC1Ev",
            "._Znwm",
        ),
        "source_basis": "image-animation construction",
    },
    {
        "original_ea": "0x11f898",
        "original_name": "TImageAnimation_TImageAnimation",
        "spectron_ea": "0x1223c8",
        "target_name": "_ZN10n_rGfa49jOD1Ev",
        "proposed_name": "v18_TImageAnimation_TImageAnimation",
        "source_metrics": (68, 17, 4),
        "target_metrics": (76, 19, 4),
        "source_call_count": 2,
        "target_call_count": 3,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            ".free",
            "plt_TPalette_TPalette",
        ),
        "required_target_calls": (
            "._ZN10NLT0HaSwmED2Ev",
            ".free",
        ),
        "source_basis": "complete image-animation destructor",
    },
    {
        "original_ea": "0x11f8dc",
        "original_name": "TImageAnimation_TImageAnimation__2",
        "spectron_ea": "0x122414",
        "target_name": "_ZN10n_rGfa49jOD0Ev",
        "proposed_name": "v18_TImageAnimation_TImageAnimation__2",
        "source_metrics": (32, 8, 2),
        "target_metrics": (32, 8, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TImageAnimation_TImageAnimation",),
        "required_target_calls": ("._ZN10n_rGfa49jOD1Ev",),
        "source_basis": "deleting image-animation destructor",
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
                raise ValueError("unexpected %s call count at %s" % (side, ea))
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
                "match_kind": "manual-image-html-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in image/html anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in image/html anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_image_html_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for HTML color initialization and image-animation lifecycle methods",
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
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable source roles while keeping the obfuscated target names and helper-wrapper changes in the evidence rows.",
            "The HTML initializer and image-animation constructor preserve their source roles. The target image-animation destructor pair also retains the optional buffer release and palette cleanup sequence.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
