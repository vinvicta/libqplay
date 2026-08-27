#!/usr/bin/env python3
"""Create reviewed anchors for panel construction and bitmap loading."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target oMhmIajzmW constructor keeps the source panel-interface base construction, window pointer assignment, and final vtable installation in the same local class cluster as the translated drawing methods.",
    "The target bitmap loader dispatches the same .png, .mng, .bmp, .dib, .gif, .jpg, .jpeg, and .tga extensions to the corresponding decoders. Spectron adds a logged GIF retry path, which is recorded as a target-version behavior difference.",
    "The target force-redownload helper preserves the source resource-client removal, download-ignore, and fresh-download sequence through the obfuscated w6qzgacqqy and uq9xgaUxlx wrappers.",
    "The target find-image-file helper preserves the source empty-name guard, level-resource lookup, extension probing, fallback download, can-load check, and resource update path. Its larger call set reflects rebuilt string and resource wrappers.",
    "The source and target rows are not already present in the semantic translation map. They are recorded as manual context anchors for the exact hashed Spectron library.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x103fcc",
        "original_name": "TPanelInterface_TPanelInterface_TWindow_TString_const",
        "spectron_ea": "0x106634",
        "target_name": "_ZN10oMhmIajzmWC2EP10LJyzga9PwyRK10C8THgaTQxF",
        "proposed_name": "v18_TPanelInterface_TPanelInterface_TWindow_TString_const",
        "source_metrics": (64, 16, 1),
        "target_metrics": (96, 24, 1),
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
        "source_basis": "panel-interface window-backed construction",
    },
    {
        "original_ea": "0x114be8",
        "original_name": "TBitmap_loadBitmap_TStream_TString_const",
        "spectron_ea": "0x1174b8",
        "target_name": "_ZN10Fcx_gaoydV10qrcBEaM4ULEP10nenvgaH9_uRK10C8THgaTQxF",
        "proposed_name": "v18_TBitmap_loadBitmap_TStream_TString_const",
        "source_metrics": (352, 88, 19),
        "target_metrics": (504, 125, 15),
        "source_call_count": 8,
        "target_call_count": 20,
        "source_string_refs": (".bmp", ".dib", ".gif", ".jpeg", ".jpg", ".mng", ".png", ".tga"),
        "target_string_refs": (".bmp", ".dib", ".gif", ".jpeg", ".jpg", ".mng", ".png", ".tga", "PROBLEM reading gif="),
        "required_source_calls": ("plt_operator_assign_TString_const_char_const",),
        "required_target_calls": (
            "._ZN10Fcx_gaoydV10lvwvCaYX7_EP10nenvgaH9_u",
            "._ZN10Fcx_gaoydV10qtm_Kamw48EP10nenvgaH9_u",
            "._ZN10Fcx_gaoydV10rQbvCaJzR_EP10nenvgaH9_ub",
            "._ZN10Fcx_gaoydV10xWJuCaYft_EP10nenvgaH9_u",
            "._ZN10Fcx_gaoydV10ABozCaljo3EP10nenvgaH9_u",
        ),
        "source_basis": "bitmap extension dispatch and decoder selection",
    },
    {
        "original_ea": "0x114f80",
        "original_name": "TBitmapLoader_forceRedownload_TResourceObject",
        "spectron_ea": "0x1178e8",
        "target_name": "_ZN10kM00HafgtE10uvNyZa6fToEP10bNZvga2Awv",
        "proposed_name": "v18_TBitmapLoader_forceRedownload_TResourceObject",
        "source_metrics": (60, 15, 4),
        "target_metrics": (160, 40, 4),
        "source_call_count": 2,
        "target_call_count": 9,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TClient_removeRequestedFile_TString_const",
            "plt_TFileDownload_ignore_TString_const",
        ),
        "required_target_calls": (
            "._ZN10w6qzgacqqy10HLi4xaSoehERK10C8THgaTQxF",
            "._ZN10uq9xgaUxlx6ignoreERK10C8THgaTQxF",
            "._ZN10uq9xgaUxlx10zO9xgagSlxERK10C8THgaTQxF",
        ),
        "source_basis": "bitmap resource force-redownload sequence",
    },
    {
        "original_ea": "0x114fbc",
        "original_name": "TBitmapLoader_findImageFile_TString_const",
        "spectron_ea": "0x117988",
        "target_name": "_ZN10kM00HafgtE10VlZyZade2oERK10C8THgaTQxF",
        "proposed_name": "v18_TBitmapLoader_findImageFile_TString_const",
        "source_metrics": (364, 90, 19),
        "target_metrics": (392, 97, 19),
        "source_call_count": 15,
        "target_call_count": 17,
        "source_string_refs": ("0",),
        "target_string_refs": ("0",),
        "required_source_calls": (
            "plt_TResourceFunctions_getLevelFileResource_TString_const",
            "plt_TFiles_extractFileExt_TString_const",
            "plt_TFileDownload_download_TString_const",
            "plt_TResourceObject_canBeLoaded_void",
            "plt_TFileDownload_update_TString_const",
        ),
        "required_target_calls": (
            "._ZN10f6WHgaQkAF10twbzgaWidyERK10C8THgaTQxF",
            "._ZN10wiULgacZUI10Rr3vga6vAvERK10C8THgaTQxF",
            "._ZN10uq9xgaUxlx10zO9xgagSlxERK10C8THgaTQxF",
            "._ZN10bNZvga2Awv10rGpygapdzxEv",
            "._ZN10uq9xgaUxlx10mP6ygaUl9xERK10C8THgaTQxF",
        ),
        "source_basis": "bitmap resource lookup and extension fallback",
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
                "match_kind": "manual-panel-bitmap-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in panel/bitmap anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in panel/bitmap anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_panel_bitmap_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for panel-interface construction and bitmap loading helpers",
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
            "The proposed v18_ labels preserve readable source roles while keeping the obfuscated target names and wrapper differences in the evidence rows.",
            "Panel construction and bitmap extension dispatch retain their original roles. Spectron's logged GIF retry is documented as a target-version difference rather than hidden.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
