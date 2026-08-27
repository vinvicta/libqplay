#!/usr/bin/env python3
"""Create a reviewed anchor for the changed Spectron GIF decoder."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target Fcx_gaoydV GIF reader is called by the reviewed bitmap extension dispatcher and remains in the same bitmap implementation class as the translated PNG, BMP, JPEG, and TGA readers.",
    "Both readers open a GIF stream, walk image and extension records, build a palette for each image, copy indexed pixels into animation steps, and finalize by allocating the first bitmap and copying the first animation step.",
    "The target keeps the Graphic Control Extension transparency and delay decoding, palette color conversion, row-order handling, animation-step allocation, and list insertion from the source body.",
    "Spectron adds an explicit retry-mode flag, GifErrorString diagnostics, and success logging. These extra branches explain the larger target body and are recorded as 2.2 behavior differences.",
    "The source and target rows are not already present in the semantic translation map. The label is a manual context anchor for the exact hashed Spectron library.",
]


ANCHOR_SPEC = {
    "original_ea": "0x150a38",
    "original_name": "TBitmap_readGIF_TStream",
    "spectron_ea": "0x153578",
    "target_name": "_ZN10Fcx_gaoydV10rQbvCaJzR_EP10nenvgaH9_ub",
    "proposed_name": "v18_TBitmap_readGIF_TStream",
    "source_metrics": (1096, 274, 50),
    "target_metrics": (1840, 457, 66),
    "source_call_count": 27,
    "target_call_count": 67,
    "source_string_refs": (),
    "target_string_refs": (
        "0gif error=",
        "1gif error=",
        "2gif error=",
        "3gif error=",
        "4gif error=",
        "5gif error=",
        "9gif error=",
        "gif seems OKAY ! aniSteps->count=",
    ),
    "required_source_calls": (
        ".DGifOpen",
        ".DGifGetRecordType",
        ".DGifGetImageDesc",
        ".DGifGetLine",
        ".DGifGetExtension",
        ".DGifGetExtensionNext",
        ".DGifCloseFile",
        "plt_TBitmap_AnimationStep_TBitmap_AnimationStep_int_int_int_int_int_int_int_TPalette",
        "plt_TList_Add_void",
        "plt_TBitmap_allocateBitmap_uint_uint_bool_TBitmap_BitmapFormat",
        "plt_TBitmap_copyFirstAnimationStep_void",
    ),
    "required_target_calls": (
        ".DGifOpen",
        ".DGifGetRecordType",
        ".DGifGetImageDesc",
        ".DGifGetLine",
        ".DGifGetExtension",
        ".DGifGetExtensionNext",
        ".DGifCloseFile",
        ".GifErrorString",
        "._ZN10UU64BayqVEC1EiiiiiiiP10NLT0HaSwmE",
        "._ZN10vy1JgaKVkH3AddEPv",
        "._ZN10Fcx_gaoydV10au69Ba236IEv",
        "._ZN10Fcx_gaoydV10uk8ZKaXCT8EjjbNS_10ke4ZKaKaQ8E",
    ),
    "source_basis": "GIF stream decoding and animation-step construction",
}


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

    source = original.get(int(ANCHOR_SPEC["original_ea"], 16))
    target = spectron.get(int(ANCHOR_SPEC["spectron_ea"], 16))
    if source is None or target is None:
        raise ValueError("missing GIF decoder feature")
    if source.get("name") != ANCHOR_SPEC["original_name"]:
        raise ValueError("original GIF decoder name mismatch")
    if target.get("name") != ANCHOR_SPEC["target_name"]:
        raise ValueError("target GIF decoder name mismatch")
    for side, function in (("source", source), ("target", target)):
        actual_metrics = (
            function.get("size"),
            function.get("instruction_count"),
            function.get("basic_block_count"),
        )
        expected_metrics = ANCHOR_SPEC["%s_metrics" % side]
        ea = ANCHOR_SPEC["original_ea" if side == "source" else "spectron_ea"]
        if actual_metrics != expected_metrics:
            raise ValueError("unexpected %s metrics at %s: %s" % (side, ea, actual_metrics))
        if function.get("call_count") != ANCHOR_SPEC["%s_call_count" % side]:
            raise ValueError("unexpected %s call count at %s" % (side, ea))
        expected_strings = list(ANCHOR_SPEC["%s_string_refs" % side])
        if function.get("string_refs", []) != expected_strings:
            raise ValueError(
                "unexpected %s string references at %s: %s"
                % (side, ea, function.get("string_refs", []))
            )
        for required_call in ANCHOR_SPEC["required_%s_calls" % side]:
            if required_call not in function.get("direct_call_names", []):
                raise ValueError("missing %s call %s at %s" % (side, required_call, ea))
    if int(ANCHOR_SPEC["spectron_ea"], 16) in semantic_targets:
        raise ValueError("target is already present in the semantic map")

    anchor = {
        "original_ea": ANCHOR_SPEC["original_ea"],
        "original_name": ANCHOR_SPEC["original_name"],
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": ANCHOR_SPEC["spectron_ea"],
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": ANCHOR_SPEC["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-gif-decoder-context-anchor",
        "semantic_match_already_present": False,
        "source_basis": ANCHOR_SPEC["source_basis"],
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_gif_decoder_manual_translation_anchor_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the changed GIF decoder",
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
            "anchor_count": 1,
            "high_confidence_count": 1,
            "already_in_semantic_map": 0,
            "new_context_anchor_count": 1,
            "target_default_name_count": int(target.get("is_default_name", False)),
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The address is valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ label preserves the readable source role while keeping the obfuscated target name and retry diagnostics in the evidence row.",
            "The decoder retains the source GIF parsing and animation construction flow. Spectron's retry-mode diagnostics are documented as target-version behavior.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
