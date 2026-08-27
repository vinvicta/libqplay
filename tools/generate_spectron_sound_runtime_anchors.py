#!/usr/bin/env python3
"""Create reviewed anchors for the residual Spectron sound runtime methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target sound manager method keeps the source extension classification, volume selection, download and cache path, music restart path, effect creation, and playback state machine.",
    "The target note helper keeps the same twelve-note table, two-character note parsing, octave conversion, semitone delta, and powf-based pitch calculation before calling the sound manager pitch method.",
    "The target Java playback method keeps the source rate limit, startSound([BII)V lookup, base-folder stripping, byte-array access and release, pan and volume calculation, playing flag, and timestamp update.",
    "Small size and call-count differences are recorded as 2.2 implementation changes. They are not treated as evidence against the role correspondences because the pseudocode preserves the same control-flow responsibilities.",
    "The source and target rows are not already present in the semantic translation map. They are recorded as manual context anchors for the exact hashed Spectron library.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0xe135c",
        "original_name": "TSounds_play_impl_TString_const_bool_bool_double_double",
        "spectron_ea": "0xe1f34",
        "target_name": "_ZN10IUKzgam4Gy10j5OZZa3ACLERK10C8THgaTQxFbbdd",
        "proposed_name": "v18_TSounds_play_impl_TString_const_bool_bool_double_double",
        "source_metrics": (1312, 328, 72),
        "target_metrics": (1328, 332, 72),
        "source_call_count": 42,
        "target_call_count": 44,
        "source_string_refs": (".mid", ".mp2 .mp3 .ogg .wma .asf"),
        "target_string_refs": (".mid", ".mp2 .mp3 .ogg .wma .asf"),
        "required_source_calls": (
            "plt_TFileDownload_download_TString_const",
            "plt_TFileDownload_update_TString_const",
            "plt_TFiles_extractFileExt_TString_const",
            "plt_TFiles_fileExists_TString_const",
            "plt_TFiles_hasAbsolutePath_TString_const",
            "plt_TFiles_lowerCaseFilename_TString_const",
            "plt_THashList_addObject_THashListObject",
            "plt_TSounds_getSoundEffect_TString_const",
            "plt_TSounds_initSounds_void",
            "plt_TSounds_stopMusic_void",
            "plt_TStringList_indexOf_TString_const",
            "plt_TString_clear_void",
            "plt_TString_indexOf_TString_const",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_operator_assign_TString_const_TString_const",
            "plt_operator_assign_TString_const_char_const",
            "plt_operator_ne_TString_const_char_const",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10IUKzgam4Gy10ZHZxfaHwcHEv",
            "._ZN10IUKzgam4Gy10adFVZaKh7HERK10C8THgaTQxF",
            "._ZN10IUKzgam4Gy10wNLMganPDJEv",
            "._ZN10KKhLga4xoI9addObjectEP10J7zOgaf09K",
            "._ZN10uq9xgaUxlx10mP6ygaUl9xERK10C8THgaTQxF",
            "._ZN10uq9xgaUxlx10zO9xgagSlxERK10C8THgaTQxF",
            "._ZN10wiULgacZUI10PhVLgaLOVIERK10C8THgaTQxF",
            "._ZN10wiULgacZUI10RUnvgavJ0uERK10C8THgaTQxF",
            "._ZN10wiULgacZUI10Rr3vga6vAvERK10C8THgaTQxF",
            "._ZN10wiULgacZUI10WIOygaAhUxERK10C8THgaTQxF",
            "._ZNK10C8THgaTQxF10JtTLgaLhUIERKS_",
            "._ZNK10vuuHgangcF10JtTLgaLhUIERK10C8THgaTQxF",
            "._ZeqRK10C8THgaTQxFPKc",
            "._ZeqRK10C8THgaTQxFS1_",
            "._ZneRK10C8THgaTQxFPKc",
        ),
        "source_basis": "sound extension classification, cache, and playback state machine",
    },
    {
        "original_ea": "0xe2858",
        "original_name": "TSounds_script_setSoundPitchByNote",
        "spectron_ea": "0xe3440",
        "target_name": "sub_E3440",
        "proposed_name": "v18_TSounds_script_setSoundPitchByNote",
        "source_metrics": (548, 135, 21),
        "target_metrics": (556, 137, 21),
        "source_call_count": 26,
        "target_call_count": 26,
        "source_string_refs": ("an,as,bn,cn,cs,dn,ds,en,fn,fs,gn,gs",),
        "target_string_refs": ("an,as,bn,cn,cs,dn,ds,en,fn,fs,gn,gs",),
        "required_source_calls": (
            ".__cxa_guard_acquire",
            ".__cxa_guard_release",
            ".atexit",
            ".powf",
            "plt_TSounds_setSoundPitch_TString_const_float",
            "plt_TStringList_TStringList_TString_const",
            "plt_TStringList_indexOf_TString_const",
            "plt_TString_clear_void",
            "plt_TString_operator_lshift_char_const",
            "plt_TString_subString_int",
            "plt_TString_subString_int_int",
            "plt_strtoint_TString_const",
        ),
        "required_target_calls": (
            ".__cxa_guard_acquire",
            ".__cxa_guard_release",
            ".atexit",
            ".powf",
            "._Z10Msu4gaSeoZRK10C8THgaTQxF",
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFlsEPKc",
            "._ZN10IUKzgam4Gy10wgG1Zawa1NERK10C8THgaTQxFf",
            "._ZN10vuuHgangcFC2ERK10C8THgaTQxFb",
            "._ZNK10C8THgaTQxF10QgaLgaQfiIEi",
            "._ZNK10C8THgaTQxF10QgaLgaQfiIEii",
            "._ZNK10vuuHgangcF10JtTLgaLhUIERK10C8THgaTQxF",
        ),
        "source_basis": "note-name parsing and sound pitch calculation",
    },
    {
        "original_ea": "0xe31d0",
        "original_name": "TSoundEffectJava_play_void",
        "spectron_ea": "0xe3dc0",
        "target_name": "_ZN10QPh5pbnC3y10dtoMgafckJEv",
        "proposed_name": "v18_TSoundEffectJava_play_void",
        "source_metrics": (720, 178, 20),
        "target_metrics": (676, 168, 19),
        "source_call_count": 12,
        "target_call_count": 9,
        "source_string_refs": ("([BII)V", "startSound", "steps"),
        "target_string_refs": ("([BII)V", "startSound"),
        "required_source_calls": (
            "plt_JNIEnv_CallStaticVoidMethod_jclass_jmethodID",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
            "plt_TString_operator_lshift_char_const",
            "plt_TString_starts_TString_const",
            "plt_TString_subString_int",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN7_JNIEnv20CallStaticVoidMethodEP7_jclassP10_jmethodIDz",
            "._ZNK10C8THgaTQxF10QgaLgaQfiIEi",
            "._ZNK10C8THgaTQxF10fEtHgarybFERKS_",
        ),
        "source_basis": "Java sound-effect playback and rate limiting",
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
                "match_kind": "manual-sound-runtime-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_sound_runtime_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual sound dispatch, pitch, and Java playback methods",
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
            "The proposed v18_ labels preserve readable source roles while keeping the obfuscated target names and the source-to-target size differences in the evidence rows.",
            "The base TSoundEffect constructor was reviewed but is intentionally not included because its stripped target constructor was not isolated with the same confidence.",
            "The target sound manager, note helper, and Java playback method preserve their source responsibilities with small 2.2 implementation differences.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
