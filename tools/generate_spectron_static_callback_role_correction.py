#!/usr/bin/env python3
"""Record the corrected role for the third 1.8 static callback.

The original review called 0xe06a8 ``TServerFlying_clearStaticStrings``.
Direct data-reference review shows that it clears the old Android TapJoy and
video state block instead.  This generator keeps the historical candidate
unchanged for reproducibility while recording the correction and the target
callbacks that were checked and rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_EA = 0xE06A8
TARGET_EAS = (0xE0220, 0xE0438)

SOURCE_GLOBALS = [
    {
        "ea": "0x391210",
        "role": "TapJoy secret or shared Android TString cache",
        "key_xref_functions": [
            "MainAndroid_script_settapjoysecret",
            "MainAndroid_script_settapjoyapplicationid",
            "JNI_connectToTapJoyService",
        ],
    },
    {
        "ea": "0x391218",
        "role": "TapJoy application-ID TString cache",
        "key_xref_functions": [
            "MainAndroid_script_settapjoyapplicationid",
            "JNI_connectToTapJoyService",
        ],
    },
    {
        "ea": "0x391238",
        "role": "video-player TString or state cache",
        "key_xref_functions": [
            "isVideoPlayerOpen_void",
            "Java_com_quattroplay_GraalClassic_Natives_onVideoLoaded",
            "Java_com_quattroplay_GraalClassic_Natives_onVideoFinished",
        ],
    },
]

TARGET_REJECTIONS = {
    0xE0220: {
        "data_refs": ["0x3a4d38", "0x3a4d40", "0x3a4d48", "0x3a4d50"],
        "role": "request and THTTPRequest static state cleanup",
        "key_xref_functions": [
            "THTTPRequest constructors",
            "THTTPRequest find-or-create helpers",
        ],
        "reason": "The cleared globals are used by request construction and lookup, not by the gId5RaV8_6 flying-object class.",
    },
    0xE0438: {
        "data_refs": ["0x3a58d0", "0x3a58d8", "0x3a58e0", "0x3a5920", "0x3a59c8"],
        "role": "video-player, Frida-detection, and input-related static state cleanup",
        "key_xref_functions": [
            "DetectFridaLoop1",
            "detect_frida_loop2",
            "JNI_setVideoPlayerRectangle",
            "openVideoPlayer_TString_const_TString_const",
            "Java_com_quattroplay_GraalClassic_Natives_QPlayMain",
            "Java_com_quattroplay_GraalClassic_Natives_QPlayLoop",
            "Java_com_quattroplay_GraalClassic_Natives_onVideoLoaded",
            "Java_com_quattroplay_GraalClassic_Natives_onVideoFinished",
        ],
        "reason": "The cleared globals are directly consumed by the target video and Android runtime paths, while target TServerFlying::animate uses a separate class-local object layout.",
    },
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
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
            "string_refs_hash",
        )
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--native-callback-candidates", required=True, type=Path)
    parser.add_argument("--symbol-overlay", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    candidates_document = load(args.native_callback_candidates)
    overlay_document = load(args.symbol_overlay)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])

    source = original.get(SOURCE_EA)
    if source is None:
        raise ValueError("missing source feature at 0x%x" % SOURCE_EA)
    if source.get("size") != 48 or source.get("instruction_count") != 11:
        raise ValueError("unexpected source metrics at 0x%x" % SOURCE_EA)
    if source.get("direct_call_names") != ["plt_TString_clear_void"]:
        raise ValueError("unexpected source calls at 0x%x" % SOURCE_EA)

    callback = next(
        (
            item
            for item in candidates_document.get("callbacks", [])
            if int(item["va"], 16) == SOURCE_EA
        ),
        None,
    )
    if callback is None:
        raise ValueError("the historical callback candidate is missing")
    if callback.get("proposed_name") != "TServerFlying_clearStaticStrings":
        raise ValueError("the historical callback role changed unexpectedly")
    if callback.get("confidence") != "high":
        raise ValueError("the historical callback confidence changed unexpectedly")

    target_rows = []
    for target_ea in TARGET_EAS:
        target = spectron.get(target_ea)
        if target is None:
            raise ValueError("missing target feature at 0x%x" % target_ea)
        if target.get("name") != "sub_%X" % target_ea:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if target.get("size") != 56 or target.get("instruction_count") != 13:
            raise ValueError("unexpected target metrics at 0x%x" % target_ea)
        target_rows.append(
            {
                "ea": "0x%x" % target_ea,
                "name": target["name"],
                "metrics": metrics(target),
                "data_refs": TARGET_REJECTIONS[target_ea]["data_refs"],
                "role": TARGET_REJECTIONS[target_ea]["role"],
                "key_xref_functions": TARGET_REJECTIONS[target_ea]["key_xref_functions"],
                "reason_rejected_as_TServerFlying": TARGET_REJECTIONS[target_ea]["reason"],
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_static_callback_role_correction_20260827",
        "scope": "correct the source role assigned to the third 1.8 static callback and preserve the unresolved 2.2 target mapping",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "native_callback_candidates": str(args.native_callback_candidates),
            "native_callback_candidates_sha256": sha256_path(args.native_callback_candidates),
            "symbol_overlay": str(args.symbol_overlay),
            "symbol_overlay_sha256": sha256_path(args.symbol_overlay),
        },
        "summary": {
            "source_claims_corrected": 1,
            "source_global_group_count": len(SOURCE_GLOBALS),
            "target_candidates_rejected": len(target_rows),
            "target_assignments": 0,
            "source_animate_forbidden_group_refs": 0,
        },
        "historical_candidate": {
            "source_ea": "0x%x" % SOURCE_EA,
            "candidate_current_ida_name": callback["current_ida_name"],
            "candidate_proposed_name": callback["proposed_name"],
            "candidate_confidence": callback["confidence"],
            "candidate_evidence": callback["evidence"],
            "status": "superseded_for_role_interpretation",
        },
        "corrected_source_role": {
            "source_ea": "0x%x" % SOURCE_EA,
            "source_feature_name_at_review": source["name"],
            "recommended_descriptive_name": "Android_TapJoy_video_clearStaticStrings",
            "confidence": "high",
            "kind": "descriptive component-level role, not an original ELF symbol",
            "status": "source_role_only_target_unresolved",
            "metrics": metrics(source),
            "direct_call_names": source.get("direct_call_names", []),
            "global_group": SOURCE_GLOBALS,
            "companion_reset_function": {
                "ea": "0xe0ad0",
                "name": "sub_E0AD0",
                "cleared_or_zeroed_fields": [
                    "0x391210",
                    "0x391218",
                    "0x391228",
                    "0x39122c",
                    "0x391230",
                    "0x391234",
                    "0x391238",
                ],
                "role": "same old Android TapJoy/video state block reset",
            },
        },
        "class_role_disproof": {
            "source_class": "TServerFlying",
            "source_animate": {
                "ea": "0x23eeb0",
                "name": "TServerFlying_animate_void",
                "forbidden_group_data_refs": [
                    "0x391210",
                    "0x391218",
                    "0x391238",
                ],
                "observed_forbidden_group_ref_count": 0,
                "observed_role_strings": [
                    "arrow",
                    "bomb.wav",
                    "arrowon.wav",
                ],
            },
            "source_properties_global": {
                "ea": "0x3911f8",
                "name": "TServerFlying_properties",
                "referencing_functions": [
                    "TServerFlying_TServerFlying_TServerLevel",
                    "TServerFlying_initStaticScriptVars_void",
                ],
            },
            "statement": "The old callback candidate's cleared globals are not referenced by TServerFlying::animate, while the class's known property global is a separate object at 0x3911f8.",
        },
        "target_review": {
            "target_class": "gId5RaV8_6",
            "constructor": "0x248dec",
            "animate": "0x248e38",
            "properties_constructor": "0x248d50",
            "properties_global": "0x3a58a0",
            "static_callback_table_entries_examined": [
                "0x36ff18 -> 0xe0128",
                "0x36ff58 -> 0xe0220",
                "0x36ff60 -> 0xe0258",
                "0x370060 -> 0xe0438",
            ],
            "rejected_candidates": target_rows,
            "target_tserverflying_static_clear": None,
            "target_assignment_status": "unresolved",
            "reason": "The target flying-object constructor, properties constructor, animate method, and destructor family do not expose a matching process-wide static TString cleanup group. The two nearby cleanup routines point to request and Android video state instead.",
        },
        "corrections": [
            {
                "old_source_ea": "0xe06a8",
                "old_source_role": "TServerFlying_clearStaticStrings",
                "old_evidence": "The body clears three adjacent TString objects used by TServerFlying::animate",
                "corrected_source_role": "Android_TapJoy_video_clearStaticStrings",
                "reason": "Direct data references and xrefs identify TapJoy credentials and video-player state; TServerFlying::animate has zero references to all three cleared globals.",
            }
        ],
        "interpretation": [
            "The historical candidate and overlay remain unchanged so the original review can be reproduced.",
            "This correction supersedes the old class-role interpretation for future IDA naming and target translation work.",
            "The recommended source name is descriptive and does not claim that an original source symbol survived.",
            "No Spectron target function is assigned by this correction artifact.",
            "The target E0220 and E0438 routines must not be renamed as TServerFlying cleanup until a matching target global group is found.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
