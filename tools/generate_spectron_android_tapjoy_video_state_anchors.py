#!/usr/bin/env python3
"""Create reviewed anchors for the Android, TapJoy, and video state block.

The earlier source-role correction showed that the third 1.8 static callback
was not a TServerFlying cleanup. This follow-up pairs its reset and cleanup
callbacks with the corresponding Spectron Android runtime state, including
the target-only string that explains the layout change.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "register_detail_hash",
    "shape_hash",
    "string_refs_hash",
)

SOURCE_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SPECTRON_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"


PAIRS = [
    {
        "source_ea": 0xE0AD0,
        "target_ea": 0xE1640,
        "source_name": "sub_E0AD0",
        "target_name": "sub_E1640",
        "source_table_ea": "0x35d2a8",
        "target_table_ea": "0x36fc88",
        "proposed_name": "v18_MainAndroid_initializeStaticState",
        "source_basis": "MainAndroid TapJoy, video, and rectangle static-state initializer",
        "match_kind": "manual-mainandroid-static-state-layout-anchor",
        "source_direct_calls": [],
        "target_direct_calls": ["._ZN10CanTfaz6bZaSEPKc"],
        "source_cleanup": {
            "ea": "0xe06a8",
            "name": "Android_TapJoy_video_clearStaticStrings",
            "ida_name": "TServerFlying_clearStaticStrings",
            "table_ea": "0x35d2f8",
        },
        "target_cleanup": {
            "ea": "0xe0438",
            "name": "v18_Android_TapJoy_video_clearStaticStrings",
            "ida_name": "sub_E0438",
            "table_ea": "0x370060",
        },
        "expected_metric_differences": {
            "size",
            "instruction_count",
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
            "register_shape_hash",
            "register_detail_hash",
            "shape_hash",
        },
    },
    {
        "source_ea": 0xE06A8,
        "target_ea": 0xE0438,
        "source_name": "TServerFlying_clearStaticStrings",
        "target_name": "sub_E0438",
        "source_table_ea": "0x35d2f8",
        "target_table_ea": "0x370060",
        "proposed_name": "v18_Android_TapJoy_video_clearStaticStrings",
        "source_basis": "Android TapJoy and video static-string cleanup callback",
        "match_kind": "manual-android-tapjoy-video-cleanup-layout-anchor",
        "source_direct_calls": ["plt_TString_clear_void"],
        "target_direct_calls": ["._ZN10C8THgaTQxF5clearEv"],
        "source_cleanup": None,
        "target_cleanup": None,
        "expected_metric_differences": {
            "size",
            "instruction_count",
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
            "register_shape_hash",
            "register_detail_hash",
            "shape_hash",
        },
    },
]


STATE_FIELDS = [
    {
        "source_name": "qword_391210",
        "source_address": "0x391210",
        "target_name": "qword_3A58D8",
        "target_address": "0x3a58d8",
        "role": "TapJoy secret or first Android TString cache",
    },
    {
        "source_name": "qword_391218",
        "source_address": "0x391218",
        "target_name": "qword_3A58E0",
        "target_address": "0x3a58e0",
        "role": "TapJoy application-ID TString cache",
    },
    {
        "source_name": "qword_391238",
        "source_address": "0x391238",
        "target_name": "qword_3A5920",
        "target_address": "0x3a5920",
        "role": "video-player callback or state TString cache",
    },
    {
        "source_name": "dword_391228",
        "source_address": "0x391228",
        "target_name": "dword_3A5908",
        "target_address": "0x3a5908",
        "role": "cached video rectangle first coordinate",
    },
    {
        "source_name": "dword_39122C",
        "source_address": "0x39122c",
        "target_name": "dword_3A590C",
        "target_address": "0x3a590c",
        "role": "cached video rectangle second coordinate",
    },
    {
        "source_name": "dword_391230",
        "source_address": "0x391230",
        "target_name": "dword_3A5910",
        "target_address": "0x3a5910",
        "role": "cached video rectangle third coordinate",
    },
    {
        "source_name": "dword_391234",
        "source_address": "0x391234",
        "target_name": "dword_3A5914",
        "target_address": "0x3a5914",
        "role": "cached video rectangle fourth coordinate",
    },
]


EVIDENCE = [
    "The source reset callback sub_E0AD0 at 0xe0ad0 is referenced by source static-initializer table slot 0x35d2a8 and zeros the three Android string fields, four video-rectangle coordinates, and one video-state string field recorded in the field map.",
    "The source data-reference audit ties qword_391210 and qword_391218 to MainAndroid TapJoy setters and JNI_connectToTapJoyService, qword_391238 to the video-open and video-event paths, and dword_391228 through dword_391234 to JNI_setVideoPlayerRectangle and the native render loop.",
    "The source cleanup callback at 0xe06a8 is registered by cleanup-table slot 0x35d2f8 and clears qword_391210, qword_391218, and qword_391238. Its old TServerFlying label was corrected because TServerFlying::animate at 0x23eeb0 has zero references to this group.",
    "The target reset callback sub_E1640 at 0xe1640 is referenced by target static-initializer table slot 0x36fc88. It zeros qword_3A5920, dword_3A5908 through dword_3A5914, qword_3A58E0, and qword_3A58D8, matching the source state group through the translated JNI and video consumers.",
    "The target cleanup callback sub_E0438 at 0xe0438 is referenced by target cleanup-table slot 0x370060 and clears qword_3A58D8, qword_3A58E0, qword_3A5920, and target-only qword_3A59C8. The cleanup order matches the source three-string order and adds one target string lifetime.",
    "The target reset callback initializes qword_3A59C8 through CanTfaz6bZ::operator=(const char *) before resetting the shared Android and video state. The target-only field is therefore independently confirmed by both initializer and cleanup, rather than inferred from proximity alone.",
    "The target dword_3A58D0 reference in sub_E1640 is an ADRL addressing base for the grouped fields, not an additional store performed by the callback. It is kept separate from the seven mapped state fields to avoid overstating the correspondence.",
    "The source reset row is 40 bytes and 10 instructions, while the target reset row is 76 bytes and 17 instructions. The source cleanup is 48 bytes and 11 instructions, while the target cleanup is 56 bytes and 13 instructions. Both pairs retain one basic block count and one return-count shape where applicable, with the target additions represented as layout changes.",
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
    return {field: function.get(field) for field in METRIC_FIELDS}


def delta_text(target_ea: int, source_ea: int) -> str:
    delta = target_ea - source_ea
    sign = "+" if delta >= 0 else "-"
    return "%s0x%x" % (sign, abs(delta))


def existing_manual_sources(artifact_root: Path, output: Path) -> set[int]:
    result = set()
    for path in artifact_root.glob("spectron_*_manual_translation_anchors_*.json"):
        if path.resolve() == output.resolve():
            continue
        try:
            document = load(path)
        except (OSError, json.JSONDecodeError):
            continue
        for anchor in document.get("anchors", []):
            value = anchor.get("original_ea")
            if isinstance(value, str):
                try:
                    result.add(int(value, 16))
                except ValueError:
                    pass
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", default=SOURCE_BINARY_SHA256)
    parser.add_argument("--spectron-binary-sha256", default=SPECTRON_BINARY_SHA256)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_sources = {
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    previous_sources = existing_manual_sources(args.artifact_root, args.output)
    anchors = []
    for pair in PAIRS:
        source_ea = pair["source_ea"]
        target_ea = pair["target_ea"]
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target row at 0x%x" % source_ea)
        if source.get("name") != pair["source_name"]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != pair["target_name"]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if target_ea in semantic_targets or source_ea in semantic_sources:
            raise ValueError("Android state pair is already in the semantic map")
        if source_ea in previous_sources:
            raise ValueError("Android state source is already manually anchored")
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string references")
        if source.get("direct_call_names", []) != pair["source_direct_calls"]:
            raise ValueError("unexpected source direct calls at 0x%x" % source_ea)
        if target.get("direct_call_names", []) != pair["target_direct_calls"]:
            raise ValueError("unexpected target direct calls at 0x%x" % target_ea)
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differences = {
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        }
        if differences != pair["expected_metric_differences"]:
            raise ValueError(
                "unexpected metric differences at 0x%x: %s"
                % (source_ea, ", ".join(sorted(differences)))
            )
        anchor = {
            "original_ea": source["ea"],
            "original_name": source["name"],
            "original_function_end": source.get("end_ea"),
            "original_metrics": source_metrics,
            "original_string_refs": source.get("string_refs", []),
            "original_direct_call_names": source.get("direct_call_names", []),
            "original_static_initializer_table_ea": pair["source_table_ea"],
            "spectron_ea": target["ea"],
            "spectron_function_end": target.get("end_ea"),
            "spectron_current_name": target["name"],
            "spectron_default_name": target.get("is_default_name", False),
            "spectron_metrics": target_metrics,
            "spectron_string_refs": target.get("string_refs", []),
            "spectron_direct_call_names": target.get("direct_call_names", []),
            "spectron_static_initializer_table_ea": pair["target_table_ea"],
            "proposed_name": pair["proposed_name"],
            "confidence": "high",
            "match_kind": pair["match_kind"],
            "semantic_match_already_present": False,
            "source_basis": pair["source_basis"],
            "context_group": "Android TapJoy, video, and JNI runtime state",
            "target_component": "Android and JNI runtime state",
            "source_cleanup": pair["source_cleanup"],
            "spectron_cleanup": pair["target_cleanup"],
            "state_field_map": STATE_FIELDS,
            "target_only_field": {
                "name": "qword_3A59C8",
                "address": "0x3a59c8",
                "type": "CanTfaz6bZ",
                "role": "additional target Android/video string initialized by sub_E1640 and cleared by sub_E0438",
            },
            "target_addressing_base": {
                "name": "dword_3A58D0",
                "address": "0x3a58d0",
                "role": "ADRL base used to address the grouped target fields; sub_E1640 does not store it",
            },
            "metric_differences": sorted(differences),
            "target_delta": delta_text(target_ea, source_ea),
            "evidence": EVIDENCE,
            "name_action": "rename-with-reviewed-role",
            "shape_equal": False,
        }
        anchors.append(anchor)

    result = {
        "schema_version": 1,
        "artifact": "spectron_android_tapjoy_video_state_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the Android TapJoy/video state reset and cleanup callbacks",
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
            "exact_shape_anchor_count": 0,
            "layout_change_anchor_count": len(anchors),
            "source_default_name_count": 1,
            "target_default_name_count": len(anchors),
            "state_field_count": len(STATE_FIELDS),
        },
        "context": {
            "source_component": "MainAndroid and Android TapJoy/video state",
            "target_component": "Android and JNI runtime state",
            "source_static_initializer_table": "0x35d2a8",
            "spectron_static_initializer_table": "0x36fc88",
            "source_cleanup_table": "0x35d2f8",
            "spectron_cleanup_table": "0x370060",
            "source_role_correction_artifact": "artifacts/spectron_static_callback_role_correction_20260827.json",
            "resolution": "matching TapJoy consumers, video-event consumers, rectangle fields, callback-table slots, cleanup order, and target-only string lifetime",
        },
        "anchors": anchors,
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The source third static callback was previously mislabeled as TServerFlying cleanup. Data references disprove that class role, and this artifact now resolves the corrected Android TapJoy/video state block in Spectron.",
            "The reset and cleanup callbacks are recorded together because the cleanup order independently confirms the three shared string mappings.",
            "The target adds qword_3A59C8 as a CanTfaz6bZ string. Its initializer and cleanup are both visible, so the additional body operations are recorded as a layout change.",
            "The v18_ aliases describe the recovered roles while the evidence retains the feature names, field map, callback-table slots, target-only field, and metric differences.",
            "The aliases are valid only for the exact hashed Spectron library recorded in this artifact. They change the IDA analysis copy only; no APK or native library is modified.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
