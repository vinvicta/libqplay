#!/usr/bin/env python3
"""Create reviewed anchors for the Java sound base-interface methods.

The source TSoundPlayer interface and the two small Java capability groups
are preserved as contiguous target method-table blocks. Every row in this
block has an exact complete ARM64 feature match, and the class-local table
order confirms which repeated stub implements each source role.
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


ANCHOR_SPECS = [
    {
        "original_ea": "0xe3544",
        "original_name": "TSoundPlayer_canPlayMusic_void",
        "spectron_ea": "0xe410c",
        "target_name": "_ZN10gqiNgaG64J10jfRMgatpIJEv",
        "source_table_ea": "0x35ed00",
        "spectron_table_ea": "0x371a80",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player can-play-music predicate",
    },
    {
        "original_ea": "0xe354c",
        "original_name": "TSoundPlayer_playMusic_TString_const_bool_int",
        "spectron_ea": "0xe4114",
        "target_name": "_ZN10gqiNgaG64J10IWJMga2fCJERK10C8THgaTQxFbi",
        "source_table_ea": "0x35ed08",
        "spectron_table_ea": "0x371a88",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player play-music hook",
    },
    {
        "original_ea": "0xe3550",
        "original_name": "TSoundPlayer_updateMusic_void",
        "spectron_ea": "0xe4118",
        "target_name": "_ZN10gqiNgaG64J10EEuMgaWopJEv",
        "source_table_ea": "0x35ed10",
        "spectron_table_ea": "0x371a90",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player music-update hook",
    },
    {
        "original_ea": "0xe3554",
        "original_name": "TSoundPlayer_isMusicPlaying_void",
        "spectron_ea": "0xe411c",
        "target_name": "_ZN10gqiNgaG64J10fXZMgaqJPJEv",
        "source_table_ea": "0x35ed18",
        "spectron_table_ea": "0x371a98",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player playing predicate",
    },
    {
        "original_ea": "0xe355c",
        "original_name": "TSoundPlayer_stopMusic_void",
        "spectron_ea": "0xe4124",
        "target_name": "_ZN10gqiNgaG64J10wNLMganPDJEv",
        "source_table_ea": "0x35ed20",
        "spectron_table_ea": "0x371aa0",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player stop-music hook",
    },
    {
        "original_ea": "0xe3560",
        "original_name": "TSoundPlayer_stopMidi_void",
        "spectron_ea": "0xe4128",
        "target_name": "_ZN10gqiNgaG64J10xcTMgag3JJEv",
        "source_table_ea": "0x35ed28",
        "spectron_table_ea": "0x371aa8",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player stop-MIDI hook",
    },
    {
        "original_ea": "0xe3564",
        "original_name": "TSoundPlayer_getMusicPosition_void",
        "spectron_ea": "0xe412c",
        "target_name": "_ZN10gqiNgaG64J10uUwHEa8heREv",
        "source_table_ea": "0x35ed30",
        "spectron_table_ea": "0x371ab0",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player music-position getter",
    },
    {
        "original_ea": "0xe356c",
        "original_name": "TSoundPlayer_getMusicLength_void",
        "spectron_ea": "0xe4134",
        "target_name": "_ZN10gqiNgaG64J10CV8GEac7UQEv",
        "source_table_ea": "0x35ed38",
        "spectron_table_ea": "0x371ab8",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player music-length getter",
    },
    {
        "original_ea": "0xe3574",
        "original_name": "TSoundPlayer_setMusicVolume_int",
        "spectron_ea": "0xe413c",
        "target_name": "_ZN10gqiNgaG64J10hPTMgaJzKJEi",
        "source_table_ea": "0x35ed40",
        "spectron_table_ea": "0x371ac0",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player music-volume hook",
    },
    {
        "original_ea": "0xe3578",
        "original_name": "TSoundPlayer_setMusicVolumeAndPan_int_int",
        "spectron_ea": "0xe4140",
        "target_name": "_ZN10gqiNgaG64J10cqUMgaI4KJEii",
        "source_table_ea": "0x35ed48",
        "spectron_table_ea": "0x371ac8",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player music-volume-and-pan hook",
    },
    {
        "original_ea": "0xe357c",
        "original_name": "TSoundPlayer_setMidiVolume_int",
        "spectron_ea": "0xe4144",
        "target_name": "_ZN10gqiNgaG64J10Gg4GEaGcRQEi",
        "source_table_ea": "0x35ed50",
        "spectron_table_ea": "0x371ad0",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player MIDI-volume hook",
    },
    {
        "original_ea": "0xe3580",
        "original_name": "TSoundPlayer_canPlaySoundEffects_void",
        "spectron_ea": "0xe4148",
        "target_name": "_ZN10gqiNgaG64J10UtswgaQzVvEv",
        "source_table_ea": "0x35ed58",
        "spectron_table_ea": "0x371ad8",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player can-play-sound-effects predicate",
    },
    {
        "original_ea": "0xe3588",
        "original_name": "TSoundPlayer_createSoundEffect_TString_const",
        "spectron_ea": "0xe4150",
        "target_name": "_ZN10gqiNgaG64J10ngWMganDMJERK10C8THgaTQxF",
        "source_table_ea": "0x35ed60",
        "spectron_table_ea": "0x371ae0",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player sound-effect factory hook",
    },
    {
        "original_ea": "0xe3590",
        "original_name": "TSoundPlayer_set3DPosition_T3DFloatPoint_const_T3DFloatPoint_const_T3DFloatPoint_const_T3DFloatPoint_const",
        "spectron_ea": "0xe4158",
        "target_name": "_ZN10gqiNgaG64J10nQlWHaFZHzERK10V6P7faBscbS2_S2_S2_",
        "source_table_ea": "0x35ed68",
        "spectron_table_ea": "0x371ae8",
        "source_class": "TSoundPlayer",
        "target_class": "gqiNgaG64J",
        "role": "base sound-player 3D-position hook",
    },
    {
        "original_ea": "0xe3594",
        "original_name": "TSoundEffectJava_isLoaded_void",
        "spectron_ea": "0xe415c",
        "target_name": "_ZN10QPh5pbnC3y10tDfwgaPLKvEv",
        "source_table_ea": "0x35ee50",
        "spectron_table_ea": "0x371bd0",
        "source_class": "TSoundEffectJava",
        "target_class": "QPh5pbnC3y",
        "role": "Java sound-effect loaded predicate",
    },
    {
        "original_ea": "0xe359c",
        "original_name": "TSoundEffectJava_hasChannel_void",
        "spectron_ea": "0xe4164",
        "target_name": "_ZN10QPh5pbnC3y10pTqwgajeUvEv",
        "source_table_ea": "0x35ee60",
        "spectron_table_ea": "0x371be0",
        "source_class": "TSoundEffectJava",
        "target_class": "QPh5pbnC3y",
        "role": "Java sound-effect channel predicate",
    },
    {
        "original_ea": "0xe35a4",
        "original_name": "TSoundPlayerJava_canPlayMusic_void",
        "spectron_ea": "0xe416c",
        "target_name": "_ZN10ohGYZakbFK10jfRMgatpIJEv",
        "source_table_ea": "0x35eda0",
        "spectron_table_ea": "0x371b20",
        "source_class": "TSoundPlayerJava",
        "target_class": "ohGYZakbFK",
        "role": "Java sound-player can-play-music predicate",
    },
    {
        "original_ea": "0xe35ac",
        "original_name": "TSoundPlayerJava_canPlaySoundEffects_void",
        "spectron_ea": "0xe4174",
        "target_name": "_ZN10ohGYZakbFK10UtswgaQzVvEv",
        "source_table_ea": "0x35edf8",
        "spectron_table_ea": "0x371b78",
        "source_class": "TSoundPlayerJava",
        "target_class": "ohGYZakbFK",
        "role": "Java sound-player can-play-sound-effects predicate",
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
    return {field: function.get(field) for field in METRIC_FIELDS}


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
    seen_targets: set[int] = set()
    for spec in ANCHOR_SPECS:
        source_ea = int(spec["original_ea"], 16)
        target_ea = int(spec["spectron_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target row at 0x%x" % source_ea)
        if source.get("name") != spec["original_name"]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != spec["target_name"]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("sound base-interface method is already in the semantic map")
        if source_ea in previous_sources:
            raise ValueError("sound base-interface method is already manually anchored")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string references")
        if source.get("direct_call_names", []) or target.get("direct_call_names", []):
            raise ValueError("unexpected direct calls")
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        if source_metrics != target_metrics:
            raise ValueError("feature mismatch at 0x%x" % source_ea)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_method_table_ea": spec["source_table_ea"],
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_method_table_ea": spec["spectron_table_ea"],
                "source_class": spec["source_class"],
                "target_class": spec["target_class"],
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-sound-base-interface-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "source_component": spec["source_class"],
                "target_component": spec["target_class"] + " sound interface",
                "metric_differences": [],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": [
                    "The source method-table record at %s identifies the reviewed %s slot." % (spec["source_table_ea"], spec["source_class"]),
                    "The target method-table record at %s identifies the corresponding %s slot." % (spec["spectron_table_ea"], spec["target_class"]),
                    "The source and target pseudocode implement the same %s behavior." % spec["role"],
                    "All recorded ARM64 features match exactly, including register detail, and neither method has literal strings or direct calls.",
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_sound_base_interface_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TSoundPlayer base interface and Java sound capability methods",
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
            "exact_shape_anchor_count": len(anchors),
            "full_metric_exact_count": len(anchors),
            "layout_change_anchor_count": 0,
            "source_default_name_count": sum(
                row["original_name"].startswith("sub_") for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "context": {
            "source_class_cluster": "TSoundPlayer, TSoundEffectJava, and TSoundPlayerJava",
            "target_class_cluster": "gqiNgaG64J, QPh5pbnC3y, and ohGYZakbFK",
            "resolution": "complete normalized ARM64 features, contiguous class-local method-table order, and matching decompiled stub behavior",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The 14 TSoundPlayer rows form one ordered base-interface block. The QPh5pbnC3y and ohGYZakbFK rows preserve the Java capability predicates in their corresponding class-local tables.",
            "The v18_ aliases are scoped to the exact hashed Spectron library in the inputs and are an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
