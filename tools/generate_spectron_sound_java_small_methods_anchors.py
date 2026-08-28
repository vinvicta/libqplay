#!/usr/bin/env python3
"""Create reviewed anchors for the small Java sound bridge methods.

The source TSoundPlayerJava and TSoundEffectJava methods have matching
contiguous method-table records in Spectron's stripped C++ classes. Their
complete recorded ARM64 features match, while the vtable receiver offsets and
class-local order identify the two short wrappers without relying on names.
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
        "original_ea": "0xe2b58",
        "original_name": "TSoundPlayerJava_stopMidi_void",
        "spectron_ea": "0xe3748",
        "target_name": "_ZN10ohGYZakbFK10xcTMgag3JJEv",
        "proposed_name": "v18_TSoundPlayerJava_stopMidi_void",
        "source_table_ea": "0x35edc8",
        "spectron_table_ea": "0x371b48",
        "source_class": "TSoundPlayerJava",
        "target_class": "ohGYZakbFK",
        "vtable_offset": 64,
        "role": "stop-MIDI sound-player dispatch",
    },
    {
        "original_ea": "0xe2b78",
        "original_name": "TSoundPlayerJava_setMusicVolumeAndPan_int_int",
        "spectron_ea": "0xe3768",
        "target_name": "_ZN10ohGYZakbFK10cqUMgaI4KJEii",
        "proposed_name": "v18_TSoundPlayerJava_setMusicVolumeAndPan_int_int",
        "source_table_ea": "0x35ede8",
        "spectron_table_ea": "0x371b68",
        "source_class": "TSoundPlayerJava",
        "target_class": "ohGYZakbFK",
        "vtable_offset": 96,
        "role": "set-music-volume-and-pan sound-player dispatch",
    },
    {
        "original_ea": "0xe2b98",
        "original_name": "TSoundEffectJava_freeResource_void",
        "spectron_ea": "0xe3788",
        "target_name": "_ZN10QPh5pbnC3y10AtwMgawWqJEv",
        "proposed_name": "v18_TSoundEffectJava_freeResource_void",
        "source_table_ea": "0x35ee40",
        "spectron_table_ea": "0x371bc0",
        "source_class": "TSoundEffectJava",
        "target_class": "QPh5pbnC3y",
        "vtable_offset": None,
        "role": "free-resource state reset",
    },
    {
        "original_ea": "0xe2ba0",
        "original_name": "TSoundEffectJava_load_void",
        "spectron_ea": "0xe3790",
        "target_name": "_ZN10QPh5pbnC3y4loadEv",
        "proposed_name": "v18_TSoundEffectJava_load_void",
        "source_table_ea": "0x35ee48",
        "spectron_table_ea": "0x371bc8",
        "source_class": "TSoundEffectJava",
        "target_class": "QPh5pbnC3y",
        "vtable_offset": None,
        "role": "load-resource no-op",
    },
    {
        "original_ea": "0xe2ba4",
        "original_name": "TSoundEffectJava_setVolume_int",
        "spectron_ea": "0xe3794",
        "target_name": "_ZN10QPh5pbnC3y10uosMgajvnJEi",
        "proposed_name": "v18_TSoundEffectJava_setVolume_int",
        "source_table_ea": "0x35ee70",
        "spectron_table_ea": "0x371bf0",
        "source_class": "TSoundEffectJava",
        "target_class": "QPh5pbnC3y",
        "vtable_offset": None,
        "role": "store sound-effect volume",
    },
    {
        "original_ea": "0xe2bac",
        "original_name": "TSoundEffectJava_setPan_int",
        "spectron_ea": "0xe379c",
        "target_name": "_ZN10QPh5pbnC3y10spDMga7LwJEi",
        "proposed_name": "v18_TSoundEffectJava_setPan_int",
        "source_table_ea": "0x35ee78",
        "spectron_table_ea": "0x371bf8",
        "source_class": "TSoundEffectJava",
        "target_class": "QPh5pbnC3y",
        "vtable_offset": None,
        "role": "store sound-effect pan",
    },
    {
        "original_ea": "0xe2bb4",
        "original_name": "TSoundEffectJava_stop_void",
        "spectron_ea": "0xe37a4",
        "target_name": "_ZN10QPh5pbnC3y10pOFMga6MyJEv",
        "proposed_name": "v18_TSoundEffectJava_stop_void",
        "source_table_ea": "0x35ee90",
        "spectron_table_ea": "0x371c10",
        "source_class": "TSoundEffectJava",
        "target_class": "QPh5pbnC3y",
        "vtable_offset": None,
        "role": "stop sound-effect state",
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
            raise ValueError("sound Java method is already in the semantic map")
        if source_ea in previous_sources:
            raise ValueError("sound Java method is already manually anchored")
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
                "vtable_offset": spec["vtable_offset"],
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-sound-java-small-method-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "source_component": spec["source_class"],
                "target_component": spec["target_class"] + " Java sound bridge",
                "metric_differences": [],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": [
                    "The source method-table record at %s identifies the reviewed %s slot." % (spec["source_table_ea"], spec["source_class"]),
                    "The target method-table record at %s is in the corresponding %s class block." % (spec["spectron_table_ea"], spec["target_class"]),
                    "The source and target pseudocode implement the same %s behavior." % spec["role"],
                    "All recorded ARM64 features match exactly, including register detail, and neither method has literal strings or direct calls.",
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_sound_java_small_methods_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TSoundPlayerJava and TSoundEffectJava small virtual methods",
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
            "source_class_cluster": "TSoundPlayerJava and TSoundEffectJava",
            "target_class_cluster": "ohGYZakbFK and QPh5pbnC3y",
            "resolution": "matching complete ARM64 features, receiver behavior, class-local order, and source/target method-table records",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The first two rows are sound-player dispatch wrappers. The remaining five rows are the compact TSoundEffectJava state methods in the matching QPh5pbnC3y method-table block.",
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
