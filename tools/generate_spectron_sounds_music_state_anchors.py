#!/usr/bin/env python3
"""Create reviewed anchors for the core TSounds music-state wrappers.

The automatic matcher left these rows ambiguous because the target contains
other short boolean and float wrappers with the same normalized shape. This
artifact records the sound-player object, virtual-table slot, callback-table
reference, and IUKzgam4Gy class-local order that resolve the ambiguity.
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
        "original_ea": "0xe0af8",
        "original_name": "TSounds_isMusicPlaying",
        "spectron_ea": "0xe16a8",
        "target_name": "sub_E16A8",
        "proposed_name": "v18_TSounds_isMusicPlaying",
        "source_basis": "TSounds music-player boolean wrapper",
        "source_callback_table_ea": "0x376198",
        "spectron_callback_table_ea": "0x3891b0",
        "vtable_offset": 56,
        "vtable_role": "TSoundPlayerJava::isMusicPlaying",
        "candidate_spectron_eas": ["0xe16a8", "0x159304", "0x159d88"],
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The source body reads TSounds::soundplayer and dispatches through its vtable at offset +56, which resolves to TSoundPlayerJava::isMusicPlaying.",
            "The Spectron body reads IUKzgam4Gy::soundplayer and uses the same +56 virtual slot.",
            "The source callback-table reference at 0x376198 and target reference at 0x3891b0 are the matching ismusicplaying records in the two sound script tables.",
            "The other shape-compatible target rows at 0x159304 and 0x159d88 read main-window and weapons state, so they are not sound-player candidates.",
        ],
    },
    {
        "original_ea": "0xe0b3c",
        "original_name": "TSounds_getMusicPos_void",
        "spectron_ea": "0xe16ec",
        "target_name": "_ZN10IUKzgam4Gy10HTzYZaBOzKEv",
        "proposed_name": "v18_TSounds_getMusicPos_void",
        "source_basis": "TSounds music-position wrapper",
        "source_callback_table_ea": "0x376058",
        "spectron_callback_table_ea": "0x389058",
        "vtable_offset": 80,
        "vtable_role": "TSoundPlayerJava::getMusicPos",
        "candidate_spectron_eas": ["0xe16ec", "0xe172c"],
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The source body checks TSounds::soundplayer, returns -1.0 when it is absent, and dispatches through the sound-player vtable at offset +80.",
            "The Spectron body has the same null fallback and the same +80 virtual slot on IUKzgam4Gy::soundplayer.",
            "The source callback-table reference at 0x376058 and target reference at 0x389058 identify the matching music-position records.",
            "The adjacent target +88 wrapper is reserved for music length, so the two otherwise identical float wrappers are disambiguated by their virtual slot and callback-table record.",
        ],
    },
    {
        "original_ea": "0xe0b7c",
        "original_name": "TSounds_getMusicLen_void",
        "spectron_ea": "0xe172c",
        "target_name": "_ZN10IUKzgam4Gy10cR7XZakdcKEv",
        "proposed_name": "v18_TSounds_getMusicLen_void",
        "source_basis": "TSounds music-length wrapper",
        "source_callback_table_ea": "0x376088",
        "spectron_callback_table_ea": "0x389088",
        "vtable_offset": 88,
        "vtable_role": "TSoundPlayerJava::getMusicLen",
        "candidate_spectron_eas": ["0xe16ec", "0xe172c"],
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The source body checks TSounds::soundplayer, returns -1.0 when it is absent, and dispatches through the sound-player vtable at offset +88.",
            "The Spectron body has the same null fallback and the same +88 virtual slot on IUKzgam4Gy::soundplayer.",
            "The source callback-table reference at 0x376088 and target reference at 0x389088 identify the matching music-length records.",
            "The adjacent target +80 wrapper is reserved for music position, so the two otherwise identical float wrappers are disambiguated by their virtual slot and callback-table record.",
        ],
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
            raise ValueError("music wrapper is already in the semantic map")
        if source_ea in previous_sources:
            raise ValueError("music wrapper source is already manually anchored")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string references")
        if source.get("direct_call_names", []) or target.get("direct_call_names", []):
            raise ValueError("unexpected direct calls")
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differing = {
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        }
        if differing != spec["expected_metric_differences"]:
            raise ValueError(
                "unexpected metric differences at 0x%x: %s"
                % (source_ea, ", ".join(sorted(differing)))
            )
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_callback_table_ea": spec["source_callback_table_ea"],
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_callback_table_ea": spec["spectron_callback_table_ea"],
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-sounds-music-state-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "source_component": "TSounds",
                "target_component": "IUKzgam4Gy sound runtime",
                "vtable_offset": spec["vtable_offset"],
                "vtable_role": spec["vtable_role"],
                "candidate_spectron_eas": spec["candidate_spectron_eas"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
                "metric_differences": sorted(differing),
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_sounds_music_state_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TSounds music-player state wrappers",
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
            "layout_change_anchor_count": 0,
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"]
                for row in anchors
            ),
            "source_default_name_count": sum(
                row["original_name"].startswith("sub_") for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "ambiguous_source_count": len(anchors),
        },
        "context": {
            "source_class": "TSounds",
            "target_class_cluster": "IUKzgam4Gy",
            "source_callback_table": "0x376058..0x376198",
            "spectron_callback_table": "0x389058..0x3891b0",
            "resolution": "sound-player global, callback-table references, virtual-table offsets, matching null fallback, and class-local order",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The automatic matcher marked the source rows ambiguous because other target wrappers share the same normalized shape. Sound-player data flow and the exact virtual slots resolve the rows here.",
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
