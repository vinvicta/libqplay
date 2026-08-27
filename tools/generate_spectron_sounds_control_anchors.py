#!/usr/bin/env python3
"""Create reviewed anchors for the remaining short TSounds control wrappers.

The source set-music-volume callback is an exact feature match. The source
update-music method shares its compact shape with the already translated
stop-MIDI method, so its sound-player virtual slot and callback-table entry
are retained as the disambiguating evidence.
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
        "original_ea": "0xe1350",
        "original_name": "TSounds_setMusicVolume",
        "spectron_ea": "0xe1f28",
        "target_name": "sub_E1F28",
        "proposed_name": "v18_TSounds_setMusicVolume",
        "source_basis": "TSounds script set-music-volume callback",
        "source_callback_table_ea": "0x376240",
        "spectron_callback_table_ea": "0x389240",
        "expected_metric_differences": set(),
        "evidence": [
            "The source callback-table record at 0x376240 is the setmusicvolume entry and the wrapper forwards the two script doubles to TSounds::setMusicVolume.",
            "The Spectron callback-table record at 0x389240 forwards the same two doubles to IUKzgam4Gy::hPTMgaJzKJ.",
            "The source and target rows match every recorded feature, including register detail, which makes this an exact ARM64 feature anchor.",
        ],
    },
    {
        "original_ea": "0xe1888",
        "original_name": "TSounds_updateMusic_void",
        "spectron_ea": "0xe2470",
        "target_name": "_ZN10IUKzgam4Gy10EEuMgaWopJEv",
        "proposed_name": "v18_TSounds_updateMusic_void",
        "source_basis": "TSounds sound-player update callback",
        "source_callback_table_ea": "0x36e748",
        "spectron_callback_table_ea": "0x387060",
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The source body returns the sound-player global when it is absent and otherwise dispatches through the sound-player vtable at offset +48.",
            "The Spectron body has the same global, null fallback, and +48 virtual call on IUKzgam4Gy::soundplayer.",
            "The source callback-table reference at 0x36e748 and target reference at 0x387060 identify the corresponding update-music record.",
            "The target stop-MIDI anchor at 0xe1c34 uses a different +72 virtual slot, so the shared compact shape does not make the two roles interchangeable.",
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
            raise ValueError("sound control row is already in the semantic map")
        if source_ea in previous_sources:
            raise ValueError("sound control source is already manually anchored")
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
                "match_kind": "manual-sounds-control-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "source_component": "TSounds",
                "target_component": "IUKzgam4Gy sound runtime",
                "metric_differences": sorted(differing),
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_sounds_control_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TSounds volume and music-update control wrappers",
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
            "full_metric_exact_count": sum(
                not row["metric_differences"] for row in anchors
            ),
            "layout_change_anchor_count": 0,
            "source_default_name_count": sum(
                row["original_name"].startswith("sub_") for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"]
                for row in anchors
            ),
        },
        "context": {
            "source_class": "TSounds",
            "target_class_cluster": "IUKzgam4Gy",
            "resolution": "callback-table references, sound-player virtual slot, class-local order, and complete normalized ARM64 features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The set-music-volume wrapper is an exact feature match. The update-music wrapper shares its normalized shape with the separate stop-MIDI method, so the +48 virtual slot and callback-table reference are recorded as role evidence.",
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
