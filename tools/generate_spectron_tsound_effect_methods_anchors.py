#!/usr/bin/env python3
"""Create reviewed anchors for the TSoundEffect virtual method block.

The constructor and cache lookup identify Spectron's fEVMgax6LJ object as the
TSoundEffect implementation. Its seven small virtual methods then line up in
the same order as the source method table and match the complete feature set.
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
        "original_ea": "0xe2b24",
        "original_name": "TSoundEffect_hasChannel_void",
        "spectron_ea": "0xe3714",
        "target_name": "_ZN10fEVMgax6LJ10pTqwgajeUvEv",
        "proposed_name": "v18_TSoundEffect_hasChannel_void",
        "source_table_ea": "0x35ec60",
        "spectron_table_ea": "0x3719e0",
        "role": "has-channel state predicate",
    },
    {
        "original_ea": "0xe2b34",
        "original_name": "TSoundEffect_isPlaying_void",
        "spectron_ea": "0xe3724",
        "target_name": "_ZN10fEVMgax6LJ10my_MgaBeQJEv",
        "proposed_name": "v18_TSoundEffect_isPlaying_void",
        "source_table_ea": "0x35ec68",
        "spectron_table_ea": "0x3719e8",
        "role": "base sound-effect playing predicate",
    },
    {
        "original_ea": "0xe2b3c",
        "original_name": "TSoundEffect_setVolume_int",
        "spectron_ea": "0xe372c",
        "target_name": "_ZN10fEVMgax6LJ10uosMgajvnJEi",
        "proposed_name": "v18_TSoundEffect_setVolume_int",
        "source_table_ea": "0x35ec70",
        "spectron_table_ea": "0x3719f0",
        "role": "base sound-effect volume setter",
    },
    {
        "original_ea": "0xe2b40",
        "original_name": "TSoundEffect_setPan_int",
        "spectron_ea": "0xe3730",
        "target_name": "_ZN10fEVMgax6LJ10spDMga7LwJEi",
        "proposed_name": "v18_TSoundEffect_setPan_int",
        "source_table_ea": "0x35ec78",
        "spectron_table_ea": "0x3719f8",
        "role": "base sound-effect pan setter",
    },
    {
        "original_ea": "0xe2b44",
        "original_name": "TSoundEffect_setPitch_float",
        "spectron_ea": "0xe3734",
        "target_name": "_ZN10fEVMgax6LJ10ACEMgabNxJEf",
        "proposed_name": "v18_TSoundEffect_setPitch_float",
        "source_table_ea": "0x35ec80",
        "spectron_table_ea": "0x371a00",
        "role": "base sound-effect pitch setter",
    },
    {
        "original_ea": "0xe2b48",
        "original_name": "TSoundEffect_set3DPosition_T3DFloatPoint_const_T3DFloatPoint_const_int",
        "spectron_ea": "0xe3738",
        "target_name": "_ZN10fEVMgax6LJ10nQlWHaFZHzERK10V6P7faBscbS2_i",
        "proposed_name": "v18_TSoundEffect_set3DPosition_T3DFloatPoint_const_T3DFloatPoint_const_int",
        "source_table_ea": "0x35ec88",
        "spectron_table_ea": "0x371a08",
        "role": "base sound-effect 3D-position setter",
    },
    {
        "original_ea": "0xe2b4c",
        "original_name": "TSoundEffect_getLength_void",
        "spectron_ea": "0xe373c",
        "target_name": "_ZN10fEVMgax6LJ10ttTHEavhxREv",
        "proposed_name": "v18_TSoundEffect_getLength_void",
        "source_table_ea": "0x35ec98",
        "spectron_table_ea": "0x371a18",
        "role": "sound-effect length getter",
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
            raise ValueError("TSoundEffect method is already in the semantic map")
        if source_ea in previous_sources:
            raise ValueError("TSoundEffect method is already manually anchored")
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
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-tsoundeffect-virtual-method-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "source_component": "TSoundEffect",
                "target_component": "fEVMgax6LJ sound-effect object",
                "metric_differences": [],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": [
                    "The source method is referenced by its TSoundEffect method table at %s." % spec["source_table_ea"],
                    "The target method is referenced by the contiguous fEVMgax6LJ method table at %s." % spec["spectron_table_ea"],
                    "The source and target pseudocode implement the same %s behavior." % spec["role"],
                    "The constructor anchor at 0xe1970 and target method family establish fEVMgax6LJ as the Spectron TSoundEffect implementation.",
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tsound_effect_methods_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TSoundEffect virtual method block",
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
            "source_class": "TSoundEffect",
            "target_class_cluster": "fEVMgax6LJ",
            "source_method_table": "0x35ec60..0x35ec98",
            "spectron_method_table": "0x3719e0..0x371a18",
            "resolution": "constructor family, contiguous method-table order, matching pseudocode, and complete normalized ARM64 features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The seven rows form one contiguous virtual interface. Every recorded feature, including register detail, matches exactly.",
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
