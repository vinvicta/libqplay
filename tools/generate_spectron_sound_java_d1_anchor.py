#!/usr/bin/env python3
"""Create the reviewed Java sound D1 destructor anchor.

The source constructor-shaped name is an IDA spelling for the complete
destructor.  Spectron exposes the same lifecycle wrapper as ohGYZakbFK D1,
immediately before the D0 deleting destructor already translated in v204.
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
SHAPE_FIELDS = tuple(field for field in METRIC_FIELDS if field != "register_detail_hash")

SOURCE_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SPECTRON_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"


ANCHOR = {
    "original_ea": "0xe35c8",
    "original_name": "TSoundPlayerJava_TSoundPlayerJava",
    "spectron_ea": "0xe417c",
    "target_name": "_ZN10ohGYZakbFKD1Ev",
    "proposed_name": "v18_TSoundPlayerJava_TSoundPlayerJava",
    "source_method_table_ea": "0x35ed80",
    "spectron_method_table_ea": "0x371b00",
    "source_class": "TSoundPlayerJava",
    "target_class": "ohGYZakbFK",
    "role": "TSoundPlayerJava complete D1 destructor",
    "expected_metric_differences": {"register_detail_hash"},
    "evidence": [
        "The source IDA name is constructor-shaped, but the decompiler's alternative ABI name is TSoundPlayerJava D1 and the body installs the class vtable and clears the embedded TString field without deleting the object.",
        "The target ohGYZakbFK D1 body performs the same complete-destructor work: it installs the target vtable and clears the C8THgaTQxF field at object offset +16 without calling operator delete.",
        "The target D1 wrapper at 0xe417c is immediately followed by the already translated ohGYZakbFK D0 wrapper at 0xe4190, matching the source D1 and D0 lifecycle pair at 0xe35c8 and 0xe360c.",
        "The source method-table reference at 0x35ed80 and target reference at 0x371b00 identify the corresponding D1 slot in the Java sound-player class.",
        "All normalized shape fields match. Only register_detail_hash differs, consistent with the rebuilt target's register allocation.",
    ],
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
    source_ea = int(ANCHOR["original_ea"], 16)
    target_ea = int(ANCHOR["spectron_ea"], 16)
    source = original.get(source_ea)
    target = spectron.get(target_ea)
    if source is None or target is None:
        raise ValueError("missing D1 source or target feature")
    if source.get("name") != ANCHOR["original_name"]:
        raise ValueError("unexpected D1 source name")
    if target.get("name") != ANCHOR["target_name"]:
        raise ValueError("unexpected D1 target name")
    if source_ea in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("sound Java D1 source is already manually anchored")
    semantic_by_source = {
        int(row["original_ea"], 16): row
        for row in semantic_document.get("matches", [])
    }
    semantic_by_target = {
        int(row["spectron_ea"], 16): row
        for row in semantic_document.get("matches", [])
    }
    if source_ea in semantic_by_source or target_ea in semantic_by_target:
        raise ValueError("sound Java D1 row is already in the semantic map")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected D1 literal string references")
    if source.get("direct_call_names", []) or target.get("direct_call_names", []):
        raise ValueError("unexpected D1 direct calls")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    differing = {
        field
        for field in METRIC_FIELDS
        if source_metrics[field] != target_metrics[field]
    }
    if differing != ANCHOR["expected_metric_differences"]:
        raise ValueError("unexpected D1 metric differences: %s" % sorted(differing))
    if any(source_metrics[field] != target_metrics[field] for field in SHAPE_FIELDS):
        raise ValueError("D1 shape mismatch")

    anchor = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "original_method_table_ea": ANCHOR["source_method_table_ea"],
        "spectron_ea": target["ea"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_method_table_ea": ANCHOR["spectron_method_table_ea"],
        "source_class": ANCHOR["source_class"],
        "target_class": ANCHOR["target_class"],
        "lifecycle_role": "complete D1 destructor",
        "proposed_name": ANCHOR["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-sound-java-d1-destructor-context-anchor",
        "semantic_match_already_present": False,
        "source_basis": ANCHOR["role"],
        "source_component": ANCHOR["source_class"],
        "target_component": ANCHOR["target_class"],
        "metric_differences": sorted(differing),
        "target_delta": "+0x%x" % (target_ea - source_ea),
        "evidence": ANCHOR["evidence"],
        "name_action": "rename-with-v18-prefix",
        "shape_equal": True,
    }

    result = {
        "schema_version": 1,
        "artifact": "spectron_sound_java_d1_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TSoundPlayerJava complete D1 destructor",
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
            "exact_shape_anchor_count": 1,
            "full_metric_exact_count": 0,
            "layout_change_anchor_count": 0,
            "source_default_name_count": 0,
            "target_default_name_count": int(target.get("is_default_name", False)),
            "register_detail_difference_count": 1,
        },
        "context": {
            "source_class": "TSoundPlayerJava",
            "target_class_cluster": "ohGYZakbFK",
            "resolution": "D1 ABI role, adjacent D0 destructor, Java sound class-local order, method-table slot, and complete normalized shape",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The constructor-shaped source label is retained in the readable alias because the body is the complete D1 destructor in the original IDA database.",
            "The v18_ alias is scoped to the exact hashed Spectron library in the inputs and is an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
