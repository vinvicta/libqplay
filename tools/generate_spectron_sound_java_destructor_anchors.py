#!/usr/bin/env python3
"""Create reviewed anchors for the Java sound deleting destructors.

The source names are constructor-shaped because of the original IDA naming
convention. Their bodies call the complete destructor and then operator
delete. Spectron keeps the corresponding D0 ABI wrappers in the QPh5pbnC3y
and ohGYZakbFK class-local method-table regions.
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


ANCHOR_SPECS = [
    {
        "original_ea": "0xe2c14",
        "original_name": "TSoundEffectJava_TSoundEffectJava__2",
        "spectron_ea": "0xe3804",
        "target_name": "_ZN10QPh5pbnC3yD0Ev",
        "proposed_name": "v18_TSoundEffectJava_TSoundEffectJava__2",
        "source_table_ea": "0x35ee28",
        "spectron_table_ea": "0x371ba8",
        "source_class": "TSoundEffectJava",
        "target_class": "QPh5pbnC3y",
        "role": "TSoundEffectJava deleting destructor",
        "expected_metric_differences": set(),
    },
    {
        "original_ea": "0xe360c",
        "original_name": "TSoundPlayerJava_TSoundPlayerJava__2",
        "spectron_ea": "0xe4190",
        "target_name": "_ZN10ohGYZakbFKD0Ev",
        "proposed_name": "v18_TSoundPlayerJava_TSoundPlayerJava_2",
        "source_table_ea": "0x35ed88",
        "spectron_table_ea": "0x371b08",
        "source_class": "TSoundPlayerJava",
        "target_class": "ohGYZakbFK",
        "role": "TSoundPlayerJava deleting destructor",
        "expected_metric_differences": {"register_detail_hash"},
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
    semantic_by_source = {
        int(row["original_ea"], 16): row
        for row in semantic_document.get("matches", [])
    }
    semantic_by_target = {
        int(row["spectron_ea"], 16): row
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
        if source_ea in previous_sources:
            raise ValueError("sound Java destructor is already manually anchored")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)

        semantic_source = semantic_by_source.get(source_ea)
        semantic_target = semantic_by_target.get(target_ea)
        if semantic_source is not None or semantic_target is not None:
            if semantic_source is None or semantic_target is None:
                raise ValueError("incomplete semantic-map destructor row at 0x%x" % source_ea)
            if semantic_source is not semantic_target:
                raise ValueError("source and target semantic-map rows disagree at 0x%x" % source_ea)
            if semantic_source.get("confidence") != "medium":
                raise ValueError("expected the existing destructor row to be medium confidence")
            proposed_name = semantic_source["alias_name"]
            semantic_present = True
        else:
            proposed_name = spec["proposed_name"]
            semantic_present = False

        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string references")
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
        if any(source_metrics[field] != target_metrics[field] for field in SHAPE_FIELDS):
            raise ValueError("destructor shape mismatch at 0x%x" % source_ea)

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
                "lifecycle_role": "deleting destructor",
                "proposed_name": proposed_name,
                "confidence": "high",
                "match_kind": "manual-sound-java-destructor-context-anchor",
                "semantic_match_already_present": semantic_present,
                "semantic_target_original_ea": None
                if semantic_target is None
                else semantic_target["original_ea"],
                "semantic_target_original_name": None
                if semantic_target is None
                else semantic_target["original_name"],
                "source_basis": spec["role"],
                "source_component": spec["source_class"],
                "target_component": spec["target_class"] + " D0 destructor",
                "metric_differences": sorted(differing),
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": [
                    "The source method-table record at %s identifies the deleting-destructor slot for %s." % (spec["source_table_ea"], spec["source_class"]),
                    "The target method-table record at %s identifies the corresponding D0 slot in %s." % (spec["spectron_table_ea"], spec["target_class"]),
                    "Both pseudocode bodies call the complete destructor and then operator delete on the same object.",
                    "The source constructor-shaped __2 label is treated as a compiler-generated deleting destructor because the body and D0 target ABI make that lifecycle role explicit.",
                    "The source and target preserve the complete normalized shape; the one register-detail difference is recorded as a compiler allocation change." if differing else "All recorded ARM64 features match exactly, including register detail.",
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_sound_java_destructor_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TSoundPlayerJava and TSoundEffectJava deleting destructors",
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
            "already_in_semantic_map": sum(
                row["semantic_match_already_present"] for row in anchors
            ),
            "new_context_anchor_count": sum(
                not row["semantic_match_already_present"] for row in anchors
            ),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
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
            "source_class_cluster": "TSoundPlayerJava and TSoundEffectJava",
            "target_class_cluster": "ohGYZakbFK and QPh5pbnC3y",
            "resolution": "D0 destructor pseudocode, class-local method-table slots, complete normalized shape, and the existing medium-confidence semantic row for the sound-player destructor",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source __2 names are constructor-shaped IDA labels for deleting destructors. The target D0 ABI names and bodies make the lifecycle role explicit.",
            "The sound-player row upgrades an existing medium-confidence semantic candidate with explicit destructor and method-table evidence; the sound-effect row adds a new reviewed context anchor.",
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
