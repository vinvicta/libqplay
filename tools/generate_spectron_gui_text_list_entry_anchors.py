#!/usr/bin/env python3
"""Create reviewed anchors for the small GuiTextListEntry property helpers.

These functions are below the broad semantic-matcher cutoff.  The source and
target pseudocode is identical, and the property-table references preserve
the getter and setter roles in the stripped Spectron build.
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
        "original_ea": "0x1dc84c",
        "original_name": "GuiTextListEntry_get_flickertime",
        "spectron_ea": "0x1e05e8",
        "target_name": "sub_1E05E8",
        "source_context": ["0x383150"],
        "spectron_context": ["0x3961b0"],
        "role": "GuiTextListEntry flickertime getter",
        "behavior": "return whether the float at receiver offset +144 is nonzero",
    },
    {
        "original_ea": "0x1dc85c",
        "original_name": "GuiTextListEntry_set_flickertime",
        "spectron_ea": "0x1e05f8",
        "target_name": "sub_1E05F8",
        "source_context": ["0x383158"],
        "spectron_context": ["0x3961b8"],
        "role": "GuiTextListEntry flickertime setter",
        "behavior": "convert the byte argument to float and store it at receiver offset +144",
    },
    {
        "original_ea": "0x1dc894",
        "original_name": "GuiTextListEntry_get_profile",
        "spectron_ea": "0x1e0630",
        "target_name": "sub_1E0630",
        "source_context": ["0x383270"],
        "spectron_context": ["0x3962d0"],
        "role": "GuiTextListEntry profile fallback getter",
        "behavior": "return the profile override at +208 when present, otherwise the base profile at +200",
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
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
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
        if source_ea in semantic_sources or source_ea in previous_sources:
            raise ValueError("source is already represented at 0x%x" % source_ea)
        if target_ea in semantic_targets or target_ea in seen_targets:
            raise ValueError("target is already represented at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string reference at 0x%x" % source_ea)
        if source.get("direct_call_names", []) or target.get("direct_call_names", []):
            raise ValueError("unexpected direct call at 0x%x" % source_ea)

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differing = [
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        ]
        if differing:
            raise ValueError(
                "feature mismatch at 0x%x: %s"
                % (source_ea, ", ".join(differing))
            )

        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_context": spec["source_context"],
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_context": spec["spectron_context"],
                "source_component": "GuiTextListEntry",
                "target_component": "Spectron GuiTextListEntry property cluster",
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-gui-text-list-entry-exact-property-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "behavior": spec["behavior"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "metric_differences": [],
                "evidence": [
                    "The source and target Hex-Rays pseudocode bodies are identical, including all receiver offsets and return behavior.",
                    "The source reference at %s and target reference at %s occupy the corresponding property-table callback slots." % (spec["source_context"][0], spec["spectron_context"][0]),
                    "The target function was an ordinary IDA sub_ name, so the readable alias restores the source property role in the analysis overlay." if target.get("is_default_name", False) else "The target retained an ABI name, and the readable alias records the source property role in the analysis overlay.",
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_text_list_entry_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the small GuiTextListEntry flickertime and profile property helpers",
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
            "source_class": "GuiTextListEntry",
            "target_class_cluster": "Spectron GuiTextListEntry property callback cluster",
            "resolution": "identical pseudocode, matching property-table slots, receiver-field behavior, and complete normalized ARM64 features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "All three rows match every recorded feature and have no literal string references or direct calls.",
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
