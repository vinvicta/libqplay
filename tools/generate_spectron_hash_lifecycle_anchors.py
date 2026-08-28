#!/usr/bin/env python3
"""Create reviewed anchors for small Spectron hash-container lifecycle helpers.

These constructors, iterator helpers, and the hash-string value setter are
below the broad semantic-matcher cutoff.  The artifact records their target
class names, decompiled behavior, local context references, and normalized
ARM64 features without changing an IDA database.
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
        "original_ea": "0xea424",
        "original_name": "THashListObject_THashListObject_TString_const",
        "spectron_ea": "0xeb010",
        "target_name": "_ZN10J7zOgaf09KC2ERK10CanTfaz6bZ",
        "source_class": "THashListObject",
        "target_class": "J7zOgaf09K",
        "role": "THashListObject constructor from TString",
        "source_context": ["0x3713e8"],
        "spectron_context": ["0x386b08"],
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The source alternative ABI name is THashListObject C1, while the target name is the corresponding J7zOgaf09K C2 constructor with a C1 alternative name.",
            "Both install the object vtable, clear the embedded string wrapper at offset +8, and assign the incoming string into that field.",
            "The source and target constructor references are 0x3713e8 and 0x386b08, respectively.",
        ],
    },
    {
        "original_ea": "0xea440",
        "original_name": "THashListLink_THashListLink_THashListObject_uint",
        "spectron_ea": "0xeb02c",
        "target_name": "_ZN10U1slUah2F0C2EP10J7zOgaf09Kj",
        "source_class": "THashListLink",
        "target_class": "U1slUah2F0",
        "role": "THashListLink constructor",
        "source_context": ["0x36df88"],
        "spectron_context": ["0x386f70"],
        "expected_metric_differences": set(),
        "evidence": [
            "The source alternative ABI name is THashListLink C2 and the target name is the corresponding U1slUah2F0 C2 constructor.",
            "Both store the hash-list object pointer, the unsigned bucket index at offset +24, and clear the two link pointers at offsets +8 and +16.",
            "The source and target constructor references are 0x36df88 and 0x386f70, respectively.",
        ],
    },
    {
        "original_ea": "0xeada4",
        "original_name": "THashString_setValue_TString_const",
        "spectron_ea": "0xeb9f0",
        "target_name": "_ZN10NYF9TaOVKR10juVsfa5YWCERK10C8THgaTQxF",
        "source_class": "THashString",
        "target_class": "NYF9TaOVKR",
        "role": "THashString value setter",
        "source_context": ["0x372ee0"],
        "spectron_context": ["0x381e28"],
        "expected_metric_differences": set(),
        "evidence": [
            "Both are two-instruction value setters that assign the incoming string wrapper to the object field at offset +8.",
            "The target NYF9TaOVKR method name carries the same setter role in the surrounding yL3_IaDMFt hash-string cluster.",
            "The source and target setter references are 0x372ee0 and 0x381e28, respectively.",
        ],
    },
    {
        "original_ea": "0xeb6c0",
        "original_name": "THashListIterator_THashListIterator",
        "spectron_ea": "0xec3ec",
        "target_name": "_ZN10R_MvgaEQlvD1Ev",
        "source_class": "THashListIterator",
        "target_class": "R_MvgaEQlv",
        "role": "THashListIterator complete destructor",
        "source_context": ["0x36f9b8"],
        "spectron_context": ["0x384d70"],
        "expected_metric_differences": set(),
        "evidence": [
            "The source constructor-shaped label has the alternative ABI name THashListIterator D2, making the lifecycle role a complete destructor rather than a constructor.",
            "The target R_MvgaEQlv D1 body has the same null-owner guard and unregisters the iterator from its owning KKhLga4xoI list.",
            "The source and target destructor references are 0x36f9b8 and 0x384d70, respectively.",
        ],
    },
    {
        "original_ea": "0xeba5c",
        "original_name": "THashListIterator_THashListIterator_THashList",
        "spectron_ea": "0xec7f8",
        "target_name": "_ZN10R_MvgaEQlvC2EP10KKhLga4xoI",
        "source_class": "THashListIterator",
        "target_class": "R_MvgaEQlv",
        "role": "THashListIterator constructor from THashList",
        "source_context": ["0x3724f8"],
        "spectron_context": ["0x385400"],
        "expected_metric_differences": set(),
        "evidence": [
            "Both constructor bodies clear the iterator owner field and then call the class-local use method with the supplied hash list.",
            "The source alternative ABI name is THashListIterator C1 and the target name is the corresponding R_MvgaEQlv C2 constructor.",
            "The source and target constructor references are 0x3724f8 and 0x385400, respectively.",
        ],
    },
    {
        "original_ea": "0xebdb4",
        "original_name": "THashStringsIterator_use_THashStrings",
        "spectron_ea": "0xecb58",
        "target_name": "_ZN10Zb7cUaSFEU10q_90ua70AIEP10yL3_IaDMFt",
        "source_class": "THashStringsIterator",
        "target_class": "Zb7cUaSFEU",
        "role": "THashStringsIterator use container",
        "source_context": ["0x36e880"],
        "spectron_context": ["0x382568"],
        "expected_metric_differences": set(),
        "evidence": [
            "Both store the hash-string container pointer, clear the iterator link, initialize the bucket index to -1, and immediately find the next object.",
            "The target Zb7cUaSFEU method is the corresponding iterator helper for the yL3_IaDMFt hash-string container.",
            "The source and target iterator references are 0x36e880 and 0x382568, respectively.",
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
            raise ValueError("source is already manually anchored at 0x%x" % source_ea)
        if source_ea in semantic_by_source or target_ea in semantic_by_target:
            raise ValueError("source or target is already in the semantic map")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string reference at 0x%x" % source_ea)
        if source.get("direct_call_names", []) or target.get("direct_call_names", []):
            raise ValueError("unexpected direct call at 0x%x" % source_ea)

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
            raise ValueError("normalized shape mismatch at 0x%x" % source_ea)

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
                "source_class": spec["source_class"],
                "target_class": spec["target_class"],
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-hash-lifecycle-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "metric_differences": sorted(differing),
                "evidence": spec["evidence"]
                + [
                    "All normalized shape fields match. The one register-detail difference is recorded as a target register-allocation change."
                    if differing
                    else "All recorded ARM64 features match exactly, including register detail."
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_hash_lifecycle_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for small hash-container constructors, iterators, and value setters",
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
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(
                not row["metric_differences"] for row in anchors
            ),
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
        },
        "context": {
            "source_class_cluster": "THashListObject, THashListLink, THashString, THashListIterator, and THashStringsIterator",
            "target_class_cluster": "J7zOgaf09K, U1slUah2F0, NYF9TaOVKR, R_MvgaEQlv, and Zb7cUaSFEU",
            "container_clusters": ["KKhLga4xoI", "yL3_IaDMFt"],
            "resolution": "constructor and destructor ABI roles, direct field behavior, class-local context references, target pseudocode, and normalized ARM64 shape",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source constructor-shaped iterator label is treated as a destructor because its alternative ABI name and pseudocode establish the lifecycle role.",
            "Five rows match every recorded metric. The THashListObject constructor differs only in register_detail_hash, while its normalized shape and direct behavior remain the same.",
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
