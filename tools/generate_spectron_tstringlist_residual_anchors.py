#!/usr/bin/env python3
"""Create reviewed anchors for the remaining TStringList methods.

The source list implementation and the Spectron list implementation use
different string wrapper classes. Three rows retain the same normalized ARM64
shape, while the case-insensitive lookup grew extra wrapper conversion and
cleanup code in Spectron. The latter is included only with class-local and
decompiled-behavior evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHORS = [
    {
        "original_ea": "0xf5334",
        "original_name": "TStringList_TStringList__2",
        "spectron_ea": "0xf6b34",
        "target_name": "_ZN10vuuHgangcFD0Ev",
        "proposed_name": "v18_TStringList_TStringList__2",
        "source_context": ["0x28d50", "0x35f228"],
        "spectron_context": ["0x3863f8", "0x3a0d88"],
        "source_basis": "TStringList deleting destructor wrapper",
        "evidence": [
            "The source wrapper calls the TStringList destructor and then operator delete.",
            "The target ABI name is the vuuHgangcF deleting destructor, and its body calls the D2 destructor followed by operator delete.",
            "The row is the destructor entry in the same vuuHgangcF list block as the translated add, clear, index, and serialization methods.",
        ],
    },
    {
        "original_ea": "0xf5708",
        "original_name": "TStringList_Remove_TString_const",
        "spectron_ea": "0xf6f08",
        "target_name": "_ZN10vuuHgangcF6RemoveERK10CanTfaz6bZ",
        "proposed_name": "v18_TStringList_Remove_TString_const",
        "source_context": ["0xe788", "0x36e1f0"],
        "spectron_context": ["0x2c0e8", "0x386408"],
        "source_basis": "TStringList repeated-value removal",
        "evidence": [
            "The source loops over indexOf and deletes every matching list entry.",
            "The target vuuHgangcF::Remove body preserves the same loop, using the rebuilt CanTfaz6bZ string wrapper and the target list helpers.",
            "The source and target rows have identical normalized and full feature metrics, including the two-call loop shape.",
        ],
    },
    {
        "original_ea": "0xf5750",
        "original_name": "TStringList_indexOfIgnoreCase_TString_const",
        "spectron_ea": "0xf6f9c",
        "target_name": "_ZNK10vuuHgangcF10W2tZ2afUk7ERK10C8THgaTQxF",
        "proposed_name": "v18_TStringList_indexOfIgnoreCase_TString_const",
        "source_context": ["0x1cc48"],
        "spectron_context": ["0x386408", "0x3a0d88"],
        "source_basis": "TStringList case-insensitive lookup",
        "layout_change": True,
        "evidence": [
            "The source scans the list and compares each TString with equalsIgnoreCase, returning the first matching index or -1.",
            "The target W2tZ2afUk7 method scans the same vuuHgangcF list, converts each CanTfaz6bZ entry to C8THgaTQxF, calls the target case-insensitive comparison helper, and cleans up the temporary wrapper.",
            "The target adds temporary conversion and cleanup, so its 176-byte, three-call body is larger than the 140-byte source body. The class-local method block and preserved return logic make this a reviewed layout-change correspondence rather than a shape-only match.",
        ],
    },
    {
        "original_ea": "0xf5df8",
        "original_name": "TStringList_operator_index_int",
        "spectron_ea": "0xf7670",
        "target_name": "_ZNK10vuuHgangcFixEi",
        "proposed_name": "v18_TStringList_operator_index_int",
        "source_context": ["0xd942c", "0x371078"],
        "spectron_context": ["0x137e8", "0x381d50"],
        "source_basis": "TStringList indexed string access",
        "evidence": [
            "The source checks the index, clears the output TString, and assigns the selected list element when the index is valid.",
            "The target vuuHgangcF::operator[] method preserves the same bounds check, output clearing, and element assignment using C8THgaTQxF.",
            "The source and target rows have identical normalized and full feature metrics. The target ABI spelling Fix is the compiler-mangled operator[] entry, not a separate semantic role.",
        ],
    },
]


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
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in document["functions"]}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document)
    spectron = by_ea(spectron_document)
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    rows = []
    for spec in ANCHORS:
        source = original.get(int(spec["original_ea"], 16))
        target = spectron.get(int(spec["spectron_ea"], 16))
        if source is None or target is None:
            raise ValueError("missing feature row for %s" % spec["original_name"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
        if int(spec["spectron_ea"], 16) in semantic_targets:
            raise ValueError("target is already present in the semantic map")

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        shape_equal = all(
            source_metrics[field] == target_metrics[field]
            for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
        )
        full_metric_equal = source_metrics == target_metrics
        if spec.get("layout_change"):
            if shape_equal:
                raise ValueError("layout-change row unexpectedly has equal shape")
        elif not shape_equal or not full_metric_equal:
            raise ValueError("expected exact row changed at %s" % spec["original_ea"])

        differences = [
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        ]
        rows.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_context": spec["source_context"],
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_context": spec["spectron_context"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-tstringlist-residual-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_component": "vuuHgangcF",
                "target_string_component": "CanTfaz6bZ / C8THgaTQxF",
                "shape_equal": shape_equal,
                "full_metric_equal": full_metric_equal,
                "layout_change": bool(spec.get("layout_change", False)),
                "metric_differences": differences,
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in rows}) != len(rows):
        raise ValueError("duplicate target in residual TStringList anchors")
    if len({row["proposed_name"] for row in rows}) != len(rows):
        raise ValueError("duplicate proposed name in residual TStringList anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tstringlist_residual_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining TStringList destructor, removal, case-insensitive lookup, and indexed-access methods",
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
        "context": {
            "source_class": "TStringList",
            "target_class": "vuuHgangcF",
            "target_string_components": ["CanTfaz6bZ", "C8THgaTQxF"],
            "target_method_block": ["0xf6b34", "0xf6f08", "0xf6f50", "0xf6f9c", "0xf7670", "0xf78ac"],
            "resolution": "class-local order, decompiled behavior, and normalized ARM64 metrics where preserved",
        },
        "summary": {
            "anchor_count": len(rows),
            "high_confidence_count": sum(row["confidence"] == "high" for row in rows),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(rows),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in rows),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in rows),
            "layout_change_anchor_count": sum(row["layout_change"] for row in rows),
            "target_default_name_count": sum(row["spectron_default_name"] for row in rows),
        },
        "anchors": rows,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the obfuscated target names and wrapper differences in the evidence rows.",
            "The case-insensitive lookup is a reviewed layout-change row because Spectron converts list entries through CanTfaz6bZ and C8THgaTQxF before comparison.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
