#!/usr/bin/env python3
"""Create a reviewed anchor for the residual update-package destructor."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The only uncovered source row in the TUpdatePackage lifecycle sequence is 0x208eb4, between the already translated constructor and canDownloadUpdatePackage helper. Its target counterpart is the deleting destructor at 0x20f04c.",
    "The source body forwards to the TUpdatePackage constructor-like cleanup entry and then calls operator delete. The Spectron body forwards to RH6ygazf9x::~RH6ygazf9x and then calls operator delete, which is the same deleting-destructor role.",
    "The source and target both have 32 bytes, 8 instructions, 2 basic blocks, 2 branches, and 1 call. Their mnemonic, opcode, and overall shape hashes also match exactly.",
    "The constructor at source 0x208dc8 and target 0x20ef60 is already in the canonical semantic map. This anchor therefore closes the adjacent deleting-destructor row without duplicating that existing match.",
    "The target destructor already has a non-default obfuscated name. The v18_ alias preserves the source database label and the evidence explains why the constructor-like label represents a deleting destructor.",
]


SOURCE_TARGETS = {0x208EB4: 0x20F04C}

EXPECTED_SOURCE_NAMES = {0x208EB4: "TUpdatePackage_TUpdatePackage__2"}

EXPECTED_TARGET_NAMES = {0x20F04C: "_ZN10RH6ygazf9xD0Ev"}


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
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
        )
    }


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
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for order, (source_ea, target_ea) in enumerate(SOURCE_TARGETS.items(), 1):
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != EXPECTED_SOURCE_NAMES[source_ea]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != EXPECTED_TARGET_NAMES[target_ea]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        if not shape_equal:
            raise ValueError("unexpected update-package destructor shape result")
        if target.get("is_default_name", False):
            raise ValueError("target is unexpectedly default at 0x%x" % target_ea)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": "0x%x" % target_ea,
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-update-package-destructor-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "update-package deleting destructor %s" % source["name"],
                "context_group": "TUpdatePackage destructor residual block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_update_package_destructor_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the residual TUpdatePackage deleting destructor",
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
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "layout_change_anchor_count": sum(not row["shape_equal"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_sequence": "0x208dc8 constructor already mapped, 0x208eb4 deleting destructor residual, and 0x208ed4 canDownloadUpdatePackage already mapped",
            "target_sequence": "0x20ef60 complete destructor already mapped, 0x20f04c deleting destructor residual, and 0x20f06c canDownloadUpdatePackage boundary",
            "source_class": "TUpdatePackage",
            "target_class": "RH6ygazf9x",
            "target_only_boundaries": ["0x20ef40 get_accounts already mapped", "0x20ef60 complete destructor already mapped"],
            "following_target_boundary": "0x20f06c canDownloadUpdatePackage helper",
        },
        "anchors": anchors,
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The address is valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ label preserves the readable source role while the evidence records that the constructor-like source label is a deleting destructor variant.",
            "The pair is an exact normalized-shape match and closes the residual row adjacent to the already mapped complete destructor.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
