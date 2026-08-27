#!/usr/bin/env python3
"""Create reviewed anchors for the client and socket static clear routines.

The 2.2 target keeps the same cleanup responsibilities but adds a field to
each routine.  These rows are therefore recorded as context and layout
anchors instead of exact normalized-shape matches.
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
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)


ANCHOR_SPECS = (
    {
        "original_ea": 0xE05EC,
        "original_name": "TClient_clearStaticStrings",
        "spectron_ea": 0xE0128,
        "spectron_name": "sub_E0128",
        "target_class": "w6qzgacqqy",
        "source_table": "0x35d2e8",
        "target_table": "0x36ff18",
        "context_order": 1,
        "source_basis": "TClient static TString cleanup callback",
        "context_group": "client and socket static clear callbacks",
    },
    {
        "original_ea": 0xE0680,
        "original_name": "TSocket_clearStaticStrings",
        "spectron_ea": 0xE0258,
        "spectron_name": "sub_E0258",
        "target_class": "XJLBgarMnA",
        "source_table": "0x35d2f0",
        "target_table": "0x36ff60",
        "context_order": 2,
        "source_basis": "TSocket static TString cleanup callback",
        "context_group": "client and socket static clear callbacks",
    },
)


EVIDENCE = [
    "The source functions are named TClient_clearStaticStrings and TSocket_clearStaticStrings and are referenced by adjacent static callback-table entries at 0x35d2e8 and 0x35d2f0.",
    "The target callback table keeps corresponding entries at 0x36ff18 and 0x36ff60.  The target bodies are normal IDA functions at sub_E0128 and sub_E0258, but both retained names are default sub_ labels.",
    "The target class names resolve independently from large class-local method families: w6qzgacqqy is the target TClient class and XJLBgarMnA is the target TSocket class.  Existing high-confidence constructor, connection, reset, accept, and connect correspondences establish those class roles.",
    "The client target clears the same eleven source TString state fields through C8THgaTQxF::clear and adds one CanTfaz6bZ::clear cleanup for a target-only field.  The socket target clears the two source socket strings and adds one target-only CanTfaz6bZ::clear cleanup.",
    "Both target bodies preserve the source two-block cleanup shape while growing by twelve bytes, two instructions, one branch, and one call.  The extra cleanup is consistent with a target object-layout change, so these are high-confidence layout anchors rather than exact byte-shape matches.",
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


def delta_text(target_ea: int, source_ea: int) -> str:
    delta = target_ea - source_ea
    sign = "+" if delta >= 0 else "-"
    return "%s0x%x" % (sign, abs(delta))


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
    semantic_sources = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        source_ea = spec["original_ea"]
        target_ea = spec["spectron_ea"]
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at 0x%x" % source_ea)
        if target.get("name") != spec["spectron_name"]:
            raise ValueError("target name mismatch at 0x%x" % target_ea)
        if not target.get("is_default_name"):
            raise ValueError("target is not a default IDA name at 0x%x" % target_ea)
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("static clear row is already in the semantic map")
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected string references at 0x%x" % source_ea)
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        shape_equal = source_metrics == target_metrics
        if shape_equal:
            raise ValueError("static clear row unexpectedly has an exact shape")

        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": "0x%x" % target_ea,
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-static-clear-layout-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "context_group": spec["context_group"],
                "context_order": spec["context_order"],
                "source_callback_table_ea": spec["source_table"],
                "spectron_callback_table_ea": spec["target_table"],
                "target_class": spec["target_class"],
                "target_delta": delta_text(target_ea, source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_static_clear_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TClient and TSocket static TString cleanup callbacks",
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
            "address_delta_groups": {
                delta: sum(row["target_delta"] == delta for row in anchors)
                for delta in sorted({row["target_delta"] for row in anchors})
            },
        },
        "context": {
            "source_callback_table": "0x35d2e8 through 0x35d2f0",
            "spectron_callback_table": "0x36ff18 and 0x36ff60",
            "target_classes": {
                "w6qzgacqqy": "TClient class family",
                "XJLBgarMnA": "TSocket class family",
            },
            "layout_change": "Each target cleanup body has one additional target-only string cleanup and is twelve bytes, two instructions, one branch, and one call larger than its source counterpart.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source callback names while retaining the obfuscated target class and default name in the evidence rows.",
            "The target-only cleanup call is recorded as a layout change. It is evidence of an added field or wrapper, not a reason to reject the otherwise stable static callback role.",
            "This artifact documents the two safe static cleanup overlays. The separate TServerFlying cleanup callback remains unresolved until its target global state is isolated.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
