#!/usr/bin/env python3
"""Create reviewed anchors for the residual GuiControl property block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControl property wrappers form one contiguous sequence from 0x1b2748 through 0x1b2b34. Spectron keeps the same sequence at a fixed +0x4500 address delta, beside the known w9XxgaJdbx GuiControl methods.",
    "The sequence preserves getter and setter order for drop handling, activity, colors, sizing, clipping, focus, flicker state, scroll lines, visibility, ownership, and the two script show wrappers.",
    "Representative pseudocode is identical in both builds. The AcceptDropFiles getter reads the same byte at object offset 340, the AreaClickPriority setter clamps to 0 through 2 and stores at offset 332, Height keeps the same virtual resize callback, and the showtop wrapper dispatches through the same vtable slot.",
    "Every reviewed pair has matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. Neither side has string references in this property block.",
    "The source rows already present in the semantic translation map are left out. The target-only helper at 0x1b7078 is also left unlabeled because it has no corresponding source row in this contiguous interval.",
]


SOURCE_START = 0x1B2748
SOURCE_END = 0x1B2B35
TARGET_DELTA = 0x4500


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

    sources = [
        function
        for ea, function in sorted(original.items())
        if SOURCE_START <= ea < SOURCE_END
        and not function.get("is_default_name")
        and function.get("name", "").startswith("GuiControl_")
        and ea not in semantic_source_eas
    ]
    if len(sources) != 61:
        raise ValueError("unexpected GuiControl property residual count: %d" % len(sources))

    anchors = []
    for order, source in enumerate(sources, 1):
        source_ea = int(source["ea"], 16)
        target_address = source_ea + TARGET_DELTA
        target = spectron.get(target_address)
        if target is None:
            raise ValueError("missing target feature at 0x%x" % target_address)
        expected_target_name = "sub_%X" % target_address
        if target.get("name") != expected_target_name:
            raise ValueError("target name mismatch at 0x%x" % target_address)
        if target_address in semantic_target_eas:
            raise ValueError("target is already present in the semantic map")
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected string references at 0x%x" % source_ea)
        if any(source.get(field) != target.get(field) for field in metrics(source)):
            raise ValueError("source and target metrics differ at 0x%x" % source_ea)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": "0x%x" % target_address,
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-guicontrol-property-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "GuiControl property %s"
                % source["name"].split("GuiControl_", 1)[1],
                "context_group": "GuiControl residual property block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_guicontrol_property_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GuiControl property block",
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
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_sequence": "0x1b2748 through 0x1b2b34, excluding rows already in the semantic map",
            "target_sequence": "0x1b6c48 through 0x1b7014 at the fixed +0x4500 delta",
            "target_class": "w9XxgaJdbx",
            "target_only_gap": "The target-only helper at 0x1b7078 is outside the translated property interval and remains unlabeled.",
            "target_delta": "0x4500",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source property names while retaining the obfuscated target context in the evidence rows.",
            "The target generic sub_ names are resolved by the fixed address delta, ordered class-local sequence, and exact normalized bodies.",
            "The target-only helper and source rows already covered by the semantic map remain explicit coverage boundaries for later review.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
