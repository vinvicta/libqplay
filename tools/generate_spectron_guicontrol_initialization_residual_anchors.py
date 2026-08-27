#!/usr/bin/env python3
"""Create reviewed anchors for the residual GuiControl initialization block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControl initialization block contains the readable initObject method at 0x1b4680 and the parameterized constructor at 0x1b48c8. Spectron keeps the same class-local order at 0x1b8cfc and 0x1b8f68 inside the obfuscated w9XxgaJdbx class.",
    "initObject preserves the complete field initialization sequence, the controls static string, the child-list allocation, the vtable slot 72 lookup, and the final array-update call. Spectron makes the CanTfaz6bZ string assignment and cleanup and the G0gxgajWBw update wrapper explicit.",
    "The parameterized constructor preserves the TGraalVar base construction, region construction at object offset 176, the same field clearing, and the call into initObject. The target C2 constructor uses an explicit temporary CanTfaz6bZ value and maps to the source constructor that accepts a TString argument.",
    "The source default constructor at 0x1b49a4 is already translated to the target C1 constructor at 0x1b9070 with identical normalized metrics. That existing pair confirms the target class and distinguishes the parameterized C2 row from the default constructor.",
    "Both reviewed target bodies have layout changes from wrapper expansion. initObject changes from 584 bytes, 145 instructions, 4 blocks, 12 branches, and 8 calls to 620/154/4/14/10. The parameterized constructor changes from 172/43/2/3/2 to 216/54/1/6/5.",
    "GuiControl_create_TString_const at 0x1b4974 is excluded because the existing semantic search leaves 26 target candidates. It remains an explicit ambiguity rather than being assigned from address order alone.",
]


TARGETS = {
    0x1B4680: 0x1B8CFC,
    0x1B48C8: 0x1B8F68,
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
    for order, (source_ea, target_ea) in enumerate(TARGETS.items(), 1):
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing feature at 0x%x or 0x%x" % (source_ea, target_ea))
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        if target.get("is_default_name"):
            raise ValueError("unexpected default target name at 0x%x" % target_ea)
        if not target.get("name", "").startswith("_ZN10w9XxgaJdbx"):
            raise ValueError("unexpected target class at 0x%x" % target_ea)
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
                "match_kind": "manual-guicontrol-initialization-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "GuiControl initialization method %s" % source["name"],
                "context_group": "GuiControl residual initialization block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": False,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_guicontrol_initialization_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GuiControl initialization block",
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
            "exact_shape_anchor_count": 0,
            "layout_change_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_sequence": "0x1b4680 initObject and 0x1b48c8 parameterized constructor",
            "target_sequence": "0x1b8cfc j9gLgaw2nI and 0x1b8f68 w9XxgaJdbx C2 constructor",
            "target_class": "w9XxgaJdbx",
            "default_constructor_source": "0x1b49a4",
            "default_constructor_target": "0x1b9070",
            "ambiguous_create_source": "0x1b4974",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target names are resolved by class-local construction order, field initialization, wrapper roles, and the already translated default constructor.",
            "Both rows are recorded as layout-change anchors because Spectron makes temporary wrapper operations explicit.",
            "The parameterized create helper remains unresolved because its existing target candidates are ambiguous.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
