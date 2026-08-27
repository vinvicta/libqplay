#!/usr/bin/env python3
"""Create a reviewed anchor for the residual GuiControl factory wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControl_create_TString_const wrapper at 0x1b4974 allocates 0x1c8 bytes and calls the parameterized GuiControl constructor before returning the object.",
    "The target factory at 0x1b9040 has the same 48-byte, 12-instruction, one-block, three-branch, two-call body. Its pseudocode allocates 0x1c8 bytes, calls the w9XxgaJdbx parameterized constructor, and returns the object.",
    "The target class and constructor call identify the correct candidate among the 26 generic factory-shaped search results. The factory is also referenced by the translated v18_guiControl_initStaticScriptVars_void caller, matching the source factory's static-script-variable use.",
    "The source and target wrappers have no string references and identical normalized metrics, mnemonic hash, opcode shape, register shape, and overall shape hash.",
]


SOURCE_EA = 0x1B4974
TARGET_EA = 0x1B9040


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
    source = original.get(SOURCE_EA)
    target = spectron.get(TARGET_EA)
    if source is None or target is None:
        raise ValueError("missing source or target factory feature")
    if SOURCE_EA in semantic_source_eas or TARGET_EA in semantic_target_eas:
        raise ValueError("factory row is already present in the semantic map")
    if target.get("is_default_name"):
        raise ValueError("unexpected default target name")
    if target.get("name") != "_Z20w9XxgaJdbxE7Bm2aaHDBRK10C8THgaTQxF":
        raise ValueError("unexpected target factory name")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected factory string references")
    shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
    if not shape_equal:
        raise ValueError("source and target factory metrics differ")

    anchor = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": "0x%x" % TARGET_EA,
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-guicontrol-create-factory-anchor",
        "semantic_match_already_present": False,
        "source_basis": "GuiControl factory wrapper and target class-specific allocator",
        "context_group": "GuiControl residual initialization and factory block",
        "context_order": 1,
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": shape_equal,
    }

    result = {
        "schema_version": 1,
        "artifact": "spectron_guicontrol_create_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the residual GuiControl factory wrapper",
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
            "layout_change_anchor_count": 0,
            "target_default_name_count": 0,
        },
        "context": {
            "source_factory": "0x1b4974 GuiControl_create_TString_const",
            "target_factory": "0x1b9040 _Z20w9XxgaJdbxE7Bm2aaHDBRK10C8THgaTQxF",
            "target_class": "w9XxgaJdbx",
            "candidate_count_before_context": 26,
            "allocation_size": "0x1c8",
            "constructor_target": "0x1b8f68",
            "translated_factory_caller": "0x1bed98",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ label preserves the readable source method name while retaining the obfuscated target context in the evidence row.",
            "The class-specific constructor call, allocation size, exact normalized shape, and factory caller resolve the previous generic candidate ambiguity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
