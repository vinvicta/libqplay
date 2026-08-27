#!/usr/bin/env python3
"""Create reviewed anchors for the residual GuiControl virtual hooks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControl base and virtual-hook rows form one contiguous sequence from 0x1ac750 through 0x1ac81c. Spectron keeps the same sequence at a fixed +0x41c0 address delta inside its obfuscated w9XxgaJdbx class.",
    "The sequence preserves cache-size reporting, minimum extent, cursor type, root and external-window lookup, client-bound refresh, the right-mouse hooks, script-access state, forced clipping, and context-menu visibility.",
    "Representative pseudocode is identical in both builds. requiredCacheSize returns the same cached size through the same output pointer, getRoot and getExternalWindow use the same parent pointer and vtable slots 416 and 432, setScriptAccessRestricted writes the same byte at offset 204, and forceClipping remains a null-returning hook.",
    "Every reviewed pair has matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. Neither side has string references in this block.",
    "The target keeps its obfuscated method names rather than generic sub_ names. The adjacent target destructor family begins at 0x1b09e4 and is outside this artifact, so the alignment does not absorb that separate class boundary.",
]


SOURCE_START = 0x1AC750
SOURCE_END = 0x1AC824
TARGET_DELTA = 0x41C0


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
    if len(sources) != 13:
        raise ValueError("unexpected GuiControl virtual residual count: %d" % len(sources))

    anchors = []
    for order, source in enumerate(sources, 1):
        source_ea = int(source["ea"], 16)
        target_address = source_ea + TARGET_DELTA
        target = spectron.get(target_address)
        if target is None:
            raise ValueError("missing target feature at 0x%x" % target_address)
        if not target.get("name", "").startswith(("_ZN10w9XxgaJdbx", "_ZNK10w9XxgaJdbx")):
            raise ValueError("unexpected target class at 0x%x" % target_address)
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
                "match_kind": "manual-guicontrol-virtual-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "GuiControl virtual hook %s"
                % source["name"].split("GuiControl_", 1)[1],
                "context_group": "GuiControl residual virtual and base hook block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_guicontrol_virtual_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GuiControl virtual and base hook block",
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
            "source_sequence": "0x1ac750 through 0x1ac81c",
            "target_sequence": "0x1b0910 through 0x1b09dc at the fixed +0x41c0 delta",
            "target_class": "w9XxgaJdbx",
            "target_destructor_boundary": "0x1b09e4",
            "target_delta": "0x41c0",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target obfuscated names are resolved by the fixed address delta, class-local order, and exact normalized bodies.",
            "The adjacent target destructor family remains a separate coverage boundary.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
