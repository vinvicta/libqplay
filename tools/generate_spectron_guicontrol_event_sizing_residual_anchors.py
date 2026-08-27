#!/usr/bin/env python3
"""Create reviewed anchors for the residual GuiControl event and sizing block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControl event and sizing methods form one ordered sequence from 0x1b2b78 through 0x1b306c. Spectron keeps the corresponding sequence at a fixed +0x4500 address delta in the obfuscated w9XxgaJdbx class.",
    "The sequence preserves child and input hooks, key-repeat forwarding, showAlwaysTop, scroll-line reporting, and the VertSizing and HorizSizing string-table wrappers.",
    "Representative pseudocode is identical in both builds. The child-resized hook and input-event default are empty, key-repeat dispatches through vtable slot 760, showAlwaysTop sets byte offset 284 before dispatching through slot 360, and the sizing setters scan the same static string tables before storing the selected index at offsets 404 and 400.",
    "Every reviewed pair has matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. Neither side has string references in this block.",
    "The unnamed source sub_1B2FDC row is retained as an explicit boundary. It has no readable 1.8 symbol to translate, even though the fixed-delta target function exists at 0x1b74dc.",
]


SOURCE_START = 0x1B2B78
SOURCE_END = 0x1B306D
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
    if len(sources) != 8:
        raise ValueError("unexpected GuiControl event/sizing residual count: %d" % len(sources))

    anchors = []
    for order, source in enumerate(sources, 1):
        source_ea = int(source["ea"], 16)
        target_address = source_ea + TARGET_DELTA
        target = spectron.get(target_address)
        if target is None:
            raise ValueError("missing target feature at 0x%x" % target_address)
        target_name = target.get("name", "")
        if not (
            target_name.startswith("_ZN10w9XxgaJdbx")
            or target_name.startswith("sub_")
        ):
            raise ValueError("unexpected target name at 0x%x" % target_address)
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
                "match_kind": "manual-guicontrol-event-sizing-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "GuiControl event or sizing method %s"
                % source["name"].split("GuiControl_", 1)[1],
                "context_group": "GuiControl residual event and sizing block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_guicontrol_event_sizing_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GuiControl event and sizing block",
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
            "source_sequence": "0x1b2b78 through 0x1b306c, excluding rows already in the semantic map and the unnamed source sub_1B2FDC row",
            "target_sequence": "0x1b7078 through 0x1b74ec at the fixed +0x4500 delta",
            "target_class": "w9XxgaJdbx",
            "source_unnamed_gap": "0x1b2fdc",
            "target_unnamed_gap": "0x1b74dc",
            "target_delta": "0x4500",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target names are resolved by the fixed address delta, ordered class-local sequence, and exact normalized bodies.",
            "The unnamed source and target rows remain explicit coverage gaps rather than being assigned invented names.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
