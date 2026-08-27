#!/usr/bin/env python3
"""Create reviewed anchors for the residual GuiControl event dispatch block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControl event-dispatch methods form one ordered class-local sequence from 0x1b3984 through 0x1b3e40. Spectron keeps the same order in the obfuscated w9XxgaJdbx class, but expands several bodies with explicit encoded-string and wrapper operations.",
    "The reviewed rows cover first-responder, dialog-push, dialog-pop, add, visibility notification, action, and both mouse-wheel events. The source rows already translated between these methods remain in the sequence as alignment anchors.",
    "Representative pseudocode preserves the event names and state transitions. Spectron's first-responder, dialog, and action methods build the corresponding target strings through KKhLga4xoI and call the same TGraalVar event path. onAdd still refreshes the parent window, notifyVisible still propagates visibility to active children, and the mouse-wheel methods retain the same control-state and vtable-slot checks.",
    "The first six target bodies are larger because the target makes temporary C8THgaTQxF values, encoded event strings, and rebuilt wrapper calls explicit. Their source and target roles remain in the same class-local order. The two mouse-wheel pairs are exact normalized-shape matches.",
    "The source event literals are visible in the original feature export. Spectron stores obfuscated or encoded equivalents, including 33cSO and 22F>NF, so the target string-reference lists are retained as evidence rather than treated as a mismatch.",
    "The target-only one-instruction thunk at 0x1b7c6c is outside this block and remains a separate boundary before the already translated resizeChildren method.",
]


SOURCE_START = 0x1B3984
SOURCE_END = 0x1B3E41
TARGETS = {
    0x1B3984: 0x1B7EB8,
    0x1B39D0: 0x1B7F3C,
    0x1B3A1C: 0x1B7FC0,
    0x1B3A68: 0x1B8044,
    0x1B3AD4: 0x1B80E8,
    0x1B3B9C: 0x1B81E0,
    0x1B3DD8: 0x1B8454,
    0x1B3E40: 0x1B84BC,
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

    sources = [
        function
        for ea, function in sorted(original.items())
        if SOURCE_START <= ea < SOURCE_END
        and not function.get("is_default_name")
        and function.get("name", "").startswith("GuiControl_")
        and ea not in semantic_source_eas
    ]
    if len(sources) != len(TARGETS):
        raise ValueError("unexpected GuiControl event-dispatch residual count: %d" % len(sources))

    anchors = []
    for order, source in enumerate(sources, 1):
        source_ea = int(source["ea"], 16)
        target_address = TARGETS.get(source_ea)
        if target_address is None:
            raise ValueError("missing reviewed target alignment for 0x%x" % source_ea)
        target = spectron.get(target_address)
        if target is None:
            raise ValueError("missing target feature at 0x%x" % target_address)
        if not target.get("name", "").startswith("_ZN10w9XxgaJdbx"):
            raise ValueError("unexpected target class at 0x%x" % target_address)
        if target_address in semantic_target_eas:
            raise ValueError("target is already present in the semantic map")
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        if source_ea in {0x1B3DD8, 0x1B3E40} and not shape_equal:
            raise ValueError("mouse-wheel metrics differ at 0x%x" % source_ea)
        if source_ea not in {0x1B3DD8, 0x1B3E40} and shape_equal:
            raise ValueError("expected expanded event body at 0x%x" % source_ea)
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
                "match_kind": "manual-guicontrol-event-dispatch-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "GuiControl event dispatch method %s"
                % source["name"].split("GuiControl_", 1)[1],
                "context_group": "GuiControl residual event dispatch block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_guicontrol_event_dispatch_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GuiControl event dispatch block",
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
            "source_sequence": "0x1b3984 through 0x1b3e40, excluding rows already in the semantic map",
            "target_sequence": "0x1b7eb8 through 0x1b84bc in the ordered w9XxgaJdbx event block",
            "target_class": "w9XxgaJdbx",
            "target_only_boundary": "0x1b7c6c",
            "expanded_source_rows": "0x1b3984 through 0x1b3b9c",
            "exact_source_rows": "0x1b3dd8 and 0x1b3e40",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target names are resolved by the explicit class-local address map and representative event pseudocode.",
            "Expanded target bodies are recorded as layout-change anchors, while the two mouse-wheel rows are exact shape matches.",
            "The source and target string-reference differences are preserved as evidence of Spectron's encoded event-string wrappers.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
