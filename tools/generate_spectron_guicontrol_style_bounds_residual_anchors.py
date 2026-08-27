#!/usr/bin/env python3
"""Create reviewed anchors for the residual GuiControl style and bounds block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControl style and bounds methods form an ordered class-local sequence. The Hint wrappers and getStyle begin at 0x1b30f8 and use the +0x4500 target delta. After the target getStyle grows by 0x34 bytes, the remaining source rows align at +0x4534 through target 0x1b7b64.",
    "The sequence preserves Hint assignment and retrieval, style-name fallback, minimum and client extents, position and extent conversion, rotation center, profile assignment, script addControl, color conversion, and bounds conversion.",
    "Representative pseudocode is behaviorally aligned. Hint uses the same object string at offset 424, the extent wrappers call the corresponding point and rectangle converters, setProfile performs the same dynamic cast and vtable dispatch at slot 792, and getColor reconstructs the same four color bytes before calling the target color-string wrapper.",
    "The target getStyle body grows from 256 bytes and 8 calls to 308 bytes and 12 calls because Spectron makes temporary string and resource wrappers explicit. It still follows the same profile lookup, nonempty-style fast path, level-resource filename fallback, and default-style fallback.",
    "The other 11 reviewed pairs have matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. Neither side has string references in this block.",
    "The target-only thunk at 0x1b7c6c is retained as a boundary before the next already mapped GuiControl method. It is not assigned to a source row from this artifact.",
]


SOURCE_START = 0x1B30F8
SOURCE_END = 0x1B3631
TARGET_STYLE = 0x1B7630
TARGET_DELTA_BEFORE_STYLE = 0x4500
TARGET_DELTA_AFTER_STYLE = 0x4534


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


def target_ea(source_ea: int) -> int:
    if source_ea <= 0x1B3130:
        return source_ea + TARGET_DELTA_BEFORE_STYLE
    if source_ea >= 0x1B33CC:
        return source_ea + TARGET_DELTA_AFTER_STYLE
    raise ValueError("no target alignment rule for 0x%x" % source_ea)


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
    if len(sources) != 12:
        raise ValueError("unexpected GuiControl style/bounds residual count: %d" % len(sources))

    anchors = []
    for order, source in enumerate(sources, 1):
        source_ea = int(source["ea"], 16)
        target_address = target_ea(source_ea)
        target = spectron.get(target_address)
        if target is None:
            raise ValueError("missing target feature at 0x%x" % target_address)
        if not target.get("name", "").startswith("sub_"):
            raise ValueError("unexpected target name at 0x%x" % target_address)
        if target_address in semantic_target_eas:
            raise ValueError("target is already present in the semantic map")
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected string references at 0x%x" % source_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        if source_ea != 0x1B3130 and not shape_equal:
            raise ValueError("source and target metrics differ at 0x%x" % source_ea)
        if source_ea == 0x1B3130 and target_address != TARGET_STYLE:
            raise ValueError("getStyle target alignment changed unexpectedly")
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
                "match_kind": "manual-guicontrol-style-bounds-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "GuiControl style or bounds method %s"
                % source["name"].split("GuiControl_", 1)[1],
                "context_group": "GuiControl residual style and bounds block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_guicontrol_style_bounds_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GuiControl style and bounds block",
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
            "source_sequence": "0x1b30f8 through 0x1b3630, excluding rows already in the semantic map",
            "target_sequence": "0x1b75f8 through 0x1b7b64 with +0x4500 before getStyle and +0x4534 afterward",
            "target_class": "w9XxgaJdbx",
            "layout_change_source": "0x1b3130",
            "layout_change_target": "0x1b7630",
            "target_only_thunk": "0x1b7c6c",
            "target_delta_before_style": "0x4500",
            "target_delta_after_style": "0x4534",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source method names while retaining the obfuscated target context in the evidence rows.",
            "The target names are resolved by the piecewise address delta, class-local sequence, and representative pseudocode.",
            "getStyle is recorded as a layout-change anchor because Spectron adds explicit temporary-wrapper work while preserving the source fallback behavior.",
            "The target-only thunk remains an explicit boundary rather than being assigned to a source method.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
