#!/usr/bin/env python3
"""Create reviewed anchors for the dense GuiControlProfile accessor block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControlProfile accessor block runs in one ordered sequence from 0x111248 through the font-color wrappers at 0x111d00. The corresponding target sequence runs from 0x113a28 through 0x11457c beside the known XoqxgaMPJw profile methods.",
    "The target preserves the source getter and setter order for boolean and integer profile fields, alignment and point fields, font-style strings, color setters, color getters, background inset, resource-file notification, and font-color conversion.",
    "Representative pseudocode keeps the same field roles and color conversion. The target replaces getStringColor and getColorString with Q9LCGaX7dt and wC1CGa7Yrt wrappers, while the source and target normalized instruction shapes remain equal.",
    "Two source rows are intentionally excluded because the target has no distinct IDA function at the aligned position: set_gradientcolor is followed by target data at 0x1140f4, and get_bordercolor is folded into the target color sequence before get_shadowcolor. The target-only 16-byte method at 0x113b98 is also left unlabeled.",
    "Every reviewed source and target pair has matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. The rows are not already present in the semantic translation map.",
]


SOURCE_START = 0x111248
SOURCE_END = 0x111D00
EXCLUDED_NAMES = {
    "GuiControlProfile_set_gradientcolor",
    "GuiControlProfile_get_bordercolor",
}


def target_ea(source_ea: int) -> int:
    if source_ea < 0x1113B8:
        return source_ea + 0x27E0
    if source_ea < 0x111974:
        return source_ea + 0x27F0
    if source_ea == 0x111974:
        return 0x114164
    if 0x1119E0 <= source_ea <= 0x111B48:
        return 0x1141F4 + (source_ea - 0x1119E0)
    if source_ea == 0x111B90:
        return 0x114380
    if source_ea in {0x111C24, 0x111C54, 0x111C78}:
        return source_ea + 0x27F0
    if source_ea == 0x111CF8:
        return 0x1144E8
    if source_ea == 0x111CFC:
        return 0x1144EC
    raise ValueError("no target alignment rule for 0x%x" % source_ea)


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

    sources = [
        function
        for ea, function in sorted(original.items())
        if SOURCE_START <= ea < SOURCE_END
        and not function.get("is_default_name")
        and function.get("name", "").startswith("GuiControlProfile_")
        and function.get("name") not in EXCLUDED_NAMES
        and ea not in semantic_source_eas
    ]
    if len(sources) != 89:
        raise ValueError("unexpected GuiControlProfile residual count: %d" % len(sources))

    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    anchors = []
    for order, source in enumerate(sources, 1):
        source_ea = int(source["ea"], 16)
        target_address = target_ea(source_ea)
        target = spectron.get(target_address)
        if target is None:
            raise ValueError("missing target feature at 0x%x" % target_address)
        expected_target_name = (
            "_ZN10XoqxgaMPJw10py0qgaE4krERK10C8THgaTQxF"
            if target_address == 0x1144E8
            else "sub_%X" % target_address
        )
        if target.get("name") != expected_target_name:
            raise ValueError("target name mismatch at 0x%x" % target_address)
        if target_address in semantic_targets:
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
                "match_kind": "manual-gui-control-profile-accessor-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "GuiControlProfile accessor %s" % source["name"].split("GuiControlProfile_", 1)[1],
                "context_group": "GuiControlProfile residual accessor block",
                "context_order": order,
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_control_profile_accessor_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GuiControlProfile accessor block",
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
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "target_class": "XoqxgaMPJw",
            "target_sequence": "Generic target accessors run from 0x113a28 through 0x11457c around the named XoqxgaMPJw profile methods. The target-only 0x113b98 method and data gaps at 0x1140f4 and 0x1141cc remain unlabeled.",
            "source_exclusions": sorted(EXCLUDED_NAMES),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source property names while retaining the obfuscated target context in the evidence rows.",
            "The target generic sub_ names are resolved by their ordered profile-class sequence and exact normalized bodies. They are not claimed to be preserved source symbols.",
            "The two excluded source rows and the target-only method are preserved as explicit coverage gaps for later review.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
