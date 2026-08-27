#!/usr/bin/env python3
"""Create reviewed anchors for the GuiControlProfile destructor family."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source GuiControlProfileProperties D2 and D0 destructor forms and their two non-virtual thunks occur as one local family. Spectron keeps the same family in the XoqxgaMPJwProperties class with identical compact bodies and the same 16-byte this adjustment.",
    "The source GuiControlProfile D2 and D0 forms occur immediately after the properties destructor family. Spectron keeps the corresponding XoqxgaMPJw D1 and D0 forms in the same class-local position.",
    "The main profile destructor pseudocode preserves the cleanup order for the string members, resource-file-user subobjects, and the TGraalVar base. Spectron uses rebuilt wrappers and a larger profile object, adding one cleanup call and two instructions to each form.",
    "The four properties destructor and thunk pairs have matching normalized shapes. The two main profile destructor pairs have the expected eight-byte object-layout growth and one additional cleanup call in the target; those rows are documented as layout-change anchors rather than exact byte-shape matches.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x112914",
        "original_name": "GuiControlProfileProperties_GuiControlProfileProperties",
        "spectron_ea": "0x1151c8",
        "target_name": "_ZN20XoqxgaMPJwPropertiesD1Ev",
        "target_prefix": "_ZN20XoqxgaMPJwProperties",
        "source_metrics": (28, 7, 2, 1, 0),
        "target_metrics": (28, 7, 2, 1, 0),
        "proposed_name": "v18_GuiControlProfileProperties_GuiControlProfileProperties",
        "source_basis": "GuiControlProfileProperties complete destructor",
        "context_order": 1,
        "shape_equal": True,
    },
    {
        "original_ea": "0x112930",
        "original_name": "non_virtual_thunk_to_GuiControlProfileProperties_GuiControlProfileProperties",
        "spectron_ea": "0x1151e4",
        "target_name": "_ZThn16_N20XoqxgaMPJwPropertiesD1Ev",
        "target_prefix": "_ZThn16_N20XoqxgaMPJwProperties",
        "source_metrics": (8, 2, 2, 1, 0),
        "target_metrics": (8, 2, 2, 1, 0),
        "proposed_name": "v18_non_virtual_thunk_to_GuiControlProfileProperties_GuiControlProfileProperties",
        "source_basis": "GuiControlProfileProperties complete-destructor thunk",
        "context_order": 2,
        "shape_equal": True,
    },
    {
        "original_ea": "0x112938",
        "original_name": "GuiControlProfileProperties_GuiControlProfileProperties__2",
        "spectron_ea": "0x1151ec",
        "target_name": "_ZN20XoqxgaMPJwPropertiesD0Ev",
        "target_prefix": "_ZN20XoqxgaMPJwProperties",
        "source_metrics": (56, 14, 2, 2, 1),
        "target_metrics": (56, 14, 2, 2, 1),
        "proposed_name": "v18_GuiControlProfileProperties_GuiControlProfileProperties__2",
        "source_basis": "GuiControlProfileProperties deleting destructor",
        "context_order": 3,
        "shape_equal": True,
    },
    {
        "original_ea": "0x112970",
        "original_name": "non_virtual_thunk_to_GuiControlProfileProperties_GuiControlProfileProperties__2",
        "spectron_ea": "0x115224",
        "target_name": "_ZThn16_N20XoqxgaMPJwPropertiesD0Ev",
        "target_prefix": "_ZThn16_N20XoqxgaMPJwProperties",
        "source_metrics": (8, 2, 2, 1, 0),
        "target_metrics": (8, 2, 2, 1, 0),
        "proposed_name": "v18_non_virtual_thunk_to_GuiControlProfileProperties_GuiControlProfileProperties__2",
        "source_basis": "GuiControlProfileProperties deleting-destructor thunk",
        "context_order": 4,
        "shape_equal": True,
    },
    {
        "original_ea": "0x112978",
        "original_name": "GuiControlProfile_GuiControlProfile",
        "spectron_ea": "0x11522c",
        "target_name": "_ZN10XoqxgaMPJwD1Ev",
        "target_prefix": "_ZN10XoqxgaMPJw",
        "source_metrics": (136, 34, 2, 11, 10),
        "target_metrics": (144, 36, 2, 12, 11),
        "proposed_name": "v18_GuiControlProfile_GuiControlProfile",
        "source_basis": "GuiControlProfile complete destructor",
        "context_order": 5,
        "shape_equal": False,
    },
    {
        "original_ea": "0x112a00",
        "original_name": "GuiControlProfile_GuiControlProfile__2",
        "spectron_ea": "0x1152bc",
        "target_name": "_ZN10XoqxgaMPJwD0Ev",
        "target_prefix": "_ZN10XoqxgaMPJw",
        "source_metrics": (144, 36, 2, 12, 11),
        "target_metrics": (152, 38, 2, 13, 12),
        "proposed_name": "v18_GuiControlProfile_GuiControlProfile__2",
        "source_basis": "GuiControlProfile deleting destructor",
        "context_order": 6,
        "shape_equal": False,
    },
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
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        source_ea = int(spec["original_ea"], 16)
        target_ea = int(spec["spectron_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at 0x%x" % source_ea)
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at 0x%x" % target_ea)
        if not target["name"].startswith(spec["target_prefix"]):
            raise ValueError("target class context mismatch at 0x%x" % target_ea)
        source_metrics = (
            source.get("size"),
            source.get("instruction_count"),
            source.get("basic_block_count"),
            source.get("branch_count"),
            source.get("call_count"),
        )
        target_metrics = (
            target.get("size"),
            target.get("instruction_count"),
            target.get("basic_block_count"),
            target.get("branch_count"),
            target.get("call_count"),
        )
        if source_metrics != spec["source_metrics"] or target_metrics != spec["target_metrics"]:
            raise ValueError("unexpected metrics at 0x%x" % source_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected string references at 0x%x" % source_ea)
        if spec["shape_equal"] and any(
            source.get(field) != target.get(field)
            for field in (
                "mnemonic_hash",
                "opcode_shape_hash",
                "register_shape_hash",
                "shape_hash",
            )
        ):
            raise ValueError("unexpected shape difference at 0x%x" % source_ea)
        if target_ea in semantic_targets:
            raise ValueError("target is already present in the semantic map")
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-gui-control-profile-destructor-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "context_group": "GuiControlProfile destructor family",
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": spec["shape_equal"],
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_control_profile_destructor_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the GuiControlProfileProperties and GuiControlProfile destructor family",
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
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "layout_change_anchor_count": sum(not row["shape_equal"] for row in anchors),
        },
        "context": {
            "target_classes": {
                "XoqxgaMPJwProperties": "profile-properties D1 and D0 destructors and their 16-byte adjusted-this thunks at 0x1151c8 through 0x11522c",
                "XoqxgaMPJw": "profile D1 and D0 destructors at 0x11522c and 0x1152bc",
            },
            "layout_change": "The main XoqxgaMPJw destructor forms are eight bytes and two instructions larger than their source counterparts and include one additional cleanup call in each form.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The four properties destructor rows are exact normalized-shape matches. The two main profile destructor rows are high-confidence lifecycle matches with documented target layout growth.",
            "The proposed v18_ labels preserve the readable source destructor roles while retaining the obfuscated target names in the evidence rows.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
