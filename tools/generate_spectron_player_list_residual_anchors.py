#!/usr/bin/env python3
"""Create reviewed anchors for the residual player-list support block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source rows are the remaining TPlayerList staff-guild setter and static initialization methods at 0x2081e4, 0x208310, and 0x208340. Spectron keeps the same local sequence at 0x20e380, 0x20e4ac, and 0x20e4dc.",
    "The setter calls the target vuuHgangcF string-list comma-text helper against the obfuscated y3t2LaCUH1 staff-guild global, matching the source TStringList comma-text setter and the readable TPlayerList role.",
    "The static initializer preserves the source allocate-construct-publish sequence. The source allocates 0x18 bytes for its TStringList, while Spectron allocates 0x20 bytes for vuuHgangcF, so this is a reviewed layout-change anchor even though the instruction and call counts remain identical.",
    "The static script-variable initializer is an exact no-op in both builds. It remains a useful boundary because the following target functions are the client-variable link helpers, not part of the player-list initializer.",
    "All three target functions are already named with obfuscated non-default symbols. The v18_ aliases add the readable 1.8 role without pretending that an original Spectron source symbol was recovered.",
]


SOURCE_TARGETS = {
    0x2081E4: 0x20E380,
    0x208310: 0x20E4AC,
    0x208340: 0x20E4DC,
}

EXPECTED_SOURCE_NAMES = {
    0x2081E4: "TPlayerList_setStaffGuilds_TString_const",
    0x208310: "TPlayerList_initStaticVars_void",
    0x208340: "TPlayerList_initStaticScriptVars_void",
}

EXPECTED_TARGET_NAMES = {
    0x20E380: "_ZN10y3t2LaCUH110UpiB7az6Z_ERK10C8THgaTQxF",
    0x20E4AC: "_Z10LG6O2aDeCZv",
    0x20E4DC: "_Z10ZdoB2ay_3Nv",
}

EXACT_SHAPE_SOURCE_EAS = {0x2081E4, 0x208340}


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
    for order, (source_ea, target_ea) in enumerate(SOURCE_TARGETS.items(), 1):
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != EXPECTED_SOURCE_NAMES[source_ea]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != EXPECTED_TARGET_NAMES[target_ea]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        expected_shape_equal = source_ea in EXACT_SHAPE_SOURCE_EAS
        if shape_equal != expected_shape_equal:
            raise ValueError("unexpected player-list shape result at 0x%x" % source_ea)
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
                "match_kind": "manual-player-list-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "player-list support method %s" % source["name"],
                "context_group": "TPlayerList residual support block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_player_list_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TPlayerList support block",
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
            "source_sequence": "0x2081e4 TPlayerList_setStaffGuilds through 0x208340 TPlayerList_initStaticScriptVars",
            "target_sequence": "0x20e380 setter, 0x20e4ac static initializer, and 0x20e4dc static script initializer",
            "source_class": "TPlayerList",
            "target_class": "y3t2LaCUH1",
            "target_only_boundaries": ["0x20e458 TGraalVar_initLinks_void and its internal labels"],
            "following_target_boundary": "0x20e4e0 client-socket lock helper",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source player-list roles while retaining the target obfuscated names in the evidence rows.",
            "The static initializer is a layout-change anchor because the target object allocation grows from 0x18 to 0x20 bytes. The setter and no-op script initializer are exact normalized-shape matches.",
            "The following client-socket lock helper is kept as a separate reviewed boundary for the next residual batch.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
