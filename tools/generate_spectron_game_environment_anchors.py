#!/usr/bin/env python3
"""Create reviewed anchors for the small TGameEnvironment startup helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)


ANCHOR_SPECS = (
    {
        "original_ea": 0xE9CF8,
        "original_name": "TGameEnvironment_getAllPlayersCount",
        "spectron_ea": 0xEA84C,
        "spectron_name": "sub_EA84C",
        "source_basis": "allplayerscount property getter",
        "target_property": "allplayerscount",
        "target_slot": "getter",
        "context_order": 1,
        "match_kind": "manual-game-environment-exact-shape-anchor",
    },
    {
        "original_ea": 0xE9D0C,
        "original_name": "TGameEnvironment_isPremiumVersion_void",
        "spectron_ea": 0xEA860,
        "spectron_name": "_ZN10QYZugaRKGu10JHX2IaxQ5vEv",
        "source_basis": "premium-version boolean getter",
        "target_property": "ispremiumversion",
        "target_slot": "setter",
        "context_order": 2,
        "match_kind": "manual-game-environment-exact-shape-anchor",
    },
    {
        "original_ea": 0xE9D14,
        "original_name": "TGameEnvironment_isDemoVersion_void",
        "spectron_ea": 0xEA868,
        "spectron_name": "_ZN10QYZugaRKGu10AdR2Ia3n0vEv",
        "source_basis": "demo-version boolean getter",
        "target_property": "isdemoversion",
        "target_slot": "setter",
        "context_order": 3,
        "match_kind": "manual-game-environment-exact-shape-anchor",
    },
    {
        "original_ea": 0xE9D1C,
        "original_name": "TGameEnvironment_script_adventureQuit",
        "spectron_ea": 0xEA870,
        "spectron_name": "sub_EA870",
        "source_basis": "adventure_quit script callback",
        "target_property": "adventure_quit",
        "target_slot": "setter",
        "context_order": 4,
        "match_kind": "manual-game-environment-layout-context-anchor",
    },
)


EVIDENCE = [
    "The four source methods are consecutive in the 1.8 TGameEnvironment cluster. The four target methods are consecutive in the corresponding QYZugaRKGu cluster, immediately before the already translated googleplay and premium-option helpers.",
    "The target property table decodes allplayerscount at record 0x389788 and points its getter slot to 0xEA84C. The source getter returns the current element count from TGameEnvironment::allplayers, while the target getter returns the count field from QYZugaRKGu::MgGzgaMaDy.",
    "The source premium and demo methods both return constants and are exact normalized feature matches for the target QYZugaRKGu methods at 0xEA860 and 0xEA868. The target property records decode to ispremiumversion and isdemoversion and point to those methods in their callback slot.",
    "The target property table decodes adventure_quit at record 0x3897B8 and points its callback slot to 0xEA870. The source callback writes closeapplication and returns its address. The target callback writes two target static flags, TI0CgaxdrB and rxN_IaKhrt, and returns the latter, which is a small target-version state-layout change.",
    "The first three source and target records match across all normalized feature fields. The adventure_quit callback keeps the same one-block, no-call control-flow role but expands from 20 to 36 bytes because of the additional target flag update.",
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
    return {field: function.get(field) for field in METRIC_FIELDS}


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
    semantic_sources = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        source_ea = spec["original_ea"]
        target_ea = spec["spectron_ea"]
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at 0x%x" % source_ea)
        if target.get("name") != spec["spectron_name"]:
            raise ValueError(
                "target name mismatch at 0x%x: expected %s, got %s"
                % (target_ea, spec["spectron_name"], target.get("name"))
            )
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("game-environment row is already in the semantic map")

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        shape_equal = source_metrics == target_metrics
        if spec["context_order"] < 4 and not shape_equal:
            raise ValueError("exact-shape game-environment row changed at 0x%x" % source_ea)
        if spec["context_order"] == 4 and shape_equal:
            raise ValueError("adventure_quit unexpectedly has an exact shape")

        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": "0x%x" % target_ea,
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": spec["match_kind"],
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_class": "QYZugaRKGu",
                "target_property": spec["target_property"],
                "target_slot": spec["target_slot"],
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_game_environment_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TGameEnvironment property callbacks and startup state helpers",
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
            "source_cluster": "0xe9cf8 through 0xe9d30",
            "spectron_cluster": "0xea84c through 0xea894",
            "target_class": "QYZugaRKGu",
            "target_property_records": {
                "allplayerscount": "0x389788",
                "adventure_quit": "0x3897b8",
                "ispremiumversion": "0x3897e8",
                "isdemoversion": "0x389818",
            },
            "layout_change": "The adventure_quit callback expands from 20 to 36 bytes and updates two target static flags. The count, premium, and demo helpers are exact normalized-shape matches.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the target's obfuscated names and property-table placement.",
            "The target stores the premium, demo, and adventure-quit callbacks in the setter slot of the property records. That slot is retained as evidence of registration role, not as a claim about the original C++ accessor declaration.",
            "The adventure_quit correspondence is high confidence by property-table name, local method order, control-flow role, and matching no-call structure, with the extra target flag update documented as a behavior difference.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
