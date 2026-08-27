#!/usr/bin/env python3
"""Create reviewed exact-shape anchors for a GSFunctionsClient batch.

This batch uses the client callback tables as the primary correspondence.
The callback pointer field relocates by ``+0x13010`` between the 1.8 and
Spectron libraries.  Normalized instruction and control-flow fingerprints
are then checked before an anchor is emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "Each source row is a GSFunctionsClient callback referenced by a pointer field in the 1.8 client callback table.",
    "For every row in this batch, the corresponding Spectron table field is exactly the source field plus 0x13010, and it contains the proposed target function address.",
    "The rows are ordered by their source table position and cover small getters, state accessors, image accessors, and weapon controls. Their script-facing names provide the role, while the table relocation ties that role to the target callback.",
    "All normalized fingerprints match: size, instruction count, basic-block count, branch count, call count, mnemonic sequence, opcode shape, register shape, and overall shape.",
    "These are reviewed semantic correspondences, not claims that Spectron retained the original debug symbols. The v18_ prefix keeps the source role visible without replacing the target binary's identity.",
]


ROWS = (
    (0x156594, "GSFunctionsClient_get_allfeatures", 0x1593BC, "sub_1593BC", 0x3782A8),
    (0x15659C, "GSFunctionsClient_get_allrenderobjecttypes", 0x1593C4, "sub_1593C4", 0x3782D8),
    (0x1565A4, "GSFunctionsClient_get_allstats", 0x1593CC, "sub_1593CC", 0x378308),
    (0x1565E4, "GSFunctionsClient_get_carriesnpc", 0x15940C, "sub_15940C", 0x378368),
    (0x156B40, "GSFunctionsClient_get_graalversion", 0x159968, "sub_159968", 0x3785A8),
    (0x156B50, "GSFunctionsClient_get_isopengl", 0x159978, "sub_159978", 0x3785D8),
    (0x156B58, "GSFunctionsClient_get_gravity", 0x159980, "sub_159980", 0x378608),
    (0x156B68, "GSFunctionsClient_set_gravity", 0x159990, "sub_159990", 0x378610),
    (0x156C48, "GSFunctionsClient_get_isonmap", 0x159A70, "sub_159A70", 0x378698),
    (0x156C70, "GSFunctionsClient_get_middlemousebuttonglobal", 0x159A98, "sub_159A98", 0x3787E8),
    (0x156C80, "GSFunctionsClient_get_mousewheeldelta", 0x159AA8, "sub_159AA8", 0x3788A8),
    (0x156DB8, "GSFunctionsClient_get_scriptedcontrols", 0x159BE0, "sub_159BE0", 0x378A28),
    (0x156DC8, "GSFunctionsClient_get_scriptedplayerlist", 0x159BF0, "sub_159BF0", 0x378A58),
    (0x156DD0, "GSFunctionsClient_get_selectedsword", 0x159BF8, "sub_159BF8", 0x378A88),
    (0x156DF0, "GSFunctionsClient_get_selectedweapon", 0x159C18, "sub_159C18", 0x378AB8),
    (0x156F40, "GSFunctionsClient_get_weapons", 0x159D68, "sub_159D68", 0x378BD8),
    (0x156F60, "GSFunctionsClient_get_weaponsenabled", 0x159D88, "sub_159D88", 0x378C08),
    (0x156FA4, "GSFunctionsClient_set_weaponsenabled", 0x159DCC, "sub_159DCC", 0x378C10),
    (0x157008, "GSFunctionsClient_set_statusimage", 0x159E30, "sub_159E30", 0x378B20),
    (0x15701C, "GSFunctionsClient_set_spritesimage", 0x159E44, "sub_159E44", 0x378AF0),
)

METRIC_FIELDS = (
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


def existing_manual_sources(root: Path, excluded: Path | None = None) -> set[int]:
    result = set()
    for path in root.glob("*.json"):
        if excluded is not None and path.resolve() == excluded.resolve():
            continue
        try:
            document = load(path)
        except (OSError, json.JSONDecodeError):
            continue
        for anchor in document.get("anchors", []):
            try:
                result.add(int(anchor["original_ea"], 16))
            except (KeyError, TypeError, ValueError):
                continue
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
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
    manual_source_eas = existing_manual_sources(args.artifact_root)

    anchors = []
    for order, (source_ea, source_name, target_ea, target_name, source_table_ea) in enumerate(ROWS, 1):
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != source_name:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != target_name:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas or source_ea in manual_source_eas:
            raise ValueError("source is already anchored at 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in METRIC_FIELDS)
        if not shape_equal:
            raise ValueError("unexpected GSFunctionsClient shape result at 0x%x" % source_ea)
        target_table_ea = source_table_ea + 0x13010
        row = {
            "original_ea": source["ea"],
            "original_name": source["name"],
            "original_metrics": metrics(source),
            "original_string_refs": source.get("string_refs", []),
            "original_direct_call_names": source.get("direct_call_names", []),
            "original_table_pointer_field": "0x%x" % source_table_ea,
            "spectron_ea": "0x%x" % target_ea,
            "spectron_current_name": target["name"],
            "spectron_default_name": target.get("is_default_name", False),
            "spectron_metrics": metrics(target),
            "spectron_string_refs": target.get("string_refs", []),
            "spectron_direct_call_names": target.get("direct_call_names", []),
            "spectron_table_pointer_field": "0x%x" % target_table_ea,
            "table_pointer_delta": "+0x13010",
            "table_pointer_value_verified": "0x%x" % target_ea,
            "proposed_name": "v18_" + source["name"],
            "confidence": "high",
            "match_kind": "manual-gsfunctions-client-table-relocation-exact-shape",
            "semantic_match_already_present": False,
            "source_basis": "GSFunctionsClient callback table role %s" % source["name"],
            "context_group": "GSFunctionsClient exact residual callback batch",
            "context_order": order,
            "target_delta": "+0x%x" % (target_ea - source_ea),
            "evidence": EVIDENCE,
            "name_action": "rename-with-v18-prefix",
            "shape_equal": shape_equal,
        }
        anchors.append(row)

    result = {
        "schema_version": 1,
        "artifact": "spectron_gsfunctions_client_exact_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for an exact-shape GSFunctionsClient callback batch",
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
            "materialized_target_function_count": 0,
        },
        "context": {
            "source_table_range": "0x3782a8 through 0x378c10, with the rows kept in source table order",
            "target_table_range": "0x38b2b8 through 0x38bc20, obtained by the verified +0x13010 relocation",
            "source_class": "GSFunctionsClient callback table",
            "target_class": "obfuscated Spectron GSFunctionsClient callback table",
            "coverage": "small getters, state accessors, image accessors, and weapon controls",
            "following_work": "callbacks whose target code is merged into a neighboring function remain review-only until their raw boundaries are materialized",
        },
        "anchors": anchors,
        "interpretation": [
            "The table relocation is the primary correspondence and the normalized shape match is an independent check.",
            "The proposed v18_ labels preserve the readable 1.8 client roles while retaining the target names in the evidence rows.",
            "No target function boundaries were created in this batch because all twenty target addresses were already separate IDA functions.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
