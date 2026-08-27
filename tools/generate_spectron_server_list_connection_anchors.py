#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron server-list handoff cluster."""

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
        "original_ea": 0x202AA0,
        "original_name": "TServerList_getServerStartParams",
        "spectron_ea": 0x208318,
        "spectron_name": "sub_208318",
        "source_basis": "server-start parameter getter",
        "target_global": "xiYWfajld1::OcLpLarkhv",
        "target_setter": "0x2082f0",
        "context_order": 1,
        "match_kind": "manual-server-list-exact-shape-anchor",
    },
    {
        "original_ea": 0x202AD8,
        "original_name": "TServerList_getServerStartConnect",
        "spectron_ea": 0x208350,
        "spectron_name": "sub_208350",
        "source_basis": "server-start connection getter",
        "target_global": "xiYWfajld1::Jq54MaebUU",
        "target_setter": "0x208304",
        "context_order": 2,
        "match_kind": "manual-server-list-exact-shape-anchor",
    },
    {
        "original_ea": 0x202B10,
        "original_name": "TServerList_getServerName",
        "spectron_ea": 0x208388,
        "spectron_name": "sub_208388",
        "source_basis": "server-name getter",
        "target_global": "xiYWfajld1::VoXXfaKA21",
        "target_setter": "0x20a1f4",
        "context_order": 3,
        "match_kind": "manual-server-list-exact-shape-anchor",
    },
    {
        "original_ea": 0x202B48,
        "original_name": "TServerList_getServerNameCopy",
        "spectron_ea": 0x2083C0,
        "spectron_name": "sub_2083C0",
        "source_basis": "script callback ABI server-name copy",
        "target_global": "xiYWfajld1::VoXXfaKA21",
        "target_setter": "0x20a1f4",
        "context_order": 4,
        "match_kind": "manual-server-list-exact-shape-anchor",
    },
    {
        "original_ea": 0x202F30,
        "original_name": "TServerList_setConnectionAttributes_TString_const_TString_const_int",
        "spectron_ea": 0x20A1F4,
        "spectron_name": "_ZN10xiYWfajld110iVlvLaT2ZzERK10C8THgaTQxFS2_i",
        "source_basis": "server connection attribute handoff and local-player restart",
        "target_global": "xiYWfajld1::VoXXfaKA21",
        "target_setter": None,
        "context_order": 5,
        "match_kind": "manual-server-list-layout-context-anchor",
    },
)


EVIDENCE = [
    "The source getter cluster contains four 56-byte, 14-instruction, one-block TString copy helpers. The target contains four functions with the same normalized metrics and the same register-shape hash.",
    "The target getter at 0x208318 copies xiYWfajld1::OcLpLarkhv, and the target setter at 0x2082f0 writes that same global. This identifies the source server-start-parameters getter without relying on an address delta.",
    "The target getter at 0x208350 copies xiYWfajld1::Jq54MaebUU, and the target setter at 0x208304 writes that same global. This identifies the source server-start-connect getter.",
    "The target getters at 0x208388 and 0x2083c0 both copy xiYWfajld1::VoXXfaKA21. The large target handoff method writes that global from its normalized server-name argument and later uses it for the main-window application identifier fallback.",
    "The source handoff normalizes the server name, stores the server name and address, parses the port, records restart state, loads tile definitions, initializes local players, starts their levels, and updates the main-window identifier. The target preserves that sequence with xiYWfajld1, C8THgaTQxF, W6NzgawMJy, and QYZugaRKGu helpers.",
    "The target handoff retains the distinctive GPFDGfY4 string and the same two local-player passes, but has a larger body and different helper names and field layout. It is therefore recorded as a high-confidence semantic layout anchor rather than an exact normalized-shape match.",
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
            raise ValueError("server-list row is already in the semantic map")

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        shape_equal = source_metrics == target_metrics
        if spec["context_order"] <= 4 and not shape_equal:
            raise ValueError("getter shape mismatch at 0x%x" % source_ea)
        if spec["context_order"] == 5:
            if shape_equal:
                raise ValueError("handoff unexpectedly has an exact normalized shape")
            if "GPFDGfY4" not in target.get("string_refs", []):
                raise ValueError("handoff is missing the GPFDGfY4 target string")
        if spec["context_order"] <= 4 and "GPFDGfY4" in target.get("string_refs", []):
            raise ValueError("getter unexpectedly references GPFDGfY4")

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
                "target_class": "xiYWfajld1",
                "target_global": spec["target_global"],
                "target_setter": spec["target_setter"],
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_list_connection_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for server-list getters and connection handoff",
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
            "source_getter_cluster": "0x202aa0 through 0x202b80",
            "spectron_getter_cluster": "0x208318 through 0x2083f8",
            "target_class": "xiYWfajld1",
            "target_global_pairs": {
                "0x2082f0 -> 0x208318": "xiYWfajld1::OcLpLarkhv",
                "0x208304 -> 0x208350": "xiYWfajld1::Jq54MaebUU",
                "0x20a1f4 -> 0x208388 and 0x2083c0": "xiYWfajld1::VoXXfaKA21",
            },
            "layout_change": "The four getter pairs retain the complete normalized feature shape. The connection handoff is larger in Spectron and uses target-only helper classes and fields, while preserving the server-name, address, port, restart, tile, local-player, and window-identifier responsibilities.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The four getter labels are exact normalized-shape matches and are additionally tied to target setter/global pairs.",
            "The connection handoff label is a high-confidence semantic overlay. Its target body has a different layout and helper vocabulary, so no exact body equivalence is claimed.",
            "The target class and global names remain in the evidence so later work can refine the server-list object model without losing the original obfuscated identifiers.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
