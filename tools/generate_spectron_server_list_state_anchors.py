#!/usr/bin/env python3
"""Create reviewed exact-shape anchors for small server-list state methods."""

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
        "original_ea": 0x202A38,
        "original_name": "TServerList_setRemoveVarsOnLogout",
        "spectron_ea": 0x2082B0,
        "spectron_name": "sub_2082B0",
        "source_basis": "remove-vars-on-logout boolean setter",
        "target_global": "xiYWfajld1::x7tqLaYXTv",
        "target_reference": None,
        "context_order": 1,
    },
    {
        "original_ea": 0x202A48,
        "original_name": "TServerList_getAllowLoginReconnect",
        "spectron_ea": 0x2082C0,
        "spectron_name": "sub_2082C0",
        "source_basis": "allow-login-reconnect boolean getter",
        "target_global": "xiYWfajld1::mLqqLax7Qv",
        "target_reference": "0x2082d0",
        "context_order": 2,
    },
    {
        "original_ea": 0x202A78,
        "original_name": "TServerList_setServerStartParams",
        "spectron_ea": 0x2082F0,
        "spectron_name": "sub_2082F0",
        "source_basis": "server-start parameter setter",
        "target_global": "xiYWfajld1::OcLpLarkhv",
        "target_reference": "0x208318",
        "context_order": 3,
    },
    {
        "original_ea": 0x202A8C,
        "original_name": "TServerList_setServerStartConnect",
        "spectron_ea": 0x208304,
        "spectron_name": "sub_208304",
        "source_basis": "server-start connection setter",
        "target_global": "xiYWfajld1::Jq54MaebUU",
        "target_reference": "0x208350",
        "context_order": 4,
    },
)


EVIDENCE = [
    "The source and target methods are adjacent within their respective TServerList or xiYWfajld1 state clusters, and all four target names were default IDA sub_ labels before this pass.",
    "The source and target feature records match across size, instruction count, basic blocks, branches, calls, returns, mnemonic hash, opcode shape, register shape, normalized shape, and string-reference hash for every row.",
    "The target method at 0x2082b0 stores xiYWfajld1::x7tqLaYXTv, matching the source remove-vars-on-logout setter role.",
    "The target getter at 0x2082c0 returns xiYWfajld1::mLqqLax7Qv. The already translated target setter at 0x2082d0 writes that same global and resets the related pre-login reconnect counter.",
    "The target methods at 0x2082f0 and 0x208304 assign xiYWfajld1::OcLpLarkhv and xiYWfajld1::Jq54MaebUU. The v178 getter anchors at 0x208318 and 0x208350 read those same globals, providing an independent setter/getter check.",
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
        if not target.get("is_default_name"):
            raise ValueError("target must be a default IDA name at 0x%x" % target_ea)
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("server-list state row is already in the semantic map")
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        if source_metrics != target_metrics:
            raise ValueError("exact-shape mismatch at 0x%x" % source_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected string references at 0x%x" % source_ea)

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
                "match_kind": "manual-server-list-state-exact-shape-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_class": "xiYWfajld1",
                "target_global": spec["target_global"],
                "target_reference": spec["target_reference"],
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_list_state_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for small server-list state accessors and setters",
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
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_cluster": "0x202a38 through 0x202aa0",
            "spectron_cluster": "0x2082b0 through 0x208318",
            "target_class": "xiYWfajld1",
            "existing_context": {
                "source_setAllowLoginReconnect": "0x202a58",
                "spectron_setAllowLoginReconnect": "0x2082d0",
                "source_start_params_getter": "0x202aa0",
                "spectron_start_params_getter": "0x208318",
                "source_start_connect_getter": "0x202ad8",
                "spectron_start_connect_getter": "0x208350",
            },
            "layout_change": "No layout change was observed in this four-row exact-shape group.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "All four source and target feature records match across the complete normalized metric set used by this generator.",
            "The target global and neighboring setter/getter references are retained so the small methods remain tied to the wider server-list state model.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
