#!/usr/bin/env python3
"""Create reviewed anchors for the residual URL-cache support block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source URL-cache rows are TURLCache_addURL at 0x207d24, TURLCache_initStaticVars at 0x207ebc, TURLCache_load at 0x207eec, and the TURLCacheEntry destructor pair at 0x20815c and 0x20819c. Spectron preserves their local roles at 0x20de90, 0x20e054, 0x20e084, 0x20e2f8, and 0x20e338.",
    "addURL still rejects .code files, looks up the URL in the cache hash list, creates a 0x18-byte entry when absent, stores the local file path, and schedules a cache save. Spectron exposes the same operations through uK2SHaPVVw, C8THgaTQxF, KKhLga4xoI, CanTfaz6bZ, and J7zOgaf09K wrappers.",
    "The URL-cache static initializer still allocates and publishes the 0x28-byte cache hash list, with an exact normalized-shape match. load still builds the base-folder URLCACHE.txt path, loads each line, splits the two fields, and calls addURL for valid entries.",
    "The TURLCacheEntry complete destructor clears both embedded string fields and restores both vtable layers. The deleting destructor performs the same cleanup and calls operator delete. The target uK2SHaPVVw::S5XSHaIaRw D2 and D0 rows have exact normalized shapes.",
    "addURL changes from 272/68/10/18/11 to 316/79/10/20/13. load changes from 288/72/6/16/15 to 292/73/6/16/15. The extra target operations are wrapper and temporary-value expansions, while the URLCACHE.txt and .code behavior remains visible.",
]


SOURCE_TARGETS = {
    0x207D24: 0x20DE90,
    0x207EBC: 0x20E054,
    0x207EEC: 0x20E084,
    0x20815C: 0x20E2F8,
    0x20819C: 0x20E338,
}

EXPECTED_SOURCE_NAMES = {
    0x207D24: "TURLCache_addURL_TString_const_TString_const",
    0x207EBC: "TURLCache_initStaticVars_void",
    0x207EEC: "TURLCache_load_void",
    0x20815C: "TURLCache_TURLCacheEntry_TURLCacheEntry",
    0x20819C: "TURLCache_TURLCacheEntry_TURLCacheEntry__2",
}

EXPECTED_TARGET_NAMES = {
    0x20DE90: "_ZN10uK2SHaPVVw10btKSHa7HFwERK10C8THgaTQxFS2_",
    0x20E054: "_Z10IMaXHaJGoAv",
    0x20E084: "_ZN10uK2SHaPVVw4loadEv",
    0x20E2F8: "_ZN10uK2SHaPVVw10S5XSHaIaRwD2Ev",
    0x20E338: "_ZN10uK2SHaPVVw10S5XSHaIaRwD0Ev",
}

EXACT_SHAPE_SOURCE_EAS = {0x207EBC, 0x20815C, 0x20819C}


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
            raise ValueError("unexpected URL-cache shape result at 0x%x" % source_ea)
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
                "match_kind": "manual-url-cache-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "URL-cache support method %s" % source["name"],
                "context_group": "URL-cache residual support block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_url_cache_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual URL-cache support block",
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
            "source_sequence": "0x207d24 addURL through 0x20819c TURLCacheEntry deleting destructor",
            "target_sequence": "0x20de90 addURL, 0x20e054 initializer, 0x20e084 load, and 0x20e2f8 through 0x20e338 entry destructors",
            "source_class": "TURLCache and TURLCacheEntry",
            "target_class": "uK2SHaPVVw and S5XSHaIaRw",
            "target_only_boundaries": ["0x20de04 mapped getURLModTime", "0x20dfcc mapped removeURL", "0x20e1a8 mapped checkSave"],
            "following_target_boundary": "0x20e380",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source URL-cache roles while retaining the target obfuscated class names in the evidence rows.",
            "addURL and load are layout-change anchors because target wrappers and temporary values expand their bodies. The static initializer and cache-entry destructors are exact normalized-shape matches.",
            "Existing getURLModTime, scheduleSave, removeURL, and checkSave anchors remain explicit neighboring boundaries.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
