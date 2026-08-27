#!/usr/bin/env python3
"""Create a reviewed anchor for the Spectron client graphics initializer."""

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

    source_ea = 0x15CE2C
    target_ea = 0x15FE84
    source = original.get(source_ea)
    target = spectron.get(target_ea)
    if source is None or target is None:
        raise ValueError("missing source or target graphics initializer feature")
    if source.get("name") != "TClientEnvironment_initGraphics_void":
        raise ValueError("unexpected source graphics initializer name")
    if target.get("name") != "_ZN10a7qxJaHqKV10bA4tIa0sV1Ev":
        raise ValueError("unexpected target graphics initializer name")
    if source_ea in semantic_sources or target_ea in semantic_targets:
        raise ValueError("graphics initializer is already in the semantic map")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics != target_metrics:
        raise ValueError("graphics initializer feature shape changed")

    anchor = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target["ea"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-client-environment-graphics-exact-shape-anchor",
        "semantic_match_already_present": False,
        "source_basis": "client-environment graphics initialization wrapper",
        "target_class": "a7qxJaHqKV",
        "context_order": 1,
        "shape_equal": True,
        "evidence": [
            "The source method is the six-instruction wrapper immediately after TClientEnvironment_freeGraphics_void and before TClientEnvironment_updateWindowSize_void_int_int.",
            "The target method at 0x15FE84 occupies the same class-local position between the target free-graphics and window-size methods. Its obfuscated symbol is a7qxJaHqKV::bA4tIa0sV1().",
            "Both pseudocodes test the corresponding adventure or graphics object, call its initGraphics-style method only when the object is present, and return the same value when it is absent.",
            "The source and target are exact across size, instruction count, basic-block count, branch count, return count, mnemonic hash, opcode shape, register shape, normalized shape, and string-reference hash.",
        ],
        "name_action": "rename-with-v18-prefix",
    }

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_environment_graphics_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the client-environment graphics initializer",
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
            "anchor_count": 1,
            "high_confidence_count": 1,
            "already_in_semantic_map": 0,
            "new_context_anchor_count": 1,
            "exact_shape_anchor_count": 1,
            "layout_change_anchor_count": 0,
            "target_default_name_count": int(anchor["spectron_default_name"]),
        },
        "context": {
            "source_cluster": "0x15cdbc through 0x15ce44",
            "spectron_cluster": "0x15fe50 through 0x15fe9c",
            "target_class": "a7qxJaHqKV",
            "source_neighbors": {
                "free_graphics": "0x15cdf8",
                "init_graphics": "0x15ce2c",
                "update_window_size": "0x15ce44",
            },
            "spectron_neighbors": {
                "free_graphics": "0x15fe50",
                "init_graphics": "0x15fe84",
                "update_window_size": "0x15fe9c",
            },
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The proposed v18_ label preserves the readable 1.8 role while keeping the target obfuscated name in the evidence record.",
            "The exact normalized shape and class-local neighbor order make this a high-confidence translation for the hashed Spectron library named in the artifact.",
            "No native code or APK bytes are changed by generating this record.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
