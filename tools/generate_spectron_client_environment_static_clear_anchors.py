#!/usr/bin/env python3
"""Create reviewed anchors for the client-environment profiler cleanup callbacks.

The source names these callbacks by the static profiler-string addresses. The
Spectron build keeps the same atexit callback positions and exact normalized
ARM64 shapes, but stores the strings in the obfuscated C8THgaTQxF class.
"""

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
        "original_ea": 0x15C620,
        "original_name": "TClientEnvironment_clearStaticString38D428",
        "spectron_ea": 0x15F678,
        "spectron_name": "sub_15F678",
        "source_static": "0x38d428",
        "spectron_static": "0x3a0ca8",
        "source_caller_ea": "0x15cf38",
        "source_caller_name": "TClientEnvironment_runTimers_void",
        "source_callsite": "0x15d060",
        "spectron_caller_ea": "0x15ff90",
        "spectron_caller_name": "v18_TClientEnvironment_runTimers_void",
        "spectron_callsite": "0x1600b8",
        "source_basis": "TClientEnvironment runTimers profiler-string atexit cleanup",
    },
    {
        "original_ea": 0x15C62C,
        "original_name": "TClientEnvironment_clearStaticString38D460",
        "spectron_ea": 0x15F684,
        "spectron_name": "sub_15F684",
        "source_static": "0x38d460",
        "spectron_static": "0x3a0ce0",
        "source_caller_ea": "0x15d224",
        "source_caller_name": "TClientEnvironment_drawGame_bool",
        "source_callsite": "0x15d304",
        "spectron_caller_ea": "0x16027c",
        "spectron_caller_name": "v18_TClientEnvironment_drawGame_bool",
        "spectron_callsite": "0x160350",
        "source_basis": "TClientEnvironment drawGame profiler-string atexit cleanup",
    },
)


EVIDENCE = [
    "The source functions are named TClientEnvironment_clearStaticString38D428 and TClientEnvironment_clearStaticString38D460. Their names identify the static TString objects at 0x38d428 and 0x38d460.",
    "The source runTimers and drawGame methods register these callbacks with atexit at 0x15d060 and 0x15d304. The corresponding Spectron methods register sub_15F678 and sub_15F684 at 0x1600b8 and 0x160350.",
    "The target functions are default-named IDA functions and each clears the matching C8THgaTQxF object at 0x3a0ca8 or 0x3a0ce0.",
    "The source and target rows have identical complete normalized ARM64 features, including size, instruction count, block and branch counts, return count, mnemonic, opcode-shape, register-shape, normalized-shape, and string-reference metrics.",
    "The two rows are resolved by their caller-local atexit position and the matching profiler-string cleanup object, not by address translation alone.",
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
    seen_targets: set[int] = set()
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
            raise ValueError("target name mismatch at 0x%x" % target_ea)
        if not target.get("is_default_name"):
            raise ValueError("target is not a default IDA name at 0x%x" % target_ea)
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("client-environment static clear row is already in the semantic map")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        if source_metrics != target_metrics:
            differing = [
                field
                for field in METRIC_FIELDS
                if source_metrics[field] != target_metrics[field]
            ]
            raise ValueError(
                "expected exact metrics for 0x%x -> 0x%x, differing fields: %s"
                % (source_ea, target_ea, ", ".join(differing))
            )
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string references at 0x%x" % source_ea)

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
                "match_kind": "manual-client-environment-static-clear-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "context_group": "client-environment profiler atexit cleanup callbacks",
                "source_static_object": spec["source_static"],
                "spectron_static_object": spec["spectron_static"],
                "source_caller_ea": spec["source_caller_ea"],
                "source_caller_name": spec["source_caller_name"],
                "source_atexit_callsite": spec["source_callsite"],
                "spectron_caller_ea": spec["spectron_caller_ea"],
                "spectron_caller_name": spec["spectron_caller_name"],
                "spectron_atexit_callsite": spec["spectron_callsite"],
                "target_class": "C8THgaTQxF",
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_environment_static_clear_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TClientEnvironment profiler-string atexit cleanup callbacks",
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
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "context": {
            "source_class": "TClientEnvironment",
            "target_class": "C8THgaTQxF",
            "source_callback_sites": ["0x15d060", "0x15d304"],
            "spectron_callback_sites": ["0x1600b8", "0x160350"],
            "resolution": "caller-local atexit registration, profiler-string object correspondence, and exact normalized ARM64 features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The aliases preserve the source callback roles while the evidence retains the obfuscated target class and default names.",
            "Both rows match the complete normalized function feature set and are valid only for the exact hashed Spectron library recorded in this artifact.",
            "The target profiler strings are represented by C8THgaTQxF objects rather than the source TString class name, but the caller registration and single-object clear behavior are unchanged.",
            "This artifact is an IDA analysis overlay only. No APK or native library was modified.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
