#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's client-environment clock path."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "Both BuildTime methods call time, localtime, and mktime in the same order and return the normalized timestamp.",
    "Both TimeExpired methods keep the same useTimeBomb or equivalent gate, cached-not-expired gate, current-time read, BuildTime call, difftime comparison, and final state reset.",
    "The target expands the source's fixed date and fixed 15-day threshold into globals. This is a target-version behavior difference, not a reason to reject the method correspondence.",
    "The two target methods sit immediately after the already translated loading-screen methods in the same obfuscated client-environment class, and TimeExpired directly calls the newly identified target BuildTime method.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x15d3a8",
        "original_name": "TClientEnvironment_BuildTime_void",
        "spectron_ea": "0x1603f4",
        "target_name": "_ZN10a7qxJaHqKV10LvYNBatwEpEv",
        "proposed_name": "v18_TClientEnvironment_BuildTime_void",
        "source_metrics": (68, 17, 1),
        "target_metrics": (100, 25, 1),
        "source_call_count": 3,
        "target_call_count": 3,
        "required_source_calls": (".time", ".localtime", ".mktime"),
        "required_target_calls": (".time", ".localtime", ".mktime"),
        "source_behavior": "time, localtime, tm_year=119, tm_mon=1, tm_mday=13, mktime",
        "target_behavior": "time, localtime, tm_year=otezibkNfe-1900, tm_mon=ATGyibuHNd-1, tm_mday=gQsyibySBd, mktime",
        "source_basis": "client-environment build timestamp helper",
    },
    {
        "original_ea": "0x15d3ec",
        "original_name": "TClientEnvironment_TimeExpired_void",
        "spectron_ea": "0x160458",
        "target_name": "_ZN10a7qxJaHqKV10XPp3GaoluQEv",
        "proposed_name": "v18_TClientEnvironment_TimeExpired_void",
        "source_metrics": (132, 33, 5),
        "target_metrics": (164, 41, 5),
        "source_call_count": 3,
        "target_call_count": 3,
        "required_source_calls": (
            ".time",
            ".difftime",
            "plt_TClientEnvironment_BuildTime_void",
        ),
        "required_target_calls": (
            ".time",
            ".difftime",
            "._ZN10a7qxJaHqKV10LvYNBatwEpEv",
        ),
        "source_behavior": "useTimeBomb and notTimeExpired gates, difftime threshold 1296000.0 seconds",
        "target_behavior": "jfnzibtane and G7szibc7re gates, difftime threshold zvCzibh0ze*24*60*60",
        "source_basis": "client-environment time-expiry check",
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
            "mnemonic_hash",
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
        source = original.get(int(spec["original_ea"], 16))
        target = spectron.get(int(spec["spectron_ea"], 16))
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        for side, function in (("source", source), ("target", target)):
            expected_metrics = spec["%s_metrics" % side]
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual_metrics != expected_metrics:
                ea = spec["original_ea" if side == "source" else "spectron_ea"]
                raise ValueError(
                    "unexpected %s metrics at %s: %s" % (side, ea, actual_metrics)
                )
            if function.get("call_count") != spec["%s_call_count" % side]:
                ea = spec["original_ea" if side == "source" else "spectron_ea"]
                raise ValueError(
                    "unexpected %s call count at %s: %s"
                    % (side, ea, function.get("call_count"))
                )
            if function.get("string_refs", []):
                ea = spec["original_ea" if side == "source" else "spectron_ea"]
                raise ValueError(
                    "%s unexpectedly has string references at %s" % (side, ea)
                )
            for required_call in spec["required_%s_calls" % side]:
                if required_call not in function.get("direct_call_names", []):
                    ea = spec["original_ea" if side == "source" else "spectron_ea"]
                    raise ValueError(
                        "missing %s call %s at %s" % (side, required_call, ea)
                    )
        if int(spec["spectron_ea"], 16) in semantic_targets:
            raise ValueError("target is already present in the semantic map")
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_behavior": spec["source_behavior"],
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_behavior": spec["target_behavior"],
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-client-environment-clock-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_environment_clock_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for client-environment build-time and expiry helpers",
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
            "high_confidence_count": sum(
                row["confidence"] == "high" for row in anchors
            ),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the obfuscated target names and version-specific clock expressions in the evidence rows.",
            "The target's configurable date and day-count expressions are recorded as behavior differences from the fixed 1.8 date and 15-day threshold.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
