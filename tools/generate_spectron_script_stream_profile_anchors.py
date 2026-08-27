#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's script stream and profile methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


GROUP_EVIDENCE = {
    "set_stream": [
        "Both methods reset the script object, build a temporary string list, parse the script byte stream, decode class and function records, recognize the `public.` marker, parse parameter types, add functions, and finish by notifying the script object that it was updated.",
        "The source is 2,380 bytes, 594 instructions, and 110 blocks. The target is 2,400 bytes, 599 instructions, and 110 blocks. Both make 67 calls and retain the `public.` string reference.",
        "The target is the class-local `zW2NgaU4IK` method that occupies the same script-parser role. Its C8THgaTQxF and vuuHgangcF wrappers replace the readable 1.8 helper names, while the bytecode walk and function-registration branches remain aligned.",
    ],
    "print_profiles": [
        "Both methods check the output list and profiling state, compute elapsed time, clear stale profile data, iterate function profiles, format percentages, sort and append the results, and then emit nested class and function profile lines beginning with `Class `.",
        "The source is 1,092 bytes, 272 instructions, and 24 blocks with 59 calls. The target is 1,176 bytes, 293 instructions, and 24 blocks with 65 calls. The target keeps the `Class ` reference but does not expose the source's separate ` %` literal as a string reference.",
        "The target uses long-double temporaries and rebuilt string, list, hash, and iterator wrappers for the same profiler calculation. The missing standalone percent literal is recorded as a target build or decompiler difference, not treated as contradictory evidence.",
    ],
}


ANCHOR_SPECS = [
    {
        "original_ea": "0x21624c",
        "original_name": "TScript_setStream_TString_const",
        "spectron_ea": "0x21cfb8",
        "target_name": "_ZN10zW2NgaU4IK10pKjZfaKdc3ERK10C8THgaTQxF",
        "target_class": "zW2NgaU4IK",
        "proposed_name": "v18_TScript_setStream_TString_const",
        "source_metrics": (2380, 594, 110),
        "target_metrics": (2400, 599, 110),
        "source_call_count": 67,
        "target_call_count": 67,
        "source_string_refs": ("public.",),
        "target_string_refs": ("public.",),
        "group": "set_stream",
        "source_basis": "script bytecode stream parsing and function registration",
    },
    {
        "original_ea": "0x217168",
        "original_name": "TScript_printFunctionProfiles_TStringList_TString_const",
        "spectron_ea": "0x21e058",
        "target_name": "_ZN10zW2NgaU4IK10JkKVfa5Ab0EP10vuuHgangcFRK10C8THgaTQxF",
        "target_class": "zW2NgaU4IK",
        "proposed_name": "v18_TScript_printFunctionProfiles_TStringList_TString_const",
        "source_metrics": (1092, 272, 24),
        "target_metrics": (1176, 293, 24),
        "source_call_count": 59,
        "target_call_count": 65,
        "source_string_refs": (" %", "Class "),
        "target_string_refs": ("Class ",),
        "group": "print_profiles",
        "source_basis": "script function and class profiler output",
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
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
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
        if spec["target_class"] not in target["name"]:
            raise ValueError(
                "target %s is not in the expected TScript class"
                % spec["spectron_ea"]
            )
        for side, function in (("source", source), ("target", target)):
            expected = spec["%s_metrics" % side]
            actual = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual != expected:
                raise ValueError(
                    "unexpected %s metrics at %s: %s"
                    % (side, spec["%s_ea" % side], actual)
                )
            expected_calls = spec["%s_call_count" % side]
            if function.get("call_count") != expected_calls:
                raise ValueError(
                    "unexpected %s call count at %s: %s"
                    % (side, spec["%s_ea" % side], function.get("call_count"))
                )
            expected_strings = list(spec["%s_string_refs" % side])
            actual_strings = function.get("string_refs", [])
            if actual_strings != expected_strings:
                raise ValueError(
                    "unexpected %s string references at %s: %s"
                    % (side, spec["%s_ea" % side], actual_strings)
                )
        if spectron_ea in semantic_targets:
            raise ValueError(
                "target %s is already present in the semantic map" % spec["spectron_ea"]
            )
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
                "match_kind": "manual-script-stream-profile-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": GROUP_EVIDENCE[spec["group"]],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script stream/profile anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in script stream/profile anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_stream_profile_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for script bytecode stream parsing and function/class profiler output",
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
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the obfuscated 2.2 names in the evidence rows.",
            "The assignments are supported by direct Hex-Rays pseudocode, matching parser and profiler behavior, equal basic-block counts within each pair, and the shared zW2NgaU4IK target class.",
            "The target's rebuilt wrappers, long-double profile temporaries, and missing standalone percent string reference are recorded as version or decompiler differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
