#!/usr/bin/env python3
"""Create reviewed anchors for the remaining script-machine parameter path."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


GROUP_EVIDENCE = {
    "prepare_parameters": [
        "Both methods walk a function signature, convert stack values to the requested float, string, object, or array form, write the converted values back into the machine list, and pack trailing string parameters into one comma-separated value.",
        "The source has 1,072 bytes, 267 instructions, and 50 blocks. The target has 1,200 bytes, 299 instructions, and 51 blocks. The target adds an `e` parameter case and uses the rebuilt string and stack-entry wrappers.",
        "The source method ends exactly at the start of callCFunction. The target method has the same adjacency before the corresponding obfuscated mTAogaaEip call-dispatch routine.",
    ],
    "call_c_function": [
        "Both methods decode the same format characters, fetch arguments from the script-machine list, convert integer and boolean values, read object values, and dispatch the native callback with up to twelve converted parameters.",
        "The source has 2,496 bytes, 618 instructions, and 100 blocks. The target has 3,412 bytes, 847 instructions, and 124 blocks. The target adds a guarded static string workspace and an `e` format branch, which explains the larger body.",
        "The source and target are contiguous after their parameter-preparation methods and immediately before the suspend-after-call helper. The target retains the same result-slot update after each callback family and the same object and string conversion boundaries.",
    ],
}


ANCHOR_SPECS = [
    {
        "original_ea": "0x21acac",
        "original_name": "TScriptMachine_prepareFunctionParameters_TString_const_int",
        "spectron_ea": "0x222924",
        "target_name": "_ZN10mTAogaaEip10F2qFPaZmt4ERK10C8THgaTQxFi",
        "proposed_name": "v18_TScriptMachine_prepareFunctionParameters_TString_const_int",
        "source_metrics": (1072, 267, 50),
        "target_metrics": (1200, 299, 51),
        "source_call_count": 29,
        "target_call_count": 38,
        "group": "prepare_parameters",
        "source_basis": "script-machine parameter conversion and packing",
    },
    {
        "original_ea": "0x21b0dc",
        "original_name": "TScriptMachine_callCFunction_TGraalVar_TString_const_void_char_char_const_int",
        "spectron_ea": "0x222dd4",
        "target_name": "_ZN10mTAogaaEip10icnYOaW7ouEP10G0gxgajWBwRK10CanTfaz6bZPvcPKci",
        "proposed_name": "v18_TScriptMachine_callCFunction_TGraalVar_TString_const_void_char_char_const_int",
        "source_metrics": (2496, 618, 100),
        "target_metrics": (3412, 847, 124),
        "source_call_count": 49,
        "target_call_count": 71,
        "group": "call_c_function",
        "source_basis": "native callback format decoding and dispatch",
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
    functions = {}
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
        if spectron_ea in semantic_targets:
            raise ValueError("target %s is already present in the semantic map" % spec["spectron_ea"])
        functions[spec["original_name"]] = (source, target)
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
                "match_kind": "manual-script-machine-tail-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": GROUP_EVIDENCE[spec["group"]],
                "name_action": "rename-with-v18-prefix",
            }
        )

    prepare_source, prepare_target = functions[
        "TScriptMachine_prepareFunctionParameters_TString_const_int"
    ]
    call_source, call_target = functions[
        "TScriptMachine_callCFunction_TGraalVar_TString_const_void_char_char_const_int"
    ]
    if prepare_source.get("end_ea") != call_source.get("ea"):
        raise ValueError("source parameter and callback methods are not adjacent")
    if prepare_target.get("end_ea") != call_target.get("ea"):
        raise ValueError("target parameter and callback methods are not adjacent")

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in script-machine tail anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in script-machine tail anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_machine_tail_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for script-machine parameter preparation and native callback dispatch",
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
            "The assignments are supported by direct Hex-Rays pseudocode, contiguous method boundaries, matching stack and callback behavior, and target wrapper differences that are recorded rather than hidden.",
            "Changed byte sizes, instruction counts, call counts, and basic-block counts are version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
