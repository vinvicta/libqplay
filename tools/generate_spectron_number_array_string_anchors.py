#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's templated numeric-array string path."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


GROUP_EVIDENCE = {
    "set_string": [
        "Both methods convert the input string to a number, load the array's virtual string setter, and dispatch the value at the requested index. The target's `nak8fakACb` helper is the rebuilt equivalent of the source `strtofloat` call.",
        "Both bodies are exactly 64 bytes, 16 instructions, and 1 block with 2 calls and no string references. The same method is present in both the double and short template instantiations.",
        "The target class is `PfQXva4zXuIdE` for double or `PfQXva4zXuIsE` for short, and the target keeps the same virtual setter slot and argument order.",
    ],
    "indexed_string": [
        "Both methods call the array's indexed numeric getter, initialize a result string, and format that value through the numeric string insertion operator. The target materializes a temporary C8THgaTQxF object before assigning the result.",
        "The source is 52 bytes, 13 instructions, and 1 block with 2 calls. Each target is 88 bytes, 22 instructions, and 1 block with 4 calls because the rebuilt string wrapper makes the temporary explicit.",
        "The same `J89mga585nEi` target method is used by the double and short template instantiations, which matches the source pair's shared indexed-string implementation.",
    ],
    "read_string": [
        "Both methods walk the numeric array using the stored count and data pointer, append each element to a result string, and insert commas between elements. The double target uses the double formatter and the short target uses the integer formatter, matching their source element types.",
        "Each source read method is 132 bytes, 33 instructions, and 5 blocks with 2 calls. The double target is 164 bytes, 41 instructions, and 6 blocks with 4 calls, while the short target has the same 164/41/6 shape.",
        "The target's `VkenganG9n` methods expose a long-double or integer temporary and assign a rebuilt string wrapper at the end. The array count, data stride, loop condition, and comma branch remain the same.",
    ],
    "write_string": [
        "Both methods split the input string into a temporary string list, iterate over every element, and call the array's virtual string setter with the corresponding index before releasing the temporary list.",
        "Each source write method is 164 bytes, 41 instructions, and 3 blocks with 6 calls. Each target is 208 bytes, 52 instructions, and 3 blocks with 10 calls because C8THgaTQxF and vuuHgangcF wrapper operations are explicit.",
        "The same `m6pngaXzjo` target method is used by the double and short template instantiations, preserving the source pair's shared write-string algorithm and virtual setter slot.",
    ],
}


ANCHOR_SPECS = [
    {
        "original_ea": "0x18a318",
        "original_name": "TNumberArrayVar_double_setArrayCellString_int_TString_const",
        "spectron_ea": "0x18eb08",
        "target_name": "_ZN10PfQXva4zXuIdE10VBZsMaAr_nEiRK10C8THgaTQxF",
        "template": "PfQXva4zXuIdE",
        "proposed_name": "v18_TNumberArrayVar_double_setArrayCellString_int_TString_const",
        "source_metrics": (64, 16, 1),
        "target_metrics": (64, 16, 1),
        "source_call_count": 2,
        "target_call_count": 2,
        "required_source_calls": ("plt_strtofloat_TString_const",),
        "required_target_calls": ("._Z10nak8fakACbRK10C8THgaTQxF",),
        "group": "set_string",
        "source_basis": "double numeric array indexed string setter",
    },
    {
        "original_ea": "0x18a440",
        "original_name": "TNumberArrayVar_double_getArrayCellString_int",
        "spectron_ea": "0x18ebac",
        "target_name": "_ZN10PfQXva4zXuIdE10J89mga585nEi",
        "template": "PfQXva4zXuIdE",
        "proposed_name": "v18_TNumberArrayVar_double_getArrayCellString_int",
        "source_metrics": (52, 13, 1),
        "target_metrics": (88, 22, 1),
        "source_call_count": 2,
        "target_call_count": 4,
        "required_source_calls": ("plt_TString_operator_lshift_double",),
        "required_target_calls": (
            "._ZN10C8THgaTQxFlsEd",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
        ),
        "group": "indexed_string",
        "source_basis": "double numeric array indexed string read",
    },
    {
        "original_ea": "0x18a3bc",
        "original_name": "TNumberArrayVar_double_readString_void",
        "spectron_ea": "0x18ec04",
        "target_name": "_ZN10PfQXva4zXuIdE10VkenganG9nEv",
        "template": "PfQXva4zXuIdE",
        "proposed_name": "v18_TNumberArrayVar_double_readString_void",
        "source_metrics": (132, 33, 5),
        "target_metrics": (164, 41, 6),
        "source_call_count": 2,
        "target_call_count": 4,
        "required_source_calls": (
            "plt_TString_operator_lshift_char",
            "plt_TString_operator_lshift_double",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxFlsEc",
            "._ZN10C8THgaTQxFlsEd",
        ),
        "group": "read_string",
        "source_basis": "double numeric array comma-separated string read",
    },
    {
        "original_ea": "0x18a474",
        "original_name": "TNumberArrayVar_double_writeString_TString_const",
        "spectron_ea": "0x18eca8",
        "target_name": "_ZN10PfQXva4zXuIdE10m6pngaXzjoERK10CanTfaz6bZ",
        "template": "PfQXva4zXuIdE",
        "proposed_name": "v18_TNumberArrayVar_double_writeString_TString_const",
        "source_metrics": (164, 41, 3),
        "target_metrics": (208, 52, 3),
        "source_call_count": 6,
        "target_call_count": 10,
        "required_source_calls": (
            "plt_TStringList_TStringList_TString_const",
            "plt_TStringList_operator_index_int",
        ),
        "required_target_calls": (
            "._ZN10vuuHgangcFC2ERK10C8THgaTQxFb",
            "._ZNK10vuuHgangcFixEi",
        ),
        "group": "write_string",
        "source_basis": "double numeric array string-list write",
    },
    {
        "original_ea": "0x1abb50",
        "original_name": "TNumberArrayVar_short_setArrayCellString_int_TString_const",
        "spectron_ea": "0x1afca0",
        "target_name": "_ZN10PfQXva4zXuIsE10VBZsMaAr_nEiRK10C8THgaTQxF",
        "template": "PfQXva4zXuIsE",
        "proposed_name": "v18_TNumberArrayVar_short_setArrayCellString_int_TString_const",
        "source_metrics": (64, 16, 1),
        "target_metrics": (64, 16, 1),
        "source_call_count": 2,
        "target_call_count": 2,
        "required_source_calls": ("plt_strtofloat_TString_const",),
        "required_target_calls": ("._Z10nak8fakACbRK10C8THgaTQxF",),
        "group": "set_string",
        "source_basis": "short numeric array indexed string setter",
    },
    {
        "original_ea": "0x1abd28",
        "original_name": "TNumberArrayVar_short_getArrayCellString_int",
        "spectron_ea": "0x1afe78",
        "target_name": "_ZN10PfQXva4zXuIsE10J89mga585nEi",
        "template": "PfQXva4zXuIsE",
        "proposed_name": "v18_TNumberArrayVar_short_getArrayCellString_int",
        "source_metrics": (52, 13, 1),
        "target_metrics": (88, 22, 1),
        "source_call_count": 2,
        "target_call_count": 4,
        "required_source_calls": ("plt_TString_operator_lshift_double",),
        "required_target_calls": (
            "._ZN10C8THgaTQxFlsEd",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
        ),
        "group": "indexed_string",
        "source_basis": "short numeric array indexed string read",
    },
    {
        "original_ea": "0x1abe00",
        "original_name": "TNumberArrayVar_short_readString_void",
        "spectron_ea": "0x1affa0",
        "target_name": "_ZN10PfQXva4zXuIsE10VkenganG9nEv",
        "template": "PfQXva4zXuIsE",
        "proposed_name": "v18_TNumberArrayVar_short_readString_void",
        "source_metrics": (132, 33, 5),
        "target_metrics": (164, 41, 6),
        "source_call_count": 2,
        "target_call_count": 4,
        "required_source_calls": (
            "plt_TString_operator_lshift_char",
            "plt_TString_operator_lshift_int",
        ),
        "required_target_calls": (
            "._ZN10C8THgaTQxFlsEc",
            "._ZN10C8THgaTQxFlsEi",
        ),
        "group": "read_string",
        "source_basis": "short numeric array comma-separated string read",
    },
    {
        "original_ea": "0x1abd5c",
        "original_name": "TNumberArrayVar_short_writeString_TString_const",
        "spectron_ea": "0x1afed0",
        "target_name": "_ZN10PfQXva4zXuIsE10m6pngaXzjoERK10CanTfaz6bZ",
        "template": "PfQXva4zXuIsE",
        "proposed_name": "v18_TNumberArrayVar_short_writeString_TString_const",
        "source_metrics": (164, 41, 3),
        "target_metrics": (208, 52, 3),
        "source_call_count": 6,
        "target_call_count": 10,
        "required_source_calls": (
            "plt_TStringList_TStringList_TString_const",
            "plt_TStringList_operator_index_int",
        ),
        "required_target_calls": (
            "._ZN10vuuHgangcFC2ERK10C8THgaTQxFb",
            "._ZNK10vuuHgangcFixEi",
        ),
        "group": "write_string",
        "source_basis": "short numeric array string-list write",
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
        if spec["template"] not in target["name"]:
            raise ValueError("target template mismatch at %s" % spec["spectron_ea"])
        for side, function in (("source", source), ("target", target)):
            expected_metrics = spec["%s_metrics" % side]
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual_metrics != expected_metrics:
                raise ValueError(
                    "unexpected %s metrics at %s: %s"
                    % (
                        side,
                        spec["original_ea" if side == "source" else "spectron_ea"],
                        actual_metrics,
                    )
                )
            expected_calls = spec["%s_call_count" % side]
            if function.get("call_count") != expected_calls:
                raise ValueError(
                    "unexpected %s call count at %s: %s"
                    % (
                        side,
                        spec["original_ea" if side == "source" else "spectron_ea"],
                        function.get("call_count"),
                    )
                )
            if function.get("string_refs", []):
                raise ValueError(
                    "%s unexpectedly has string references at %s"
                    % (
                        side,
                        spec["original_ea" if side == "source" else "spectron_ea"],
                    )
                )
            for required_call in spec["required_%s_calls" % side]:
                if required_call not in function.get("direct_call_names", []):
                    raise ValueError(
                        "missing %s call %s at %s"
                        % (
                            side,
                            required_call,
                            spec["original_ea" if side == "source" else "spectron_ea"],
                        )
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
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-number-array-string-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": GROUP_EVIDENCE[spec["group"]],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in number-array string anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in number-array string anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_number_array_string_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for double and short numeric-array string conversion methods",
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
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the obfuscated template names in the evidence rows.",
            "The assignments are supported by direct Hex-Rays pseudocode, matching virtual getter and setter slots, shared loop geometry, and parallel double and short template instantiations.",
            "The target's explicit string-wrapper temporaries and changed call counts are rebuild differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
