#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's client-variable send path."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target functions remain in the obfuscated znLtuaytEf class immediately after its translated constructor and createChild methods, in the same order as the source TGraalClientVar family.",
    "send preserves the client-present and dont-send gates, dotted child-name construction, virtual value read, zero-value unset branch, and flag-send branch. The target adds explicit C8THgaTQxF conversions around the same operations.",
    "writeString preserves the type-byte and cached-value equality check, base-class write, and send-on-change behavior. setArrayCellString preserves the virtual current-value read, equality check, base-class setter, and send-on-change behavior.",
    "The changed target sizes and call counts are wrapper and string-representation differences. Direct pseudocode and the shared virtual slots support the role assignments without claiming byte identity.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x166ee8",
        "original_name": "TGraalClientVar_send_void",
        "spectron_ea": "0x16a81c",
        "target_name": "_ZN10znLtuaytEf4sendEv",
        "proposed_name": "v18_TGraalClientVar_send_void",
        "source_metrics": (400, 100, 12),
        "target_metrics": (448, 112, 12),
        "source_call_count": 18,
        "target_call_count": 22,
        "source_string_refs": ("0",),
        "target_string_refs": ("0",),
        "required_source_calls": (
            "plt_TClient_sendFlag_TString_const",
            "plt_TClient_sendUnsetFlag_TString_const",
            "plt_operator_ne_TString_const_char_const",
        ),
        "required_target_calls": (
            "._ZN10w6qzgacqqy10P937xa16okERK10C8THgaTQxF",
            "._ZN10w6qzgacqqy10I3b8xaMLvkERK10C8THgaTQxF",
            "._ZneRK10C8THgaTQxFPKc",
        ),
        "source_basis": "client-variable flag send and unset dispatcher",
    },
    {
        "original_ea": "0x1670c0",
        "original_name": "TGraalClientVar_writeString_TString_const",
        "spectron_ea": "0x16aa24",
        "target_name": "_ZN10znLtuaytEf10m6pngaXzjoERK10CanTfaz6bZ",
        "proposed_name": "v18_TGraalClientVar_writeString_TString_const",
        "source_metrics": (100, 25, 5),
        "target_metrics": (96, 24, 5),
        "source_call_count": 2,
        "target_call_count": 2,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TGraalVar_writeString_TString_const",
            "plt_operator_assign_TString_const_TString_const",
        ),
        "required_target_calls": (
            "._ZN10G0gxgajWBw10m6pngaXzjoERK10CanTfaz6bZ",
            "._ZNK10CanTfaz6bZ6EqualsERKS_",
        ),
        "source_basis": "client-variable string write with change suppression",
    },
    {
        "original_ea": "0x1671b4",
        "original_name": "TGraalClientVar_setArrayCellString_int_TString_const",
        "spectron_ea": "0x16ab54",
        "target_name": "_ZN10znLtuaytEf10VBZsMaAr_nEiRK10C8THgaTQxF",
        "proposed_name": "v18_TGraalClientVar_setArrayCellString_int_TString_const",
        "source_metrics": (120, 30, 3),
        "target_metrics": (152, 38, 3),
        "source_call_count": 5,
        "target_call_count": 7,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TGraalClientVar_send_void",
            "plt_TGraalVar_setArrayCellString_int_TString_const",
            "plt_operator_assign_TString_const_TString_const",
        ),
        "required_target_calls": (
            "._ZN10znLtuaytEf4sendEv",
            "._ZN10G0gxgajWBw10VBZsMaAr_nEiRK10C8THgaTQxF",
            "._ZeqRK10C8THgaTQxFS1_",
        ),
        "source_basis": "client-variable indexed string write with change suppression",
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
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            expected_metrics = spec["%s_metrics" % side]
            ea = spec["original_ea" if side == "source" else "spectron_ea"]
            if actual_metrics != expected_metrics:
                raise ValueError(
                    "unexpected %s metrics at %s: %s" % (side, ea, actual_metrics)
                )
            if function.get("call_count") != spec["%s_call_count" % side]:
                raise ValueError(
                    "unexpected %s call count at %s: %s"
                    % (side, ea, function.get("call_count"))
                )
            expected_strings = list(spec["%s_string_refs" % side])
            if function.get("string_refs", []) != expected_strings:
                raise ValueError(
                    "unexpected %s string references at %s: %s"
                    % (side, ea, function.get("string_refs", []))
                )
            for required_call in spec["required_%s_calls" % side]:
                if required_call not in function.get("direct_call_names", []):
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
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-client-variable-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in client-variable anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in client-variable anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_var_core_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TGraalClientVar send and string-update methods",
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
            "The proposed v18_ labels preserve the readable 1.8 roles while keeping the obfuscated target names and wrapper differences in the evidence rows.",
            "The send and change-suppression relationships are supported by direct pseudocode and the shared virtual read and setter slots.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
