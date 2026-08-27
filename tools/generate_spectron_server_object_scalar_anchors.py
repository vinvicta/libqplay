#!/usr/bin/env python3
"""Create reviewed anchors for small Spectron server-object methods.

The semantic matcher leaves some short accessors unmatched because several
getter and setter bodies share the same normalized shape. This batch resolves
those collisions with class-local order, target pseudocode, and exact feature
records for TServerBomb, TServerChest, TServerFlying, and TExplosion.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


DEFAULT_ORIGINAL_BINARY = Path(
    "/home/v/Desktop/graal-decomp/GraalOnline+Classic_1.8_APKPure/"
    "lib/arm64-v8a/libqplay.so"
)
DEFAULT_SPECTRON_BINARY = Path(
    "/tmp/spectron-libqplay-inspect/lib/arm64-v8a/libqplay.so"
)

METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)

GENERAL_EVIDENCE = [
    "The source and target methods occupy the corresponding class-local server-object clusters. The target preserves the surrounding obfuscated C++ implementation order even when a short body has only a default sub_ name.",
    "The complete normalized ARM64 feature record matches for every row in this batch. The comparison includes function size, instruction count, control-flow counts, mnemonic, opcode, register, overall-shape, and string-reference fields.",
    "Addresses are valid only for the exact hashed ARM64 libraries recorded in the artifact. This is a static analysis overlay and does not modify the APK.",
]

ANCHOR_SPECS = [
    {
        "original_ea": "0x23ce9c",
        "original_name": "TServerBomb_getTime",
        "spectron_ea": "0x246db4",
        "target_name_fragment": "sub_246DB4",
        "source_basis": "TServerBomb scalar time getter",
        "evidence": [
            "Both return the integer time field at object offset +244 divided by 20.0.",
            "The target is the first short accessor after the obfuscated server-bomb property callbacks, which fixes the getter identity despite its default name.",
        ],
    },
    {
        "original_ea": "0x23cf10",
        "original_name": "TServerBomb_getOrderPoint_void",
        "spectron_ea": "0x246e28",
        "target_name_fragment": "irqhGaERgb10JhjWgazQFREv",
        "source_basis": "TServerBomb draw-order point helper",
        "evidence": [
            "Both call the virtual x and y accessors, add the same tile offsets, and write the resulting pair through the caller-provided float buffer.",
            "The target name identifies the obfuscated server-bomb class and the method body is identical in normalized form.",
        ],
    },
    {
        "original_ea": "0x23cf98",
        "original_name": "TServerBomb_setImage",
        "spectron_ea": "0x246eb0",
        "target_name_fragment": "sub_246EB0",
        "source_basis": "TServerBomb image member setter",
        "evidence": [
            "Both assign the incoming string to the image member at object offset +264 and return the object pointer.",
            "The short setter sits between the order-point helper and the server-bomb constructor in both class-local layouts.",
        ],
    },
    {
        "original_ea": "0x23e3e0",
        "original_name": "TServerChest_setOpen_bool",
        "spectron_ea": "0x248368",
        "target_name_fragment": "dJ10YaC3tX10tLt0YaEE0WEb",
        "source_basis": "TServerChest open-state setter",
        "evidence": [
            "Both store the boolean argument at object offset +248 and return the object pointer.",
            "The target obfuscated class name and exact eight-byte setter shape place the body in the server-chest property cluster.",
        ],
    },
    {
        "original_ea": "0x23ec34",
        "original_name": "TServerFlying_getDx",
        "spectron_ea": "0x248bbc",
        "target_name_fragment": "sub_248BBC",
        "source_basis": "TServerFlying dx getter",
        "evidence": [
            "Both return the double at object offset +248.",
            "The getter is the first member accessor in the ordered dx, dy, type, from, and order-point sequence.",
        ],
    },
    {
        "original_ea": "0x23ec3c",
        "original_name": "TServerFlying_setDx",
        "spectron_ea": "0x248bc4",
        "target_name_fragment": "sub_248BC4",
        "source_basis": "TServerFlying dx setter",
        "evidence": [
            "Both store the double argument at object offset +248 and return the object pointer.",
            "The setter immediately follows the dx getter in both class-local sequences.",
        ],
    },
    {
        "original_ea": "0x23ec44",
        "original_name": "TServerFlying_getDy",
        "spectron_ea": "0x248bcc",
        "target_name_fragment": "sub_248BCC",
        "source_basis": "TServerFlying dy getter",
        "evidence": [
            "Both return the double at object offset +256.",
            "The target follows the dx getter and setter in the same four-accessor sequence.",
        ],
    },
    {
        "original_ea": "0x23ec4c",
        "original_name": "TServerFlying_setDy",
        "spectron_ea": "0x248bd4",
        "target_name_fragment": "sub_248BD4",
        "source_basis": "TServerFlying dy setter",
        "evidence": [
            "Both store the double argument at object offset +248 in the analyzed client build and return the object pointer.",
            "The setter follows the dy getter and retains the exact source feature shape. The observed field store is recorded as-is rather than corrected from an expected member layout.",
        ],
    },
    {
        "original_ea": "0x23ec54",
        "original_name": "TServerFlying_getType",
        "spectron_ea": "0x248bdc",
        "target_name_fragment": "sub_248BDC",
        "source_basis": "TServerFlying type getter",
        "evidence": [
            "Both return the unsigned integer at object offset +272.",
            "The target follows the dx and dy accessors in the same class-local order.",
        ],
    },
    {
        "original_ea": "0x23ec5c",
        "original_name": "TServerFlying_getFrom",
        "spectron_ea": "0x248be4",
        "target_name_fragment": "sub_248BE4",
        "source_basis": "TServerFlying source-object getter",
        "evidence": [
            "Both return the unsigned integer at object offset +264.",
            "The target follows the type getter and precedes the larger order-point helper, preserving the source accessor sequence.",
        ],
    },
    {
        "original_ea": "0x23ec64",
        "original_name": "TServerFlying_getOrderPoint_void",
        "spectron_ea": "0x248bec",
        "target_name_fragment": "gId5RaV8_610JhjWgazQFREv",
        "source_basis": "TServerFlying draw-order point helper",
        "evidence": [
            "Both call the virtual x and y accessors, add the same tile offsets, and write the resulting pair through the caller-provided float buffer.",
            "The target obfuscated class name and exact 136-byte shape distinguish this helper from the equivalent TServerBomb order-point body.",
        ],
    },
    {
        "original_ea": "0x23caa0",
        "original_name": "TExplosion_TExplosion_TServerLevel",
        "spectron_ea": "0x246950",
        "target_name_fragment": "Dq2rua2EceC2EP10zF9VgaBKxR",
        "source_basis": "TExplosion constructor and property initialization",
        "evidence": [
            "Both call the level-object base constructor, install the derived vtable, set the active and type bytes, and store the class property singleton.",
            "The target retains both C1 and C2 constructor-role names around the same 76-byte body, which confirms the constructor interpretation.",
        ],
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
    return {field: function.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary", type=Path, default=DEFAULT_ORIGINAL_BINARY)
    parser.add_argument("--spectron-binary", type=Path, default=DEFAULT_SPECTRON_BINARY)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])

    anchors = []
    seen_targets: set[int] = set()
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None or target is None:
            raise ValueError(
                "missing feature row for %s -> %s"
                % (spec["original_ea"], spec["spectron_ea"])
            )
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "source name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        if spec["target_name_fragment"] not in target.get("name", ""):
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        if spectron_ea in seen_targets:
            raise ValueError("duplicate target address %s" % spec["spectron_ea"])
        seen_targets.add(spectron_ea)

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        if source_metrics != target_metrics:
            differing = [
                field
                for field in METRIC_FIELDS
                if source_metrics[field] != target_metrics[field]
            ]
            raise ValueError(
                "expected exact metrics for %s -> %s, differing fields: %s"
                % (spec["original_ea"], spec["spectron_ea"], ", ".join(differing))
            )

        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target.get("name"),
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-server-object-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_delta": "+0x%x" % (spectron_ea - original_ea),
                "evidence": GENERAL_EVIDENCE + spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_object_scalar_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for exact-shape server-bomb, server-chest, server-flying, and explosion methods",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary": str(args.original_binary),
            "original_binary_sha256": args.original_binary_sha256
            or sha256_path(args.original_binary),
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256
            or sha256_path(args.spectron_binary),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "address_delta_groups": dict(
                sorted(Counter(row["target_delta"] for row in anchors).items())
            ),
        },
        "context": {
            "source_classes": [
                "TServerBomb",
                "TServerChest",
                "TServerFlying",
                "TExplosion",
            ],
            "target_class_clusters": [
                "irqhGaERgb",
                "dJ10YaC3tX",
                "gId5RaV8_6",
                "Dq2rua2Ece",
            ],
            "resolution": "class-local order plus exact normalized function features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "Every row matches the complete normalized function feature set. The short repeated accessor shapes are resolved by their class-local order and target pseudocode behavior.",
            "The v18_ aliases are scoped to the exact hashed Spectron library in the inputs and are an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
