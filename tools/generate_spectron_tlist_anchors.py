#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron TList helper family.

The target keeps the container under an obfuscated C++ class. This artifact
records the list mutation, access, bulk-copy, and sorting correspondences
using decompiled behavior, local method order, and complete normalized ARM64
features.
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
    "The source and target rows are corresponding methods in the TList and vy1JgaKVkH class-local clusters. The target retains an obfuscated C++ class name, so the readable alias is an analysis translation rather than recovered target debug information.",
    "The complete normalized ARM64 feature record matches for every row. The comparison includes size, instruction count, control-flow counts, mnemonic, opcode, register, overall-shape, and string-reference fields.",
    "Addresses are valid only for the exact hashed ARM64 libraries recorded in the artifact. This is a static IDA analysis overlay and does not modify the APK or native library.",
]

ANCHOR_SPECS = [
    {
        "original_ea": "0xec9f8",
        "original_name": "TList_Replace_int_void",
        "spectron_ea": "0xed9c8",
        "target_name_fragment": "vy1JgaKVkH7ReplaceEiPv",
        "source_basis": "TList indexed replacement",
        "evidence": [
            "Both reject negative or out-of-range indexes and store the incoming pointer into the indexed list slot.",
            "The target Replace method is the first mutation helper in the corresponding local TList cluster.",
        ],
    },
    {
        "original_ea": "0xecbac",
        "original_name": "TList_Remove_void",
        "spectron_ea": "0xedb7c",
        "target_name_fragment": "vy1JgaKVkH6RemoveEPv",
        "source_basis": "TList repeated-value removal",
        "evidence": [
            "Both repeatedly find the value and delete the matching index until the search returns a negative result.",
            "The target Remove method follows the indexed replacement area and retains the same loop over indexOf and Delete.",
        ],
    },
    {
        "original_ea": "0xecd78",
        "original_name": "TList_AddList_TList",
        "spectron_ea": "0xedd48",
        "target_name_fragment": "vy1JgaKVkH10TF9BgaVKIAEPS_",
        "source_basis": "TList full-list append wrapper",
        "evidence": [
            "Both check for a non-null source list and forward its complete range, from index zero through the source count, to the four-argument AddList implementation.",
            "The target TF9BgaVKIA method is the compact bulk-copy wrapper in the same local list-helper sequence.",
        ],
    },
    {
        "original_ea": "0xecdb8",
        "original_name": "TList_getS32_int",
        "spectron_ea": "0xedd88",
        "target_name_fragment": "vy1JgaKVkH10iqwRgaITDNEi",
        "source_basis": "TList signed 32-bit indexed accessor",
        "evidence": [
            "Both return zero for a negative or out-of-range index and otherwise load the indexed pointer-sized list element.",
            "The target iqwRgaITDN method is the first member of the adjacent signed and unsigned accessor pair.",
        ],
    },
    {
        "original_ea": "0xecde4",
        "original_name": "TList_getU32_int",
        "spectron_ea": "0xeddb4",
        "target_name_fragment": "vy1JgaKVkH10sULREacVQZEi",
        "source_basis": "TList unsigned 32-bit indexed accessor",
        "evidence": [
            "Both use the same negative and bounds checks as getS32 and load the indexed list element when valid.",
            "The target sULREacVQZ method immediately follows the signed accessor and is distinguished by the ordered C++ overload name.",
        ],
    },
    {
        "original_ea": "0xece10",
        "original_name": "TList_qsort_void_ulong_ulong_int_void_const_void_const",
        "spectron_ea": "0xedde0",
        "target_name_fragment": "vy1JgaKVkH5qsortEPvmmPFiPKvS2_E",
        "source_basis": "TList qsort thunk",
        "evidence": [
            "Both are four-byte thunks that forward the base pointer, element count, element size, and comparator directly to qsort.",
            "The target qsort method closes the same TList helper cluster after the signed and unsigned accessors.",
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
                "match_kind": "manual-tlist-exact-anchor",
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
        "artifact": "spectron_tlist_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TList mutation, access, append, and sorting helpers",
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
            "source_classes": ["TList"],
            "target_class_clusters": ["vy1JgaKVkH"],
            "resolution": "class-local helper order, container behavior, target pseudocode, and exact normalized function features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "Every row matches the complete normalized function feature set. Repeated signed and unsigned accessor shapes are resolved by their adjacent overload order and shared list bounds behavior.",
            "The v18_ aliases are scoped to the exact hashed Spectron library in the inputs and are an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
