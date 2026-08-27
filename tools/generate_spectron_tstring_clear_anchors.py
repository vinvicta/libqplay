#!/usr/bin/env python3
"""Create the reviewed Spectron TString clear-method anchor.

The clear body is shared by more than one string-like target class, so the
class-qualified target name and the surrounding TString method cluster are
recorded alongside the exact normalized feature match.
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

    original_ea = 0xF0EF8
    spectron_ea = 0xF23D0
    source = original.get(original_ea)
    target = spectron.get(spectron_ea)
    if source is None or target is None:
        raise ValueError("missing feature row for TString clear anchor")
    if source.get("name") != "TString_clear_void":
        raise ValueError("unexpected source name: %s" % source.get("name"))
    if "C8THgaTQxF5clearEv" not in target.get("name", ""):
        raise ValueError("unexpected target name: %s" % target.get("name"))

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics != target_metrics:
        differing = [
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        ]
        raise ValueError("expected exact metrics, differing fields: %s" % ", ".join(differing))

    anchor = {
        "original_ea": "0xf0ef8",
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": "0xf23d0",
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target.get("name"),
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_TString_clear_void",
        "confidence": "high",
        "match_kind": "manual-tstring-clear-exact-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TString reference-counted storage clear method",
        "target_delta": "+0x14d8",
        "evidence": [
            "The source and target pseudocode both load the string storage pointer, free it when its reference count is at most one, decrement the count otherwise, and then clear the object pointer.",
            "The target method is class-qualified as C8THgaTQxF::clear and sits at the start of the translated TString method cluster. The other identical-shape clear body belongs to the separate CanTfaz6bZ class and is therefore not the TString target.",
            "The complete normalized ARM64 feature record matches, including size, instruction count, control-flow counts, mnemonic, opcode, register, overall-shape, and string-reference fields.",
            "Addresses are valid only for the exact hashed ARM64 libraries recorded in the artifact. This is a static IDA analysis overlay and does not modify the APK or native library.",
        ],
        "name_action": "rename-with-v18-prefix",
        "shape_equal": True,
    }

    result = {
        "schema_version": 1,
        "artifact": "spectron_tstring_clear_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TString reference-counted clear method",
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
            "anchor_count": 1,
            "high_confidence_count": 1,
            "new_context_anchor_count": 1,
            "exact_shape_anchor_count": 1,
            "layout_change_anchor_count": 0,
            "target_default_name_count": int(anchor["spectron_default_name"]),
            "address_delta_groups": dict(
                sorted(Counter([anchor["target_delta"]]).items())
            ),
        },
        "context": {
            "source_classes": ["TString"],
            "target_class_clusters": ["C8THgaTQxF"],
            "resolution": "class-qualified target name, sibling method ordering, IDA pseudocode, and exact normalized function features",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The exact feature shape is shared by another target string-like class, so the class-qualified C8THgaTQxF name is required to resolve the candidate safely.",
            "The v18_ alias is scoped to the exact hashed Spectron library in the inputs and is an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
