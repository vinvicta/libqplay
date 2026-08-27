#!/usr/bin/env python3
"""Create a reviewed anchor for Spectron's MNG animation decoder."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "Both routines decode a TMNGAnimationStep through the same pass offset and pass length helpers, channel and color-mode branches, row-copy loops, and pixel-buffer cleanup. The direct calls are the step pixel accessor, the pass geometry helpers, and memcpy.",
    "The source is 16,324 bytes and 4,081 instructions with 504 basic blocks. The target is also 16,324 bytes and 4,081 instructions, with 505 blocks. Both feature records contain exactly four direct calls and no string references.",
    "The target sits immediately after the translated TMNGAnimationStep constructor and pixel accessor in the same image-animation cluster. Its one extra basic block and renamed helper calls are normal rebuild differences, while the large body and control-flow shape remain aligned.",
]


ANCHOR = {
    "original_ea": "0x11b7a0",
    "original_name": "TMNGAnimation_decode_TMNGAnimationStep",
    "spectron_ea": "0x11e2d0",
    "target_name": "_ZN10_5EhmbQbtm10yVYfmb2R2kEP10FZpembCtKj",
    "proposed_name": "v18_TMNGAnimation_decode_TMNGAnimationStep",
    "source_metrics": (16324, 4081, 504),
    "target_metrics": (16324, 4081, 505),
    "source_basis": "MNG animation-step decoder and pixel-pass reconstruction",
}


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

    original_ea = int(ANCHOR["original_ea"], 16)
    spectron_ea = int(ANCHOR["spectron_ea"], 16)
    source = original.get(original_ea)
    target = spectron.get(spectron_ea)
    if source is None:
        raise ValueError("missing original feature at %s" % ANCHOR["original_ea"])
    if target is None:
        raise ValueError("missing Spectron feature at %s" % ANCHOR["spectron_ea"])
    if source.get("name") != ANCHOR["original_name"]:
        raise ValueError(
            "original name mismatch at %s: %s"
            % (ANCHOR["original_ea"], source.get("name"))
        )
    if target.get("name") != ANCHOR["target_name"]:
        raise ValueError(
            "target name mismatch at %s: %s"
            % (ANCHOR["spectron_ea"], target.get("name"))
        )
    for side, function in (("source", source), ("target", target)):
        expected = ANCHOR["%s_metrics" % side]
        actual = (
            function.get("size"),
            function.get("instruction_count"),
            function.get("basic_block_count"),
        )
        if actual != expected:
            raise ValueError(
                "unexpected %s metrics at %s: %s"
                % (side, ANCHOR["%s_ea" % side], actual)
            )
        if function.get("call_count") != 4:
            raise ValueError(
                "%s call count changed at %s: %s"
                % (side, ANCHOR["%s_ea" % side], function.get("call_count"))
            )
        if function.get("string_refs"):
            raise ValueError(
                "%s unexpectedly has string references at %s"
                % (side, ANCHOR["%s_ea" % side])
            )
    if ".memcpy" not in source.get("direct_call_names", []):
        raise ValueError("source decoder lacks memcpy")
    if ".memcpy" not in target.get("direct_call_names", []):
        raise ValueError("target decoder lacks memcpy")
    if spectron_ea in semantic_targets:
        raise ValueError("target %s is already present in the semantic map" % ANCHOR["spectron_ea"])

    row = {
        "original_ea": ANCHOR["original_ea"],
        "original_name": ANCHOR["original_name"],
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": ANCHOR["spectron_ea"],
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": ANCHOR["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-image-animation-context-anchor",
        "semantic_match_already_present": False,
        "source_basis": ANCHOR["source_basis"],
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
    }

    result = {
        "schema_version": 1,
        "artifact": "spectron_mng_animation_manual_translation_anchor_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the MNG animation-step decoder",
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
            "target_default_name_count": int(target.get("is_default_name", False)),
        },
        "anchors": [row],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The address is valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ label preserves the readable 1.8 role while keeping the obfuscated 2.2 name in the evidence row.",
            "The assignment is supported by direct Hex-Rays pseudocode, identical size and instruction count, matching four-call structure, the shared memcpy operation, and the adjacent translated MNG helper cluster.",
            "The one-block difference is recorded as a rebuild difference. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
