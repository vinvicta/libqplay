#!/usr/bin/env python3
"""Create reviewed destructor anchors and correct a prior class collision."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source pseudocode identifies the two TPixelBuffer rows as the D1 destructor and deleting-destructor pair, and the two TBitmap rows as the matching D1 and deleting-destructor pair.",
    "The target has a separate uSjUgask_P destructor pair at 0x1074e4 and 0x107514 and a separate Fcx_gaoydV destructor pair at 0x1156f4 and 0x115724.",
    "Each target destructor calls the corresponding target class cleanup method, restores the target vtable, and clears the class string. The deleting forms then call the matching base destructor and operator delete.",
    "The target uSjUgask_P pair is the correction for a prior medium-confidence shape-only collision that assigned the 1.8 TPixelBuffer destructor to the Fcx_gaoydV bitmap destructor. That automatic candidate was never applied to the disposable IDA database.",
    "The rows are recorded for the exact hashed Spectron library, and the source-to-target pairings are not treated as restored original debug symbols.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x104e5c",
        "original_name": "TPixelBuffer_TPixelBuffer",
        "spectron_ea": "0x1074e4",
        "target_name": "_ZN10uSjUgask_PD1Ev",
        "proposed_name": "v18_TPixelBuffer_TPixelBuffer",
        "source_metrics": (48, 12, 2),
        "target_metrics": (48, 12, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TPixelBuffer_destroyPixels_void",),
        "required_target_calls": ("._ZN10uSjUgask_P10pSeYgan7hTEv",),
        "source_basis": "TPixelBuffer D1 destructor and pixel cleanup",
    },
    {
        "original_ea": "0x104e8c",
        "original_name": "TPixelBuffer_TPixelBuffer__2",
        "spectron_ea": "0x107514",
        "target_name": "_ZN10uSjUgask_PD0Ev",
        "proposed_name": "v18_TPixelBuffer_TPixelBuffer__2",
        "source_metrics": (32, 8, 2),
        "target_metrics": (32, 8, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TPixelBuffer_TPixelBuffer__2",),
        "required_target_calls": ("._ZN10uSjUgask_PD1Ev",),
        "source_basis": "TPixelBuffer deleting-destructor wrapper",
    },
    {
        "original_ea": "0x112e24",
        "original_name": "TBitmap_TBitmap",
        "spectron_ea": "0x1156f4",
        "target_name": "_ZN10Fcx_gaoydVD2Ev",
        "proposed_name": "v18_TBitmap_TBitmap",
        "source_metrics": (48, 12, 2),
        "target_metrics": (48, 12, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TBitmap_deleteImage_void",),
        "required_target_calls": ("._ZN10Fcx_gaoydV10MJw7Bag9WGEv",),
        "source_basis": "TBitmap D1 destructor and image cleanup",
    },
    {
        "original_ea": "0x112e54",
        "original_name": "TBitmap_TBitmap__2",
        "spectron_ea": "0x115724",
        "target_name": "_ZN10Fcx_gaoydVD0Ev",
        "proposed_name": "v18_TBitmap_TBitmap__2",
        "source_metrics": (32, 8, 2),
        "target_metrics": (32, 8, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": ("plt_TBitmap_TBitmap",),
        "required_target_calls": ("._ZN10Fcx_gaoydVD2Ev",),
        "source_basis": "TBitmap deleting-destructor wrapper",
    },
]

EXPECTED_SUPERSEDED = {
    "original_ea": "0x104e5c",
    "original_name": "TPixelBuffer_TPixelBuffer",
    "spectron_ea": "0x1156f4",
    "spectron_current_name": "_ZN10Fcx_gaoydVD2Ev",
    "confidence": "medium",
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
    semantic_matches = semantic_document.get("matches", [])
    semantic_targets = {int(row["spectron_ea"], 16) for row in semantic_matches}
    previous = next(
        (
            row
            for row in semantic_matches
            if row.get("original_ea") == EXPECTED_SUPERSEDED["original_ea"]
        ),
        None,
    )
    if previous is None:
        raise ValueError("the expected prior medium-confidence collision is missing")
    for key, expected in EXPECTED_SUPERSEDED.items():
        if previous.get(key) != expected:
            raise ValueError("unexpected prior collision field %s" % key)

    anchors = []
    for spec in ANCHOR_SPECS:
        source = original.get(int(spec["original_ea"], 16))
        target = spectron.get(int(spec["spectron_ea"], 16))
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("original name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
        for side, function in (("source", source), ("target", target)):
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            expected_metrics = spec["%s_metrics" % side]
            ea = spec["original_ea" if side == "source" else "spectron_ea"]
            if actual_metrics != expected_metrics:
                raise ValueError("unexpected %s metrics at %s: %s" % (side, ea, actual_metrics))
            if function.get("call_count") != spec["%s_call_count" % side]:
                raise ValueError("unexpected %s call count at %s" % (side, ea))
            expected_strings = list(spec["%s_string_refs" % side])
            if function.get("string_refs", []) != expected_strings:
                raise ValueError(
                    "unexpected %s string references at %s: %s"
                    % (side, ea, function.get("string_refs", []))
                )
            for required_call in spec["required_%s_calls" % side]:
                if required_call not in function.get("direct_call_names", []):
                    raise ValueError("missing %s call %s at %s" % (side, required_call, ea))

        target_ea = int(spec["spectron_ea"], 16)
        target_claim = None
        if target_ea in semantic_targets:
            target_claim = next(
                row for row in semantic_matches if int(row["spectron_ea"], 16) == target_ea
            )
            if not (
                target_ea == int(EXPECTED_SUPERSEDED["spectron_ea"], 16)
                and target_claim.get("original_ea") == EXPECTED_SUPERSEDED["original_ea"]
                and target_claim.get("confidence") == "medium"
            ):
                raise ValueError("unexpected semantic target collision at %s" % spec["spectron_ea"])
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
                "match_kind": "manual-pixelbuffer-bitmap-lifecycle-correction-anchor",
                "semantic_match_already_present": False,
                "semantic_target_already_present": target_claim is not None,
                "supersedes_semantic_match": previous if spec["original_ea"] == EXPECTED_SUPERSEDED["original_ea"] else None,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_pixelbuffer_bitmap_lifecycle_correction_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 destructor anchors correcting a medium-confidence pixel-buffer and bitmap collision",
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
            "already_in_semantic_map": 1,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "superseded_medium_match_count": 1,
        },
        "anchors": anchors,
        "corrections": [
            {
                "old_original_ea": EXPECTED_SUPERSEDED["original_ea"],
                "old_original_name": EXPECTED_SUPERSEDED["original_name"],
                "old_spectron_ea": EXPECTED_SUPERSEDED["spectron_ea"],
                "old_spectron_name": EXPECTED_SUPERSEDED["spectron_current_name"],
                "old_confidence": EXPECTED_SUPERSEDED["confidence"],
                "new_rows": ["0x104e5c -> 0x1074e4", "0x112e24 -> 0x1156f4"],
                "reason": "shape-only matching confused two same-sized destructor bodies; class identity and cleanup callees separate the pixel-buffer and bitmap lifecycles",
            }
        ],
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The prior medium-confidence shape-only match remains in the original automatic report for reproducibility, but this correction artifact supersedes it for the translated IDA database.",
            "The uSjUgask_P and Fcx_gaoydV destructor pairs are separate class lifecycles, and the target cleanup callees confirm which source destructor belongs to each pair.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
