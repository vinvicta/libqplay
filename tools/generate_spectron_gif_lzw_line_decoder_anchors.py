#!/usr/bin/env python3
"""Create a reviewed anchor for Spectron's internal GIF LZW line decoder."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)
NORMALIZED_FIELDS = METRIC_FIELDS[:-1]


SPEC = {
    "source_ea": "0x2acb20",
    "target_ea": "0x2b9f90",
    "source_name": "DGifDecompressLine",
    "role": "DGifDecompressLine",
    "source_file": "dgif_lib.c",
    "source_callers": [
        "DGifGetLine at 0x2ae28c",
        "DGifGetPixel at 0x2ae350",
    ],
    "target_callers": [
        "v18_DGifGetLine at 0x2bb6ac",
        "v18_DGifGetPixel at 0x2bb770",
    ],
    "operation": "decompresses one GIF raster line from the LZW stream, drains pending stack bytes, reads packed sub-blocks, updates the code dictionary, and writes decoded pixels to the caller buffer",
    "expected_differences": ["register_detail_hash"],
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"].lower(): row for row in document["functions"]}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original = by_ea(load(args.original_features))[SPEC["source_ea"]]
    spectron = by_ea(load(args.spectron_features))[SPEC["target_ea"]]
    if not original.get("is_default_name"):
        raise ValueError("source candidate is not a default name")
    if not spectron.get("is_default_name"):
        raise ValueError("target candidate is not a default name")

    original_metrics = metrics(original)
    spectron_metrics = metrics(spectron)
    differences = [
        field
        for field in METRIC_FIELDS
        if original_metrics[field] != spectron_metrics[field]
    ]
    if differences != SPEC["expected_differences"]:
        raise ValueError("unexpected metric differences: %s" % differences)
    normalized_equal = all(
        original_metrics[field] == spectron_metrics[field]
        for field in NORMALIZED_FIELDS
    )
    if not normalized_equal:
        raise ValueError("normalized metrics do not match")

    anchor = {
        "original_ea": SPEC["source_ea"],
        "original_name": original["name"],
        "original_current_name": original["name"],
        "original_default_name": True,
        "original_metrics": original_metrics,
        "original_function_end": original.get("end_ea"),
        "original_string_refs": original.get("string_refs", []),
        "original_direct_call_names": original.get("direct_call_names", []),
        "spectron_ea": SPEC["target_ea"],
        "spectron_current_name": spectron["name"],
        "spectron_default_name": True,
        "spectron_metrics": spectron_metrics,
        "spectron_function_end": spectron.get("end_ea"),
        "spectron_string_refs": spectron.get("string_refs", []),
        "spectron_direct_call_names": spectron.get("direct_call_names", []),
        "proposed_name": "v18_DGifDecompressLine",
        "confidence": "high",
        "match_kind": "manual-gif-dgif-lib-static-role-anchor",
        "family": "giflib GIF decoder",
        "source_name": SPEC["source_name"],
        "source_role": SPEC["role"],
        "source_file": SPEC["source_file"],
        "source_component": "DGifGetLine and DGifGetPixel in dgif_lib.c",
        "target_component": "v18_DGifGetLine and v18_DGifGetPixel",
        "source_basis": "giflib %s static helper body and caller relationships" % SPEC["source_name"],
        "source_callers": SPEC["source_callers"],
        "target_callers": SPEC["target_callers"],
        "operation": SPEC["operation"],
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The official giflib dgif_lib.c source defines DGifDecompressLine as the internal helper that fills a caller-provided raster line by repeatedly obtaining LZW codes and draining the decoder stack.",
            "The target v18_DGifGetLine and v18_DGifGetPixel bodies both call the 1,508-byte target helper at 0x2b9f90, matching the source callers of 0x2acb20.",
            "The target pseudocode checks the GIF private state, copies pending stack pixels, reads compressed sub-blocks through the configured read callback or fread, maintains the prefix and suffix tables, and returns the same GIF error codes as the source helper.",
            "The source and target normalized ARM64 feature metrics match; only register allocation detail differs.",
        ],
        "name_action": "rename-with-v18-prefix",
    }

    result = {
        "schema_version": 1,
        "artifact": "spectron_gif_lzw_line_decoder_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the internal giflib LZW raster-line decoder",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "source_function": "sub_2ACB20, static DGifDecompressLine in dgif_lib.c",
            "target_function": "sub_2B9F90, static DGifDecompressLine in the stripped Spectron build",
            "source_file": "dgif_lib.c",
            "role_resolution": "official giflib source, target caller relationships, reviewed pseudocode, and ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because the target retained only an IDA auto-generated name",
            "reference_source": "https://android.googlesource.com/platform/external/giflib/%2B/dc07290edccc2c3fc4062da835306f809cea1fdc/dgif_lib.c",
        },
        "summary": {
            "anchor_count": 1,
            "unique_target_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": 1,
            "source_default_name_count": 1,
            "normalized_shape_exact_count": 1,
            "full_metric_exact_count": 0,
            "register_detail_difference_count": 1,
            "gif_lzw_decoder_role_count": 1,
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed giflib role label, not a restored original debug symbol, because the static helper had no surviving source name in either feature export.",
            "DGifDecompressLine is distinct from the public DGifGetLZCodes API. The target helper takes a line buffer and length, and its callers are the line and pixel readers.",
            "The source and target bodies match in normalized ARM64 shape. The only recorded difference is compiler register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
