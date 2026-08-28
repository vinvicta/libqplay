#!/usr/bin/env python3
"""Create the reviewed Spectron zlib inflate_fast residual anchor.

Both binaries keep this helper as a default IDA name, so the artifact records
the inferred zlib role separately from each database's current name. The
target label is applied only after the body, caller, strings, and feature
metrics have been checked together.
"""

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
NORMALIZED_FIELDS = (
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
)


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

    original = by_ea(load(args.original_features))["0x28a2f4"]
    spectron = by_ea(load(args.spectron_features))["0x297764"]
    if original["name"] != "sub_28A2F4" or not original.get("is_default_name"):
        raise ValueError("unexpected source inflate_fast candidate")
    if spectron["name"] != "sub_297764" or not spectron.get("is_default_name"):
        raise ValueError("unexpected target inflate_fast candidate")

    original_metrics = metrics(original)
    spectron_metrics = metrics(spectron)
    normalized_equal = all(
        original_metrics[field] == spectron_metrics[field]
        for field in NORMALIZED_FIELDS
    )
    full_metric_equal = original_metrics == spectron_metrics
    differences = [
        field for field in METRIC_FIELDS if original_metrics[field] != spectron_metrics[field]
    ]
    if not normalized_equal or differences != ["register_detail_hash"]:
        raise ValueError("unexpected source and target inflate_fast metrics")

    source_strings = sorted(original.get("string_refs", []))
    target_strings = sorted(spectron.get("string_refs", []))
    expected_strings = [
        "invalid distance code",
        "invalid distance too far back",
        "invalid literal/length code",
    ]
    if source_strings != expected_strings or target_strings != expected_strings:
        raise ValueError("unexpected inflate_fast string references")

    anchor = {
        "original_ea": "0x28a2f4",
        "original_name": original["name"],
        "original_current_name": original["name"],
        "original_default_name": True,
        "original_metrics": original_metrics,
        "original_function_end": original.get("end_ea"),
        "original_string_refs": original.get("string_refs", []),
        "original_direct_call_names": original.get("direct_call_names", []),
        "spectron_ea": "0x297764",
        "spectron_current_name": spectron["name"],
        "spectron_default_name": True,
        "spectron_metrics": spectron_metrics,
        "spectron_function_end": spectron.get("end_ea"),
        "spectron_string_refs": spectron.get("string_refs", []),
        "spectron_direct_call_names": spectron.get("direct_call_names", []),
        "proposed_name": "v18_zlib_inflate_fast",
        "confidence": "high",
        "match_kind": "manual-zlib-internal-role-exact-anchor",
        "family": "zlib",
        "source_name": "zlib_inflate_fast",
        "source_role": "zlib inflate_fast hot loop",
        "source_basis": "zlib inflate call-site, error strings, Huffman decode body, and cross-build metrics",
        "target_component": "Spectron zlib inflate implementation",
        "source_component": "1.8 zlib inflate implementation",
        "source_parent": "inflate at 0x284198",
        "source_call_site": "0x28566c",
        "target_parent": "v18_inflate at 0x291608",
        "target_call_site": "0x292adc",
        "operation": "decodes literal/length and distance Huffman entries, then copies matched bytes into the output window",
        "source_references": [
            "https://github.com/madler/zlib/blob/develop/inflate.c",
        ],
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The source default function at 0x28a2f4 is the helper called from inflate at 0x28566c.",
            "The target default function at 0x297764 is the helper called from v18_inflate at 0x292adc.",
            "Both bodies contain the zlib invalid literal/length, invalid distance, and invalid distance too far back strings.",
            "Both bodies decode literal/length and distance Huffman tables and copy backreferences into the output window, which identifies the inflate_fast role.",
            "The complete recorded feature metrics match except for register allocation detail, and the target remained a default sub_ name before this pass.",
        ],
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_zlib_inflate_fast_manual_translation_anchor_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the residual zlib inflate_fast helper",
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
            "source_current_name": "sub_28A2F4",
            "target_current_name": "sub_297764",
            "source_parent": "inflate at 0x284198",
            "target_parent": "v18_inflate at 0x291608",
            "source_call_site": "0x28566c",
            "target_call_site": "0x292adc",
            "role_resolution": "call-site plus zlib error strings, Huffman decode, backreference copy loop, and feature metrics",
            "source_role_name_policy": "zlib_inflate_fast is an inferred role because the source function itself retained a default IDA name",
        },
        "summary": {
            "anchor_count": 1,
            "unique_target_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": 1,
            "source_default_name_count": 1,
            "normalized_shape_exact_count": int(normalized_equal),
            "full_metric_exact_count": int(full_metric_equal),
            "register_detail_difference_count": int("register_detail_hash" in differences),
            "inflate_fast_count": 1,
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic role label, not a restored original debug symbol, because both source and target databases retain default names at these addresses.",
            "The target label is supported by the matching caller position, zlib error strings, Huffman decoder and backreference copy logic, and complete feature metrics.",
            "The target body differs from the source only in register allocation detail, so the v18 prefix records the source-version context without claiming an original exported name.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
