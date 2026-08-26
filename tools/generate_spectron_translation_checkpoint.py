#!/usr/bin/env python3
"""Record hashes and counts for a persisted Spectron translation checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--verification", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manual-anchors", type=Path)
    parser.add_argument("--manual-verification", type=Path)
    parser.add_argument("--network-anchors", type=Path)
    parser.add_argument("--network-verification", type=Path)
    args = parser.parse_args()

    translation = load(args.map)
    verification = load(args.verification)
    if translation.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected translation map artifact")
    if not verification.get("verified"):
        raise ValueError("IDA reopen verification did not pass")
    expected = translation["summary"]["mapped_high_confidence"]
    if verification["high_confidence_match_count"] != expected:
        raise ValueError("verification match count differs from translation map")
    manual = None
    if args.manual_anchors or args.manual_verification:
        if not args.manual_anchors or not args.manual_verification:
            raise ValueError("manual anchors and manual verification must be supplied together")
        manual_document = load(args.manual_anchors)
        manual_verification = load(args.manual_verification)
        if manual_document.get("artifact") != "spectron_manual_translation_anchors_20260826":
            raise ValueError("unexpected manual-anchor artifact")
        if not manual_verification.get("verified"):
            raise ValueError("manual-anchor reopen verification did not pass")
        expected_manual = len(manual_document["anchors"])
        if manual_verification["verified_name_count"] != expected_manual:
            raise ValueError("manual-anchor verification count differs from artifact")
        manual = {
            "anchor_path": str(args.manual_anchors),
            "anchor_sha256": sha256_path(args.manual_anchors),
            "reopen_verification": str(args.manual_verification),
            "anchor_count": expected_manual,
            "verified_name_count": manual_verification["verified_name_count"],
            "reopen_failure_count": manual_verification["failure_count"],
        }
    network = None
    if args.network_anchors or args.network_verification:
        if not args.network_anchors or not args.network_verification:
            raise ValueError("network anchors and network verification must be supplied together")
        network_document = load(args.network_anchors)
        network_verification = load(args.network_verification)
        if network_document.get("artifact") != "spectron_network_manual_translation_anchors_20260826":
            raise ValueError("unexpected network-anchor artifact")
        if not network_verification.get("verified"):
            raise ValueError("network-anchor reopen verification did not pass")
        expected_network = len(network_document["anchors"])
        if network_verification["verified_name_count"] != expected_network:
            raise ValueError("network-anchor verification count differs from artifact")
        network = {
            "anchor_path": str(args.network_anchors),
            "anchor_sha256": sha256_path(args.network_anchors),
            "reopen_verification": str(args.network_verification),
            "anchor_count": expected_network,
            "verified_name_count": network_verification["verified_name_count"],
            "reopen_failure_count": network_verification["failure_count"],
        }
    result = {
        "schema_version": 1,
        "artifact": "spectron_translation_checkpoint_20260826",
        "scope": "persisted high-confidence 1.8-to-Spectron ARM64 semantic labels",
        "network_contacted": False,
        "inputs": {
            "original_binary_sha256": translation["inputs"].get("original_binary_sha256"),
            "spectron_binary_sha256": translation["inputs"].get("spectron_binary_sha256"),
            "translation_map": str(args.map),
            "translation_map_sha256": sha256_path(args.map),
            "reopen_verification": str(args.verification),
        },
        "database": {
            "path": str(args.database),
            "sha256": sha256_path(args.database),
            "format": "packed IDA 9.3 database",
            "close_reopen_verified": True,
            "function_count": verification["function_count"],
            "default_sub_function_count": verification["default_sub_function_count"],
        },
        "translation": {
            "mapped_functions": translation["summary"]["mapped_functions"],
            "high_confidence_applied": translation["summary"]["mapped_high_confidence"],
            "medium_confidence_review_only": translation["summary"]["mapped_medium_confidence"],
            "ambiguous_functions": translation["summary"]["ambiguous_functions"],
            "unmatched_functions": translation["summary"]["unmatched_functions"],
            "unique_spectron_targets": translation["summary"]["unique_spectron_targets"],
            "reopen_failure_count": verification["failure_count"],
        },
        "interpretation": [
            "The saved database contains v18_ analysis labels on the verified high-confidence target functions.",
            "The labels preserve the original 1.8 semantic names while keeping the Spectron address and obfuscated name in the map.",
            "The medium-confidence, ambiguous, and unmatched functions remain review-only and were not silently renamed.",
        ],
    }
    if manual is not None:
        result["manual_anchors"] = manual
        result["interpretation"].append(
            "The second database revision also contains the separately reviewed manual context anchors."
        )
    if network is not None:
        result["network_anchors"] = network
        result["interpretation"].append(
            "The third database revision also contains the separately reviewed connector and socket context anchors."
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **result["translation"], "database_sha256": result["database"]["sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
