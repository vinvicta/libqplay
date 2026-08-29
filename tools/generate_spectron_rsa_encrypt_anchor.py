#!/usr/bin/env python3
"""Create the reviewed Spectron RSA public-encryption anchor."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_EA = "0xf7218"
SOURCE_NAME = "TEncryption_rsa_encrypt_TString_const_TString_const"
TARGET_EA = "0xf94ac"
TARGET_SYMBOL = "_ZN10cHovga0n1u10D855FaUMK1ERK10C8THgaTQxFS2_"
TARGET_NAME_FRAGMENT = "cHovga0n1u10D855FaUMK1"
PROPOSED_NAME = "v18_TEncryption_rsa_encrypt_TString_const_TString_const"
ARTIFACT = "spectron_rsa_encrypt_manual_translation_anchor_20260829"
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


def by_ea(rows: list[dict]) -> dict[str, dict]:
    return {row["ea"]: row for row in rows}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def evidence_by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"]: row for row in document.get("targets", [])}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--dynamic-symbol-coverage", required=True, type=Path)
    parser.add_argument("--original-binary", required=True, type=Path)
    parser.add_argument("--spectron-binary", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    source_evidence = load(args.source_evidence)
    target_evidence = load(args.target_evidence)
    semantic_map = load(args.semantic_map)
    dynamic_coverage = load(args.dynamic_symbol_coverage)

    source = by_ea(original_document["functions"]).get(SOURCE_EA)
    target = by_ea(spectron_document["functions"]).get(TARGET_EA)
    if source is None or target is None:
        raise ValueError("RSA feature rows are missing")
    if source.get("name") != SOURCE_NAME:
        raise ValueError("unexpected source RSA function name")
    if TARGET_NAME_FRAGMENT not in target.get("name", ""):
        raise ValueError("unexpected target RSA function name")
    if metrics(source) != metrics(target):
        raise ValueError("RSA public-encryption normalized metrics do not match")

    mapped_source_eas = {row["original_ea"] for row in semantic_map.get("matches", [])}
    mapped_target_eas = {row["spectron_ea"] for row in semantic_map.get("matches", [])}
    if SOURCE_EA in mapped_source_eas or TARGET_EA in mapped_target_eas:
        raise ValueError("RSA public-encryption row is already mapped")
    ambiguous = [
        row
        for row in semantic_map.get("ambiguous", [])
        if row.get("original_ea") == SOURCE_EA
    ]
    if len(ambiguous) != 1 or TARGET_EA not in ambiguous[0].get("candidate_spectron_eas", []):
        raise ValueError("RSA public-encryption row is not the expected ambiguity")

    dynamic_rows = [
        row
        for row in dynamic_coverage.get("rows", [])
        if row.get("value") == TARGET_EA and row.get("dynamic_name") == TARGET_SYMBOL
    ]
    if len(dynamic_rows) != 1:
        raise ValueError("RSA target dynamic symbol row is missing")
    if dynamic_rows[0].get("dynamic_symbol_status") != "exact_retained_dynamic_name":
        raise ValueError("RSA target dynamic symbol was not retained before apply")

    source_row = evidence_by_ea(source_evidence).get(SOURCE_EA)
    target_row = evidence_by_ea(target_evidence).get(TARGET_EA)
    if source_row is None or target_row is None:
        raise ValueError("RSA pseudocode evidence rows are missing")

    anchor = {
        "original_ea": SOURCE_EA,
        "original_name": SOURCE_NAME,
        "original_function_end": source.get("end_ea"),
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": TARGET_EA,
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target.get("name"),
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": PROPOSED_NAME,
        "confidence": "high",
        "match_kind": "manual-encryption-rsa-public-exact-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TEncryption RSA public-key encryption wrapper",
        "target_delta": "+0x2294",
        "evidence": [
            "The source body decodes an RSA public key, initializes an RNG, calculates the RSA output size, encrypts the input with the public-key routine, appends a positive result, and frees the key state.",
            "The target D855FaUMK1 body preserves the same hidden-string-return wrapper, guards, temporary buffers, call order, and cleanup, while using the target C8THgaTQxF and CyaInt wrapper names.",
            "The adjacent target GjD5FacHl1 method is already the reviewed RSA private-key signing counterpart at 0xf96f8. Its private-key decode and RsaSSL_Sign calls distinguish it from this public-key method.",
            "The source and target complete normalized ARM64 feature records match. Register-detail allocation differs only because the target rebuilt its string wrapper.",
            "This row resolves the source 0xf7218 ambiguity between the public-encryption and private-signing target bodies by direct algorithm-specific pseudocode.",
        ],
        "name_action": "rename-with-v18-prefix",
        "shape_equal": True,
        "source_pseudocode": source_row.get("pseudocode"),
        "target_pseudocode": target_row.get("pseudocode"),
        "source_xrefs": source_row.get("xrefs_to", []),
        "target_xrefs": target_row.get("xrefs_to", []),
    }

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TEncryption RSA public-encryption wrapper",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_evidence": str(args.source_evidence),
            "original_evidence_sha256": sha256_path(args.source_evidence),
            "original_binary": str(args.original_binary),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_evidence": str(args.target_evidence),
            "spectron_evidence_sha256": sha256_path(args.target_evidence),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
            "dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
            "dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
        },
        "summary": {
            "anchor_count": 1,
            "high_confidence_count": 1,
            "new_context_anchor_count": 1,
            "exact_shape_anchor_count": 1,
            "layout_change_anchor_count": 0,
            "target_default_name_count": int(target.get("is_default_name", False)),
            "address_delta_groups": {"+0x2294": 1},
        },
        "context": {
            "source_classes": ["TEncryption"],
            "target_class_clusters": ["cHovga0n1u"],
            "resolution": "algorithm-specific RSA public-key pseudocode, the already reviewed private-signing sibling, class-local order, and exact normalized function features",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a claim that stripped Spectron debug symbols were recovered.",
            "The source and target rows match across the complete normalized feature set. Public-key decode and encryption calls resolve the ambiguity with the target private-signing sibling.",
            "The v18_ alias is scoped to the exact hashed Spectron library in the inputs and is an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
