#!/usr/bin/env python3
"""Create reviewed labels for the Spectron encoded-string helper cluster.

The target contains a copy-on-write string buffer whose contents are XOR
encoded with a process-generated three-byte key.  Its bridge into the normal
``C8THgaTQxF`` string wrapper has no one-to-one 1.8 feature counterpart.  The
artifact records descriptive target-only labels and keeps ordinary source
feature collisions separate from semantic matches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_encoded_string_target_only_labels_20260829"
TARGET_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"

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

SOURCE_REFERENCE_EAS = ("0xf10b8", "0xf1288", "0xf2fa0", "0xf5e50")

# Address, expected raw name, function end, descriptive label, short role,
# operation summary.  The raw class names are retained in the proposed names
# where no 1.8 source class can be claimed safely.
SPECS = (
    (
        "0xf37bc",
        "_ZN10C8THgaTQxF10QhxbJaMCjDERK10CanTfaz6bZ",
        "0xf3888",
        "spectron_C8THgaTQxF_decodeFromCanTfaz6bZ_const",
        "C8THgaTQxF decode bridge",
        "decodes the encoded CanTfaz6bZ buffer into the ordinary C8THgaTQxF string wrapper",
    ),
    (
        "0xf3888",
        "_ZN10C8THgaTQxFaSER10CanTfaz6bZ",
        "0xf38b8",
        "spectron_C8THgaTQxF_assignCanTfaz6bZ",
        "C8THgaTQxF encoded-buffer assignment",
        "clears the destination and assigns it from the encoded CanTfaz6bZ buffer",
    ),
    (
        "0xf8b90",
        "_ZN10CanTfaz6bZ10uTzSjboOwkEv",
        "0xf8c60",
        "spectron_CanTfaz6bZ_initXorKey_void",
        "encoded-buffer key initialization",
        "initializes the three-byte lower-case XOR key once using the target random source",
    ),
    (
        "0xf8c64",
        "_ZN10CanTfaz6bZ5clearEv",
        "0xf8ca8",
        "spectron_CanTfaz6bZ_clear_void",
        "encoded-buffer cleanup",
        "releases or decrements the shared encoded buffer and clears the object pointer",
    ),
    (
        "0xf8ca8",
        "_ZN10CanTfaz6bZaSERKS_",
        "0xf8d00",
        "spectron_CanTfaz6bZ_assign_CanTfaz6bZ_const",
        "encoded-buffer copy assignment",
        "shares the encoded buffer with copy-on-write reference counting",
    ),
    (
        "0xf8d00",
        "_ZN10CanTfaz6bZ10OZpSjbLtokERK10C8THgaTQxF",
        "0xf8de0",
        "spectron_CanTfaz6bZ_encodeFromC8THgaTQxF",
        "encoded-buffer string conversion",
        "clears the destination and XOR-encodes a C8THgaTQxF string into a new buffer",
    ),
    (
        "0xf8de0",
        "_ZN10CanTfaz6bZ10wsWEEaIN2OERKS_",
        "0xf8e54",
        "spectron_CanTfaz6bZ_decodeToC8THgaTQxF",
        "encoded-buffer decode conversion",
        "decodes a non-empty encoded buffer into a hidden C8THgaTQxF return value",
    ),
    (
        "0xf8e54",
        "_ZN10CanTfaz6bZ10lgBtMalYvoES_",
        "0xf8ec8",
        "spectron_CanTfaz6bZ_decodeToC8THgaTQxF_variant",
        "encoded-buffer decode conversion variant",
        "performs the const decode-to-C8THgaTQxF path with the same hidden return layout",
    ),
    (
        "0xf8ec8",
        "_ZNK10CanTfaz6bZ6EqualsERKS_",
        "0xf8f54",
        "spectron_CanTfaz6bZ_equals_CanTfaz6bZ_const",
        "encoded-buffer equality",
        "compares encoded lengths and bytes, using the shared buffer representation",
    ),
    (
        "0xf8f54",
        "_ZNK10CanTfaz6bZ10fEtHgarybFERKS_",
        "0xf8fc8",
        "spectron_CanTfaz6bZ_startsWithEncoded_CanTfaz6bZ_const",
        "encoded-buffer prefix comparison",
        "tests whether the argument bytes form a prefix of the current encoded buffer",
    ),
    (
        "0xf8fc8",
        "_ZNK10CanTfaz6bZ10lHgfJa9EsGERKS_",
        "0xf9090",
        "spectron_CanTfaz6bZ_startsWithIgnoreCase_CanTfaz6bZ_const",
        "decoded case-insensitive prefix comparison",
        "XOR-decodes both buffers while comparing the argument as a case-insensitive prefix",
    ),
    (
        "0xf9090",
        "_ZNK10CanTfaz6bZ10Ven3gakasYERKS_",
        "0xf9178",
        "spectron_CanTfaz6bZ_equalsIgnoreCase_CanTfaz6bZ_const",
        "decoded case-insensitive equality",
        "requires equal lengths and compares both decoded buffers without case sensitivity",
    ),
    (
        "0xf9178",
        "_ZN10CanTfaz6bZ10gwFWfaPxY0Ev",
        "0xf9198",
        "spectron_CanTfaz6bZ_decodeCopyToC8THgaTQxF",
        "encoded-buffer decode wrapper",
        "wraps the encoded-buffer decode conversion and returns its hidden C8THgaTQxF result",
    ),
    (
        "0xf9198",
        "_ZN10CanTfaz6bZaSERK10C8THgaTQxF",
        "0xf91b8",
        "spectron_CanTfaz6bZ_assignFromC8THgaTQxF",
        "encoded-buffer assignment from string",
        "encodes a C8THgaTQxF source through the target encoded-buffer conversion helper",
    ),
    (
        "0xf91b8",
        "_ZN10CanTfaz6bZ9setbufferEPKci",
        "0xf9264",
        "spectron_CanTfaz6bZ_setXorEncodedBuffer_char_const_int",
        "encoded-buffer byte setter",
        "allocates an encoded buffer and XOR-encodes the supplied byte span",
    ),
    (
        "0xf9264",
        "_ZN10CanTfaz6bZ10y_WHgaffAFEv",
        "0xf92d8",
        "spectron_CanTfaz6bZ_makeUnique_void",
        "encoded-buffer copy-on-write",
        "clones a shared encoded buffer before mutation and decrements the old reference",
    ),
    (
        "0xf92d8",
        "_ZN10CanTfaz6bZaSEPKc",
        "0xf9310",
        "spectron_CanTfaz6bZ_assignCStringXorEncoded_char_const",
        "encoded-buffer C-string assignment",
        "measures a C string and stores its XOR-encoded contents",
    ),
    (
        "0xf9310",
        "_ZNK10CanTfaz6bZixEi",
        "0xf9374",
        "spectron_CanTfaz6bZ_indexDecoded_int",
        "encoded-buffer indexed access",
        "returns one decoded byte at a one-based index or zero for an invalid index",
    ),
    (
        "0xf9374",
        "_ZN10CanTfaz6bZ3AddERKS_",
        "0xf94ac",
        "spectron_CanTfaz6bZ_appendXorEncoded_CanTfaz6bZ_const",
        "encoded-buffer concatenation",
        "appends an encoded buffer while correcting both source and destination XOR positions",
    ),
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
    return {row["ea"].lower(): row for row in rows}


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def metric_matches(source_rows: list[dict], target: dict, fields: tuple[str, ...]) -> list[str]:
    return [
        row["ea"]
        for row in source_rows
        if all(row.get(field) == target.get(field) for field in fields)
    ]


def evidence_by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"].lower(): row for row in document.get("targets", [])}


def dynamic_by_value(document: dict) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for row in document.get("rows", []):
        result.setdefault(str(row.get("value", "")).lower(), []).append(row)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path)
    parser.add_argument("--dynamic-symbol-coverage", required=True, type=Path)
    parser.add_argument("--symbol-table", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256", default=TARGET_BINARY_SHA256)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    target_evidence_document = load(args.target_evidence)
    source_evidence_document = load(args.source_evidence)
    dynamic_document = load(args.dynamic_symbol_coverage)
    symbol_document = load(args.symbol_table)
    semantic_document = load(args.semantic_map)

    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    target_evidence = evidence_by_ea(target_evidence_document)
    source_evidence = evidence_by_ea(source_evidence_document)
    dynamic_rows = dynamic_by_value(dynamic_document)
    named_symbols = symbol_document["spectron"]["named_symbols"]

    source_reference_rows = []
    for ea in SOURCE_REFERENCE_EAS:
        row = original.get(ea)
        trace = source_evidence.get(ea)
        if row is None or trace is None:
            raise ValueError("missing source reference evidence for %s" % ea)
        if trace.get("pseudocode") is None:
            raise ValueError("source pseudocode is unavailable for %s" % ea)
        source_reference_rows.append(
            {
                "ea": ea,
                "name": row["name"],
                "function_end": row["end_ea"],
                "metrics": metric_record(row),
                "pseudocode_sha256": hashlib.sha256(
                    trace["pseudocode"].encode("utf-8")
                ).hexdigest(),
                "pseudocode": trace["pseudocode"],
            }
        )

    labels = []
    exact_collision_count = 0
    normalized_11_collision_count = 0
    normalized_10_collision_count = 0
    for target_ea, raw_name, function_end, proposed_name, script_name, operation in SPECS:
        target = spectron.get(target_ea)
        trace = target_evidence.get(target_ea)
        if target is None or trace is None:
            raise ValueError("missing target feature or evidence for %s" % target_ea)
        if target["name"] != raw_name or target["end_ea"] != function_end:
            raise ValueError("target feature identity changed for %s" % target_ea)
        if trace.get("name") != raw_name or trace.get("function_end") != function_end:
            raise ValueError("target evidence identity changed for %s" % target_ea)
        if trace.get("pseudocode") is None:
            raise ValueError("target pseudocode is unavailable for %s" % target_ea)

        exact_matches = metric_matches(original_document["functions"], target, METRIC_FIELDS)
        normalized_11_fields = tuple(field for field in METRIC_FIELDS if field != "register_detail_hash")
        normalized_10_fields = tuple(
            field for field in normalized_11_fields if field != "string_refs_hash"
        )
        normalized_11_matches = metric_matches(
            original_document["functions"], target, normalized_11_fields
        )
        normalized_10_matches = metric_matches(
            original_document["functions"], target, normalized_10_fields
        )
        exact_collision_count += bool(exact_matches)
        normalized_11_collision_count += bool(normalized_11_matches)
        normalized_10_collision_count += bool(normalized_10_matches)

        rows = [
            row
            for row in dynamic_rows.get(target_ea, [])
            if row.get("is_defined") is True and row.get("type") == "FUNC"
        ]
        if len(rows) != 1:
            raise ValueError("expected one defined dynamic FUNC for %s" % target_ea)
        dynamic_row = rows[0]
        if dynamic_row.get("dynamic_name") != raw_name:
            raise ValueError("dynamic symbol identity changed for %s" % target_ea)

        symbol_rows = [
            row
            for row in named_symbols
            if row.get("name") == raw_name
            and "0x%x" % row.get("value", -1) == target_ea
        ]
        if len(symbol_rows) != 1:
            raise ValueError("target symbol table identity changed for %s" % target_ea)

        semantic_target_claimed = any(
            row.get("spectron_ea") == target_ea
            for row in semantic_document.get("matches", [])
        )
        if semantic_target_claimed:
            raise ValueError("target-only function is already in the semantic map: %s" % target_ea)

        labels.append(
            {
                "target_ea": target_ea,
                "current_name": raw_name,
                "function_end": function_end,
                "proposed_name": proposed_name,
                "target_default_name": target.get("is_default_name", False),
                "target_metrics": metric_record(target),
                "target_string_refs": target.get("string_refs", []),
                "target_direct_call_names": target.get("direct_call_names", []),
                "target_pseudocode_sha256": hashlib.sha256(
                    trace["pseudocode"].encode("utf-8")
                ).hexdigest(),
                "target_pseudocode": trace["pseudocode"],
                "target_xrefs_to": trace.get("xrefs_to", []),
                "target_dynamic_symbol": {
                    "dynamic_index": dynamic_row["dynamic_index"],
                    "dynamic_name": dynamic_row["dynamic_name"],
                    "binding": dynamic_row["binding"],
                    "type": dynamic_row["type"],
                    "section_index": dynamic_row["section_index"],
                    "value": dynamic_row["value"],
                    "size": dynamic_row["size"],
                    "prelabel_status": dynamic_row["dynamic_symbol_status"],
                },
                "target_symbol_table_row": symbol_rows[0],
                "script_name": script_name,
                "target_role": "copy-on-write three-byte XOR encoded string buffer or bridge",
                "operation": operation,
                "source_counterpart": None,
                "source_counterpart_status": "not-demonstrated; target encoded-string subsystem has no one-to-one 1.8 function",
                "source_feature_collisions": {
                    "exact_metric_match_eas": exact_matches,
                    "normalized_11_match_eas": normalized_11_matches,
                    "normalized_10_match_eas": normalized_10_matches,
                },
                "semantic_target_claimed_before_label": semantic_target_claimed,
                "confidence": "high",
                "match_kind": "reviewed-target-only-encoded-string-helper",
                "name_action": "rename-with-spectron-prefix",
                "evidence": [
                    "The target dynamic symbol table defines this address as one global FUNC symbol with the recorded raw name and size.",
                    "Target pseudocode shows the copy-on-write encoded-buffer operation recorded in the operation field.",
                    "The CanTfaz6bZ cluster shares a process-generated three-byte XOR key and decoded access paths; the C8THgaTQxF bridge methods convert between the encoded and ordinary string representations.",
                    "The target function is outside the 1.8 semantic map. Any ordinary source feature collisions are recorded as metric collisions rather than source correspondences.",
                    "The spectron_ prefix marks a reviewed target-specific description and does not claim recovery of a 1.8 debug symbol.",
                ],
            }
        )

    if len({row["proposed_name"] for row in labels}) != len(labels):
        raise ValueError("duplicate proposed target-only label")

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed target-only labels for the Spectron C8THgaTQxF and CanTfaz6bZ XOR-encoded string helper cluster",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "target_evidence": str(args.target_evidence),
            "target_evidence_sha256": sha256_path(args.target_evidence),
            "source_evidence": str(args.source_evidence),
            "source_evidence_sha256": sha256_path(args.source_evidence),
            "dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
            "dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
            "symbol_table": str(args.symbol_table),
            "symbol_table_sha256": sha256_path(args.symbol_table),
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "context": {
            "target_component": "C8THgaTQxF and CanTfaz6bZ encoded-string runtime at 0xf37bc through 0xf94ac",
            "source_references": source_reference_rows,
            "source_comparison": "The 1.8 inventory contains ordinary TString and TStringList helpers but no one-to-one counterpart for this target-only XOR-encoded buffer class. Three target rows have ordinary metric collisions, which are retained as evidence and not promoted into the semantic map.",
            "key_behavior": "CanTfaz6bZ initializes a three-byte lower-case XOR key once, stores length and reference count beside encoded bytes, supports copy-on-write mutation, and decodes bytes for indexed access and comparisons.",
            "mapping_boundary": "All rows are descriptive target-only labels. They are excluded from the 1.8-to-Spectron semantic mapping count.",
        },
        "summary": {
            "label_count": len(labels),
            "target_only_count": len(labels),
            "high_confidence_count": sum(row["confidence"] == "high" for row in labels),
            "target_default_name_count": sum(row["target_default_name"] for row in labels),
            "source_counterpart_count": sum(row["source_counterpart"] is not None for row in labels),
            "defined_dynamic_symbol_count": len(labels),
            "exact_metric_collision_target_count": exact_collision_count,
            "normalized_11_collision_target_count": normalized_11_collision_count,
            "normalized_10_collision_target_count": normalized_10_collision_count,
            "semantic_target_claimed_count": sum(
                row["semantic_target_claimed_before_label"] for row in labels
            ),
        },
        "labels": labels,
        "interpretation": [
            "The spectron_ prefix marks target-specific descriptions rather than restored 1.8 symbols.",
            "The CanTfaz6bZ class is an encoded string buffer with a random three-byte XOR key, copy-on-write storage, decoded indexing, case-insensitive comparisons, and concatenation.",
            "C8THgaTQxF::QhxbJaMCjD and its assignment wrapper decode the encoded buffer into the ordinary target string wrapper.",
            "Ordinary source metric collisions are explicitly retained as collisions and are not treated as source correspondences.",
            "No live endpoint was contacted while producing this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
