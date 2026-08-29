#!/usr/bin/env python3
"""Create a reviewed label for the Spectron-only resource path helper.

The target inserts a second hidden-sret resource path routine between its
resource-modification-time and resource-stream methods.  The 1.8 library has
the related ``getGameFile`` method, but the target already has a separate
body mapped to that source method.  This artifact therefore records the new
target boundary as a descriptive label instead of claiming a duplicate
source correspondence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_resource_path_helper_target_only_labels_20260829"
TARGET_EA = "0xefbcc"
TARGET_END = "0xefcd0"
TARGET_NAME = "_ZN10f6WHgaQkAF10iaBygafTIxERK10C8THgaTQxFb"
TARGET_PROPOSED_NAME = "spectron_TResourceFunctions_resolveResourcePath_TString_const_bool"
SOURCE_GAME_FILE_EA = "0xeec84"
SOURCE_ABS_PATH_EA = "0xedf40"
TARGET_EXISTING_GAME_FILE_EA = "0xefe78"

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


def pseudocode_sha256(row: dict | None) -> str | None:
    if row is None or row.get("pseudocode") is None:
        return None
    return hashlib.sha256(row["pseudocode"].encode("utf-8")).hexdigest()


def metric_differences(left: dict, right: dict, fields: tuple[str, ...]) -> list[str]:
    return [field for field in fields if left.get(field) != right.get(field)]


def evidence_by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"].lower(): row for row in document.get("targets", [])}


def selected_dynamic_symbol(document: dict) -> dict:
    rows = [
        row
        for row in document["rows"]
        if row.get("dynamic_name") == TARGET_NAME
        and row.get("value") == TARGET_EA
    ]
    if len(rows) != 1:
        raise ValueError("expected one defined dynamic symbol for the target helper")
    return rows[0]


def selected_data_pointer(document: dict) -> dict:
    for row in document.get("rows", []):
        if row.get("ea") != "0x154b0":
            continue
        pointers = [item for item in row.get("pointers", []) if item.get("ea") == "0x154b8"]
        if len(pointers) != 1:
            raise ValueError("expected one helper pointer in the target data window")
        pointer = pointers[0]
        if pointer.get("value") != TARGET_EA or pointer.get("name") != TARGET_NAME:
            raise ValueError("target data window does not point at the expected helper")
        return {
            "window_ea": row["ea"],
            "window_item_size": row.get("item_size"),
            "pointer_ea": pointer["ea"],
            "pointer_value": pointer["value"],
            "pointer_name": pointer["name"],
            "pointer_item_size": pointer.get("item_size"),
        }
    raise ValueError("target data window does not contain 0x154b0")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--target-game-file-evidence", required=True, type=Path)
    parser.add_argument("--target-data-evidence", required=True, type=Path)
    parser.add_argument("--resource-anchor", required=True, type=Path)
    parser.add_argument("--dynamic-symbol-coverage", required=True, type=Path)
    parser.add_argument("--symbol-table", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    source_document = load(args.source_evidence)
    target_document = load(args.target_evidence)
    target_game_file_document = load(args.target_game_file_evidence)
    data_document = load(args.target_data_evidence)
    resource_anchor_document = load(args.resource_anchor)
    dynamic_document = load(args.dynamic_symbol_coverage)
    symbol_document = load(args.symbol_table)
    semantic_document = load(args.semantic_map)

    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    source_evidence = evidence_by_ea(source_document)
    target_evidence = evidence_by_ea(target_document)
    target_game_file_evidence = evidence_by_ea(target_game_file_document)

    target = spectron.get(TARGET_EA)
    target_trace = target_evidence.get(TARGET_EA)
    source_game_file = original.get(SOURCE_GAME_FILE_EA)
    source_abs_path = original.get(SOURCE_ABS_PATH_EA)
    source_game_file_trace = source_evidence.get(SOURCE_GAME_FILE_EA)
    source_abs_path_trace = source_evidence.get(SOURCE_ABS_PATH_EA)
    target_game_file = spectron.get(TARGET_EXISTING_GAME_FILE_EA)
    target_game_file_trace = target_game_file_evidence.get(TARGET_EXISTING_GAME_FILE_EA)

    if target is None or target_trace is None:
        raise ValueError("missing target helper feature or evidence")
    if target["name"] != TARGET_NAME or target["end_ea"] != TARGET_END:
        raise ValueError("target helper feature identity changed")
    if target_trace.get("name") != TARGET_NAME or target_trace.get("function_end") != TARGET_END:
        raise ValueError("target helper evidence identity changed")
    if target_trace.get("pseudocode") is None:
        raise ValueError("target helper pseudocode is unavailable")
    if source_game_file is None or source_abs_path is None:
        raise ValueError("missing source resource comparison feature")
    if source_game_file_trace is None or source_abs_path_trace is None:
        raise ValueError("missing source resource comparison evidence")
    if source_game_file_trace.get("pseudocode") is None or source_abs_path_trace.get("pseudocode") is None:
        raise ValueError("source resource comparison pseudocode is unavailable")
    if target_game_file is None or target_game_file_trace is None:
        raise ValueError("missing existing target getGameFile evidence")
    if target_game_file.get("name") != "v18_TResourceFunctions_getGameFile_TString_const_bool":
        raise ValueError("existing target getGameFile alias changed")
    if target_game_file_trace.get("name") != target_game_file.get("name"):
        raise ValueError("existing target getGameFile evidence changed")

    resource_anchors = [
        row
        for row in resource_anchor_document.get("anchors", [])
        if row.get("original_ea") == SOURCE_GAME_FILE_EA
        and row.get("spectron_ea") == TARGET_EXISTING_GAME_FILE_EA
    ]
    if len(resource_anchors) != 1:
        raise ValueError("existing source-to-target getGameFile anchor is missing")
    existing_resource_anchor = resource_anchors[0]

    dynamic_row = selected_dynamic_symbol(dynamic_document)
    if dynamic_row.get("is_defined") is not True or dynamic_row.get("type") != "FUNC":
        raise ValueError("target helper is not a defined FUNC dynamic symbol")
    symbol_rows = [
        row
        for row in symbol_document["spectron"]["named_symbols"]
        if row.get("name") == TARGET_NAME and "0x%x" % row.get("value", -1) == TARGET_EA
    ]
    if len(symbol_rows) != 1:
        raise ValueError("target symbol table does not contain exactly one helper symbol")
    symbol_row = symbol_rows[0]
    if symbol_row.get("size") != target.get("size"):
        raise ValueError("target dynamic symbol size does not match feature size")

    data_pointer = selected_data_pointer(data_document)
    source_metrics = metric_record(source_game_file)
    source_abs_metrics = metric_record(source_abs_path)
    target_metrics = metric_record(target)
    all_source_rows = original_document["functions"]
    exact_matches = [
        row["ea"]
        for row in all_source_rows
        if metric_record(row) == target_metrics
    ]
    normalized_11_fields = tuple(field for field in METRIC_FIELDS if field != "register_detail_hash")
    normalized_10_fields = tuple(
        field
        for field in normalized_11_fields
        if field != "string_refs_hash"
    )
    normalized_11_matches = [
        row["ea"]
        for row in all_source_rows
        if not metric_differences(row, target, normalized_11_fields)
    ]
    normalized_10_matches = [
        row["ea"]
        for row in all_source_rows
        if not metric_differences(row, target, normalized_10_fields)
    ]
    semantic_target_claimed = any(
        row.get("spectron_ea") == TARGET_EA
        for row in semantic_document.get("matches", [])
    )

    label = {
        "target_ea": TARGET_EA,
        "current_name": TARGET_NAME,
        "function_end": TARGET_END,
        "proposed_name": TARGET_PROPOSED_NAME,
        "target_default_name": target.get("is_default_name", False),
        "target_metrics": target_metrics,
        "target_string_refs": target.get("string_refs", []),
        "target_direct_call_names": target.get("direct_call_names", []),
        "target_pseudocode_sha256": pseudocode_sha256(target_trace),
        "target_pseudocode": target_trace["pseudocode"],
        "target_xrefs_to": target_trace.get("xrefs_to", []),
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
        "target_data_symbol_record": data_pointer,
        "script_name": "Spectron resource path/update helper",
        "target_role": "resource path, optional update, and download fallback helper",
        "operation": "resolves an absolute or level-relative resource, optionally updates a loaded resource or requests a missing download, and returns the composed local resource path through the hidden X8 TString output",
        "source_counterpart": None,
        "source_counterpart_status": "not-demonstrated; target already has a separate getGameFile correspondence",
        "source_comparison": {
            "source_game_file": {
                "ea": SOURCE_GAME_FILE_EA,
                "name": source_game_file["name"],
                "function_end": source_game_file["end_ea"],
                "metrics": source_metrics,
                "metric_differences": metric_differences(source_game_file, target, METRIC_FIELDS),
                "pseudocode_sha256": pseudocode_sha256(source_game_file_trace),
                "pseudocode": source_game_file_trace["pseudocode"],
            },
            "source_absolute_path_resource_lookup": {
                "ea": SOURCE_ABS_PATH_EA,
                "name": source_abs_path["name"],
                "function_end": source_abs_path["end_ea"],
                "metrics": source_abs_metrics,
                "metric_differences": metric_differences(source_abs_path, target, METRIC_FIELDS),
                "pseudocode_sha256": pseudocode_sha256(source_abs_path_trace),
                "pseudocode": source_abs_path_trace["pseudocode"],
            },
            "existing_target_game_file": {
                "ea": TARGET_EXISTING_GAME_FILE_EA,
                "name": target_game_file["name"],
                "function_end": target_game_file["end_ea"],
                "metrics": metric_record(target_game_file),
                "pseudocode_sha256": pseudocode_sha256(target_game_file_trace),
                "pseudocode": target_game_file_trace["pseudocode"],
                "source_anchor": existing_resource_anchor,
            },
            "source_feature_count": len(all_source_rows),
            "exact_metric_match_count": len(exact_matches),
            "exact_metric_match_eas": exact_matches,
            "normalized_11_fields": list(normalized_11_fields),
            "normalized_11_match_count": len(normalized_11_matches),
            "normalized_11_match_eas": normalized_11_matches,
            "normalized_10_fields": list(normalized_10_fields),
            "normalized_10_match_count": len(normalized_10_matches),
            "normalized_10_match_eas": normalized_10_matches,
            "semantic_target_claimed_before_label": semantic_target_claimed,
        },
        "confidence": "high",
        "match_kind": "reviewed-target-only-resource-path-helper",
        "name_action": "rename-with-spectron-prefix",
        "evidence": [
            "The target dynamic symbol table defines this address as one global FUNC symbol with value 0xefbcc and size 0x104.",
            "The target function takes a resource-function receiver, a boolean update flag, and a hidden X8 TString output. It selects an absolute-path or level-relative resource lookup, checks loadability, optionally updates or downloads the resource, and concatenates the stored path and resource name.",
            "The target data window at 0x154b0 contains the dynamic-symbol record whose function value at 0x154b8 is 0xefbcc.",
            "The only incoming xref is that dynamic-symbol data record. No code caller was demonstrated, so the label records an exported target boundary without inventing an internal call graph.",
            "The 1.8 getGameFile body is already represented by the separate target function at 0xefe78, which has the reviewed v18_TResourceFunctions_getGameFile_TString_const_bool alias.",
            "The target helper is a distinct dynamic symbol and its complete feature record has no match in the 1.8 function inventory, including the 11-field and 10-field normalized comparisons recorded here.",
            "No 1.8 source address is claimed for this second target boundary. The spectron_ prefix marks a reviewed target-specific description.",
        ],
    }

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "one reviewed target-only Spectron resource path helper with a separate existing getGameFile source correspondence",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "source_evidence": str(args.source_evidence),
            "source_evidence_sha256": sha256_path(args.source_evidence),
            "target_evidence": str(args.target_evidence),
            "target_evidence_sha256": sha256_path(args.target_evidence),
            "target_game_file_evidence": str(args.target_game_file_evidence),
            "target_game_file_evidence_sha256": sha256_path(args.target_game_file_evidence),
            "target_data_evidence": str(args.target_data_evidence),
            "target_data_evidence_sha256": sha256_path(args.target_data_evidence),
            "resource_anchor": str(args.resource_anchor),
            "resource_anchor_sha256": sha256_path(args.resource_anchor),
            "dynamic_symbol_coverage": str(args.dynamic_symbol_coverage),
            "dynamic_symbol_coverage_sha256": sha256_path(args.dynamic_symbol_coverage),
            "symbol_table": str(args.symbol_table),
            "symbol_table_sha256": sha256_path(args.symbol_table),
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "context": {
            "target_component": "f6WHgaQkAF resource-functions block at 0xef090 through 0xf0058",
            "source_component": "TResourceFunctions resource block at 0xedb10 through 0xeef3c",
            "existing_related_alias": "v18_TResourceFunctions_getGameFile_TString_const_bool at target 0xefe78",
            "comparison_boundary": "The helper shares high-level path construction with getGameFile, but it is a distinct target function with absolute-path selection and update/loadability behavior. It is not counted as a duplicate source match.",
            "label_policy": "spectron_ names describe target-only behavior and remain outside the 1.8-to-Spectron semantic mapping count",
        },
        "summary": {
            "label_count": 1,
            "target_only_count": 1,
            "high_confidence_count": 1,
            "source_counterpart_count": 0,
            "target_default_name_count": int(target.get("is_default_name", False)),
            "target_code_caller_count": 0,
            "defined_dynamic_symbol_count": 1,
            "exact_metric_match_count": len(exact_matches),
            "normalized_11_match_count": len(normalized_11_matches),
            "normalized_10_match_count": len(normalized_10_matches),
        },
        "labels": [label],
        "interpretation": [
            "This is a descriptive target-only name, not a recovered upstream symbol.",
            "The target's separate 0xefe78 body remains the source-backed getGameFile alias. The new 0xefbcc boundary is therefore kept separate even though both return composed resource paths.",
            "The target helper is useful for future runtime work because it can refresh a loaded resource, request a missing download, and return the resulting local path using the target's C8THgaTQxF string wrapper.",
            "No live endpoint was contacted while producing this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
