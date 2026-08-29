#!/usr/bin/env python3
"""Create reviewed anchors for the resource-object static helper cluster."""

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


ANCHOR_SPECS = (
    {
        "original_ea": "0xf0434",
        "original_name": "TResourceObject_initStaticVars_void",
        "spectron_ea": "0xf1910",
        "spectron_name": "_Z10dZEN2aa5nYv",
        "proposed_name": "v18_TResourceObject_initStaticVars_void",
        "operation": "allocates and installs the resource-object hash list",
        "source_calls": ["plt_THashList_THashList_void__2", "plt_operator_new_ulong__2"],
        "target_calls": ["._ZN10KKhLga4xoIC1Ev", "._Znwm"],
    },
    {
        "original_ea": "0xf0464",
        "original_name": "TEncodedFileKey_TEncodedFileKey",
        "spectron_ea": "0xf1940",
        "spectron_name": "_ZN10uVBvgaZvcvD2Ev",
        "proposed_name": "v18_TEncodedFileKey_TEncodedFileKey",
        "operation": "resets the TEncodedFileKey vtable and clears both string members",
        "source_calls": ["plt_TString_clear_void"],
        "target_calls": ["._ZN10C8THgaTQxF5clearEv"],
    },
    {
        "original_ea": "0xf04a4",
        "original_name": "TEncodedFileKey_TEncodedFileKey__2",
        "spectron_ea": "0xf1980",
        "spectron_name": "_ZN10uVBvgaZvcvD0Ev",
        "proposed_name": "v18_TEncodedFileKey_TEncodedFileKey__2",
        "operation": "clears both TEncodedFileKey strings and releases the object",
        "source_calls": ["plt_TString_clear_void"],
        "target_calls": ["._ZN10C8THgaTQxF5clearEv", "._ZN10CanTfaz6bZ5clearEv"],
    },
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(rows: list[dict]) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in rows}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def evidence_by_ea(paths: list[Path]) -> tuple[dict[int, dict], list[dict]]:
    rows: dict[int, dict] = {}
    inputs = []
    for path in paths:
        document = load(path)
        inputs.append({"path": str(path), "sha256": sha256_path(path)})
        for row in document.get("targets", []):
            ea = int(row["ea"], 16)
            previous = rows.get(ea)
            if previous is not None:
                if previous.get("name") != row.get("name") or previous.get("pseudocode") != row.get("pseudocode"):
                    raise ValueError("conflicting evidence row at %s" % row["ea"])
                continue
            rows[ea] = row
    return rows, inputs


def pseudocode_sha256(row: dict) -> str | None:
    pseudocode = row.get("pseudocode")
    if pseudocode is None:
        return None
    return hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()


def semantic_rows(document: dict) -> dict[tuple[int, int], dict]:
    return {
        (int(row["original_ea"], 16), int(row["spectron_ea"], 16)): row
        for row in document.get("matches", [])
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path, action="append")
    parser.add_argument("--target-evidence", required=True, type=Path, action="append")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    source_evidence, source_inputs = evidence_by_ea(args.source_evidence)
    target_evidence, target_inputs = evidence_by_ea(args.target_evidence)
    semantic = semantic_rows(semantic_document)

    anchors = []
    for reviewed in ANCHOR_SPECS:
        original_ea = int(reviewed["original_ea"], 16)
        spectron_ea = int(reviewed["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        source_trace = source_evidence.get(original_ea)
        target_trace = target_evidence.get(spectron_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % reviewed["original_ea"])
        if source.get("name") != reviewed["original_name"]:
            raise ValueError("source name mismatch at %s" % reviewed["original_ea"])
        if target.get("name") != reviewed["spectron_name"]:
            raise ValueError("target name mismatch at %s" % reviewed["spectron_ea"])
        if target.get("is_default_name"):
            raise ValueError("target unexpectedly has a default name at %s" % reviewed["spectron_ea"])
        if source_trace is None or target_trace is None:
            raise ValueError("missing pseudocode evidence at %s" % reviewed["original_ea"])
        if source_trace.get("name") != reviewed["original_name"] or target_trace.get("name") != reviewed["spectron_name"]:
            raise ValueError("evidence name mismatch at %s" % reviewed["original_ea"])
        if source_trace.get("pseudocode") is None or target_trace.get("pseudocode") is None:
            raise ValueError("pseudocode was unavailable at %s" % reviewed["original_ea"])
        for call in reviewed["source_calls"]:
            if call not in source.get("direct_call_names", []):
                raise ValueError("missing source call at %s" % reviewed["original_ea"])
        for call in reviewed["target_calls"]:
            if call not in target.get("direct_call_names", []):
                raise ValueError("missing target call at %s" % reviewed["spectron_ea"])

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differences = [
            field for field in METRIC_FIELDS if source_metrics.get(field) != target_metrics.get(field)
        ]
        semantic_row = semantic.get((original_ea, spectron_ea))
        anchors.append(
            {
                "original_ea": reviewed["original_ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_string_refs": source.get("string_refs", []),
                "source_pseudocode_sha256": pseudocode_sha256(source_trace),
                "source_evidence_name": source_trace["name"],
                "spectron_ea": reviewed["spectron_ea"],
                "spectron_name": target["name"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_metrics": target_metrics,
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_string_refs": target.get("string_refs", []),
                "target_pseudocode_sha256": pseudocode_sha256(target_trace),
                "target_evidence_name": target_trace["name"],
                "source_component": "bundled TResourceObject and TEncodedFileKey runtime",
                "target_component": "obfuscated resource-object runtime",
                "operation": reviewed["operation"],
                "proposed_name": reviewed["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-resource-object-static-layout-anchor",
                "exact_metric_match": not differences,
                "normalized_shape_match": (
                    source_metrics["size"] == target_metrics["size"]
                    and source_metrics["instruction_count"] == target_metrics["instruction_count"]
                    and source_metrics["basic_block_count"] == target_metrics["basic_block_count"]
                    and source_metrics["mnemonic_hash"] == target_metrics["mnemonic_hash"]
                    and source_metrics["opcode_shape_hash"] == target_metrics["opcode_shape_hash"]
                    and source_metrics["register_shape_hash"] == target_metrics["register_shape_hash"]
                    and source_metrics["shape_hash"] == target_metrics["shape_hash"]
                ),
                "metric_differences": differences,
                "semantic_match_already_present": semantic_row is not None,
                "semantic_match_confidence": None if semantic_row is None else semantic_row.get("confidence"),
                "semantic_match_method": None if semantic_row is None else semantic_row.get("method"),
                "source_basis": "Hex-Rays pseudocode, exact normalized ARM64 shape, direct constructor or destructor calls, and adjacent resource-object order",
                "evidence": [
                    "The initializer allocates the target hash-list wrapper and installs it in the same resource-object static slot as the source.",
                    "Both TEncodedFileKey forms reset the vtable, clear the two embedded strings, and differ only by the final object release.",
                    "The target preserves the three-method order immediately before its TStream helpers, while wrapper spellings and register-detail allocation change.",
                ],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in resource-object anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_resource_object_static_residual_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TResourceObject and TEncodedFileKey static cluster",
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
            "source_evidence": source_inputs,
            "target_evidence": target_inputs,
        },
        "summary": {
            "anchor_count": len(anchors),
            "exact_metric_anchor_count": sum(row["exact_metric_match"] for row in anchors),
            "normalized_shape_match_count": sum(row["normalized_shape_match"] for row in anchors),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "layout_change_anchor_count": sum(not row["exact_metric_match"] for row in anchors),
            "source_pseudocode_count": sum(row["source_pseudocode_sha256"] is not None for row in anchors),
            "target_pseudocode_count": sum(row["target_pseudocode_sha256"] is not None for row in anchors),
            "semantic_promotion_count": sum(row["semantic_match_already_present"] for row in anchors),
            "new_context_anchor_count": sum(not row["semantic_match_already_present"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "The three anchors are separated by their source and target class-local order and direct constructor or destructor behavior.",
            "The v18_ prefix is an analysis label and does not claim that Spectron retained the original source symbol.",
            "The saved evidence is offline and does not contact a live server or decrypt external data.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
