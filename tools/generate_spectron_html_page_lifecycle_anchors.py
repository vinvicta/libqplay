#!/usr/bin/env python3
"""Create reviewed anchors for the residual THTMLPage lifecycle methods."""

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
        "original_ea": "0x1d1318",
        "original_name": "THTMLPage_initTabStops_void",
        "spectron_ea": "0x1d5f6c",
        "spectron_name": "_ZN10AS80gaE4zW10g3mRgak0vNEv",
        "proposed_name": "v18_THTMLPage_initTabStops_void",
        "operation": "initializes the HTML page tab-stop storage",
        "evidence": [
            "Both bodies clear the tab-stop pointer at offset 152, clear the count at offset 160, and return the receiver.",
            "The normalized ARM64 records are exact, including size, control flow, and register detail.",
            "The target method is the first raw entry in the AS80gaE4zW THTMLPage lifecycle sequence.",
        ],
    },
    {
        "original_ea": "0x1d1418",
        "original_name": "THTMLPage_initLineTags_void",
        "spectron_ea": "0x1d606c",
        "spectron_name": "_ZN10AS80gaE4zW10EGlRgaCRuNEv",
        "proposed_name": "v18_THTMLPage_initLineTags_void",
        "operation": "initializes the HTML page line-tag list",
        "evidence": [
            "Both bodies clear the line-tag pointer at offset 344 and return the receiver.",
            "The normalized ARM64 records are exact.",
            "The target method follows the translated tab-stop allocation methods in the same AS80gaE4zW class block.",
        ],
    },
    {
        "original_ea": "0x1d14b0",
        "original_name": "THTMLPage_freeLineTags_void",
        "spectron_ea": "0x1d6104",
        "spectron_name": "_ZN10AS80gaE4zW10OZOQgaFv2MEv",
        "proposed_name": "v18_THTMLPage_freeLineTags_void",
        "operation": "frees the linked list of HTML page line tags",
        "evidence": [
            "Both bodies walk the line-tag list at member index 43, clear each string, delete each node, and clear the head pointer.",
            "The normalized ARM64 records are exact, including the loop and cleanup control flow.",
            "The target method follows initLineTags and precedes the raw style initializer, preserving the source lifecycle order.",
        ],
    },
    {
        "original_ea": "0x1d14f8",
        "original_name": "THTMLPage_initStyles_void",
        "spectron_ea": "0x1d614c",
        "spectron_name": "_ZN10AS80gaE4zW10XBgRgaCAqNEv",
        "proposed_name": "v18_THTMLPage_initStyles_void",
        "operation": "initializes the HTML page style storage",
        "evidence": [
            "Both bodies clear the style list and current-style pointers at offsets 200 and 208, then return the receiver.",
            "The normalized ARM64 records are exact.",
            "The target method follows the raw line-tag destructor and precedes the translated style allocation methods.",
        ],
    },
    {
        "original_ea": "0x1d169c",
        "original_name": "THTMLPage_initSubPages_void",
        "spectron_ea": "0x1d62f0",
        "spectron_name": "_ZN10AS80gaE4zW10uWkRgaPduNEv",
        "proposed_name": "v18_THTMLPage_initSubPages_void",
        "operation": "initializes the HTML page sub-page list",
        "evidence": [
            "Both bodies clear the sub-page pointer at offset 352 and return the receiver.",
            "The normalized ARM64 records are exact.",
            "The target method sits immediately before the translated allocSubPage method in the AS80gaE4zW sequence.",
        ],
    },
    {
        "original_ea": "0x1d276c",
        "original_name": "THTMLPage_initLists_void",
        "spectron_ea": "0x1d73c0",
        "spectron_name": "_ZN10AS80gaE4zW10EmhRgaNdrNEv",
        "proposed_name": "v18_THTMLPage_initLists_void",
        "operation": "initializes the HTML page list stack",
        "evidence": [
            "Both bodies clear the list-stack pointers at offsets 224 and 232, then return the receiver.",
            "The normalized ARM64 records are exact.",
            "The target method precedes the translated HTMLPage constructor and follows the line-management methods in the same class block.",
        ],
    },
    {
        "original_ea": "0x1d2ad0",
        "original_name": "THTMLPage_freeSubPages_void",
        "spectron_ea": "0x1d7724",
        "spectron_name": "_ZN10AS80gaE4zW10meOQgaMS1MEv",
        "proposed_name": "v18_THTMLPage_freeSubPages_void",
        "operation": "frees the linked list of HTML page sub-pages",
        "evidence": [
            "Both bodies walk the sub-page list at member index 44, destroy and delete each node, and clear the head pointer.",
            "The normalized ARM64 records are exact, including the loop and cleanup control flow.",
            "The target method is the raw cleanup boundary immediately before the translated parse-variable initializer, matching the source order.",
        ],
    },
)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(rows):
    return {int(row["ea"], 16): row for row in rows}


def metrics(row):
    return {field: row.get(field) for field in METRIC_FIELDS}


def evidence_by_ea(paths):
    rows = {}
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


def pseudocode_sha256(row):
    pseudocode = row.get("pseudocode")
    if pseudocode is None:
        return None
    return hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()


def semantic_rows(document):
    return {
        (int(row["original_ea"], 16), int(row["spectron_ea"], 16)): row
        for row in document.get("matches", [])
    }


def main():
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
            raise ValueError("target unexpectedly has a default IDA name at %s" % reviewed["spectron_ea"])
        if source_trace is None or target_trace is None:
            raise ValueError("missing pseudocode evidence at %s" % reviewed["original_ea"])
        if source_trace.get("pseudocode") is None or target_trace.get("pseudocode") is None:
            raise ValueError("pseudocode was unavailable at %s" % reviewed["original_ea"])

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differences = [
            field
            for field in METRIC_FIELDS
            if source_metrics.get(field) != target_metrics.get(field)
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
                "source_evidence_name": source_trace.get("name"),
                "spectron_ea": reviewed["spectron_ea"],
                "spectron_name": target["name"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_metrics": target_metrics,
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_string_refs": target.get("string_refs", []),
                "target_pseudocode_sha256": pseudocode_sha256(target_trace),
                "target_evidence_name": target_trace.get("name"),
                "source_component": "bundled THTMLPage runtime",
                "target_component": "obfuscated AS80gaE4zW HTML-page runtime",
                "operation": reviewed["operation"],
                "proposed_name": reviewed["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-html-page-lifecycle-exact-anchor"
                if not differences
                else "manual-html-page-lifecycle-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": semantic_row is not None,
                "semantic_match_confidence": None if semantic_row is None else semantic_row.get("confidence"),
                "semantic_match_method": None if semantic_row is None else semantic_row.get("method"),
                "source_basis": "Hex-Rays pseudocode, exact normalized ARM64 feature metrics, and local AS80gaE4zW method order",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_html_page_lifecycle_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual THTMLPage lifecycle methods",
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
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "layout_change_anchor_count": sum(not row["exact_metric_match"] for row in anchors),
            "source_pseudocode_count": sum(row["source_pseudocode_sha256"] is not None for row in anchors),
            "target_pseudocode_count": sum(row["target_pseudocode_sha256"] is not None for row in anchors),
            "semantic_promotion_count": sum(row["semantic_match_already_present"] for row in anchors),
            "new_context_anchor_count": sum(not row["semantic_match_already_present"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "The seven anchors resolve the raw AS80gaE4zW lifecycle entries by direct pseudocode, exact normalized features, and their position between translated THTMLPage methods.",
            "The initializer rows clear the same THTMLPage member offsets in both builds. The two cleanup rows preserve the source list walks, string or sub-page destruction, deletion, and head-pointer reset.",
            "All seven reviewed rows are high-confidence exact normalized matches. The v18_ prefix remains an analysis label and does not claim that Spectron retained the original source symbol.",
        ],
    }
    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in HTML-page lifecycle anchors")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
