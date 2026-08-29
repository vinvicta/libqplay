#!/usr/bin/env python3
"""Create a reviewed anchor for the residual bitmap JPEG static initializer."""

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


REVIEW = {
    "original_ea": "0x151394",
    "original_name": "TBitmap_jpeg_initStaticScriptVars_void",
    "spectron_ea": "0x1541bc",
    "spectron_name": "_Z10eY1M1algS6v",
    "proposed_name": "v18_TBitmap_jpeg_initStaticScriptVars_void",
    "operation": "registers the bitmap JPEG script property table",
    "evidence": [
        "Both bodies perform one property-table registration call with a null receiver, a static definition table, and count one.",
        "The source and target are both 20-byte two-block ARM64 functions with identical normalized opcode, control-flow, register-shape, and call metrics.",
        "The target entry sits immediately before the already translated TGA error and loader helpers, matching the source bitmap codec order.",
    ],
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def metrics(row):
    return {field: row.get(field) for field in METRIC_FIELDS}


def evidence_row(path: Path, ea: str):
    document = load(path)
    for row in document.get("targets", []):
        if row.get("ea") == ea:
            return row
    raise ValueError("missing evidence row at %s" % ea)


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
    parser.add_argument("--source-evidence", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = {int(row["ea"], 16): row for row in original_document["functions"]}
    spectron = {int(row["ea"], 16): row for row in spectron_document["functions"]}
    source = original.get(int(REVIEW["original_ea"], 16))
    target = spectron.get(int(REVIEW["spectron_ea"], 16))
    if source is None or target is None:
        raise ValueError("missing source or target feature")
    if source.get("name") != REVIEW["original_name"]:
        raise ValueError("source name mismatch")
    if target.get("name") != REVIEW["spectron_name"]:
        raise ValueError("target name mismatch")
    if target.get("is_default_name"):
        raise ValueError("target unexpectedly has a default IDA name")

    source_trace = evidence_row(args.source_evidence, REVIEW["original_ea"])
    target_trace = evidence_row(args.target_evidence, REVIEW["spectron_ea"])
    if source_trace.get("pseudocode") is None or target_trace.get("pseudocode") is None:
        raise ValueError("pseudocode was unavailable")
    source_metrics = metrics(source)
    target_metrics = metrics(target)
    differences = [
        field for field in METRIC_FIELDS
        if source_metrics.get(field) != target_metrics.get(field)
    ]
    semantic = semantic_rows(semantic_document).get(
        (int(REVIEW["original_ea"], 16), int(REVIEW["spectron_ea"], 16))
    )
    anchor = {
        "original_ea": REVIEW["original_ea"],
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": source_metrics,
        "original_direct_call_names": source.get("direct_call_names", []),
        "original_string_refs": source.get("string_refs", []),
        "source_pseudocode_sha256": pseudocode_sha256(source_trace),
        "source_evidence_name": source_trace.get("name"),
        "spectron_ea": REVIEW["spectron_ea"],
        "spectron_name": target["name"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_metrics": target_metrics,
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_string_refs": target.get("string_refs", []),
        "target_pseudocode_sha256": pseudocode_sha256(target_trace),
        "target_evidence_name": target_trace.get("name"),
        "source_component": "TBitmap JPEG script-property runtime",
        "target_component": "obfuscated bitmap codec runtime",
        "operation": REVIEW["operation"],
        "proposed_name": REVIEW["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-bitmap-jpeg-static-layout-anchor",
        "exact_metric_match": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": semantic is not None,
        "semantic_match_confidence": None if semantic is None else semantic.get("confidence"),
        "semantic_match_method": None if semantic is None else semantic.get("method"),
        "source_basis": "Hex-Rays pseudocode, normalized ARM64 feature metrics, and bitmap codec class-local order",
        "evidence": REVIEW["evidence"],
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_bitmap_jpeg_static_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the residual bitmap JPEG static initializer",
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
            "source_evidence": [{"path": str(args.source_evidence), "sha256": sha256_path(args.source_evidence)}],
            "target_evidence": [{"path": str(args.target_evidence), "sha256": sha256_path(args.target_evidence)}],
        },
        "summary": {
            "anchor_count": 1,
            "exact_metric_anchor_count": int(anchor["exact_metric_match"]),
            "high_confidence_count": 1,
            "layout_change_anchor_count": int(not anchor["exact_metric_match"]),
            "source_pseudocode_count": int(anchor["source_pseudocode_sha256"] is not None),
            "target_pseudocode_count": int(anchor["target_pseudocode_sha256"] is not None),
            "semantic_promotion_count": int(anchor["semantic_match_already_present"]),
            "new_context_anchor_count": int(not anchor["semantic_match_already_present"]),
        },
        "anchors": [anchor],
        "interpretation": [
            "The target eY1M1algS6 entry is the obfuscated counterpart of TBitmap_jpeg_initStaticScriptVars_void. Both register one static bitmap JPEG property table through the corresponding target property helper.",
            "The source and target have the same normalized 20-byte registration shape. The only recorded difference is register-detail allocation after the target wrapper rebuild.",
            "This is a high-confidence manual anchor and was not present in the carried-forward automatic semantic map.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
