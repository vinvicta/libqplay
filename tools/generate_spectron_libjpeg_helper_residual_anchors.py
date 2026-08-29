#!/usr/bin/env python3
"""Create reviewed anchors for the remaining libjpeg helper symbols."""

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
        "original_ea": "0x294ee8",
        "original_name": "jpeg_get_small_jpeg_common_struct_ulong",
        "spectron_ea": "0x2a2358",
        "spectron_name": "_Z14jpeg_get_smallP18jpeg_common_structm",
        "proposed_name": "v18_jpeg_get_small_jpeg_common_struct_ulong",
        "operation": "allocates a small libjpeg memory block",
        "evidence": [
            "Both bodies ignore the jpeg_common_struct receiver and return malloc(byte_count).",
            "The normalized ARM64 records are exact, including the two-block branch shape and register allocation.",
            "The target entry is the first raw method in the contiguous memory-manager helper cluster.",
        ],
    },
    {
        "original_ea": "0x294ef0",
        "original_name": "jpeg_free_small_jpeg_common_struct_void_ulong",
        "spectron_ea": "0x2a2360",
        "spectron_name": "_Z15jpeg_free_smallP18jpeg_common_structPvm",
        "proposed_name": "v18_jpeg_free_small_jpeg_common_struct_void_ulong",
        "operation": "frees a small libjpeg memory block",
        "evidence": [
            "Both bodies ignore the jpeg_common_struct receiver and call free(p).",
            "The normalized ARM64 records are exact and match the neighboring get-small helper.",
            "The target method follows jpeg_get_small in the same memory-manager cluster.",
        ],
    },
    {
        "original_ea": "0x294ef8",
        "original_name": "jpeg_get_large_jpeg_common_struct_ulong",
        "spectron_ea": "0x2a2368",
        "spectron_name": "_Z14jpeg_get_largeP18jpeg_common_structm",
        "proposed_name": "v18_jpeg_get_large_jpeg_common_struct_ulong",
        "operation": "allocates a large libjpeg memory block",
        "evidence": [
            "Both bodies ignore the jpeg_common_struct receiver and return malloc(byte_count).",
            "The normalized ARM64 records are exact, including register shape.",
            "The target method is the large-allocation counterpart immediately after the small-allocation pair.",
        ],
    },
    {
        "original_ea": "0x294f00",
        "original_name": "jpeg_free_large_jpeg_common_struct_void_ulong",
        "spectron_ea": "0x2a2370",
        "spectron_name": "_Z15jpeg_free_largeP18jpeg_common_structPvm",
        "proposed_name": "v18_jpeg_free_large_jpeg_common_struct_void_ulong",
        "operation": "frees a large libjpeg memory block",
        "evidence": [
            "Both bodies ignore the jpeg_common_struct receiver and call free(p).",
            "The normalized ARM64 records are exact and match jpeg_free_small.",
            "The target method closes the four-entry small/large allocation pair before the accounting helpers.",
        ],
    },
    {
        "original_ea": "0x294f08",
        "original_name": "jpeg_mem_available_jpeg_common_struct_long_long_long",
        "spectron_ea": "0x2a2378",
        "spectron_name": "_Z18jpeg_mem_availableP18jpeg_common_structlll",
        "proposed_name": "v18_jpeg_mem_available_jpeg_common_struct_long_long_long",
        "operation": "reports the available libjpeg memory amount supplied by the caller",
        "evidence": [
            "Both bodies return the third argument unchanged.",
            "The normalized ARM64 records are exact, with one return block and the same register allocation.",
            "The target entry follows the four allocation helpers and preserves the source memory-manager order.",
        ],
    },
    {
        "original_ea": "0x294f10",
        "original_name": "jpeg_open_backing_store_jpeg_common_struct_backing_store_struct_long",
        "spectron_ea": "0x2a2380",
        "spectron_name": "_Z23jpeg_open_backing_storeP18jpeg_common_structP20backing_store_structl",
        "proposed_name": "v18_jpeg_open_backing_store_jpeg_common_struct_backing_store_struct_long",
        "operation": "initializes the backing-store method tag and dispatches its open callback",
        "evidence": [
            "Both bodies load the backing_store_struct, write 49 to its method field at offset 40, and call its first virtual callback.",
            "The normalized ARM64 records are exact, including the indirect call shape.",
            "The target entry immediately follows jpeg_mem_available in the same raw memory-manager cluster.",
        ],
    },
    {
        "original_ea": "0x294f38",
        "original_name": "jpeg_mem_init_jpeg_common_struct",
        "spectron_ea": "0x2a23a8",
        "spectron_name": "_Z13jpeg_mem_initP18jpeg_common_struct",
        "proposed_name": "v18_jpeg_mem_init_jpeg_common_struct",
        "operation": "performs the no-op libjpeg memory-manager initialization and returns zero",
        "evidence": [
            "Both bodies return zero without using the receiver.",
            "The normalized ARM64 records are exact.",
            "The target method follows jpeg_open_backing_store and precedes jpeg_mem_term, matching the source order.",
        ],
    },
    {
        "original_ea": "0x294f40",
        "original_name": "jpeg_mem_term_jpeg_common_struct",
        "spectron_ea": "0x2a23b0",
        "spectron_name": "_Z13jpeg_mem_termP18jpeg_common_struct",
        "proposed_name": "v18_jpeg_mem_term_jpeg_common_struct",
        "operation": "performs the empty libjpeg memory-manager termination hook",
        "evidence": [
            "Both bodies are a single return instruction with no side effects.",
            "The normalized ARM64 records are exact.",
            "The target entry closes the raw memory-manager helper cluster immediately before the translated color-quantizer code.",
        ],
    },
    {
        "original_ea": "0x297e40",
        "original_name": "jdiv_round_up_long_long",
        "spectron_ea": "0x2a52b0",
        "spectron_name": "_Z13jdiv_round_upll",
        "proposed_name": "v18_jdiv_round_up_long_long",
        "operation": "divides two long integers with upward rounding",
        "evidence": [
            "Both bodies compute (a1 + a2 - 1) / a2 with the same four-instruction ARM64 sequence.",
            "The normalized ARM64 records are exact, including the arithmetic register allocation.",
            "The target helper is in the second libjpeg utility cluster immediately before jround_up.",
        ],
    },
    {
        "original_ea": "0x297e50",
        "original_name": "jround_up_long_long",
        "spectron_ea": "0x2a52c0",
        "spectron_name": "_Z9jround_upll",
        "proposed_name": "v18_jround_up_long_long",
        "operation": "rounds a long integer up to the next multiple",
        "evidence": [
            "Both bodies compute a2 - 1 + a1 - (a2 - 1 + a1) % a2 with the same six-instruction sequence.",
            "The normalized ARM64 records are exact.",
            "The target method follows jdiv_round_up and precedes the translated sample-row copy helper.",
        ],
    },
    {
        "original_ea": "0x297ec8",
        "original_name": "jcopy_block_row_short_64_short_64_uint",
        "spectron_ea": "0x2a5338",
        "spectron_name": "_Z15jcopy_block_rowPA64_sS0_j",
        "proposed_name": "v18_jcopy_block_row_short_64_short_64_uint",
        "operation": "copies one 64-coefficient JPEG block row",
        "evidence": [
            "Both bodies call memcpy(dest, src, a3 << 7), preserving the 128-byte block-row stride.",
            "The normalized ARM64 records are exact, including the two-block branch layout.",
            "The target helper is the raw counterpart of the translated jcopy_sample_rows method in the same libjpeg utility sequence.",
        ],
    },
    {
        "original_ea": "0x297edc",
        "original_name": "jzero_far_void_ulong",
        "spectron_ea": "0x2a534c",
        "spectron_name": "_Z9jzero_farPvm",
        "proposed_name": "v18_jzero_far_void_ulong",
        "operation": "clears a far JPEG buffer",
        "evidence": [
            "Both bodies call memset(a1, 0, a2).",
            "The normalized ARM64 records are exact, including the same two-block control-flow shape.",
            "The target entry closes the small raw helper gap before the translated jpeg_CreateCompress method.",
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
                "source_component": "bundled libjpeg helper runtime",
                "target_component": "obfuscated Spectron libjpeg helper runtime",
                "operation": reviewed["operation"],
                "proposed_name": reviewed["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-libjpeg-helper-residual-exact-anchor"
                if not differences
                else "manual-libjpeg-helper-residual-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": semantic_row is not None,
                "semantic_match_confidence": None if semantic_row is None else semantic_row.get("confidence"),
                "semantic_match_method": None if semantic_row is None else semantic_row.get("method"),
                "source_basis": "Hex-Rays pseudocode, exact normalized ARM64 feature metrics, and local libjpeg helper order",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_libjpeg_helper_residual_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining libjpeg helper symbols",
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
            "The first eight anchors resolve the raw memory-manager methods by direct pseudocode, exact normalized features, and their contiguous libjpeg order.",
            "The final four anchors resolve the raw arithmetic, block-copy, and buffer-clear helpers by exact normalized features and their second libjpeg utility sequence.",
            "All twelve reviewed rows are high-confidence exact normalized matches. The v18_ prefix remains an analysis label and does not claim that Spectron retained the original source symbol.",
        ],
    }
    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in libjpeg helper anchors")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
