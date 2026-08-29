#!/usr/bin/env python3
"""Create reviewed anchors for the residual Adventure static/runtime entries."""

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
        "original_ea": "0x15ae0c",
        "original_name": "gsfunctions_client_initStaticVars_void",
        "spectron_ea": "0x15de64",
        "spectron_name": "_Z10aitCvaXfZcv",
        "proposed_name": "v18_gsfunctions_client_initStaticVars_void",
        "operation": "allocates and clears the GSFunctionsClient static shootparams storage",
        "evidence": [
            "Both bodies allocate eight bytes, clear the first qword, and store the resulting pointer in the class-specific static variable.",
            "The normalized ARM64 records match in size, instruction count, control-flow shape, opcode sequence, register shape, and overall shape; only register-detail allocation differs.",
            "The target entry immediately precedes the already translated gsfunctions_client_initStaticScriptVars_void body, preserving the source class-local order.",
        ],
    },
    {
        "original_ea": "0x15b4d0",
        "original_name": "TAdventure_freeResources_void",
        "spectron_ea": "0x15e528",
        "spectron_name": "_ZN10oJlO1aTTY710wgSQgaCg5MEv",
        "proposed_name": "v18_TAdventure_freeResources_void",
        "operation": "frees the Adventure graphics and sound resources",
        "evidence": [
            "The source body calls the client-environment graphics cleanup and then frees the returned sound object.",
            "The target body preserves the same two-call cleanup sequence through its rebuilt oJlO1aTTY7 and IUKzgam4Gy classes.",
            "The target entry sits between initResources and the translated TAdventure constructor, exactly where the source freeResources entry occurs.",
        ],
    },
    {
        "original_ea": "0x15bf38",
        "original_name": "TAdventure_handleMouseMove_void",
        "spectron_ea": "0x15ef90",
        "spectron_name": "_ZN10oJlO1aTTY710SenF1ahaq0Ev",
        "proposed_name": "v18_TAdventure_handleMouseMove_void",
        "operation": "handles the Adventure mouse-move callback as a no-op",
        "evidence": [
            "Both source and target functions are one-instruction empty callbacks with the same exact normalized feature record.",
            "The target raw method is inside the oJlO1aTTY7 Adventure block and immediately precedes the translated paintGraphics method.",
            "The source method has the same position between handleMouseEvent and paintGraphics, so the empty body is not assigned from size alone.",
        ],
    },
    {
        "original_ea": "0x15c224",
        "original_name": "TAdventure_initStaticScriptVars_void",
        "spectron_ea": "0x15f27c",
        "spectron_name": "_Z10H0oQ2aeFH_v",
        "proposed_name": "v18_TAdventure_initStaticScriptVars_void",
        "operation": "runs the Adventure static script-variable initializer, currently empty",
        "evidence": [
            "Both source and target entries are one-instruction empty functions with the same exact normalized feature record.",
            "The target entry follows the translated TAdventure_initStaticVars_void method and immediately precedes translated openSecureURL, matching the source order.",
            "The target raw identifier is therefore resolved by class-local placement and neighboring method roles, not by an unqualified empty-function collision.",
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
                "source_component": "GSFunctionsClient and TAdventure residual runtime",
                "target_component": "obfuscated oJlO1aTTY7 Adventure runtime",
                "operation": reviewed["operation"],
                "proposed_name": reviewed["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-adventure-static-residual-exact-anchor"
                if not differences
                else "manual-adventure-static-residual-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": semantic_row is not None,
                "semantic_match_confidence": None if semantic_row is None else semantic_row.get("confidence"),
                "semantic_match_method": None if semantic_row is None else semantic_row.get("method"),
                "source_basis": "Hex-Rays pseudocode, normalized ARM64 feature metrics, and GSFunctionsClient/TAdventure local method order",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_adventure_static_residual_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GSFunctionsClient and TAdventure entries",
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
            "The raw aitCvaXfZc target entry is the GSFunctionsClient static-variable initializer because it allocates and clears the same eight-byte shootparams storage and precedes the already translated script-variable initializer.",
            "The raw oJlO1aTTY7 entries resolve the TAdventure freeResources, handleMouseMove, and initStaticScriptVars roles from direct pseudocode, exact normalized features, and class-local order.",
            "All four reviewed rows are high-confidence manual anchors. The freeResources, handleMouseMove, and initStaticScriptVars rows are exact normalized matches; the static-variable initializer differs only in register-detail allocation.",
        ],
    }
    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in Adventure residual anchors")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
