#!/usr/bin/env python3
"""Create reviewed anchors for the next TScriptMachine static tail."""

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
        "original_ea": "0x21f30c",
        "original_name": "TScriptMachine_initStaticScriptVars_void",
        "spectron_ea": "0x227780",
        "spectron_name": "_Z10DgaM1aDf85v",
        "operation": "allocates and registers the static TCallStackEntryProperties object",
        "evidence": [
            "Both static helpers allocate the class-specific property object, call its default constructor, store the global pointer, and return the address of that global.",
            "The target DgaM1aDf85 helper allocates 0x68 bytes for the rebuilt l8eTfaIl5YProperties object where the 1.8 helper allocates 0x58 bytes, while retaining the same 12-instruction control-flow shape and class-local position.",
        ],
    },
    {
        "original_ea": "0x21f394",
        "original_name": "TCallStackEntry_TCallStackEntry__2",
        "spectron_ea": "0x227808",
        "spectron_name": "_ZN10l8eTfaIl5YD0Ev",
        "operation": "runs the deleting TCallStackEntry destructor",
        "evidence": [
            "Both deleting destructors call the D2 body and then operator delete on the receiver.",
            "The target l8eTfaIl5Y D0 body follows the static property initializer and TCallStackEntry constructor in the same class-local slot, with an identical normalized feature record.",
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
    semantic_sources = {
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
    }

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
        if original_ea in semantic_sources or spectron_ea in semantic_targets:
            raise ValueError("automatic semantic match already claims %s" % reviewed["original_ea"])
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
                "source_component": "TScriptMachine static initialization and TCallStackEntry lifecycle",
                "target_component": "mTAogaaEip and l8eTfaIl5Y obfuscated runtime families",
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-script-machine-static-tail-exact-anchor"
                if not differences
                else "manual-script-machine-static-tail-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "source_basis": "Hex-Rays pseudocode, C++ ABI form, class-local order, and source/target allocation agreement",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in static-tail anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_machine_static_tail_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for static script-machine setup and TCallStackEntry cleanup",
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
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "exact_metric_anchor_count": sum(row["exact_metric_match"] for row in anchors),
            "layout_change_anchor_count": sum(not row["exact_metric_match"] for row in anchors),
            "source_pseudocode_count": sum(row["source_pseudocode_sha256"] is not None for row in anchors),
            "target_pseudocode_count": sum(row["target_pseudocode_sha256"] is not None for row in anchors),
            "new_context_anchor_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "The DgaM1aDf85 helper is the target rebuild of TScriptMachine_initStaticScriptVars_void. The allocation size changes with the target property layout, so it is recorded as a layout-change anchor.",
            "The l8eTfaIl5Y D0 body is an exact normalized match for TCallStackEntry_TCallStackEntry__2.",
            "The nearby C8THgaTQxF overload at 0x221928 is a target string-wrapper adapter around the already translated CanTfaz6bZ resolver and is intentionally outside this source-backed anchor set.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
