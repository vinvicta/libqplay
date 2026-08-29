#!/usr/bin/env python3
"""Create reviewed residual anchors for the Spectron TScriptUniverse block."""

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
        "original_ea": "0x22b1f8",
        "original_name": "TScriptExecutionStats_TScriptExecutionStats__2",
        "spectron_ea": "0x234bc0",
        "spectron_name": "_ZN10R94BFa3XECD0Ev",
        "operation": "runs the TScriptExecutionStats destructor and releases the object",
        "basis": "Hex-Rays pseudocode, exact normalized feature metrics, C++ D0 form, and class-local order",
        "evidence": [
            "Both functions call the complete destructor on the receiver and then operator delete it.",
            "The target R94BFa3XE D0 body is an exact normalized feature match for the source TScriptExecutionStats D0 body.",
        ],
    },
    {
        "original_ea": "0x22b3b4",
        "original_name": "TScriptUniverse_setExecutingNPC_TServerNPC",
        "spectron_ea": "0x234d98",
        "spectron_name": "_ZN10e4ZYfa8PV210eh9ZuaaqUGEP10LBgVgaqANQ",
        "operation": "updates the universe's executing-NPC and action-NPC state",
        "basis": "Hex-Rays pseudocode, target parameter class LBgVgaqANQ, exact class-local setter position, and normalized metrics",
        "evidence": [
            "The target parameter is LBgVgaqANQ, the translated TServerNPC class, and the body stores the same two NPC execution-state globals as the source setter.",
            "The source and target retain the same 28-byte, one-block setter shape; only register-detail normalization differs.",
        ],
    },
    {
        "original_ea": "0x22b3d0",
        "original_name": "TScriptUniverse_setExecutingPlayer_TServerPlayer",
        "spectron_ea": "0x234db4",
        "spectron_name": "_ZN10e4ZYfa8PV210hgXZuahtJGEP10MpGzgariDy",
        "operation": "updates the universe's executing-player and action-player state",
        "basis": "Hex-Rays pseudocode, target parameter class MpGzgariDy, adjacent setter order, and normalized metrics",
        "evidence": [
            "The target parameter is MpGzgariDy, the translated TServerPlayer class, and the body stores the same two player execution-state globals as the source setter.",
            "The source and target retain the same 28-byte, one-block setter shape; only register-detail normalization differs.",
        ],
    },
    {
        "original_ea": "0x22b614",
        "original_name": "TScriptUniverse_removeStaticObject_TGraalVar",
        "spectron_ea": "0x235000",
        "spectron_name": "_ZN10e4ZYfa8PV210ufZhMaE8JeEP10G0gxgajWBw",
        "operation": "removes a static object from the universe hash list when that list exists",
        "basis": "Hex-Rays pseudocode, exact normalized metrics, receiver field 12, and placement immediately before addStaticObject",
        "evidence": [
            "Both methods read universe field 12, return immediately when the hash list is absent, and otherwise call the target-specific hash-list removal operation.",
            "The source and target are exact 16-byte, four-instruction normalized matches, and the target sits directly before the already translated addStaticObject method.",
        ],
    },
    {
        "original_ea": "0x22c068",
        "original_name": "TScriptUniverse_addToFreeMachines_TScriptMachine",
        "spectron_ea": "0x235a50",
        "spectron_name": "_ZN10e4ZYfa8PV210WR0Lua3k0uEP10mTAogaaEip",
        "operation": "adds a non-null script machine to the free-machine list only when it is not already present",
        "basis": "Hex-Rays pseudocode, target parameter class mTAogaaEip, exact normalized metrics, and adjacency to getFreeMachine and clearGraalScriptMachines",
        "evidence": [
            "The target mTAogaaEip parameter is the rebuilt TScriptMachine class, and the body performs the same list membership test followed by conditional append.",
            "The source and target are exact 76-byte, five-call normalized matches in the same free-machine lifecycle sequence.",
        ],
    },
    {
        "original_ea": "0x22c210",
        "original_name": "TScriptUniverse_TScriptUniverse__2",
        "spectron_ea": "0x235bf8",
        "spectron_name": "_ZN10e4ZYfa8PV2D0Ev",
        "operation": "runs the deleting TScriptUniverse destructor and releases the object",
        "basis": "Hex-Rays pseudocode, exact normalized feature metrics, C++ D0 form, and adjacency to the target TScriptUniverse D2 body",
        "evidence": [
            "Both deleting destructors call the complete universe destructor and then operator delete the receiver.",
            "The target e4ZYfa8PV2 D0 body is an exact normalized feature match and immediately follows the translated universe D2 body.",
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

        semantic_row = semantic.get((original_ea, spectron_ea))
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
                "source_component": "TScriptUniverse residual lifecycle and execution-state methods",
                "target_component": "e4ZYfa8PV2 obfuscated script-universe runtime",
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-tscript-universe-residual-exact-anchor"
                if not differences
                else "manual-tscript-universe-residual-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": semantic_row is not None,
                "semantic_match_confidence": None if semantic_row is None else semantic_row.get("confidence"),
                "semantic_match_method": None if semantic_row is None else semantic_row.get("method"),
                "source_basis": reviewed["basis"],
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in TScriptUniverse residual anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tscript_universe_residual_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TScriptUniverse lifecycle, execution-state, static-object, and free-machine methods",
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
            "The R94BFa3XE D0 body is the exact target ABI counterpart of TScriptExecutionStats_TScriptExecutionStats__2.",
            "The two 28-byte e4ZYfa8PV2 setters are identified by their target parameter classes, adjacent source and target order, and the two execution-state stores shown in pseudocode.",
            "The ufZhMaE8Je method is the target removeStaticObject helper. The WR0Lua3k0u method is addToFreeMachines, and the e4ZYfa8PV2 D0 body is the target deleting universe destructor.",
            "Small setters and wrappers below the broad matcher's size threshold are retained as manual anchors after direct pseudocode review. Ambiguous destructor shape matches are resolved by class-local order and target class identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
