#!/usr/bin/env python3
"""Create reviewed anchors for the remaining Spectron TScript destructor block."""

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


def item(original_ea, original_name, spectron_ea, spectron_name, operation, evidence):
    return {
        "original_ea": original_ea,
        "original_name": original_name,
        "spectron_ea": spectron_ea,
        "spectron_name": spectron_name,
        "operation": operation,
        "evidence": evidence,
    }


ANCHOR_SPECS = (
    item(
        "0x214794",
        "TScript_getLogName_void",
        "0x21b324",
        "_ZN10zW2NgaU4IK10XmPXfa5PW1Ev",
        "builds the script log name from the Class prefix and script name",
        [
            "Both bodies append the literal Class prefix to a temporary string, copy it to the result, append the script name at object offset 8, and clear the temporary storage.",
            "The target has two additional wrapper operations for its rebuilt C8THgaTQxF string class, while the literal and final concatenation remain exact semantic markers of TScript::getLogName.",
        ],
    ),
    item(
        "0x2150ec",
        "TScript_TScript__2",
        "0x21bcfc",
        "_ZN10zW2NgaU4IKD0Ev",
        "runs the TScript destructor and releases the script object",
        [
            "Both bodies call the complete TScript destructor and then operator delete on the same receiver.",
            "The target is the deleting destructor immediately after the translated TScript constructor and has an identical two-block, eight-instruction ABI wrapper.",
        ],
    ),
    item(
        "0x2175b8",
        "TScriptFunctionProperties_TScriptFunctionProperties",
        "0x21e4f8",
        "_ZN20AICTfaebpZPropertiesD1Ev",
        "destroys the TScriptFunctionProperties object and its TProperties base",
        [
            "The source pseudocode identifies the body as the TScriptFunctionProperties D1/D2 destructor, resets both vtable slots, and calls the TProperties base destructor.",
            "The target AICTfaebpZProperties destructor has the same two-block, seven-instruction body and follows the script-function property methods in the corresponding class block.",
        ],
    ),
    item(
        "0x2175d4",
        "non_virtual_thunk_to_TScriptFunctionProperties_TScriptFunctionProperties",
        "0x21e514",
        "_ZThn16_N20AICTfaebpZPropertiesD1Ev",
        "adjusts the receiver and forwards to the TScriptFunctionProperties destructor",
        [
            "Both non-virtual thunks subtract 16 from the receiver and tail-call the complete property destructor.",
            "The source and target have identical two-block, two-instruction normalized ARM64 records, and each thunk follows the corresponding destructor body.",
        ],
    ),
    item(
        "0x2175dc",
        "TScriptFunctionProperties_TScriptFunctionProperties__2",
        "0x21e51c",
        "_ZN20AICTfaebpZPropertiesD0Ev",
        "runs the TScriptFunctionProperties destructor and releases the object",
        [
            "Both deleting destructors reset the property vtable slots, call the TProperties base destructor, and then call operator delete.",
            "The target is the matching D0 body directly after the non-deleting destructor. Its only recorded metric difference is register-detail allocation around the rebuilt base wrapper.",
        ],
    ),
    item(
        "0x217614",
        "non_virtual_thunk_to_TScriptFunctionProperties_TScriptFunctionProperties__2",
        "0x21e554",
        "_ZThn16_N20AICTfaebpZPropertiesD0Ev",
        "adjusts the receiver and forwards to the deleting property destructor",
        [
            "Both non-virtual D0 thunks subtract 16 from the receiver and forward to the deleting destructor.",
            "The two-instruction thunk has an identical normalized ARM64 record and occupies the same position after the D0 body in both builds.",
        ],
    ),
    item(
        "0x21761c",
        "TFunctionProfile_TFunctionProfile",
        "0x21e55c",
        "_ZN10hYSWfaoR80D2Ev",
        "destroys a function-profile name string",
        [
            "The source pseudocode exposes the alternative D2 name, resets the profile vtable, and clears the TString stored at object offset 8.",
            "The target hYSWfaoR80 body performs the same vtable reset and clears its rebuilt CanTfaz6bZ string in the next class-local slot after the property destructors.",
        ],
    ),
    item(
        "0x217630",
        "TFunctionProfile_TFunctionProfile__2",
        "0x21e570",
        "_ZN10hYSWfaoR80D0Ev",
        "runs the function-profile destructor and releases the profile object",
        [
            "Both deleting destructors reset the profile vtable, clear the name string, and call operator delete.",
            "The target D0 body follows the D2 body and preserves the same two-block cleanup sequence; the changed register-detail hash reflects the target string wrapper.",
        ],
    ),
)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(functions):
    return {int(row["ea"], 16): row for row in functions}


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
    semantic_sources = {int(row["original_ea"], 16) for row in semantic_document.get("matches", [])}
    semantic_targets = {int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])}

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
        differences = [field for field in METRIC_FIELDS if source_metrics.get(field) != target_metrics.get(field)]
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
                "source_component": "TScript, TScriptFunctionProperties, and TFunctionProfile destructor families",
                "target_component": "zW2NgaU4IK and AICTfaebpZProperties and hYSWfaoR80 obfuscated runtime families",
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-tscript-destructor-exact-anchor" if not differences else "manual-tscript-destructor-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "source_basis": "Hex-Rays pseudocode, C++ ABI destructor form, class-local order, and source/target cleanup agreement",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in TScript destructor anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tscript_destructor_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining TScript destructor and profile cleanup block",
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
            "These are reviewed semantic correspondences, not claims that the stripped target retained the original source symbols.",
            "The source destructor aliases retain the historical IDA names, while the compact pseudocode records the underlying D1, D2, and D0 ABI forms.",
            "The target class-local order and cleanup calls distinguish the property and profile destructor families from nearby target-only methods.",
            "Changed metric fields are recorded explicitly when rebuilt string wrappers alter register allocation or body size.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
