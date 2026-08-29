#!/usr/bin/env python3
"""Create descriptive labels for target-only TScriptSpace boundaries."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRICS = (
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


LABEL_SPECS = (
    {
        "target_ea": "0x23332c",
        "current_name": "_ZN10N67CMatrxw10dOBHMaPpiAERK10C8THgaTQxFRK10CanTfaz6bZP10G0gxgajWBw",
        "proposed_name": "spectron_TScriptSpace_receiveEvent_TString_const_CanTfaz6bZ_const_TGraalVar",
        "role": "TScriptSpace receiveEvent overload with a normalized event-name wrapper",
        "operation": "applies the event queue limit, duplicate-event policy, priority insertion, and script activation to a CanTfaz6bZ event-name argument",
        "source_counterpart_status": "target-only overload; the distinct 1.8 source boundary is not present",
        "evidence": [
            "The target signature has a C8THgaTQxF event name, a CanTfaz6bZ event-name wrapper, and a G0gxgajWBw object receiver argument.",
            "The body duplicates the already translated receiveEvent policy while avoiding the second wrapper conversion, and it is a separate target function boundary immediately before the scheduled-event helpers.",
        ],
    },
    {
        "target_ea": "0x2339b4",
        "current_name": "_ZN10N67CMatrxw10XzgcMa1yW9Ev",
        "proposed_name": "spectron_TScriptSpace_clearScheduledEventsAndCancelActions_void",
        "role": "TScriptSpace scheduled-event and pending-action cleanup helper",
        "operation": "deletes every scheduled event and marks every pending action as canceled",
        "source_counterpart_status": "target-only helper; no distinct 1.8 source boundary was found",
        "evidence": [
            "The target body walks the scheduled-event list backwards, destroys each yXeHMaPb_z object, and removes every list entry.",
            "It then walks the pending-action list and sets the action cancellation byte for every entry, which is broader than the named cancelEvents method beside it.",
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


def metric_record(row):
    return {field: row.get(field) for field in METRICS}


def evidence_by_ea(path: Path):
    document = load(path)
    return {int(row["ea"], 16): row for row in document.get("targets", [])}


def pseudocode_sha256(row):
    pseudocode = row.get("pseudocode")
    if pseudocode is None:
        return None
    return hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    feature_document = load(args.spectron_features)
    features = {row["ea"]: row for row in feature_document["functions"]}
    evidence = evidence_by_ea(args.target_evidence)
    labels = []
    for spec in LABEL_SPECS:
        target = features.get(spec["target_ea"])
        trace = evidence.get(int(spec["target_ea"], 16))
        if target is None or trace is None:
            raise ValueError("missing target feature or evidence at %s" % spec["target_ea"])
        if target.get("name") != spec["current_name"]:
            raise ValueError("target name mismatch at %s" % spec["target_ea"])
        labels.append(
            {
                "target_ea": spec["target_ea"],
                "current_name": target["name"],
                "function_end": target["end_ea"],
                "proposed_name": spec["proposed_name"],
                "target_default_name": target.get("is_default_name", False),
                "target_metrics": metric_record(target),
                "target_string_refs": target.get("string_refs", []),
                "target_direct_call_names": target.get("direct_call_names", []),
                "target_pseudocode_sha256": pseudocode_sha256(trace),
                "target_evidence_name": trace.get("name"),
                "target_role": spec["role"],
                "operation": spec["operation"],
                "source_counterpart": None,
                "source_counterpart_status": spec["source_counterpart_status"],
                "confidence": "high",
                "match_kind": "reviewed-tscript-space-target-only-label",
                "evidence": spec["evidence"],
                "name_action": "rename-with-spectron-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tscript_space_residual_labels_20260829",
        "scope": "reviewed descriptive labels for two Spectron 2.2 TScriptSpace boundaries without a demonstrated 1.8 source counterpart",
        "network_contacted": False,
        "inputs": {
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "target_evidence": str(args.target_evidence),
            "target_evidence_sha256": sha256_path(args.target_evidence),
        },
        "context": {
            "target_component": "N67CMatrxw TScriptSpace residual methods",
            "resolution": "target signatures, class-local order, neighboring translated methods, target control flow, and Hex-Rays pseudocode",
            "mapping_boundary": "These labels describe target behavior only. They are excluded from the 1.8-to-Spectron source mapping count.",
        },
        "summary": {
            "label_count": len(labels),
            "high_confidence_count": sum(row["confidence"] == "high" for row in labels),
            "target_default_name_count": sum(row["target_default_name"] for row in labels),
            "source_counterpart_count": sum(row["source_counterpart"] is not None for row in labels),
            "target_only_count": len(labels),
        },
        "labels": labels,
        "interpretation": [
            "The spectron_ prefix marks a target-specific descriptive label rather than a restored 1.8 symbol.",
            "The receiveEvent overload is kept separate from the existing C8THgaTQxF-to-C8THgaTQxF source-backed alias because its CanTfaz6bZ parameter creates a distinct target ABI boundary.",
            "The cleanup helper clears all scheduled events and marks pending actions canceled. Its no-argument boundary has no distinct 1.8 source counterpart in the recovered TScriptSpace method set.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
