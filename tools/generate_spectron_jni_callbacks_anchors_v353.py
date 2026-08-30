#!/usr/bin/env python3
"""Create reviewed JNI callback anchors for the v353 translation pass.

The five rows in this pass retain their exact JNI export names in both ARM64
builds.  The semantic matcher left them unresolved because the 2.2 build adds
application lifecycle and frame-loop work.  Direct pseudocode review confirms
that the preserved names still refer to the same native callback roles.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ARTIFACT = "spectron_jni_callbacks_manual_translation_anchors_20260829"
TARGET_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
ROWS = (
    {
        "original_ea": "0x2440f4",
        "target_ea": "0x250ee0",
        "name": "Java_com_quattroplay_GraalClassic_Natives_QPlayLoop",
        "role": "native frame loop and render dispatch",
        "delta": "+0xcdec",
        "reason": "The target keeps the frame clock, input pump, graphics reset, timer execution, loading/game draw split, video overlay, frame callback, and lifecycle state machine, while adding target-side periodic status handling.",
    },
    {
        "original_ea": "0x2443b8",
        "target_ea": "0x251500",
        "name": "Java_com_quattroplay_GraalClassic_Natives_onKeyEvent",
        "role": "native keyboard event adapter",
        "delta": "+0xd148",
        "reason": "Both bodies gate on the main window and hardware keyboard setting, convert Unicode input, normalize the scan-code table and modifier flags, dispatch TWindow::onKeyEvent, and clear temporary strings.",
    },
    {
        "original_ea": "0x244990",
        "target_ea": "0x251adc",
        "name": "Java_com_quattroplay_GraalClassic_Natives_onAppEnterBackground",
        "role": "background lifecycle event adapter",
        "delta": "+0xd14c",
        "reason": "Both bodies invoke onAppEnterBackground on the universe, locate the -Games object, and call prepareEnterBackground when it exists. The target uses the rebuilt hash and script object classes.",
    },
    {
        "original_ea": "0x244ac0",
        "target_ea": "0x251c04",
        "name": "Java_com_quattroplay_GraalClassic_Natives_onAppPause",
        "role": "pause state transition adapter",
        "delta": "+0xd144",
        "reason": "Both callbacks examine client and loading state before requesting application closure. The target expresses the same lifecycle result through its explicit close-state and pause-state globals.",
    },
    {
        "original_ea": "0x245f54",
        "target_ea": "0x253380",
        "name": "Java_com_quattroplay_GraalClassic_Natives_onInvokeEvent",
        "role": "Java event bridge",
        "delta": "+0xd42c",
        "reason": "Both bodies read two Java strings, recognize onDeviceBackButton, test the universe event catcher, optionally construct a string-list variable, invoke the universe event, and request the matching close state when no catcher exists.",
    },
)
METRIC_FIELDS = ("size", "instruction_count", "basic_block_count")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def evidence_by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"]: row for row in document.get("targets", [])}


def exact_by_ea(document: dict) -> dict[str, dict]:
    return {row["original_ea"]: row for row in document.get("anchors", [])}


def target_metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def source_metrics(row: dict) -> dict:
    return {
        "size": row.get("original_size"),
        "instruction_count": row.get("original_instruction_count"),
        "basic_block_count": row.get("original_basic_block_count"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-map", required=True, type=Path)
    parser.add_argument("--exact-name-artifact", required=True, type=Path)
    parser.add_argument("--target-features", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.parent_map)
    exact = exact_by_ea(load(args.exact_name_artifact))
    target_document = load(args.target_features)
    target_by_ea = {row["ea"]: row for row in target_document["functions"]}
    source_evidence = evidence_by_ea(load(args.source_evidence))
    target_evidence = evidence_by_ea(load(args.target_evidence))

    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected parent semantic map")
    if target_document.get("function_count") != 11707:
        raise ValueError("unexpected target function count")
    if target_document.get("network_contacted") is not False:
        raise ValueError("target feature export is not offline")
    parent_sources = {row["original_ea"] for row in parent.get("matches", [])}
    parent_targets = {row["spectron_ea"] for row in parent.get("matches", [])}
    unmatched = {row["original_ea"] for row in parent.get("unmatched", [])}

    anchors = []
    for spec in ROWS:
        source_ea = spec["original_ea"]
        target_ea = spec["target_ea"]
        shared = exact.get(source_ea)
        target = target_by_ea.get(target_ea)
        source_trace = source_evidence.get(source_ea)
        target_trace = target_evidence.get(target_ea)
        if source_ea not in unmatched or source_ea in parent_sources:
            raise ValueError("source is not an unmatched parent row: %s" % source_ea)
        if target_ea in parent_targets:
            raise ValueError("target is already mapped: %s" % target_ea)
        if shared is None or shared.get("original_name") != spec["name"]:
            raise ValueError("exact shared-name evidence is missing: %s" % source_ea)
        if target is None or target.get("name") != spec["name"]:
            raise ValueError("target exact JNI name is missing: %s" % target_ea)
        if target.get("is_default_name"):
            raise ValueError("target JNI row unexpectedly has a default name")
        if source_trace is None or target_trace is None:
            raise ValueError("direct pseudocode evidence is missing")

        original = source_metrics(shared)
        spectron = target_metrics(target)
        differences = [field for field in METRIC_FIELDS if original.get(field) != spectron.get(field)]
        anchors.append(
            {
                "original_ea": source_ea,
                "original_name": spec["name"],
                "original_function_end": source_trace.get("function_end"),
                "original_metrics": original,
                "original_string_refs": [],
                "original_direct_call_names": [],
                "spectron_ea": target_ea,
                "spectron_function_end": target.get("end_ea") or target_trace.get("function_end"),
                "spectron_current_name": target.get("name"),
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": spectron,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + spec["name"],
                "confidence": "high",
                "match_kind": "manual-jni-exact-name-pseudocode-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "target_delta": spec["delta"],
                "evidence": [
                    "The exact non-default JNI export name appears once in each build's feature export.",
                    spec["reason"],
                    "The source and target rows were reviewed through fresh Hex-Rays pseudocode evidence from the corresponding IDA databases.",
                    "The target name is renamed only by adding the v18_ analysis prefix; its original export name remains in the artifact and dynamic-symbol evidence.",
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": not differences,
                "layout_change": bool(differences),
                "changed_metric_fields": differences,
                "layout_metric_delta": {
                    field: {"original": original.get(field), "spectron": spectron.get(field)}
                    for field in differences
                },
                "source_pseudocode": source_trace.get("pseudocode"),
                "target_pseudocode": target_trace.get("pseudocode"),
                "source_xrefs": source_trace.get("xrefs_to", []),
                "target_xrefs": target_trace.get("xrefs_to", []),
            }
        )

    deltas = Counter(anchor["target_delta"] for anchor in anchors)
    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the five retained JNI native callbacks",
        "network_contacted": False,
        "inputs": {
            "parent_map": str(args.parent_map),
            "parent_map_sha256": sha256_path(args.parent_map),
            "exact_name_artifact": str(args.exact_name_artifact),
            "exact_name_artifact_sha256": sha256_path(args.exact_name_artifact),
            "target_features": str(args.target_features),
            "target_features_sha256": sha256_path(args.target_features),
            "source_evidence": str(args.source_evidence),
            "source_evidence_sha256": sha256_path(args.source_evidence),
            "target_evidence": str(args.target_evidence),
            "target_evidence_sha256": sha256_path(args.target_evidence),
            "database": str(args.database),
            "database_sha256": sha256_path(args.database),
            "original_binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8",
            "spectron_binary_sha256": TARGET_BINARY_SHA256,
        },
        "method": {
            "selection": "exact one-to-one JNI name, fresh source and target pseudocode role review, and current target feature verification",
            "address_policy": "source and target addresses remain separate fields; no address is copied between builds",
            "name_policy": "the target's retained JNI name receives a v18_ IDA analysis prefix",
            "interpretation": "these are retained native export names with direct role confirmation, not guesses about unrelated obfuscated C++ methods",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "exact_name_anchor_count": len(anchors),
            "layout_change_anchor_count": sum(bool(a["layout_change"]) for a in anchors),
            "target_default_name_count": sum(bool(a["spectron_default_name"]) for a in anchors),
            "address_delta_groups": dict(sorted(deltas.items())),
        },
        "context": {
            "source_classes": ["JNI native bridge", "TTime", "TWindow", "TGameEnvironment"],
            "target_class_clusters": ["zYRMgaG0IJ", "LJyzga9Pwy", "QYZugaRKGu", "a7qxJaHqKV"],
            "resolution": "preserved JNI export names plus direct pseudocode role correspondence; target-specific lifecycle and frame-loop additions are recorded as layout changes",
        },
        "anchors": sorted(anchors, key=lambda row: int(row["original_ea"], 16)),
        "interpretation": [
            "The source and target export names are exact shared JNI names, so the translation does not infer a stripped C++ symbol.",
            "The target QPlayLoop is larger because the 2.2 build adds periodic status work and an explicit lifecycle state machine. The callback role remains unambiguous.",
            "The target database change is an analysis overlay only: five retained JNI names are prefixed v18_ and receive review comments; native code is unchanged.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
