#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron property constructor tail."""

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
        "0x225c14",
        "TProperties_TProperties_TString_const_TString_const",
        "0x22e49c",
        "_ZN10c76BgaJBGAC2ERK10C8THgaTQxFS2_",
        "constructs a named TProperties object and registers it globally",
        [
            "Both constructors initialize the hash-list base, construct the property list, store the display name, initialize the owner and flags, and add the object to the global property-list registry.",
            "The target c76BgaJBGA C2 symbol carries the matching C1 alternative name and uses rebuilt CanTfaz6bZ, C8THgaTQxF, and KKhLga4xoI wrappers for the same ownership steps.",
        ],
    ),
    item(
        "0x225cb8",
        "TProperties_compileProperties_void",
        "0x22e568",
        "_ZN10c76BgaJBGA10_TCjIaUk7TEv",
        "compiles inherited and local property definitions",
        [
            "Both bodies guard on the compiled flag, clear and rebuild the property list, recursively compile the inherited property object, remove replaced definitions, and release the temporary list or string storage.",
            "The target c76BgaJBGA method follows its constructor and retains the source sixteen-block loop structure. The smaller target body reflects rebuilt helper wrappers rather than a changed operation.",
        ],
    ),
    item(
        "0x225ea0",
        "getPropertyList_TString_const",
        "0x22e748",
        "_Z10nYwjIaul2TRK10C8THgaTQxF",
        "looks up a property list by its name",
        [
            "Both functions return zero when the global registry is absent, compute the name hash, and perform the same hash-list lookup.",
            "The source and target feature records are identical and the target helper follows the c76BgaJBGA compiler in the corresponding global property block.",
        ],
    ),
    item(
        "0x225ee8",
        "TObjectCreator_TObjectCreator_TString_const_TGraalVar_TString_const",
        "0x22e790",
        "_ZN10VxVm2aj1TBC2ERK10C8THgaTQxFPFP10G0gxgajWBwS2_E",
        "constructs and registers an object-creator callback",
        [
            "Both constructors initialize the string-keyed base, store the factory callback, create the global object-creator registry when needed, and add the new creator to it.",
            "The target VxVm2aj1TB C2 symbol carries the matching C1 alternative name and preserves the source registry ownership sequence with rebuilt wrappers.",
        ],
    ),
    item(
        "0x22693c",
        "TScriptProperty_initStaticScriptVars_void",
        "0x22f540",
        "_Z10dNXM2a4UNXv",
        "registers the static TScriptProperty definitions",
        [
            "Both are five-instruction static helpers that call the TScriptProperty property-registration method with one definition-table entry.",
            "The target helper is in the exact class-local position after addFuncs and before the creator and property destructor tail, and its normalized feature record is identical to the source.",
        ],
    ),
    item(
        "0x226950",
        "TObjectCreator_TObjectCreator",
        "0x22f554",
        "_ZN10VxVm2aj1TBD1Ev",
        "destroys an object creator and clears its name",
        [
            "The source pseudocode comment exposes the D2 destructor form. Both bodies reset the base vtable and clear the inherited name string.",
            "The target VxVm2aj1TB D1 symbol carries the matching D2 alternative name and has the same two-block, five-instruction feature record.",
        ],
    ),
    item(
        "0x226964",
        "TObjectCreator_TObjectCreator__2",
        "0x22f568",
        "_ZN10VxVm2aj1TBD0Ev",
        "runs the object-creator destructor and releases the object",
        [
            "Both D0 bodies reset the base vtable, clear the inherited name string, and call operator delete.",
            "The source and target records have the same twelve-instruction, two-block ABI cleanup shape.",
        ],
    ),
    item(
        "0x226994",
        "TScriptProperty_TScriptProperty",
        "0x22f598",
        "_ZN10cWWYfaxbT2D2Ev",
        "destroys a TScriptProperty and its inherited name",
        [
            "The source name is a historical IDA alias whose comment exposes the D1 destructor. Both bodies reset the derived vtable, clear the derived string at offset 48, restore the base vtable, and clear the inherited name at offset 8.",
            "The target cWWYfaxbT2 D2 symbol carries the matching D1 alternative name and preserves the same field offsets and cleanup order.",
        ],
    ),
    item(
        "0x2269d4",
        "TScriptProperty_TScriptProperty__2",
        "0x22f5d8",
        "_ZN10cWWYfaxbT2D0Ev",
        "runs the TScriptProperty destructor and releases the object",
        [
            "Both deleting destructors perform the derived and inherited string cleanup before calling operator delete.",
            "The target D0 body follows the D2 body and has the same eighteen-instruction, two-block feature record as the source.",
        ],
    ),
    item(
        "0x226a1c",
        "TAniProperty_TAniProperty",
        "0x22f620",
        "_ZN10ScpN2avPaYD1Ev",
        "destroys an animation property and its inherited name",
        [
            "The source and target bodies are the same inherited-string cleanup routine, with the target ScpN2avPaY D1 symbol carrying the D2 alternative name.",
            "The identical metrics and adjacent derived-property destructor order distinguish this row from unrelated target-only cleanup code.",
        ],
    ),
    item(
        "0x226a5c",
        "TAniProperty_TAniProperty__2",
        "0x22f660",
        "_ZN10ScpN2avPaYD0Ev",
        "runs the animation-property destructor and releases the object",
        [
            "Both D0 bodies clear the derived and inherited strings and then call operator delete.",
            "The target ScpN2avPaY D0 body has the same eighteen-instruction, two-block record and follows its D1 body.",
        ],
    ),
    item(
        "0x226aa4",
        "TJoinedClassesProperty_TJoinedClassesProperty",
        "0x22f6a8",
        "_ZN10KGeN2aIY1XD1Ev",
        "destroys a joined-classes property and its inherited name",
        [
            "Both bodies reset the derived vtable, clear the derived string at offset 48, restore the base vtable, and clear the inherited name.",
            "The target KGeN2aIY1X D1 symbol carries the D2 alternative name and is the next sibling in the same derived-property destructor run.",
        ],
    ),
    item(
        "0x226ae4",
        "TJoinedClassesProperty_TJoinedClassesProperty__2",
        "0x22f6e8",
        "_ZN10KGeN2aIY1XD0Ev",
        "runs the joined-classes destructor and releases the object",
        [
            "Both D0 bodies perform the same two-string cleanup and call operator delete.",
            "The target KGeN2aIY1X D0 body follows the D1 body and has an identical normalized feature record.",
        ],
    ),
    item(
        "0x226b2c",
        "TAcceptStringProperty_TAcceptStringProperty",
        "0x22f730",
        "_ZN10q4yI2aq75TD2Ev",
        "destroys an accept-string property and its inherited name",
        [
            "The source name carries the D1 alternative symbol. Both bodies reset the derived vtable, clear the derived string, restore the base vtable, and clear the inherited name.",
            "The target q4yI2aq75T D2 symbol carries the matching D1 alternative name and follows the other derived-property cleanup pairs.",
        ],
    ),
    item(
        "0x226b6c",
        "TAcceptStringProperty_TAcceptStringProperty__2",
        "0x22f770",
        "_ZN10q4yI2aq75TD0Ev",
        "runs the accept-string destructor and releases the object",
        [
            "Both D0 bodies clear the derived and inherited strings and then call operator delete.",
            "The target q4yI2aq75T D0 body is the final sibling in the run and has the same normalized feature record as the source.",
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
                "source_component": "TProperties, TObjectCreator, and derived property runtime families",
                "target_component": "c76BgaJBGA, VxVm2aj1TB, cWWYfaxbT2, ScpN2avPaY, KGeN2aIY1X, and q4yI2aq75T obfuscated runtime families",
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-property-tail-exact-anchor" if not differences else "manual-property-tail-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "source_basis": "Hex-Rays pseudocode, C++ ABI form, class-local order, and source/target ownership agreement",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in property-tail anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_property_constructor_destructor_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for property construction, static registration, and destructor tails",
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
            "The c76BgaJBGA constructor and compiler are identified by global property-list ownership, inherited compilation, and class-local placement.",
            "The object-creator and derived-property cleanup rows use the C++ D1, D2, and D0 ABI forms plus identical field cleanup order.",
            "The nearby one-argument cWWYfaxbT2 constructor is intentionally outside this artifact because it is an additional target overload without an established 1.8 source counterpart.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
