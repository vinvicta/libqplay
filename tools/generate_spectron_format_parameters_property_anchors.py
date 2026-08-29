#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron format and property runtime block."""

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
        "0x224248",
        "TScriptMachine_FormatParameters_TScriptMachine_FormatParameters",
        "0x22c810",
        "_ZN10OV5NOaoBLlD1Ev",
        "destroys the format-parameter wrapper without releasing its allocation",
        [
            "The source symbol carries the alternative C++ name TScriptMachine_FormatParameters D2, and the target OV5NOaoBLl D1 symbol carries the same D2 alternative name.",
            "The target body clears the rebuilt parameter-string array before returning. This is a target layout extension of the source empty D2 body, while the class-local method sequence and the following property destructor block identify the wrapper.",
        ],
    ),
    item(
        "0x22424c",
        "TCallStackEntryProperties_TCallStackEntryProperties",
        "0x22c858",
        "_ZN20l8eTfaIl5YPropertiesD2Ev",
        "destroys the call-stack-entry property object and its TProperties base",
        [
            "The source pseudocode resets the derived and base vtable slots and calls the TProperties destructor. The target l8eTfaIl5YProperties body has the same two-block, seven-instruction cleanup shape and calls the target c76BgaJBGA base destructor.",
            "Both symbols carry the alternate D1/D2 destructor names and occupy the first property destructor position immediately after the format-parameter destructor.",
        ],
    ),
    item(
        "0x224268",
        "non_virtual_thunk_to_TCallStackEntryProperties_TCallStackEntryProperties",
        "0x22c874",
        "_ZThn16_N20l8eTfaIl5YPropertiesD1Ev",
        "adjusts the receiver and forwards to the call-stack-entry property destructor",
        [
            "Both non-virtual thunks subtract 16 from the receiver and call the complete call-stack-entry property destructor.",
            "The source and target are identical two-instruction ARM64 ABI thunks in the corresponding class-local position.",
        ],
    ),
    item(
        "0x224270",
        "TCallStackEntryProperties_TCallStackEntryProperties__2",
        "0x22c87c",
        "_ZN20l8eTfaIl5YPropertiesD0Ev",
        "runs the call-stack-entry property destructor and releases the object",
        [
            "Both deleting destructors reset the derived and base vtable slots, call the TProperties base destructor, and then call operator delete.",
            "The target D0 body follows the D1/D2 body and preserves the same two-block, fourteen-instruction cleanup shape.",
        ],
    ),
    item(
        "0x2242a8",
        "non_virtual_thunk_to_TCallStackEntryProperties_TCallStackEntryProperties__2",
        "0x22c8b4",
        "_ZThn16_N20l8eTfaIl5YPropertiesD0Ev",
        "adjusts the receiver and forwards to the deleting call-stack-entry property destructor",
        [
            "Both non-virtual D0 thunks subtract 16 from the receiver and forward to the deleting property destructor.",
            "The two-instruction thunk has the same normalized ARM64 record and follows the matching D0 body in both builds.",
        ],
    ),
    item(
        "0x2242b0",
        "TScriptMachine_FormatParameters_TScriptMachine_FormatParameters__2",
        "0x22c8bc",
        "_ZN10OV5NOaoBLlD0Ev",
        "runs the format-parameter destructor and releases the wrapper",
        [
            "The source symbol is the deleting destructor for TScriptMachine_FormatParameters and directly calls operator delete.",
            "The target OV5NOaoBLl D0 body performs the target array cleanup before operator delete. Its placement after the D1/D2 body and before the format-parameter accessors preserves the class identity despite the added cleanup work.",
        ],
    ),
    item(
        "0x224400",
        "TScriptMachine_FormatParameters_getNextU32_void",
        "0x22ca58",
        "_ZN10OV5NOaoBLl10tfvpgaJU3pEv",
        "reads the next script float and converts it to an unsigned 32-bit value",
        [
            "Both bodies call the format-parameter owner's next-float reader, add the 0.0001 conversion bias, truncate to an integer, and apply the same negative-value correction.",
            "The target method is the first accessor after the format-parameter destructor pair and has the same 64-byte, sixteen-instruction shape as the source.",
        ],
    ),
    item(
        "0x224448",
        "TScriptMachine_FormatParameters_getNextS32_void",
        "0x22caa0",
        "_ZN10OV5NOaoBLl10mgCpgamO9pEv",
        "reads the next script float and converts it to a signed 32-bit value",
        [
            "The source and target repeat the same next-float conversion body, including the 0.0001 bias and negative-value correction.",
            "The target method is the second accessor in the same obfuscated OV5NOaoBLl class block and retains the source size and control-flow shape.",
        ],
    ),
    item(
        "0x224490",
        "TScriptMachine_FormatParameters_getNextF64_void",
        "0x22cae8",
        "_ZN10OV5NOaoBLl10LlopgaY5YpEv",
        "returns the next script float without conversion",
        [
            "Both bodies are a direct return of the format-parameter owner's next-float reader.",
            "The target one-return accessor follows the two integer accessors and has the same compact two-instruction shape as the source.",
        ],
    ),
    item(
        "0x224498",
        "TScriptMachine_FormatParameters_getIndexedU32_int",
        "0x22caf0",
        "_ZN10OV5NOaoBLl10nn9ogamvMpEi",
        "reads an indexed script float and converts it to an unsigned 32-bit value",
        [
            "Both bodies pass the index to the format-parameter owner's indexed-float reader, then use the same biased integer conversion and negative correction as getNextU32.",
            "The target method follows the no-conversion next-float accessor in the same class-local order and preserves the source size and branch shape.",
        ],
    ),
    item(
        "0x2244e0",
        "TScriptMachine_FormatParameters_getIndexedS32_int",
        "0x22cb38",
        "_ZN10OV5NOaoBLl10a67ogaLqLpEi",
        "reads an indexed script float and converts it to a signed 32-bit value",
        [
            "The source and target use the same indexed-float call and biased signed conversion sequence.",
            "The target method is the second indexed integer accessor in the OV5NOaoBLl block and retains the source instruction and control-flow shape.",
        ],
    ),
    item(
        "0x224528",
        "TScriptMachine_FormatParameters_getIndexedF64_int",
        "0x22cb80",
        "_ZN10OV5NOaoBLl10iJypgaNP6pEi",
        "returns an indexed script float without conversion",
        [
            "Both bodies directly return the format-parameter owner's indexed-float reader with the caller-supplied index.",
            "The target two-instruction accessor follows the two indexed conversion methods in the same order as the source class block.",
        ],
    ),
    item(
        "0x224530",
        "TScriptMachine_FormatParameters_getNextString_void",
        "0x22cb88",
        "_ZN10OV5NOaoBLl10B8wpgaSu5pEv",
        "returns the next formatted script string",
        [
            "The source and target each forward directly to the owning script machine's next-string reader.",
            "The target method is the first string accessor after the indexed numeric accessors and has the same two-block, three-instruction wrapper shape.",
        ],
    ),
    item(
        "0x224538",
        "TScriptMachine_FormatParameters_getIndexedString_int",
        "0x22cb94",
        "_ZN10OV5NOaoBLl10Ym2oga0BGpEi",
        "returns an indexed formatted script string",
        [
            "Both bodies forward the index to the owning script machine's indexed-string reader.",
            "The target method is the final accessor in the OV5NOaoBLl block, matching the source class-local order and compact wrapper shape.",
        ],
    ),
    item(
        "0x2245cc",
        "TProperties_TProperties",
        "0x22cc48",
        "_ZN10c76BgaJBGAD1Ev",
        "destroys a TProperties object and releases its owned runtime state",
        [
            "The source destructor resets the derived and base vtable slots, destroys the owned property list object when present, clears the derived strings, destroys the hash list, restores the base vtable, and clears the inherited name string.",
            "The target c76BgaJBGA D1/D2 body performs the same ownership cleanup through rebuilt KKhLga4xoI and C8THgaTQxF/CanTfaz6bZ wrappers. The extra field clears account for the layout change.",
        ],
    ),
    item(
        "0x224638",
        "non_virtual_thunk_to_TProperties_TProperties",
        "0x22ccbc",
        "_ZThn16_N10c76BgaJBGAD1Ev",
        "adjusts the receiver and forwards to the TProperties destructor",
        [
            "Both non-virtual thunks subtract 16 from the receiver and call the complete TProperties destructor.",
            "The two-instruction target thunk follows the c76BgaJBGA destructor and has the same normalized ARM64 form as the source thunk.",
        ],
    ),
    item(
        "0x224640",
        "TProperties_TProperties__2",
        "0x22ccc4",
        "_ZN10c76BgaJBGAD0Ev",
        "runs the TProperties destructor and releases the object",
        [
            "Both deleting destructors run the complete TProperties cleanup and then call operator delete.",
            "The target D0 body follows the D1/D2 body and retains the same compact two-block ABI wrapper and instruction count.",
        ],
    ),
    item(
        "0x224660",
        "non_virtual_thunk_to_TProperties_TProperties__2",
        "0x22cce4",
        "_ZThn16_N10c76BgaJBGAD0Ev",
        "adjusts the receiver and forwards to the deleting TProperties destructor",
        [
            "Both non-virtual D0 thunks subtract 16 from the receiver and forward to the deleting TProperties destructor.",
            "The target thunk is in the matching vtable-wrapper position and has the same two-instruction normalized form.",
        ],
    ),
    item(
        "0x224668",
        "TJoinedClassesProperty_writeObject_TGraalVar_TGraalVar",
        "0x22ce20",
        "_ZN10KGeN2aIY1X10Cu3DMaoyjxEP10G0gxgajWBwS1_",
        "converts an object value to a string and writes it through the property callback",
        [
            "Both bodies check for a non-null source value, obtain its string representation through the TGraalVar virtual call, pass that temporary string to the property writer at vtable slot 64, and clear temporary storage before returning.",
            "The target adds a rebuilt CanTfaz6bZ conversion and C8THgaTQxF cleanup, explaining the larger body while preserving the source callback and ownership sequence.",
        ],
    ),
    item(
        "0x2246c8",
        "TAniProperty_writeObject_TGraalVar_TGraalVar",
        "0x22cea0",
        "_ZN10ScpN2avPaY10Cu3DMaoyjxEP10G0gxgajWBwS1_",
        "converts an animation object value to a string and writes it through the property callback",
        [
            "The source and target bodies have the same null check, TGraalVar string conversion, property callback dispatch, and temporary cleanup sequence.",
            "The target ScpN2avPaY method is the adjacent sibling of the KGeN2aIY1X writer and differs only in the obfuscated derived-property class and rebuilt string wrapper details.",
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
                "source_component": "TScriptMachine::FormatParameters and TProperties runtime families",
                "target_component": "OV5NOaoBLl, l8eTfaIl5YProperties, c76BgaJBGA, KGeN2aIY1X, and ScpN2avPaY obfuscated runtime families",
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-format-property-exact-anchor" if not differences else "manual-format-property-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "source_basis": "Hex-Rays pseudocode, C++ ABI form, class-local order, and source/target ownership or conversion agreement",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in format/property anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_format_parameters_property_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for format-parameter accessors and property runtime cleanup",
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
            "The format-parameter accessor sequence is identified by identical conversion behavior, owner calls, and class-local order.",
            "The destructor rows use the C++ D1, D2, and D0 ABI forms plus ownership cleanup to distinguish the corresponding obfuscated classes.",
            "Changed metric fields are recorded explicitly when the target adds parameter storage or rebuilt string and property-list wrappers.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
