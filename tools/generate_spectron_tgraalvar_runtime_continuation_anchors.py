#!/usr/bin/env python3
"""Create reviewed anchors for the next Spectron TGraalVar method block.

This block is recovered from source and target Hex-Rays output.  The target
uses rebuilt string, list, and iterator classes, so the aliases are recorded
even when the low-level feature hashes changed.  Each row keeps the original
and target metrics, evidence fingerprints, and the reviewed behavior.
"""

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


def spec(
    original_ea: str,
    original_name: str,
    spectron_ea: str,
    spectron_name: str,
    operation: str,
    evidence: list[str],
) -> dict:
    return {
        "original_ea": original_ea,
        "original_name": original_name,
        "spectron_ea": spectron_ea,
        "spectron_name": spectron_name,
        "source_component": "TGraalVar runtime method family",
        "target_component": "G0gxgajWBw runtime method family",
        "operation": operation,
        "evidence": evidence,
    }


ANCHOR_SPECS = (
    spec(
        "0x20d7dc",
        "TGraalVar_runScript_void",
        "0x213c84",
        "_ZN10G0gxgajWBw10_xWAgaiSGzEv",
        "forwards runScript to the attached script space when one exists",
        [
            "Both bodies load the object field at offset 80, test it for null, and forward through the same virtual operation.",
            "The source and target are four-instruction, four-block wrappers; the target only changes the rebuilt class names.",
        ],
    ),
    spec(
        "0x20e598",
        "TGraalVar_leaveClass_TString_const",
        "0x214a4c",
        "_ZN10G0gxgajWBw10fssWfaryN0ERK10C8THgaTQxF",
        "ensures a script space exists and leaves the requested class",
        [
            "Both methods call the lazy script-space creator and then invoke the attached script-space leaveClass operation with the supplied string.",
            "The target preserves the source two-call wrapper shape and differs only through rebuilt string and script-space types.",
        ],
    ),
    spec(
        "0x20eaf0",
        "TGraalVar_cancelEvents_TString_const",
        "0x214fc4",
        "_ZN10G0gxgajWBw10hH2bMa5SK9ERK10C8THgaTQxF",
        "forwards event cancellation to the attached script space when present",
        [
            "Both bodies test the script-space field and forward the call only when it is non-null.",
            "The source and target retain the same four-instruction, four-block conditional wrapper.",
        ],
    ),
    spec(
        "0x20eb04",
        "TGraalVar_setScript_TString_const",
        "0x214fec",
        "_ZN10G0gxgajWBw10lhv_fahWb4ERK10C8THgaTQxF",
        "ensures a script space exists and replaces its script from a string",
        [
            "Both methods call the lazy creator and pass the input string to the same script-space setter.",
            "The target has the same two-call wrapper structure with explicit rebuilt-string types.",
        ],
    ),
    spec(
        "0x20eb2c",
        "TGraalVar_setScript_TScript",
        "0x215014",
        "_ZN10G0gxgajWBw10lhv_fahWb4EP10zW2NgaU4IK",
        "ensures a script space exists and replaces its script from a script object",
        [
            "The source and target both call the lazy creator followed by the script-space setter, with the second overload taking the script object.",
            "The target preserves the source wrapper structure and changes only the rebuilt class names.",
        ],
    ),
    spec(
        "0x20eb54",
        "TGraalVar_freeScript_void",
        "0x21503c",
        "_ZN10G0gxgajWBw10ctWGMa8NJzEv",
        "forwards script release to the attached script space when present",
        [
            "Both bodies load the script-space field, test it, and call its freeScript operation only on the non-null path.",
            "The target retains the same four-instruction conditional wrapper as the source.",
        ],
    ),
    spec(
        "0x210a8c",
        "TGraalVar_hasFunction_TString_const",
        "0x217198",
        "_ZN10G0gxgajWBw10Z1jrMamtBmERK10C8THgaTQxF",
        "checks the primary script, global player script, and function table for a named function",
        [
            "Both methods perform the primary function lookup, scripted-function fallback, global-universe player identity check, and final function-count test.",
            "The target keeps the same decision tree and method position in the class-local runtime block, with wrapper conversions around string values.",
        ],
    ),
    spec(
        "0x210b40",
        "TGraalVar_sortList_bool",
        "0x21727c",
        "_ZN10G0gxgajWBw10VtHbMaXbs9Eb",
        "sorts array entries by their values using temporary records and a value comparator",
        [
            "Both methods build temporary records, optionally read each entry's string value, qsort the records, write the pointers back, clear the temporaries, and mark the array updated.",
            "The target has the same record layout and comparator role; changed list and string wrappers explain the larger call set.",
        ],
    ),
    spec(
        "0x210ce8",
        "TGraalVar_sortListByValue_TString_const_TString_const_bool",
        "0x217444",
        "_ZN10G0gxgajWBw10y55fMaiK9cERK10C8THgaTQxFS2_b",
        "sorts array entries by numeric or string values in ascending or descending order",
        [
            "Both methods check the array length, inspect the requested comparison mode, build temporary value records, qsort them, restore the array pointers, and mark the array updated.",
            "The target preserves the source's mixed numeric and string branches and only adds rebuilt-wrapper conversions.",
        ],
    ),
    spec(
        "0x210f98",
        "TGraalVar_listSubVars_TStringList_TString_const",
        "0x217754",
        "_ZN10G0gxgajWBw10VVjmgapnonEP10vuuHgangcFRK10C8THgaTQxF",
        "walks persistent variables, emits name-value lines, and recursively lists child variables",
        [
            "Both methods iterate the persistent hash, skip the same object cases, read each value, emit prefix plus name plus value, and recurse with a dotted prefix for child lists.",
            "The target has the same loop and recursion roles, with explicit conversions for its rebuilt string wrapper.",
        ],
    ),
    spec(
        "0x211178",
        "TGraalVar_saveVarsToArray_void",
        "0x21797c",
        "_ZN10G0gxgajWBw10sbidMalVNaEv",
        "serializes visible script properties and persistent variables into an array",
        [
            "Both methods enumerate properties, skip name and initialized fields, compare stored properties, append name-value entries, and then call listSubVars with an empty prefix.",
            "The target preserves the same static helper initialization and property filtering before the persistent-variable pass.",
        ],
    ),
    spec(
        "0x211850",
        "TGraalVar_writeFloatOrString_TString_const",
        "0x21805c",
        "_ZN10G0gxgajWBw10v18tMaTcZoERK10C8THgaTQxF",
        "parses a numeric string when possible and otherwise stores the original string",
        [
            "Both methods test numeric syntax, parse the float, round-trip it through a temporary string, and choose the numeric or string virtual setter accordingly.",
            "The target keeps the same branch and cleanup sequence while using the rebuilt string wrapper.",
        ],
    ),
    spec(
        "0x21190c",
        "TGraalVar_setSubVar_TString_const",
        "0x218134",
        "_ZN10G0gxgajWBw10oRlmgaC_pnERK10C8THgaTQxF",
        "walks a dotted or equals-separated variable path and assigns the final value",
        [
            "Both methods split the path at the first separator, resolve or create the child variable, recurse for dotted paths, and handle zero, one, or general values with the same setters.",
            "The target preserves the source's path parsing and recursive control flow; wrapper conversion calls account for the changed names and metrics.",
        ],
    ),
    spec(
        "0x211c00",
        "TGraalVar_setVarValue_TString_const_TString_const",
        "0x218468",
        "_ZN10G0gxgajWBw10gVHMMaRyAEERK10C8THgaTQxFS2_",
        "sets a named variable directly or constructs an equals-separated subvariable assignment",
        [
            "Both methods try the primary lookup and property setter first, then construct name plus equals plus value and pass it to setSubVar when the lookup misses.",
            "The target has the same two-path behavior and cleanup with explicit conversions between rebuilt string wrappers.",
        ],
    ),
    spec(
        "0x2124c0",
        "TGraalVar_getArrayMember_TString_const",
        "0x218d70",
        "_ZN10G0gxgajWBw10MSgsMaQOonERK10C8THgaTQxF",
        "finds an array member by case-insensitive name",
        [
            "Both methods iterate the array through virtual size and indexed-member slots, compare each member name case-insensitively, and return the matching member or null.",
            "The target preserves the source loop bounds and return behavior with only a temporary string conversion around the member name.",
        ],
    ),
    spec(
        "0x21277c",
        "TGraalVar_copyFrom_TGraalVar",
        "0x219050",
        "_ZN10G0gxgajWBw10OEwsMa54BnEPS_",
        "copies scalar state, arrays, properties, and persistent child variables from another variable",
        [
            "Both methods reject self-copy, unlink the existing value, clone arrays, copy typed properties through the property virtual slots, recursively copy persistent children, and release old storage.",
            "The target preserves the same property-type switch and recursive hash traversal; rebuilt list, iterator, and string classes account for the metric changes.",
        ],
    ),
    spec(
        "0x2135b0",
        "TGraalVar_getFunctions_void",
        "0x219ed0",
        "_ZN10G0gxgajWBw10E3ArMaINPmEv",
        "returns an array describing visible script functions and their scope",
        [
            "Both methods create an output array, enumerate the script environment and inherited script lists, create one result object per function, and set parameters and scope fields.",
            "The target keeps the same inherited-list aggregation and public-versus-protected decision, with rebuilt array and string wrappers.",
        ],
    ),
    spec(
        "0x213b10",
        "TGraalVar_writeStringList_TStringList",
        "0x21a64c",
        "_ZN10G0gxgajWBw10KerMMa3wmEEP10vuuHgangcF",
        "writes a string list into an array, creating, replacing, or removing cells to match its length",
        [
            "Both methods validate access, force array type, update existing cells, append new cells initialized to empty strings, and delete excess cells from the end.",
            "The target retains the source's length-controlled loop structure and uses the corresponding target list and string operations.",
        ],
    ),
    spec(
        "0x213e48",
        "TGraalVar_insertArrayCellFloat_int_double",
        "0x21a970",
        "_ZN10G0gxgajWBw10krOlgaG2XmEid",
        "creates a numeric array cell with an empty name and inserts it at the requested index",
        [
            "Both methods validate array access, set the array and cell types, allocate an empty-named value, store the supplied float, insert it, and return it.",
            "The target preserves the source's short constructor-and-insert sequence with a rebuilt empty-string constant.",
        ],
    ),
    spec(
        "0x213f04",
        "TGraalVar_insertArrayCellString_int_TString_const",
        "0x21aa0c",
        "_ZN10G0gxgajWBw10E453HaEJ3GEiRK10CanTfaz6bZ",
        "creates a string array cell with an empty name and inserts it at the requested index",
        [
            "Both methods validate array access, set the array and cell types, allocate an empty-named value, store the supplied string, insert it, and return it.",
            "The target preserves the source's short sequence while passing the rebuilt string wrapper to the virtual setter.",
        ],
    ),
    spec(
        "0x213fc0",
        "TGraalVar_insertArrayCellObject_int_TGraalVar",
        "0x21aab0",
        "_ZN10G0gxgajWBw10M4msgaG1tsEiPS_",
        "creates an object array cell with an empty name and inserts it at the requested index",
        [
            "Both methods validate array access, set the array and cell types, allocate an empty-named value, assign the supplied object through virtual slot +208, insert it, and return it.",
            "The target preserves the source's short sequence with the rebuilt object and list classes.",
        ],
    ),
    spec(
        "0x21407c",
        "TGraalVar_initStaticScriptVars_void",
        "0x21ab54",
        "_Z10S4hxMaMPCrv",
        "initializes the static property table and registers the script variable property definitions",
        [
            "Both methods allocate the class property object, run its constructor, store it in the class static, and register the same property definition table.",
            "The source and target have identical two-block, two-call initialization structure and matching allocation size after the target class rebuild.",
        ],
    ),
    spec(
        "0x2140c0",
        "TGraalVar_writeString_TString_const",
        "0x21ab98",
        "_ZN10G0gxgajWBw10m6pngaXzjoERK10CanTfaz6bZ",
        "stores a string value, parses quoted or comma-separated text into an array, and removes the array for scalar text",
        [
            "Both methods update the scalar string state, unlink the prior value, recognize quoted or valid comma text, build an array from the parsed text, and otherwise remove the array.",
            "The target preserves the source's parsing branches and initialized flag while adding rebuilt string and array wrapper operations.",
        ],
    ),
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(functions: list[dict]) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in functions}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def evidence_by_ea(paths: list[Path]) -> tuple[dict[int, dict], list[dict]]:
    rows = {}
    inputs = []
    for path in paths:
        document = load(path)
        inputs.append({"path": str(path), "sha256": sha256_path(path)})
        for row in document.get("targets", []):
            ea = int(row["ea"], 16)
            if ea in rows:
                previous = rows[ea]
                if (
                    previous.get("name") != row.get("name")
                    or previous.get("pseudocode") != row.get("pseudocode")
                ):
                    raise ValueError("conflicting evidence row at %s" % row["ea"])
                continue
            rows[ea] = row
    return rows, inputs


def pseudocode_sha256(row: dict) -> str | None:
    pseudocode = row.get("pseudocode")
    if pseudocode is None:
        return None
    return hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()


def main() -> None:
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
    source_evidence, source_evidence_inputs = evidence_by_ea(args.source_evidence)
    target_evidence, target_evidence_inputs = evidence_by_ea(args.target_evidence)
    semantic_sources = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
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
        if original_ea in semantic_sources:
            raise ValueError("source already has a semantic match at %s" % reviewed["original_ea"])
        if spectron_ea in semantic_targets:
            raise ValueError("target already has a semantic match at %s" % reviewed["spectron_ea"])
        if source_trace is None or target_trace is None:
            raise ValueError("missing pseudocode evidence at %s" % reviewed["original_ea"])
        if source_trace.get("pseudocode") is None or target_trace.get("pseudocode") is None:
            raise ValueError("pseudocode was unavailable at %s" % reviewed["original_ea"])

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differences = [
            field for field in METRIC_FIELDS if source_metrics.get(field) != target_metrics.get(field)
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
                "source_component": reviewed["source_component"],
                "target_component": reviewed["target_component"],
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": (
                    "manual-tgraalvar-runtime-continuation-exact-anchor"
                    if not differences
                    else "manual-tgraalvar-runtime-continuation-layout-anchor"
                ),
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "source_basis": "Hex-Rays pseudocode, class-local method order, and source/target data-flow agreement",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    source_eas = {row["original_ea"] for row in anchors}
    target_eas = {row["spectron_ea"] for row in anchors}
    if len(source_eas) != len(anchors) or len(target_eas) != len(anchors):
        raise ValueError("duplicate source or target in TGraalVar continuation anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tgraalvar_runtime_continuation_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the next unresolved TGraalVar runtime methods",
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
            "source_evidence": source_evidence_inputs,
            "target_evidence": target_evidence_inputs,
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
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
