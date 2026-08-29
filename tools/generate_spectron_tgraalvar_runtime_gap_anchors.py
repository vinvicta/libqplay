#!/usr/bin/env python3
"""Create reviewed anchors for a remaining Spectron TGraalVar method block.

The target was rebuilt with a different string wrapper and several renamed
support classes.  That makes broad feature matching conservative, but the
Hex-Rays output still preserves the method-level behavior.  This generator
records the source and target metrics, the decompiler evidence fingerprints,
and the reasoning used for each reviewed alias.
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


ANCHOR_SPECS = (
    {
        "original_ea": "0x20d304",
        "original_name": "TGraalVar_receiveEvent_script_event",
        "spectron_ea": "0x2136c4",
        "spectron_name": "_ZN10G0gxgajWBw10rVjVga1mQQE10RiQ7IaxCcA",
        "source_component": "TGraalVar event forwarding methods",
        "target_component": "G0gxgajWBw event forwarding methods",
        "operation": "builds the fixed event name, forwards it through virtual slot +128, then clears the temporary string",
        "evidence": [
            "The source and target decompilations have the same one-block, 24-instruction control flow.",
            "Both methods build a temporary string from the same event-name literal, call the object virtual slot at +128 with the script event and a zero fourth argument, and clear the temporary.",
            "The target method is the unresolved candidate in the same G0gxgajWBw class-local event block; the other automatic candidate belongs to the already translated TGaniObject event wrapper.",
        ],
    },
    {
        "original_ea": "0x20e070",
        "original_name": "TGraalVar_getVarNames_bool_bool_bool",
        "spectron_ea": "0x214520",
        "spectron_name": "_ZN10G0gxgajWBw10w6jsMacxrnEbbb",
        "source_component": "TGraalVar variable-name enumeration",
        "target_component": "G0gxgajWBw variable-name enumeration",
        "operation": "collects script properties and variables according to the three visibility flags, removes duplicates, and sorts the result",
        "evidence": [
            "The source and target decompilations preserve the same two enumeration phases, flag tests, duplicate check, and final sort.",
            "The target keeps the source method's 29 basic blocks, 40 branches, and 21 calls, with only small changes from rebuilt list, iterator, and string wrapper classes.",
            "The method sits in the same G0gxgajWBw class-local sequence between the known TGraalVar property callbacks and the script parser helpers.",
        ],
    },
    {
        "original_ea": "0x20e5c4",
        "original_name": "parseDynamicFunctionParameters_char_const_std_va_list",
        "spectron_ea": "0x214a78",
        "spectron_name": "_Z10_jfDMawvDwPKcSt9__va_list",
        "source_component": "GS2 dynamic call parameter parser",
        "target_component": "obfuscated dynamic call parameter parser",
        "operation": "walks the format string and converts boolean, string, numeric, object, and coordinate arguments into an array variable",
        "evidence": [
            "The source and target decompilations preserve every format case, including the coordinate triple and the AArch64 va_list cursor handling.",
            "The target retains 48 basic blocks and the same branch structure; its extra instructions and calls are wrapper conversions for the rebuilt string and array classes.",
            "The target method is immediately after the known TGraalVar variable-name block and before the known execute-function wrappers, matching the source runtime sequence.",
        ],
    },
    {
        "original_ea": "0x20ec60",
        "original_name": "TGraalVar_executeStringFunctionF_TString_const_char_const",
        "spectron_ea": "0x215148",
        "spectron_name": "_ZN10G0gxgajWBw10SkGGMakewzERK10C8THgaTQxFPKcz",
        "source_component": "TGraalVar formatted string function execution",
        "target_component": "G0gxgajWBw formatted string function execution",
        "operation": "parses variadic GS2 arguments, invokes the named function, extracts the returned string, and releases temporary values",
        "evidence": [
            "The source and target decompilations have the same empty-format fast path, dynamic-parser call, function invocation, result extraction, output initialization, and cleanup sequence.",
            "The target's 82-instruction body is a rebuilt-wrapper version of the source's 89-instruction body and still calls the target parser and the corresponding execute-function method.",
            "The target is directly after the two already translated executeFunction overloads in the G0gxgajWBw method block.",
        ],
    },
    {
        "original_ea": "0x20f014",
        "original_name": "TGraalVar_saveString_TString_const_uint",
        "spectron_ea": "0x2154e0",
        "spectron_name": "_ZN10G0gxgajWBw10gi98La2qj7ERK10C8THgaTQxFj",
        "source_component": "TGraalVar script string persistence",
        "target_component": "G0gxgajWBw script string persistence",
        "operation": "resolves the script-access path, serializes the current string state, creates directories, writes the stream, and updates the resource object",
        "evidence": [
            "The source and target decompilations preserve the same path guard, stream allocation, virtual string extraction, append-or-assign choice, file write, resource update, counter adjustment, and cleanup.",
            "The target adds explicit CanTfaz6bZ conversion and cleanup around the same logical string values, accounting for its larger body and changed call set.",
            "The target appears in the matching G0gxgajWBw save/load sequence immediately after the known activateScript and deactivateScript methods.",
        ],
    },
    {
        "original_ea": "0x20f17c",
        "original_name": "TGraalVar_saveLines_TString_const_uint",
        "spectron_ea": "0x215660",
        "spectron_name": "_ZN10G0gxgajWBw10eGW8LacZ76ERK10C8THgaTQxFj",
        "source_component": "TGraalVar script line-list persistence",
        "target_component": "G0gxgajWBw script line-list persistence",
        "operation": "resolves the script-access path, serializes each script line into a string list, writes it, and updates the resource object",
        "evidence": [
            "The source and target decompilations both iterate the object's line list, extract each entry through virtual slot +184, append it to a temporary list, save the list, and release it.",
            "The target preserves the same eight-block loop structure; the extra work is the target string conversion and wrapper cleanup.",
            "The method follows the reviewed saveString method in the target class-local sequence, as it does in the source.",
        ],
    },
    {
        "original_ea": "0x20f2ac",
        "original_name": "TGraalVar_loadString_TString_const",
        "spectron_ea": "0x2157a8",
        "spectron_name": "_ZN10G0gxgajWBw10xJkbMaW288ERK10C8THgaTQxF",
        "source_component": "TGraalVar script string loading",
        "target_component": "G0gxgajWBw script string loading",
        "operation": "checks script access, loads a stream from the resolved path, passes the loaded string through virtual slot +200, and cleans up",
        "evidence": [
            "The source and target decompilations preserve the same access check, path resolution, stream allocation, file load, virtual setter call at +200, and cleanup paths.",
            "The target's larger body adds the expected wrapper conversion before the virtual setter, but retains the source's nine-block, three-return shape.",
            "The target method follows the reviewed saveLines method and precedes the reviewed variable access methods in the same G0gxgajWBw block.",
        ],
    },
    {
        "original_ea": "0x20f3bc",
        "original_name": "TGraalVar_setVarValueAsFloat_TString_const_double",
        "spectron_ea": "0x2158e4",
        "spectron_name": "_ZN10G0gxgajWBw10HdbMMaa38DERK10C8THgaTQxFd",
        "source_component": "TGraalVar numeric variable setter",
        "target_component": "G0gxgajWBw numeric variable setter",
        "operation": "looks up a variable by name, falls back to the persistent hash and creates a variable when needed, then stores the supplied floating-point value",
        "evidence": [
            "The source and target decompilations have the same primary virtual lookup, persistent-hash fallback, variable creation fallback, and final virtual numeric setter at +192.",
            "The target keeps the source's six basic blocks and adds only explicit string-wrapper conversion and cleanup around the name argument.",
            "The method is the first of the two unresolved variable value accessors directly before the reviewed getVarValue method.",
        ],
    },
    {
        "original_ea": "0x20f474",
        "original_name": "TGraalVar_getVarValue_TString_const",
        "spectron_ea": "0x2159f4",
        "spectron_name": "_ZN10G0gxgajWBw10yKnMMaNAjEERK10C8THgaTQxF",
        "source_component": "TGraalVar variable value getter",
        "target_component": "G0gxgajWBw variable value getter",
        "operation": "returns the primary variable value when present, otherwise consults the persistent hash and returns a copied value or null",
        "evidence": [
            "The source and target decompilations preserve the same primary lookup, value-copy virtual call at +40, persistent-hash fallback, null return, and copied fallback value.",
            "The target keeps the source's seven basic blocks and return behavior while adding target string-wrapper conversion around the lookup key.",
            "The target follows the reviewed numeric setter in the G0gxgajWBw class-local sequence.",
        ],
    },
    {
        "original_ea": "0x20fc18",
        "original_name": "TGraalVar_setArrayCellObject_int_TGraalVar",
        "spectron_ea": "0x216174",
        "spectron_name": "_ZN10G0gxgajWBw10VBZsMaAr_nEiRK10C8THgaTQxF",
        "source_component": "TGraalVar object-array mutation",
        "target_component": "G0gxgajWBw string-wrapper array mutation",
        "operation": "validates an array index, assigns a value through virtual slot +200 on the selected cell, and marks the array updated",
        "evidence": [
            "The source and target decompilations preserve the same index bounds check, list indexing, virtual setter at +200, and array-updated call.",
            "The target method is interleaved between the known float and string cell setters because the rebuilt target represents the incoming value through C8THgaTQxF; its extra conversion and cleanup explain the changed shape.",
            "The automatic matcher assigned the nearby target string setter to the source string setter, so this independently reviewed target body is required to recover the object-array method identity.",
        ],
    },
    {
        "original_ea": "0x20fe5c",
        "original_name": "TGraalVar_getVarValueAsFloat_TString_const",
        "spectron_ea": "0x216454",
        "spectron_name": "_ZN10G0gxgajWBw10JGPAHaB5AhERK10C8THgaTQxF",
        "source_component": "TGraalVar floating-point value getter",
        "target_component": "G0gxgajWBw floating-point value getter",
        "operation": "looks up a named value and returns its numeric projection, falling back to the persistent hash when the primary lookup misses",
        "evidence": [
            "The source and target decompilations preserve the same primary lookup and value projection through virtual slot +32, followed by the persistent-hash fallback and null return.",
            "Both methods have seven basic blocks and the same high-level branch structure; target wrapper conversions account for the extra instructions and calls.",
            "The target method follows the reviewed object-array and string cell setters and precedes the reviewed array-string updater, matching the source method order after rebuild insertions.",
        ],
    },
    {
        "original_ea": "0x20ff2c",
        "original_name": "TGraalVar_updateArrayString_void",
        "spectron_ea": "0x216558",
        "spectron_name": "_ZN10G0gxgajWBw10wu6lMao4ciEv",
        "source_component": "TGraalVar array-string cache updater",
        "target_component": "G0gxgajWBw array-string cache updater",
        "operation": "rebuilds the comma-separated string representation of array cells, handles empty entries, and marks the value initialized",
        "evidence": [
            "The source and target decompilations preserve the same empty-list path, cell iteration, value extraction through virtual slot +184, comma insertion, single-element trailing comma behavior, and initialized flag.",
            "The target's 13-block body is a wrapper-expanded version of the source's 12-block body and still uses the corresponding target value and string helpers.",
            "The target method is immediately before the already translated get_joinedclasses method, which calls this updater in both builds.",
        ],
    },
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
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        source_trace = source_evidence.get(original_ea)
        target_trace = target_evidence.get(spectron_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % spec["original_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["spectron_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
        if target.get("is_default_name"):
            raise ValueError("target unexpectedly has a default IDA name at %s" % spec["spectron_ea"])
        if original_ea in semantic_sources:
            raise ValueError("source already has a semantic match at %s" % spec["original_ea"])
        if spectron_ea in semantic_targets:
            raise ValueError("target already has a semantic match at %s" % spec["spectron_ea"])
        if source_trace is None or target_trace is None:
            raise ValueError("missing pseudocode evidence at %s" % spec["original_ea"])
        if source_trace.get("pseudocode") is None or target_trace.get("pseudocode") is None:
            raise ValueError("pseudocode was unavailable at %s" % spec["original_ea"])

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differences = [
            field for field in METRIC_FIELDS if source_metrics.get(field) != target_metrics.get(field)
        ]
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_string_refs": source.get("string_refs", []),
                "source_pseudocode_sha256": pseudocode_sha256(source_trace),
                "source_evidence_name": source_trace.get("name"),
                "spectron_ea": spec["spectron_ea"],
                "spectron_name": target["name"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_metrics": target_metrics,
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_string_refs": target.get("string_refs", []),
                "target_pseudocode_sha256": pseudocode_sha256(target_trace),
                "target_evidence_name": target_trace.get("name"),
                "source_component": spec["source_component"],
                "target_component": spec["target_component"],
                "operation": spec["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": (
                    "manual-tgraalvar-runtime-exact-anchor"
                    if not differences
                    else "manual-tgraalvar-runtime-layout-anchor"
                ),
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "source_basis": "Hex-Rays pseudocode, class-local method order, and source/target data-flow agreement",
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    source_eas = {row["original_ea"] for row in anchors}
    target_eas = {row["spectron_ea"] for row in anchors}
    if len(source_eas) != len(anchors) or len(target_eas) != len(anchors):
        raise ValueError("duplicate source or target in TGraalVar runtime anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tgraalvar_runtime_gap_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for unresolved TGraalVar runtime methods",
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
