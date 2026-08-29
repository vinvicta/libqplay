#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron TScript runtime family.

The source and target use different string, list, and script classes, so the
normal feature matcher leaves this class-local block unresolved.  This tool
keeps the reviewed source and target evidence, checks that the addresses are
not already claimed by the automatic map, and records the proposed v18 names.
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


def item(
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
        "operation": operation,
        "evidence": evidence,
    }


ANCHOR_SPECS = (
    item(
        "0x2148dc",
        "TScriptFunction_TScriptFunction_TScript_TString_const_int_int",
        "0x21b490",
        "_ZN10AICTfaebpZC2EP10zW2NgaU4IKRK10C8THgaTQxFii",
        "constructs a script function variable, records its owner and source range, and creates its free-call-stack list",
        [
            "Both constructors initialize the TGraalVar-derived value, install the script-function property table, copy the function name, record the owning script and two integer fields, and allocate an empty call-stack list.",
            "The target class-local block has the same constructor position and object layout. Its extra operations are the rebuilt string and base-variable wrappers.",
        ],
    ),
    item(
        "0x214a24",
        "TScriptFunction_addToFreeCallStackEntries_TCallStackEntry",
        "0x21b5f8",
        "_ZN10AICTfaebpZ10h2dTfavq4YEP10l8eTfaIl5Y",
        "adds a call-stack entry only when it is not already present",
        [
            "Both methods reject a null entry, search the owned list, and append only when the list lookup returns a negative index.",
            "The source and target have identical 19-instruction, five-block normalized ARM64 metrics; only the rebuilt list method name changes.",
        ],
    ),
    item(
        "0x214a70",
        "TScriptFunction_clearCallStackEntries_void",
        "0x21b644",
        "_ZN10AICTfaebpZ10Yw3SfaqAWYEv",
        "releases every owned call-stack entry and clears the list",
        [
            "Both methods walk the list, invoke the entry destructor through its virtual slot, reload the list, and clear it after the final entry.",
            "The complete normalized ARM64 feature record is identical, and the target method is the next body in the same TScriptFunction class block.",
        ],
    ),
    item(
        "0x214aec",
        "TScriptFunction_TScriptFunction",
        "0x21b6c0",
        "_ZN10AICTfaebpZD1Ev",
        "destroys the script-function call-stack state and its TGraalVar base",
        [
            "IDA marks both bodies as the non-deleting C++ destructor form. Both reset the vtable, clear call-stack entries, release the list, and destroy the base variable.",
            "The source and target have the same four-block, 18-instruction destructor shape.",
        ],
    ),
    item(
        "0x214b34",
        "TScriptFunction_TScriptFunction__2",
        "0x21b708",
        "_ZN10AICTfaebpZD0Ev",
        "runs the script-function destructor and then releases the object",
        [
            "Both bodies are the deleting-destructor form that calls the complete destructor and then operator delete.",
            "The two-instruction ABI wrapper is identical in normalized ARM64 features and directly follows the non-deleting destructor in both class blocks.",
        ],
    ),
    item(
        "0x214b54",
        "TScript_TScript_TString_const",
        "0x21b728",
        "_ZN10zW2NgaU4IKC1ERK10C8THgaTQxF",
        "constructs a script, its function tables, its root function, and the joined-class child array",
        [
            "Both constructors initialize the variable base, copy the script name, allocate the hash and list members, create the root function, initialize the two script lists, and create the joinedclasses child variable.",
            "The target preserves the same four-block constructor sequence and all distinctive fields. The larger body comes from the rebuilt string, hash, and child-variable classes.",
        ],
    ),
    item(
        "0x21510c",
        "TScript_addCatchedEvent_TString_const_TString_const_int",
        "0x21bd1c",
        "_ZN10zW2NgaU4IK10lWtWfaGNO0ERK10C8THgaTQxFS2_i",
        "finds or creates a caught-event function for an object, event, and event index",
        [
            "Both methods scan the caught-event list by case-insensitive object and event names plus the integer event index, then allocate and append a function when no match exists.",
            "The target retains the same list fields, dotted function-name construction, function subclass allocation, and final event-name assignments in the adjacent TScript block.",
        ],
    ),
    item(
        "0x215488",
        "TScript_getFunction_TString_const",
        "0x21c0dc",
        "_ZN10zW2NgaU4IK10EpeWfajKB0ERK10C8THgaTQxF",
        "resolves a function by direct name or by a qualified script name",
        [
            "Both methods split names at the double-colon separator, look up direct names in the primary hash, search inherited scripts on a miss, and recursively resolve the qualified form.",
            "The target pseudocode preserves the same lowercasing, substring, hash lookup, inherited-list recursion, and cleanup sequence with rebuilt string wrappers.",
        ],
    ),
    item(
        "0x2157f4",
        "TScript_getEventFunctions_TList_TString_const",
        "0x21c460",
        "_ZN10zW2NgaU4IK10iYjWfappG0EP10vy1JgaKVkHRK10C8THgaTQxF",
        "collects matching on-prefixed event functions from this script and inherited scripts",
        [
            "Both methods build the on-plus-event search name, iterate the script hash through an iterator, append case-insensitive matches, and recurse through the inherited script list.",
            "The target's iterator construction and destructor, list append, and recursive call occupy the corresponding class-local method slot.",
        ],
    ),
    item(
        "0x215950",
        "TScript_installSelfEventCatchers_TGraalVar",
        "0x21c5dc",
        "_ZN10zW2NgaU4IK10QQ5Vfadxu0EP10G0gxgajWBw",
        "installs self-event catchers for on-prefixed functions and inherited scripts",
        [
            "Both methods iterate the function hash, filter names beginning with on, register each event on the supplied script space, and recurse through inherited scripts.",
            "The target preserves the source's iterator lifecycle, event-prefix test, empty source-class argument, and inherited-list loop while using rebuilt string and script-space helpers.",
        ],
    ),
    item(
        "0x215a9c",
        "TScript_installEventCatchers_TGraalVar",
        "0x21c758",
        "_ZN10zW2NgaU4IK10WKUVfagmk0EP10G0gxgajWBw",
        "installs event catchers for local and inherited caught-event functions",
        [
            "Both methods ensure the receiver has a script space, register every local caught event, walk inherited caught-event lists, and finish by installing self-event catchers.",
            "The target pseudocode retains both nested list walks and the final self-catcher call. The expanded metrics are caused by rebuilt list and string operations.",
        ],
    ),
    item(
        "0x215cc4",
        "TScript_addFunctionProfilerTime_TString_const_double_double",
        "0x21ca08",
        "_ZN10zW2NgaU4IK10poCVfa8U4_ERK10C8THgaTQxFdd",
        "accumulates positive function-profile time in a per-script hash",
        [
            "Both methods gate on profiling and positive elapsed time, lazily allocate the profile hash, clear it after a new profiling epoch, find or create the named record, and update its accumulated time.",
            "The target body has the same ten-block control flow and the same hash-record lifecycle, with target string and hash classes replacing the source wrappers.",
        ],
    ),
    item(
        "0x215eac",
        "TScript_optimizeByteCode_void",
        "0x21cc10",
        "_ZN10zW2NgaU4IK10ejpZfaRUg3Ev",
        "rewrites bytecode instruction patterns into compact opcodes and resolves property references",
        [
            "Both methods walk the bytecode records, fold the same constant and property instruction patterns, use the property hash for the object cases, and update the instruction stream in place.",
            "The target has the same 51 basic blocks, 32 branches, and five direct helper calls. Its 40-byte instruction records account for the small size and instruction-count change.",
        ],
    ),
    item(
        "0x216de8",
        "TScript_loadScriptEncrypted_int_TString_const_uint",
        "0x21db68",
        "_ZN10zW2NgaU4IK10pH_0fadms5EiRK10C8THgaTQxFj",
        "loads, verifies, and compiles an encrypted script, then reports success or requests missing content",
        [
            "Both methods gate on the script-loading mode, derive the class-code filename, decode or request the encrypted content, compare the checksum and script limits, and update the script event state.",
            "The target retains the success path, cached-content path, download-request path, server-privilege test, and two event notifications. Its extra cleanup calls belong to rebuilt target wrappers.",
        ],
    ),
    item(
        "0x216fa0",
        "TScript_checkRequestScript_int_TString_const_uint",
        "0x21dde0",
        "_ZN10zW2NgaU4IK10rjF0faYma5EiRK10C8THgaTQxFj",
        "checks whether a requested encrypted script is available and reports the result",
        [
            "Both methods handle the no-request case, derive the class-code filename, test the decoded content and file state, and route the success or failure result through the same script events.",
            "The target is the next large method after the encrypted loader and preserves its fallback call to the loader for nonzero request modes.",
        ],
    ),
    item(
        "0x217108",
        "TScript_initStaticVars_void",
        "0x21dff8",
        "_Z10AlE0faNy94v",
        "allocates the global requested-class-script list",
        [
            "The source allocates and constructs the static TStringList used for requested class scripts. The target allocates and constructs its rebuilt vuuHgangcF list replacement and stores it in the corresponding static.",
            "Both are one-block, 12-instruction static constructors with the same allocation and constructor call pattern, and the target sits at the static-initializer boundary after the TScript method block.",
        ],
    ),
    item(
        "0x217138",
        "TScript_initStaticScriptVars_void",
        "0x21e028",
        "_Z10QSc0faUrN4v",
        "allocates the global script-function property table",
        [
            "Both methods allocate the script-function property object, invoke its constructor, store the resulting static pointer, and return that static's address.",
            "The target constructor name identifies the obfuscated AICTfaebpZProperties class, and the complete normalized ARM64 feature record is identical.",
        ],
    ),
    item(
        "0x2176d8",
        "TScriptEnvironment_getPropertyList_TString_const",
        "0x21e618",
        "_ZN10D6TlgajP1m10nYwjIaul2TERK10C8THgaTQxF",
        "looks up a property list in the global property-list hash",
        [
            "Both methods return null when the global property list registry is absent, compute the key hash, and return the matching object from the registry.",
            "The source and target are identical 18-instruction, four-block normalized ARM64 helpers. The competing target candidate is outside the TScriptEnvironment method neighborhood and has a different role.",
        ],
    ),
    item(
        "0x217908",
        "TScriptEnvironment_makeTempVar_void",
        "0x21e848",
        "_ZN10D6TlgajP1m10_ymjIa8AUTEv",
        "creates a temporary script variable and links it to the active universe",
        [
            "Both methods allocate an empty-named TGraalVar, link it to the active universe's temporary-variable list when available, and otherwise mark it as non-garbage-managed.",
            "The target's D6TlgajP1m class block places this helper immediately before the array-variable constructor and preserves the same four-block allocation and active-universe test.",
        ],
    ),
    item(
        "0x2179a4",
        "TScriptEnvironment_makeArrayVar_bool",
        "0x21e8bc",
        "_ZN10D6TlgajP1m10BPMlga2GWmEb",
        "creates an empty array script variable with optional universe ownership",
        [
            "Both methods allocate an empty-named variable, optionally add it to the active universe, set the array and cell types, and allocate the empty cell list.",
            "The target preserves the six-block constructor-and-list setup and differs only in rebuilt object and list wrappers plus the relocated static fields.",
        ],
    ),
    item(
        "0x217af0",
        "TScriptEnvironment_makeVarFromStringList_TStringList_const_bool",
        "0x21e9ec",
        "_ZN10D6TlgajP1m10I4logaIb6oEPK10vuuHgangcFb",
        "creates an array variable and copies every string-list element into it",
        [
            "Both methods call the array-variable factory, iterate the input list, and write each indexed string through the array variable's string setter.",
            "The target's rebuilt vuuHgangcF list indexer and CanTfaz6bZ temporary cleanup are the only material additions around the same five-block loop.",
        ],
    ),
    item(
        "0x217b80",
        "TScriptEnvironment_makeVarFromCommaText_TString_const_bool",
        "0x21eaa0",
        "_ZN10D6TlgajP1m10M203Ha_u_GERK10C8THgaTQxFb",
        "creates an array variable from comma text, escaping it when needed",
        [
            "Both methods create an array variable, validate comma syntax, escape and append a comma for scalar input, then write the resulting text through the array setter.",
            "The target preserves the source's three-block branch structure and the same helper sequence, with renamed validation and escape functions from the rebuilt string class.",
        ],
    ),
    item(
        "0x217cd8",
        "TScriptEnvironment_makeStringListFromVar_TGraalVar",
        "0x21ec14",
        "_ZN10D6TlgajP1m10aWO3HavsPGEP10G0gxgajWBw",
        "copies indexed values from a script variable into a new string list",
        [
            "Both methods allocate a new string list, query the source variable count and indexed values through virtual slots, append each value, and clear the temporary string.",
            "The target retains the five-block loop and uses the rebuilt vuuHgangcF list and CanTfaz6bZ string operations.",
        ],
    ),
    item(
        "0x217db4",
        "TScriptEnvironment_initStaticVars_void",
        "0x21ed10",
        "_Z10lke3HaOFkGv",
        "initializes the global script event-name registries",
        [
            "The source creates the global event-name hash and the global script-event list from the long built-in event tables. The target creates the corresponding obfuscated event-name objects and inserts the same registry entries through its rebuilt string and list classes.",
            "The target is the large static initializer immediately after the TScriptEnvironment methods. Its expanded one-block body reflects individual target object construction in place of the source's compact comma-text constructors, so the size difference is intentional.",
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
            previous = rows.get(ea)
            if previous is not None:
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
    source_evidence, source_inputs = evidence_by_ea(args.source_evidence)
    target_evidence, target_inputs = evidence_by_ea(args.target_evidence)
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
            raise ValueError("source already has an automatic match at %s" % reviewed["original_ea"])
        if spectron_ea in semantic_targets:
            raise ValueError("target already has an automatic match at %s" % reviewed["spectron_ea"])
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
                "source_component": "TScript and TScriptEnvironment runtime method family",
                "target_component": "zW2NgaU4IK and D6TlgajP1m obfuscated runtime method family",
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": (
                    "manual-tscript-runtime-exact-anchor"
                    if not differences
                    else "manual-tscript-runtime-layout-anchor"
                ),
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "source_basis": "Hex-Rays pseudocode, class-local method order, target ABI names, and source/target data-flow agreement",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    source_eas = {row["original_ea"] for row in anchors}
    target_eas = {row["spectron_ea"] for row in anchors}
    if len(source_eas) != len(anchors) or len(target_eas) != len(anchors):
        raise ValueError("duplicate source or target in TScript runtime anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tscript_runtime_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TScript, TScriptFunction, and TScriptEnvironment runtime blocks",
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
            "Every target address is valid only for the hashed Spectron 2.2 ARM64 library in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated target name in the evidence row.",
            "Changed metrics are recorded explicitly because rebuilt string, list, hash, and event-registry classes alter the target layout.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
