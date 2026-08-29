#!/usr/bin/env python3
"""Create reviewed anchors for the residual Format2 parameter block."""

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
        "original_ea": "0x20cd20",
        "original_name": "gsfunctions_initStaticScriptVars_void",
        "spectron_ea": "0x2130b0",
        "spectron_name": "_Z10HWyrga7_Nrv",
        "proposed_name": "v18_gsfunctions_initStaticScriptVars_void",
        "operation": "registers the GSFunctions script-function table",
        "evidence": [
            "Both bodies make one static function-table registration call with a null receiver, a table pointer, and count 37.",
            "The normalized records match in size, instruction count, control-flow shape, opcode sequence, register shape, and overall shape; only register-detail allocation differs.",
            "The target entry immediately precedes the already translated randomstring method, matching the source initializer order.",
        ],
    },
    {
        "original_ea": "0x20ce88",
        "original_name": "TFormat2_FormatParameters_getNextS32_void",
        "spectron_ea": "0x213218",
        "spectron_name": "_ZN10giqpgaXJ_p10mgCpgamO9pEv",
        "proposed_name": "v18_TFormat2_FormatParameters_getNextS32_void",
        "operation": "reads and truncates the next formatted numeric argument as a signed integer",
        "evidence": [
            "The source and target bodies read the same virtual numeric getter at slot 224, increment the argument index, add 0.0001, and apply the same negative truncation correction.",
            "The target method is in the giqpgaXJ_p Format2 parameter cluster between the translated floating-point getter and the corresponding unsigned getter.",
            "All normalized feature metrics are exact, including register detail.",
        ],
    },
    {
        "original_ea": "0x20cf10",
        "original_name": "TFormat2_FormatParameters_getNextU32_void",
        "spectron_ea": "0x2132a0",
        "spectron_name": "_ZN10giqpgaXJ_p10tfvpgaJU3pEv",
        "proposed_name": "v18_TFormat2_FormatParameters_getNextU32_void",
        "operation": "reads and truncates the next formatted numeric argument as an unsigned integer",
        "evidence": [
            "The source and target bodies have the same virtual getter, index increment, 0.0001 adjustment, and negative-result correction.",
            "The target method follows the translated signed next-argument getter in the same giqpgaXJ_p class block.",
            "All normalized feature metrics are exact, including register detail.",
        ],
    },
    {
        "original_ea": "0x20cfd0",
        "original_name": "TFormat2_FormatParameters_getIndexedS32_int",
        "spectron_ea": "0x213360",
        "spectron_name": "_ZN10giqpgaXJ_p10a67ogaLqLpEi",
        "proposed_name": "v18_TFormat2_FormatParameters_getIndexedS32_int",
        "operation": "reads and truncates an indexed formatted numeric argument as a signed integer",
        "evidence": [
            "Both bodies read the Format2 value object through virtual slot 224, add 0.0001, and use the same signed truncation correction without advancing the index.",
            "The target method follows the translated indexed floating-point getter and precedes the matching unsigned indexed getter.",
            "All normalized feature metrics are exact, including register detail.",
        ],
    },
    {
        "original_ea": "0x20d040",
        "original_name": "TFormat2_FormatParameters_getIndexedU32_int",
        "spectron_ea": "0x2133d0",
        "spectron_name": "_ZN10giqpgaXJ_p10nn9ogamvMpEi",
        "proposed_name": "v18_TFormat2_FormatParameters_getIndexedU32_int",
        "operation": "reads and truncates an indexed formatted numeric argument as an unsigned integer",
        "evidence": [
            "The source and target bodies preserve the same indexed virtual getter and numeric conversion sequence.",
            "The target method is the second indexed integer accessor in the giqpgaXJ_p cluster, immediately before the destructor boundary.",
            "All normalized feature metrics are exact, including register detail.",
        ],
    },
    {
        "original_ea": "0x20d0b0",
        "original_name": "TFormat2_FormatParameters_TFormat2_FormatParameters",
        "spectron_ea": "0x213440",
        "spectron_name": "_ZN10giqpgaXJ_pD1Ev",
        "proposed_name": "v18_TFormat2_FormatParameters_TFormat2_FormatParameters",
        "operation": "runs the complete Format2 parameter destructor",
        "evidence": [
            "The source alternative name identifies a D1/D2 destructor, and the body resets the vtable before clearing the embedded string at offset 24.",
            "The target explicit D1 body resets the giqpgaXJ_p vtable and clears the rebuilt C8THgaTQxF member at the same offset.",
            "The target D1 entry is positioned between the indexed accessors and the string accessors, matching the source class layout.",
        ],
    },
    {
        "original_ea": "0x20d0c4",
        "original_name": "TFormat2_FormatParameters_getIndexedString_int",
        "spectron_ea": "0x213454",
        "spectron_name": "_ZN10giqpgaXJ_p10Ym2oga0BGpEi",
        "proposed_name": "v18_TFormat2_FormatParameters_getIndexedString_int",
        "operation": "reads, converts, and stores an indexed formatted string argument",
        "evidence": [
            "Both bodies call the value object's virtual string getter at slot 232, convert the temporary string, assign the embedded result, clear temporaries, and return the stored string or dummy string.",
            "The target body expands because the source TString is represented by rebuilt CanTfaz6bZ and C8THgaTQxF wrappers, but the cleanup and return flow remain identifiable.",
            "The target method follows the D1 boundary and precedes the next-string accessor in the same class-local sequence.",
        ],
    },
    {
        "original_ea": "0x20d148",
        "original_name": "TFormat2_FormatParameters_getNextString_void",
        "spectron_ea": "0x2134f0",
        "spectron_name": "_ZN10giqpgaXJ_p10B8wpgaSu5pEv",
        "proposed_name": "v18_TFormat2_FormatParameters_getNextString_void",
        "operation": "reads, converts, and stores the next formatted string argument",
        "evidence": [
            "The source and target bodies call the value object's virtual string getter at slot 232, advance the index, convert the temporary, assign the embedded result, clear temporaries, and return the stored string or dummy string.",
            "The target wrapper rebuild adds the expected conversion and cleanup calls, explaining the larger body while preserving data flow.",
            "The target method is immediately before the explicit D0 destructor, matching the source class-local order.",
        ],
    },
    {
        "original_ea": "0x20d1d4",
        "original_name": "TFormat2_FormatParameters_TFormat2_FormatParameters__2",
        "spectron_ea": "0x213598",
        "spectron_name": "_ZN10giqpgaXJ_pD0Ev",
        "proposed_name": "v18_TFormat2_FormatParameters_TFormat2_FormatParameters__2",
        "operation": "runs the deleting Format2 parameter destructor",
        "evidence": [
            "The source D0 body resets the vtable, clears the embedded string member at offset 24, and calls operator delete.",
            "The target explicit D0 body preserves the same cleanup-then-delete sequence for the rebuilt C8THgaTQxF member.",
            "The target D0 entry closes the giqpgaXJ_p class block immediately before the translated TGraalVar methods.",
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

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differences = [
            field
            for field in METRIC_FIELDS
            if source_metrics.get(field) != target_metrics.get(field)
        ]
        semantic_row = semantic.get((original_ea, spectron_ea))
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
                "source_component": "GSFunctionsInitstaticscriptvars and TFormat2 runtime",
                "target_component": "obfuscated giqpgaXJ_p Format2 runtime",
                "operation": reviewed["operation"],
                "proposed_name": reviewed["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-format2-residual-exact-anchor"
                if not differences
                else "manual-format2-residual-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": semantic_row is not None,
                "semantic_match_confidence": None if semantic_row is None else semantic_row.get("confidence"),
                "semantic_match_method": None if semantic_row is None else semantic_row.get("method"),
                "source_basis": "Hex-Rays pseudocode, normalized ARM64 feature metrics, and GSFunctionsInitstaticscriptvars/TFormat2 class-local order",
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_format2_residual_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual GSFunctionsInitstaticscriptvars and TFormat2 parameter block",
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
            "The raw HWyrga7_Nr entry is the GSFunctions script-function initializer because it performs the same count-37 registration immediately before the translated randomstring method.",
            "The raw giqpgaXJ_p methods form the remaining signed, unsigned, indexed, string, and destructor entries of the TFormat2_FormatParameters class-local block.",
            "The numeric accessors are exact normalized matches. The D1 and D0 rows differ only in the expected rebuilt string-wrapper register detail, while the two string accessors record the target's expanded wrapper conversion and cleanup layout.",
        ],
    }
    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in Format2 residual anchors")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
