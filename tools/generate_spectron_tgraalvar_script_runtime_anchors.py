#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for TGraalVar script callbacks.

These callbacks live in the script-function tables rather than in ordinary
class method tables. Four target bodies retain the complete source shape. The
addnamedstring callback was rebuilt around the target string wrapper and is
recorded as a layout-change anchor with its table evidence.
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
        "original_ea": "0x20d26c",
        "original_name": "TGraalVar_script_clearvars",
        "original_table_record": "0x3875b0",
        "original_callback_xref": "0x3875c8",
        "spectron_ea": "0x21362c",
        "spectron_name": "sub_21362C",
        "spectron_table_record": "0x39a700",
        "spectron_callback_xref": "0x39a718",
        "script_name": "clearvars",
        "source_owner": "TGraalVarProperties_TGraalVarProperties_void",
        "target_class": "G0gxgajWBw",
        "source_basis": "TGraalVar script clearvars callback",
        "evidence": [
            "The source callback is registered as clearvars in the TGraalVar script table and its table callback cell is 0x3875c8.",
            "The target callback cell at 0x39a718 points directly to sub_21362C in the corresponding target script table.",
            "Both bodies are an exact eight-instruction forwarding wrapper through virtual slot +56, with identical recorded ARM64 metrics and hashes.",
        ],
    },
    {
        "original_ea": "0x20d4dc",
        "original_name": "TGraalVar_script_savejsontostring",
        "original_table_record": "0x387b80",
        "original_callback_xref": "0x387b98",
        "spectron_ea": "0x2137ec",
        "spectron_name": "sub_2137EC",
        "spectron_table_record": "0x39acd0",
        "spectron_callback_xref": "0x39ace8",
        "script_name": "savejsontostring",
        "source_owner": "TGraalVarProperties_TGraalVarProperties_void",
        "target_class": "G0gxgajWBw",
        "source_basis": "TGraalVar script JSON serialization callback",
        "evidence": [
            "The source callback is registered as savejsontostring in the TGraalVar script table and calls TGraalVar::writeJSON with the incoming mode.",
            "The target callback cell at 0x39ace8 points to sub_2137EC, which calls the retained target writeJSON method at 0x2385E0.",
            "The source and target wrappers have identical recorded metrics and hashes, including the one-block, eight-instruction shape.",
        ],
    },
    {
        "original_ea": "0x20d500",
        "original_name": "TGraalVar_script_parsejson",
        "original_table_record": "0x387d00",
        "original_callback_xref": "0x387d18",
        "spectron_ea": "0x213810",
        "spectron_name": "sub_213810",
        "spectron_table_record": "0x39ae50",
        "spectron_callback_xref": "0x39ae68",
        "script_name": "parsejson",
        "source_owner": "TGraalVar_initStaticScriptVars_void",
        "target_class": "G0gxgajWBw",
        "source_basis": "TGraalVar script JSON parsing callback",
        "evidence": [
            "The source callback is registered as parsejson and conditionally forwards to TGraalVar::readJSON.",
            "The target callback cell at 0x39ae68 points to sub_213810, which conditionally forwards to the target readJSON method at 0x237DC0.",
            "The source and target wrappers have identical recorded metrics and hashes, including the same twelve-byte, three-instruction body.",
        ],
    },
    {
        "original_ea": "0x20d50c",
        "original_name": "TGraalVar_script_loadini",
        "original_table_record": "0x3879a0",
        "original_callback_xref": "0x3879b8",
        "spectron_ea": "0x21381c",
        "spectron_name": "sub_21381C",
        "spectron_table_record": "0x39aaf0",
        "spectron_callback_xref": "0x39ab08",
        "script_name": "loadini",
        "source_owner": "TGraalVarProperties_TGraalVarProperties_void",
        "target_class": "G0gxgajWBw",
        "source_basis": "TGraalVar script INI loading callback",
        "evidence": [
            "The source callback is registered as loadini and forwards to readIniFromFile with the constant enabled flag 1.",
            "The target callback cell at 0x39ab08 points to sub_21381C, which forwards to the target eU79LaTf87 INI helper with the same constant flag.",
            "The source and target wrappers have identical recorded metrics and hashes, including the same eight-byte, two-instruction body.",
        ],
    },
    {
        "original_ea": "0x20d3e8",
        "original_name": "TGraalVar_script_addnamedstring",
        "original_table_record": "0x3874f0",
        "original_callback_xref": "0x387508",
        "spectron_ea": "0x2138b0",
        "spectron_name": "sub_2138B0",
        "spectron_table_record": "0x39a610",
        "spectron_callback_xref": "0x39a628",
        "script_name": "addnamedstring",
        "source_owner": "TGraalVarProperties_TGraalVarProperties_void",
        "target_class": "G0gxgajWBw",
        "source_basis": "TGraalVar script named-string construction callback",
        "evidence": [
            "The source callback is registered as addnamedstring and obtains a variable through virtual slot +288 before assigning the supplied string to result offset +8.",
            "The target callback cell at 0x39a628 points to sub_2138B0 and sits in the same ordered TGraalVar callback block immediately after the target addarraymember row.",
            "The target body performs the same virtual variable lookup and result assignment, but first constructs and clears a target CanTfaz6bZ temporary from a third name argument. This explains the growth from 72 to 120 bytes and the changed call set.",
            "The 14-byte target table name at the adjacent record decodes to addnamedstring, providing an independent identity anchor for the layout-changed body.",
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


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_sources = {
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % spec["original_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["spectron_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
        if not target.get("is_default_name"):
            raise ValueError("target is not a default IDA name at %s" % spec["spectron_ea"])
        if original_ea in semantic_sources or spectron_ea in semantic_targets:
            raise ValueError("script-runtime row is already in the semantic map")

        source_metrics = metric_record(source)
        target_metrics = metric_record(target)
        exact = source_metrics == target_metrics
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_script_table_record": spec["original_table_record"],
                "original_callback_xref": spec["original_callback_xref"],
                "spectron_ea": spec["spectron_ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_script_table_record": spec["spectron_table_record"],
                "spectron_callback_xref": spec["spectron_callback_xref"],
                "script_name": spec["script_name"],
                "source_owner": spec["source_owner"],
                "target_class": spec["target_class"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": (
                    "manual-tgraalvar-script-runtime-exact-anchor"
                    if exact
                    else "manual-tgraalvar-script-runtime-layout-anchor"
                ),
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "exact_metric_match": exact,
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate target in TGraalVar script-runtime anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tgraalvar_script_runtime_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TGraalVar script callbacks",
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
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": sum(row["exact_metric_match"] for row in anchors),
            "layout_change_anchor_count": sum(not row["exact_metric_match"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "original_script_tables": ["0x3874c0", "0x387d00"],
            "spectron_script_table_region": "0x39a610 through 0x39ae68",
            "target_class": "G0gxgajWBw, the obfuscated TGraalVar class family",
            "translation_boundary": "Four rows are exact metric matches. addnamedstring is a high-confidence layout anchor because the target adds a named-string temporary and a third argument.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not a claim that the stripped target retained original debug names.",
            "The addresses are valid only for the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 callback names while keeping target table records and obfuscated names in the evidence rows.",
            "The four exact rows are short forwarding wrappers whose complete normalized metric records agree across builds.",
            "The addnamedstring row relies on table identity, callback order, target pseudocode, and the target-only string-wrapper construction. Its changed layout is recorded rather than hidden.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
