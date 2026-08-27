#!/usr/bin/env python3
"""Create reviewed anchors for residual script math and string helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source rows are the GSFunctions script callbacks degtorad, radtodeg, the shared temporary-string clearer, compareIgnoreCase, uppercase, and lowercase. Their target roles occur at 0x210dc8, the code-pointer callback at 0x210df0, and 0x210fbc through 0x210ff0.",
    "The degtorad callback multiplies by pi and divides by 180. The radtodeg callback multiplies by 180 and divides by pi. Spectron keeps both six-instruction formulas and its script table points degtorad to 0x210dc8 and radtodeg to the raw code range 0x210df0-0x210e08.",
    "The target radtodeg body was not initially a function boundary in IDA. The script-table pointer, the adjacent literal pool, and the RET at 0x210e04 establish the explicit 24-byte range. The artifact records that boundary so the applier can materialize it before renaming.",
    "The shared clearer releases the same static TString used by the findpathinarray helper. The compareIgnoreCase jump forwards to the target C8THgaTQxF comparison routine, while uppercase and lowercase forward to the corresponding target string methods.",
    "All six pairs have identical size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape. Five target rows were default names before this batch; the compareIgnoreCase jump already had a non-default name.",
]


SOURCE_TARGETS = {
    0x20ABC8: 0x210DC8,
    0x20ABF0: 0x210DF0,
    0x20ADBC: 0x210FBC,
    0x20ADCC: 0x210FCC,
    0x20ADD0: 0x210FD0,
    0x20ADF0: 0x210FF0,
}

EXPECTED_SOURCE_NAMES = {
    0x20ABC8: "GSFunctionsInitstaticscriptvars_script_degtorad",
    0x20ABF0: "GSFunctionsInitstaticscriptvars_script_radtodeg",
    0x20ADBC: "sub_20ADBC",
    0x20ADCC: "jump_TString_compareIgnoreCase_TString_const",
    0x20ADD0: "GSFunctionsInitstaticscriptvars_script_uppercase",
    0x20ADF0: "GSFunctionsInitstaticscriptvars_script_lowercase",
}

EXPECTED_TARGET_NAMES = {
    0x210DC8: "sub_210DC8",
    0x210DF0: "sub_210DF0",
    0x210FBC: "sub_210FBC",
    0x210FCC: "j_._ZNK10C8THgaTQxF10nVCrgaSlRrERKS_",
    0x210FD0: "sub_210FD0",
    0x210FF0: "sub_210FF0",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(functions: list[dict]) -> dict[int, dict]:
    return {int(function["ea"], 16): function for function in functions}


def metrics(function: dict) -> dict:
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
        )
    }


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
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for order, (source_ea, target_ea) in enumerate(SOURCE_TARGETS.items(), 1):
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != EXPECTED_SOURCE_NAMES[source_ea]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != EXPECTED_TARGET_NAMES[target_ea]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        if not shape_equal:
            raise ValueError("unexpected GSFunctions shape result at 0x%x" % source_ea)
        row = {
            "original_ea": source["ea"],
            "original_name": source["name"],
            "original_metrics": metrics(source),
            "original_string_refs": source.get("string_refs", []),
            "original_direct_call_names": source.get("direct_call_names", []),
            "spectron_ea": "0x%x" % target_ea,
            "spectron_current_name": target["name"],
            "spectron_default_name": target.get("is_default_name", False),
            "spectron_metrics": metrics(target),
            "spectron_string_refs": target.get("string_refs", []),
            "spectron_direct_call_names": target.get("direct_call_names", []),
            "proposed_name": "v18_" + source["name"],
            "confidence": "high",
            "match_kind": "manual-gsfunctions-math-string-context-anchor",
            "semantic_match_already_present": False,
            "source_basis": "GSFunctions script callback %s" % source["name"],
            "context_group": "GSFunctions math and string residual callback block",
            "context_order": order,
            "target_delta": "+0x%x" % (target_ea - source_ea),
            "evidence": EVIDENCE,
            "name_action": "rename-with-v18-prefix",
            "shape_equal": shape_equal,
        }
        if target_ea == 0x210DF0:
            row["spectron_function_end"] = target["end_ea"]
            row["spectron_boundary_source"] = "script-table code pointer at 0x399f00 and raw RET at 0x210e04"
            row["boundary_materialization"] = "add-function-range-before-rename"
        anchors.append(row)

    result = {
        "schema_version": 1,
        "artifact": "spectron_gsfunctions_math_string_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual GSFunctions math and string callbacks",
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
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "layout_change_anchor_count": sum(not row["shape_equal"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "materialized_target_function_count": sum("spectron_function_end" in row for row in anchors),
        },
        "context": {
            "source_sequence": "0x20abc8 degtorad, 0x20abf0 radtodeg, 0x20adbc shared clearer, 0x20adcc compareIgnoreCase jump, and 0x20add0 through 0x20adf0 case conversion callbacks",
            "target_sequence": "0x210dc8 degtorad, 0x210df0 radtodeg raw range, and 0x210fbc through 0x210ff0 string helpers",
            "source_class": "GSFunctions script callback table",
            "target_class": "obfuscated target string and script helpers",
            "target_only_boundaries": ["0x210de0 through 0x210dec literal pool", "0x210e18 compareNearestPlayers already mapped"],
            "following_target_boundary": "0x211010 GSFunctions getcallstack helper already mapped",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source script roles while retaining the target obfuscated or default names in the evidence rows.",
            "The radtodeg target function is materialized from an independently reviewed script-table code pointer and explicit raw-code range before the alias is applied.",
            "All six pairs are exact normalized-shape matches. The five default target names include the newly materialized radtodeg boundary.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
