#!/usr/bin/env python3
"""Create reviewed anchors for the remaining GSFunctions callbacks.

The source and target script tables retain the same callback order even
though the target names are stripped or obfuscated.  This generator records
that table-order evidence together with normalized function-shape results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source rows are the remaining GSFunctions callbacks from the 1.8 script table: getstringkeys, callnpc, getmapx, getmapy, getimgwidth, getimgheight, clearemptyglobalvars, arcsin, arccos, aindexof, echo, trace, and findpathinarray.",
    "The source table records these callbacks in the order aindexof, arccos, arcsin, callnpc, clearemptyglobalvars, contains, copystrings, degtorad, radtodeg, echo, trace, the nearest-player helpers, getimgheight, getimgwidth, getmapx, getmapy, and the later lookup helpers. Spectron preserves the same order in its target table, with the already translated callbacks providing fixed landmarks.",
    "The target table places getstringkeys at 0x2111d8, callnpc at 0x211908, getmapx at 0x211580, getmapy at 0x2114b0, getimgwidth at 0x211610, getimgheight at 0x211654, clearemptyglobalvars at 0x2118f0, arcsin at 0x211ad4, arccos at 0x211afc, aindexof at 0x211b24, echo at 0x211b3c, trace at 0x211f2c, and findpathinarray at 0x21224c.",
    "The getstringkeys target was not initially assigned an IDA function boundary. Its script-table code pointer is at 0x39a290, the body begins at 0x2111d8, all cleanup branches return within the block, and the next table callback begins at 0x211424. The reviewed range is therefore 0x2111d8 through 0x211424.",
    "The small callbacks getimgwidth, getimgheight, clearemptyglobalvars, arcsin, arccos, aindexof, echo, and trace have identical normalized size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape. The larger callbacks preserve the table role and control-flow neighborhood but grow or change helper calls in the stripped build.",
    "The getstringkeys body still derives a prefix from the requested name, walks the active script variable hash, filters visible matching entries, sorts the resulting names, and returns a script string list. callnpc still checks the action NPC and universe bounds, extracts the requested script name, and invokes the selected NPC. findpathinarray still builds a profiler-scoped array while walking the supplied path data; its target body grows from 2,348 to 2,524 bytes.",
]


SOURCE_TARGETS = {
    0x20AFD8: 0x2111D8,
    0x20B268: 0x211908,
    0x20B404: 0x211580,
    0x20B460: 0x2114B0,
    0x20B4F8: 0x211610,
    0x20B53C: 0x211654,
    0x20B7D8: 0x2118F0,
    0x20B7F0: 0x211AD4,
    0x20B818: 0x211AFC,
    0x20B840: 0x211B24,
    0x20B858: 0x211B3C,
    0x20BC48: 0x211F2C,
    0x20BF6C: 0x21224C,
}


EXPECTED_SOURCE_NAMES = {
    0x20AFD8: "GSFunctionsInitstaticscriptvars_script_getstringkeys",
    0x20B268: "GSFunctionsInitstaticscriptvars_script_callnpc",
    0x20B404: "GSFunctionsInitstaticscriptvars_script_getmapx",
    0x20B460: "GSFunctionsInitstaticscriptvars_script_getmapy",
    0x20B4F8: "GSFunctionsInitstaticscriptvars_script_getimgwidth",
    0x20B53C: "GSFunctionsInitstaticscriptvars_script_getimgheight",
    0x20B7D8: "GSFunctionsInitstaticscriptvars_script_clearemptyglobalvars",
    0x20B7F0: "GSFunctionsInitstaticscriptvars_script_arcsin",
    0x20B818: "GSFunctionsInitstaticscriptvars_script_arccos",
    0x20B840: "GSFunctionsInitstaticscriptvars_script_aindexof",
    0x20B858: "GSFunctionsInitstaticscriptvars_script_echo",
    0x20BC48: "GSFunctionsInitstaticscriptvars_script_trace",
    0x20BF6C: "GSFunctionsInitstaticscriptvars_script_findpathinarray",
}


EXPECTED_TARGET_NAMES = {
    0x2111D8: "sub_2111D8",
    0x211908: "sub_211908",
    0x211580: "sub_211580",
    0x2114B0: "sub_2114B0",
    0x211610: "sub_211610",
    0x211654: "sub_211654",
    0x2118F0: "sub_2118F0",
    0x211AD4: "sub_211AD4",
    0x211AFC: "sub_211AFC",
    0x211B24: "sub_211B24",
    0x211B3C: "sub_211B3C",
    0x211F2C: "sub_211F2C",
    0x21224C: "sub_21224C",
}


EXACT_SHAPE_SOURCE_EAS = {
    0x20B4F8,
    0x20B53C,
    0x20B7D8,
    0x20B7F0,
    0x20B818,
    0x20B840,
    0x20B858,
    0x20BC48,
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
        expected_shape_equal = source_ea in EXACT_SHAPE_SOURCE_EAS
        if shape_equal != expected_shape_equal:
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
            "match_kind": "manual-gsfunctions-callback-table-context-anchor",
            "semantic_match_already_present": False,
            "source_basis": "GSFunctions script callback %s" % source["name"],
            "context_group": "GSFunctions callback table residual block",
            "context_order": order,
            "target_delta": "+0x%x" % (target_ea - source_ea),
            "evidence": EVIDENCE,
            "name_action": "rename-with-v18-prefix",
            "shape_equal": shape_equal,
        }
        if target_ea == 0x2111D8:
            row["spectron_function_end"] = target["end_ea"]
            row["spectron_boundary_source"] = "script-table code pointer at 0x39a290, cleanup branches, and next callback boundary at 0x211424"
            row["boundary_materialization"] = "add-function-range-before-rename"
        anchors.append(row)

    result = {
        "schema_version": 1,
        "artifact": "spectron_gsfunctions_callback_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining GSFunctions callbacks",
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
            "source_sequence": "0x20afd8 getstringkeys, 0x20b268 callnpc, 0x20b404 and 0x20b460 map coordinate helpers, 0x20b4f8 and 0x20b53c image dimensions, 0x20b7d8 through 0x20b840 small string helpers, 0x20b858 echo, 0x20bc48 trace, and 0x20bf6c findpathinarray",
            "target_sequence": "0x2111d8 getstringkeys raw boundary, 0x211908 callnpc, 0x211580 and 0x2114b0 map coordinate helpers, 0x211610 and 0x211654 image dimensions, 0x2118f0 through 0x211b24 small string helpers, 0x211b3c echo, 0x211f2c trace, and 0x21224c findpathinarray",
            "source_class": "GSFunctions script callback table",
            "target_class": "obfuscated target string, script, player, and path helpers",
            "target_only_boundaries": ["0x2111d8 through 0x211424 getstringkeys range was materialized", "0x212c30 copystrings already mapped"],
            "following_target_boundary": "0x212c30 copystrings already mapped in the later table block",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source script roles while retaining the target default names in the evidence rows.",
            "The target getstringkeys range is materialized from its script-table pointer and explicit control-flow boundary before the alias is applied.",
            "Eight pairs have exact normalized shape. The five layout-change pairs are still high-confidence table-order correspondences because the surrounding script-table landmarks and behavior agree.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
