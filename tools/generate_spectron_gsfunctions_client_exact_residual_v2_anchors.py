#!/usr/bin/env python3
"""Create the second reviewed exact-shape GSFunctionsClient batch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from generate_spectron_gsfunctions_client_exact_residual_anchors import (
    METRIC_FIELDS,
    by_ea,
    existing_manual_sources,
    load,
    metrics,
    sha256_path,
)


EVIDENCE = [
    "Each source row is a GSFunctionsClient callback referenced by a pointer field in the 1.8 client callback table.",
    "For every row in this batch, the corresponding Spectron table field is exactly the source field plus 0x13010, and it contains the proposed target function address.",
    "The rows cover shooting parameters, image and weapon state, mouse globals, URL and key helpers, file cleanup, and Adventure file operations. Their script-facing names provide the role, while the table relocation ties that role to the target callback.",
    "All normalized fingerprints match: size, instruction count, basic-block count, branch count, call count, mnemonic sequence, opcode shape, register shape, and overall shape.",
    "These are reviewed semantic correspondences, not claims that Spectron retained the original debug symbols. The v18_ prefix keeps the source role visible without replacing the target binary's identity.",
]


ROWS = (
    (0x157030, "GSFunctionsClient_script_setshootparams", 0x159E58, "sub_159E58", 0x37A200),
    (0x15706C, "GSFunctionsClient_get_statusimage", 0x159E94, "sub_159E94", 0x378B18),
    (0x1570A4, "GSFunctionsClient_get_spritesimage", 0x159ECC, "sub_159ECC", 0x378AE8),
    (0x1570DC, "GSFunctionsClient_script_adventure_getinstallationpath", 0x159F04, "sub_159F04", 0x378D60),
    (0x157110, "GSFunctionsClient_set_selectedweapon", 0x159F38, "sub_159F38", 0x378AC0),
    (0x157174, "GSFunctionsClient_set_selectedsword", 0x159F9C, "sub_159F9C", 0x378A90),
    (0x157650, "GSFunctionsClient_get_rightmousebuttonglobal", 0x15A478, "sub_15A478", 0x378848),
    (0x157670, "GSFunctionsClient_get_leftmousebuttonglobal", 0x15A498, "sub_15A498", 0x378788),
    (0x157748, "GSFunctionsClient_script_adventure_geteditaccountnames", 0x15A570, "sub_15A570", 0x378D30),
    (0x158378, "GSFunctionsClient_script_setsword", 0x15B208, "sub_15B208", 0x37A290),
    (0x1586E8, "GSFunctionsClient_script_setshield", 0x15B65C, "sub_15B65C", 0x37A140),
    (0x1588B4, "GSFunctionsClient_script_sendtorc", 0x15B828, "sub_15B828", 0x379F30),
    (0x158B80, "GSFunctionsClient_script_opengraalurl", 0x15BB2C, "sub_15BB2C", 0x379D20),
    (0x158E84, "GSFunctionsClient_script_keyname2", 0x15BE30, "sub_15BE30", 0x379A80),
    (0x158EA4, "GSFunctionsClient_script_keyname", 0x15BE50, "sub_15BE50", 0x379A50),
    (0x159550, "GSFunctionsClient_script_freefileresources", 0x15C4F8, "sub_15C4F8", 0x379660),
    (0x15986C, "GSFunctionsClient_script_adventure_requestfilesmove", 0x15C830, "sub_15C830", 0x3791E0),
    (0x159890, "GSFunctionsClient_script_adventure_requestfilerename", 0x15C854, "sub_15C854", 0x3791B0),
    (0x1598B4, "GSFunctionsClient_script_adventure_requestfolderdeletion", 0x15C878, "sub_15C878", 0x379180),
    (0x1598D0, "GSFunctionsClient_script_adventure_requestfiledeletion", 0x15C894, "sub_15C894", 0x379150),
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
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
    manual_source_eas = existing_manual_sources(args.artifact_root, args.output)

    anchors = []
    for order, (source_ea, source_name, target_ea, target_name, source_table_ea) in enumerate(ROWS, 1):
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != source_name:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != target_name:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas or source_ea in manual_source_eas:
            raise ValueError("source is already anchored at 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in METRIC_FIELDS)
        if not shape_equal:
            raise ValueError("unexpected GSFunctionsClient shape result at 0x%x" % source_ea)
        target_table_ea = source_table_ea + 0x13010
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_table_pointer_field": "0x%x" % source_table_ea,
                "spectron_ea": "0x%x" % target_ea,
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_table_pointer_field": "0x%x" % target_table_ea,
                "table_pointer_delta": "+0x13010",
                "table_pointer_value_verified": "0x%x" % target_ea,
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-gsfunctions-client-table-relocation-exact-shape-v2",
                "semantic_match_already_present": False,
                "source_basis": "GSFunctionsClient callback table role %s" % source["name"],
                "context_group": "GSFunctionsClient exact residual callback batch v2",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_gsfunctions_client_exact_residual_v2_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the second exact-shape GSFunctionsClient callback batch",
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
            "materialized_target_function_count": 0,
        },
        "context": {
            "source_table_range": "0x378788 through 0x37a290, with the rows kept in source table order",
            "target_table_range": "0x38b798 through 0x38d2a0, obtained by the verified +0x13010 relocation",
            "source_class": "GSFunctionsClient callback table",
            "target_class": "obfuscated Spectron GSFunctionsClient callback table",
            "coverage": "shooting, image and weapon state, mouse globals, URL and key helpers, file cleanup, and Adventure file operations",
            "following_work": "callbacks whose target code is merged into a neighboring function remain review-only until their raw boundaries are materialized",
        },
        "anchors": anchors,
        "interpretation": [
            "The table relocation is the primary correspondence and the normalized shape match is an independent check.",
            "The proposed v18_ labels preserve the readable 1.8 client roles while retaining the target names in the evidence rows.",
            "No target function boundaries were created in this batch because all twenty target addresses were already separate IDA functions.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
