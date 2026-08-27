#!/usr/bin/env python3
"""Create reviewed boundary-aware anchors for merged client callbacks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from generate_spectron_gsfunctions_client_exact_residual_anchors import (
    existing_manual_sources,
    load,
    sha256_path,
)


EVIDENCE = [
    "Each source row is a GSFunctionsClient callback referenced by a pointer field in the 1.8 client callback table.",
    "For every row, the corresponding Spectron table field is exactly the source field plus 0x13010, and it contains the target code pointer.",
    "The target addresses did not have IDA function records, so the saved ranges come from a raw ARM64 control-flow walk. Conditional branches reach every listed return, and tail branches leave the callback for an identified obfuscated helper.",
    "The adjacent target table pointer is recorded as a structural boundary check. It is not used as a substitute for decoding the target code range, since table order and code order are not always the same.",
    "These are reviewed semantic correspondences, not claims that Spectron retained the original debug symbols. The v18_ prefix keeps the source role visible without replacing the target binary's identity.",
]


ROWS = (
    {
        "source_ea": 0x156A78,
        "source_name": "GSFunctionsClient_get_focusy",
        "source_table_ea": 0x378518,
        "target_ea": 0x1598A0,
        "target_name": "loc_1598A0",
        "target_end": 0x159904,
        "next_target_table_ea": 0x38B558,
        "next_target_ea": 0x159910,
        "return_eas": (0x1598F0, 0x159900),
        "raw_instruction_count": 25,
        "boundary_basis": "CBZ split plus both cleanup RET paths at 0x1598f0 and 0x159900; the following table pointer is 0x159910",
    },
    {
        "source_ea": 0x156AE8,
        "source_name": "GSFunctionsClient_get_isfocused",
        "source_table_ea": 0x378548,
        "target_ea": 0x159910,
        "target_name": "loc_159910",
        "target_end": 0x15993C,
        "next_target_table_ea": 0x38B588,
        "next_target_ea": 0x159948,
        "return_eas": (0x159930, 0x159938),
        "raw_instruction_count": 11,
        "boundary_basis": "CBZ split plus the normal and zero-result RET paths at 0x159930 and 0x159938; the following table pointer is 0x159948",
    },
    {
        "source_ea": 0x156B20,
        "source_name": "GSFunctionsClient_get_ghostsnear",
        "source_table_ea": 0x378578,
        "target_ea": 0x159948,
        "target_name": "loc_159948",
        "target_end": 0x159968,
        "next_target_table_ea": 0x38B5B8,
        "next_target_ea": 0x159968,
        "return_eas": (0x15995C, 0x159964),
        "raw_instruction_count": 8,
        "boundary_basis": "CBZ split plus the byte-result and zero-result RET paths at 0x15995c and 0x159964; the next callback starts at 0x159968",
    },
    {
        "source_ea": 0x156C00,
        "source_name": "GSFunctionsClient_get_iscarrying",
        "source_table_ea": 0x378638,
        "target_ea": 0x159A28,
        "target_name": "loc_159A28",
        "target_end": 0x159A48,
        "next_target_table_ea": 0x38B678,
        "next_target_ea": 0x159A48,
        "return_eas": (0x159A3C, 0x159A44),
        "raw_instruction_count": 8,
        "boundary_basis": "CBZ split plus the byte-result and zero-result RET paths at 0x159a3c and 0x159a44; the next callback starts at 0x159a48",
    },
    {
        "source_ea": 0x156DB0,
        "source_name": "GSFunctionsClient_get_screenpixelscale",
        "source_table_ea": 0x3789F8,
        "target_ea": 0x159BD8,
        "target_name": "loc_159BD8",
        "target_end": 0x159BE0,
        "next_target_table_ea": 0x38BA38,
        "next_target_ea": 0x159BE0,
        "return_eas": (0x159BDC,),
        "raw_instruction_count": 2,
        "boundary_basis": "Two-instruction constant-return body ending at 0x159bdc; the following callback starts at 0x159be0",
    },
    {
        "source_ea": 0x157480,
        "source_name": "GSFunctionsClient_get_mousey",
        "source_table_ea": 0x378908,
        "target_ea": 0x15A2A8,
        "target_name": "loc_15A2A8",
        "target_end": 0x15A2C4,
        "next_target_table_ea": 0x38B948,
        "next_target_ea": 0x15A05C,
        "return_eas": (0x15A2C0,),
        "raw_instruction_count": 7,
        "boundary_basis": "CBZ split, external tail branch at 0x15a2b8, and local zero-result RET at 0x15a2c0",
    },
    {
        "source_ea": 0x157600,
        "source_name": "GSFunctionsClient_get_mousex",
        "source_table_ea": 0x3788D8,
        "target_ea": 0x15A428,
        "target_name": "loc_15A428",
        "target_end": 0x15A444,
        "next_target_table_ea": 0x38B918,
        "next_target_ea": 0x15A2A8,
        "return_eas": (0x15A440,),
        "raw_instruction_count": 7,
        "boundary_basis": "CBZ split, external tail branch at 0x15a438, and local zero-result RET at 0x15a440",
    },
    {
        "source_ea": 0x157C30,
        "source_name": "GSFunctionsClient_script_worldy",
        "source_table_ea": 0x37A4D0,
        "target_ea": 0x15AA58,
        "target_name": "loc_15AA58",
        "target_end": 0x15AAE8,
        "next_target_table_ea": 0x38D510,
        "next_target_ea": 0x15A5BC,
        "return_eas": (0x15AAE4,),
        "raw_instruction_count": 36,
        "boundary_basis": "Two coordinate conversion branches, two external tail calls, and the zero-result RET at 0x15aae4",
    },
    {
        "source_ea": 0x157CC8,
        "source_name": "GSFunctionsClient_script_worldx",
        "source_table_ea": 0x37A4A0,
        "target_ea": 0x15AAF0,
        "target_name": "loc_15AAF0",
        "target_end": 0x15AB40,
        "next_target_table_ea": 0x38D4E0,
        "next_target_ea": 0x15AA58,
        "return_eas": (0x15AB3C,),
        "raw_instruction_count": 20,
        "boundary_basis": "Coordinate conversion branches, two external tail calls, and the zero-result RET at 0x15ab3c",
    },
    {
        "source_ea": 0x157D20,
        "source_name": "GSFunctionsClient_script_adventure_uploadfile",
        "source_table_ea": 0x37A470,
        "target_ea": 0x15AB48,
        "target_name": "loc_15AB48",
        "target_end": 0x15AB64,
        "next_target_table_ea": 0x38D4B0,
        "next_target_ea": 0x15AAF0,
        "return_eas": (0x15AB60,),
        "raw_instruction_count": 7,
        "boundary_basis": "Null-check and external upload dispatch tail at 0x15ab5c followed by the local RET at 0x15ab60",
    },
    {
        "source_ea": 0x158958,
        "source_name": "GSFunctionsClient_script_screenx",
        "source_table_ea": 0x379ED0,
        "target_ea": 0x15B8D0,
        "target_name": "loc_15B8D0",
        "target_end": 0x15B950,
        "next_target_table_ea": 0x38CF10,
        "next_target_ea": 0x15B844,
        "return_eas": (0x15B928, 0x15B944),
        "raw_instruction_count": 32,
        "boundary_basis": "Two screen-coordinate return paths at 0x15b928 and 0x15b944 plus the null-client path at 0x15b948 that joins the local epilogue",
    },
    {
        "source_ea": 0x15A530,
        "source_name": "GSFunctionsClient_script_freezeplayer",
        "source_table_ea": 0x379690,
        "target_ea": 0x15D340,
        "target_name": "loc_15D340",
        "target_end": 0x15D3F4,
        "next_target_table_ea": 0x38C6D0,
        "next_target_ea": 0x15C454,
        "return_eas": (0x15D3B4,),
        "raw_instruction_count": 45,
        "boundary_basis": "Guarded freeze update, external action tail at 0x15d3a8, shared cleanup RET at 0x15d3b4, and the bounded loop branches through 0x15d3f0",
    },
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original = {
        int(row["ea"], 16): row
        for row in load(args.original_features)["functions"]
    }
    semantic_document = load(args.semantic_map)
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    manual_source_eas = existing_manual_sources(args.artifact_root, args.output)

    anchors = []
    for order, row in enumerate(ROWS, 1):
        source = original.get(row["source_ea"])
        if source is None:
            raise ValueError("missing source feature at 0x%x" % row["source_ea"])
        if source.get("name") != row["source_name"]:
            raise ValueError("unexpected source name at 0x%x" % row["source_ea"])
        if row["source_ea"] in semantic_source_eas or row["source_ea"] in manual_source_eas:
            raise ValueError("source is already anchored at 0x%x" % row["source_ea"])
        if row["target_ea"] in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % row["target_ea"])
        target_table_ea = row["source_table_ea"] + 0x13010
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_table_pointer_field": "0x%x" % row["source_table_ea"],
                "spectron_ea": "0x%x" % row["target_ea"],
                "spectron_current_name": row["target_name"],
                "spectron_default_name": False,
                "spectron_table_pointer_field": "0x%x" % target_table_ea,
                "table_pointer_delta": "+0x13010",
                "table_pointer_value_verified": "0x%x" % row["target_ea"],
                "spectron_function_end": "0x%x" % row["target_end"],
                "spectron_raw_range_size": row["target_end"] - row["target_ea"],
                "spectron_raw_instruction_count": row["raw_instruction_count"],
                "spectron_raw_return_eas": ["0x%x" % ea for ea in row["return_eas"]],
                "spectron_next_table_pointer_field": "0x%x" % row["next_target_table_ea"],
                "spectron_next_table_pointer_value": "0x%x" % row["next_target_ea"],
                "boundary_basis": row["boundary_basis"],
                "boundary_materialization": "add-function-range-before-rename",
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-gsfunctions-client-table-relocation-raw-boundary-v1",
                "semantic_match_already_present": False,
                "source_basis": "GSFunctionsClient callback table role %s" % source["name"],
                "context_group": "GSFunctionsClient merged callback boundary batch",
                "context_order": order,
                "target_delta": "+0x%x" % (row["target_ea"] - row["source_ea"]),
                "evidence": EVIDENCE,
                "name_action": "add-reviewed-function-range-and-rename",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_gsfunctions_client_boundary_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for GSFunctionsClient callbacks whose target code lacked IDA boundaries",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": 0,
            "materialized_target_function_count": len(anchors),
            "raw_boundary_anchor_count": len(anchors),
            "raw_return_count": sum(len(row["return_eas"]) for row in ROWS),
        },
        "context": {
            "source_table_range": "0x378518 through 0x37a4d0, with callbacks from several client script-table record clusters",
            "target_table_range": "0x38b528 through 0x38d4e0, obtained by the verified +0x13010 relocation",
            "source_class": "GSFunctionsClient callback table",
            "target_class": "obfuscated Spectron GSFunctionsClient callback table",
            "coverage": "focus, ghost, carry, pixel scale, mouse, world coordinates, upload, screen, and freeze callbacks",
            "boundary_method": "raw ARM64 control-flow walk with explicit return addresses, tail branches, and adjacent table-pointer checks",
            "following_work": "the client-table translation is complete after this batch; remaining unmatching functions require separate semantic review",
        },
        "anchors": anchors,
        "interpretation": [
            "The table relocation is the primary cross-build correspondence.",
            "The target ranges are materialized only after every conditional path and return address in the raw window was reviewed.",
            "The proposed v18_ labels preserve the readable 1.8 client roles while retaining the target names in the evidence rows.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
