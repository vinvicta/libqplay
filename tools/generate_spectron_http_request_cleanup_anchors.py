#!/usr/bin/env python3
"""Create reviewed anchors for request cleanup and properties destructors."""

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
)


ANCHOR_SPECS = (
    {
        "original_ea": 0x1FF40C,
        "original_name": "THTTPRequest_clearRequest_void",
        "spectron_ea": 0x204D5C,
        "spectron_name": "_ZN10ZAuvgaUl6u10zs2GHaFGPmEv",
        "source_basis": "HTTP request cleanup and reset",
        "target_class": "ZAuvgaUl6u",
        "lifecycle_role": "request cleanup",
        "context_order": 1,
        "match_kind": "manual-http-request-cleanup-layout-context-anchor",
    },
    {
        "original_ea": 0x2029D0,
        "original_name": "THTTPRequestProperties_THTTPRequestProperties",
        "spectron_ea": 0x208248,
        "spectron_name": "_ZN20ZAuvgaUl6uPropertiesD2Ev",
        "source_basis": "THTTPRequestProperties complete destructor",
        "target_class": "ZAuvgaUl6uProperties",
        "lifecycle_role": "complete destructor",
        "context_order": 2,
        "match_kind": "manual-http-request-properties-exact-shape-anchor",
    },
    {
        "original_ea": 0x2029EC,
        "original_name": "non_virtual_thunk_to_THTTPRequestProperties_THTTPRequestProperties",
        "spectron_ea": 0x208264,
        "spectron_name": "_ZThn16_N20ZAuvgaUl6uPropertiesD1Ev",
        "source_basis": "THTTPRequestProperties complete-destructor non-virtual thunk",
        "target_class": "ZAuvgaUl6uProperties",
        "lifecycle_role": "complete destructor thunk",
        "context_order": 3,
        "match_kind": "manual-http-request-properties-exact-shape-anchor",
    },
    {
        "original_ea": 0x2029F4,
        "original_name": "THTTPRequestProperties_THTTPRequestProperties__2",
        "spectron_ea": 0x20826C,
        "spectron_name": "_ZN20ZAuvgaUl6uPropertiesD0Ev",
        "source_basis": "THTTPRequestProperties deleting destructor",
        "target_class": "ZAuvgaUl6uProperties",
        "lifecycle_role": "deleting destructor",
        "context_order": 4,
        "match_kind": "manual-http-request-properties-exact-shape-anchor",
    },
    {
        "original_ea": 0x202A2C,
        "original_name": "non_virtual_thunk_to_THTTPRequestProperties_THTTPRequestProperties__2",
        "spectron_ea": 0x2082A4,
        "spectron_name": "_ZThn16_N20ZAuvgaUl6uPropertiesD0Ev",
        "source_basis": "THTTPRequestProperties deleting-destructor non-virtual thunk",
        "target_class": "ZAuvgaUl6uProperties",
        "lifecycle_role": "deleting destructor thunk",
        "context_order": 5,
        "match_kind": "manual-http-request-properties-exact-shape-anchor",
    },
)


EVIDENCE = [
    "The source request cleanup calls the keep-alive check, releases the request socket, removes the data variable from the request hash list, clears the response stream, resets counters and flags, and restores the request string fields to empty values.",
    "The target ZAuvgaUl6u method at 0x204d5c preserves the same field offsets for the request socket, variable table, response stream, flags, counters, and string fields. It performs the same data-variable removal and reset sequence through KKhLga4xoI, J7zOgaf09K, nenvgaH9_u, and C8THgaTQxF helpers.",
    "The source cleanup is 488 bytes, 122 instructions, 12 basic blocks, 36 branches, and 29 calls. The target is 480 bytes, 120 instructions, 11 basic blocks, 34 branches, and 28 calls. The preserved offsets and cleanup responsibilities establish the role despite this small implementation change.",
    "The source THTTPRequestProperties names are constructor-like because of the original IDA naming convention. The source body at 0x2029d0 is the complete D2 destructor, and the source body at 0x2029f4 is the deleting D0 destructor. The target keeps the explicit ZAuvgaUl6uProperties D2 and D0 ABI names.",
    "The two source non-virtual thunks subtract 16 from the adjusted this pointer and forward to the corresponding properties destructor. The target D1 and D0 thunk bodies preserve that ABI adjustment and match the complete normalized shape.",
    "The four properties destructor rows are adjacent in both databases and share exact size, instruction, block, branch, call, return, mnemonic, opcode, register, normalized-shape, and string-reference metrics.",
]


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
    return {field: function.get(field) for field in METRIC_FIELDS}


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
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        source_ea = spec["original_ea"]
        target_ea = spec["spectron_ea"]
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at 0x%x" % source_ea)
        if target.get("name") != spec["spectron_name"]:
            raise ValueError(
                "target name mismatch at 0x%x: expected %s, got %s"
                % (target_ea, spec["spectron_name"], target.get("name"))
            )
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("HTTP cleanup row is already in the semantic map")

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        shape_equal = source_metrics == target_metrics
        if spec["context_order"] > 1 and not shape_equal:
            raise ValueError("properties destructor shape mismatch at 0x%x" % source_ea)
        if spec["context_order"] == 1:
            if shape_equal:
                raise ValueError("request cleanup unexpectedly has an exact shape")
            if "data" not in source.get("string_refs", []) or "data" not in target.get("string_refs", []):
                raise ValueError("request cleanup must retain the data string")
        elif shape_equal is not True:
            raise ValueError("properties destructor unexpectedly changed shape")

        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": "0x%x" % target_ea,
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": spec["match_kind"],
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_class": spec["target_class"],
                "lifecycle_role": spec["lifecycle_role"],
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_http_request_cleanup_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for HTTP request cleanup and request-properties destructor ABI methods",
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
        },
        "context": {
            "source_request_cleanup": "0x1ff40c",
            "spectron_request_cleanup": "0x204d5c",
            "source_properties_cluster": "0x2029d0 through 0x202a34",
            "spectron_properties_cluster": "0x208248 through 0x2082ac",
            "target_classes": {
                "ZAuvgaUl6u": "HTTP request object",
                "ZAuvgaUl6uProperties": "HTTP request properties object",
                "u3cBgayBVz": "request socket connection object",
                "c76BgaJBGA": "properties base object",
            },
            "layout_change": "The request cleanup is eight bytes and two instructions shorter in Spectron, with one fewer block, two fewer branches, and one fewer direct call. The properties destructor family is exact across the normalized feature set.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The request cleanup label is a high-confidence layout-context match based on field offsets, the data-variable removal, and the complete reset sequence.",
            "The source constructor-like properties names are preserved in the proposed aliases, while lifecycle_role records the D2, D0, and adjusted-this thunk meanings visible in both IDA databases.",
            "The target methods already have obfuscated C++ names, so this batch adds readable overlays without changing the default sub-function count.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
