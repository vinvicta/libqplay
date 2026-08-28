#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron libjpeg memory manager."""

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
NORMALIZED_FIELDS = (
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


SPECS = (
    {
        "source_ea": "0x292cf8",
        "target_ea": "0x2a0168",
        "role": "alloc_small",
        "method_index": 0,
        "target_install_sites": ["0x2a21e8", "0x2a21f0"],
        "operation": "allocates an aligned small object from a pool, creating a new pool with class-specific slop when existing pools cannot satisfy the request",
        "expected_differences": [
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
            "register_detail_hash",
        ],
        "layout_difference": True,
        "layout_difference_reason": "The source and target use different visible call targets for the small-object allocator, a PLT thunk in 1.8 and the retained target export in Spectron, while their decompiled allocation and pool logic is the same.",
        "target_context": "memory-manager method table index 0",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 0.",
            "The target body rounds the request for alignment, searches the small-pool list, creates a pool with first or extra slop when needed, and updates used and remaining bytes.",
            "The source and target have identical size, mnemonic, control-flow counts, and decompiled pool-allocation behavior; the recorded shape differences are isolated to the visible call and register layout.",
        ],
    },
    {
        "source_ea": "0x292ef8",
        "target_ea": "0x2a0368",
        "role": "alloc_large",
        "method_index": 9,
        "target_install_sites": ["0x2a2278", "0x2a2280"],
        "operation": "allocates a large object in a dedicated linked pool and records the allocation for later release",
        "expected_differences": [],
        "layout_difference": False,
        "target_context": "memory-manager method table index 9",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 9.",
            "The target body validates and aligns the request, obtains a large block, links its header into the selected pool, and updates total allocated space.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x293058",
        "target_ea": "0x2a04c8",
        "role": "alloc_sarray",
        "method_index": 1,
        "target_install_sites": ["0x2a21f8", "0x2a2200"],
        "operation": "allocates a two-dimensional sample array, grouping rows into large chunks and accounting for data precision",
        "expected_differences": [],
        "layout_difference": False,
        "target_context": "memory-manager method table index 1",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 1.",
            "The target body computes a safe rows-per-chunk value, allocates row pointers and sample storage, and handles the supported sample precisions.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x293168",
        "target_ea": "0x2a05d8",
        "role": "alloc_barray",
        "method_index": 7,
        "target_install_sites": ["0x2a2258", "0x2a2260"],
        "operation": "allocates a two-dimensional coefficient-block array with chunked row storage",
        "expected_differences": [],
        "layout_difference": False,
        "target_context": "memory-manager method table index 7",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 7.",
            "The target body computes the maximum chunk height, allocates row pointers and large coefficient blocks, and fills each row pointer with its chunk offset.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x293500",
        "target_ea": "0x2a0970",
        "role": "realize_virt_arrays",
        "method_index": 8,
        "target_install_sites": ["0x2a2268", "0x2a2270"],
        "operation": "allocates in-memory buffers for requested virtual sample and coefficient arrays and divides available memory among them",
        "expected_differences": [],
        "layout_difference": False,
        "target_context": "memory-manager method table index 8",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 8.",
            "The target body walks the virtual sample and coefficient lists, calculates minimum and maximum buffer heights, allocates the backing memory, and initializes virtual-array state.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x2938b0",
        "target_ea": "0x2a0d20",
        "role": "request_virt_sarray",
        "method_index": 4,
        "target_install_sites": ["0x2a2228", "0x2a2230"],
        "operation": "creates and links a virtual sample-array control block without realizing its in-memory buffer yet",
        "expected_differences": ["register_detail_hash"],
        "layout_difference": False,
        "target_context": "memory-manager method table index 4",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 4.",
            "The target body allocates the control block, records dimensions, access limits, pre-zero state, and links it into the virtual sample-array list.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x293acc",
        "target_ea": "0x2a0f3c",
        "role": "request_virt_barray",
        "method_index": 5,
        "target_install_sites": ["0x2a2238", "0x2a2240"],
        "operation": "creates and links a virtual coefficient-array control block without realizing its in-memory buffer yet",
        "expected_differences": ["register_detail_hash"],
        "layout_difference": False,
        "target_context": "memory-manager method table index 5",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 5.",
            "The target body records the coefficient-array dimensions, access limits, pre-zero state, and list linkage in the same control-block contract as the source.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x293ce8",
        "target_ea": "0x2a1158",
        "role": "access_virt_barray",
        "method_index": 10,
        "target_install_sites": ["0x2a2288", "0x2a2290"],
        "operation": "makes a requested coefficient-array strip accessible, reading backing storage or zeroing new rows as required",
        "expected_differences": [],
        "layout_difference": False,
        "target_context": "memory-manager method table index 10",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 10.",
            "The target body validates the requested range, swaps strips through backing storage when needed, zeroes newly exposed rows, marks writable buffers dirty, and returns the adjusted row pointer.",
            "The source and target functions have identical complete ARM64 feature metrics.",
        ],
    },
    {
        "source_ea": "0x293e50",
        "target_ea": "0x2a12c0",
        "role": "access_virt_sarray",
        "method_index": 2,
        "target_install_sites": ["0x2a2208", "0x2a2210"],
        "operation": "makes a requested sample-array strip accessible, reading backing storage or zeroing new rows as required",
        "expected_differences": ["register_detail_hash"],
        "layout_difference": False,
        "target_context": "memory-manager method table index 2",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 2.",
            "The target body validates the requested range, manages backing-store reads and writes, zeroes undefined rows when requested, marks writable data dirty, and returns the selected rows.",
            "The source and target normalized feature metrics match; only register allocation detail differs.",
        ],
    },
    {
        "source_ea": "0x2941d0",
        "target_ea": "0x2a1640",
        "role": "free_pool",
        "method_index": 3,
        "target_install_sites": ["0x2a2218", "0x2a2220"],
        "operation": "closes virtual-array backing stores for an image pool and releases every large and small allocation in that pool",
        "expected_differences": [
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
            "register_detail_hash",
        ],
        "layout_difference": True,
        "layout_difference_reason": "The source and target use different visible call targets for the small and large pool release operations, PLT thunks in 1.8 and retained target exports in Spectron, while their decompiled pool-release logic is the same.",
        "target_context": "memory-manager method table index 3",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 3.",
            "The target body closes virtual stores for the image pool, walks and frees large pools, then walks and frees small pools while updating total allocated space.",
            "The source and target have identical size, mnemonic, control-flow counts, and decompiled pool-release behavior; the recorded shape differences are isolated to the visible call and register layout.",
        ],
    },
    {
        "source_ea": "0x294534",
        "target_ea": "0x2a19a4",
        "role": "self_destruct",
        "method_index": 6,
        "target_install_sites": ["0x2a2248", "0x2a2250"],
        "operation": "releases all pools and virtual storage, frees the memory-manager object, clears the manager pointer, and terminates system-dependent memory state",
        "expected_differences": [],
        "layout_difference": False,
        "target_context": "memory-manager method table index 6",
        "evidence": [
            "The target memory-manager initializer stores this function in public method slot 6.",
            "The target body frees pools in reverse lifetime order, releases the manager control block, clears cinfo->mem, and calls jpeg_mem_term.",
            "The source and target functions have identical complete ARM64 feature metrics.",
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


def by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"].lower(): row for row in document["functions"]}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original_rows = by_ea(load(args.original_features))
    spectron_rows = by_ea(load(args.spectron_features))
    anchors = []
    for spec in SPECS:
        original = original_rows[spec["source_ea"]]
        spectron = spectron_rows[spec["target_ea"]]
        if not original.get("is_default_name"):
            raise ValueError("source candidate is not a default name: %s" % spec["source_ea"])
        if not spectron.get("is_default_name"):
            raise ValueError("target candidate is not a default name: %s" % spec["target_ea"])
        original_metrics = metrics(original)
        spectron_metrics = metrics(spectron)
        differences = [
            field
            for field in METRIC_FIELDS
            if original_metrics[field] != spectron_metrics[field]
        ]
        if differences != spec["expected_differences"]:
            raise ValueError(
                "unexpected metric differences for %s: %s"
                % (spec["role"], differences)
            )
        normalized_equal = all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        )
        if normalized_equal == spec["layout_difference"]:
            raise ValueError("unexpected normalized-shape state for %s" % spec["role"])
        anchors.append(
            {
                "original_ea": spec["source_ea"],
                "original_name": original["name"],
                "original_current_name": original["name"],
                "original_default_name": True,
                "original_metrics": original_metrics,
                "original_function_end": original.get("end_ea"),
                "original_string_refs": original.get("string_refs", []),
                "original_direct_call_names": original.get("direct_call_names", []),
                "spectron_ea": spec["target_ea"],
                "spectron_current_name": spectron["name"],
                "spectron_default_name": True,
                "spectron_metrics": spectron_metrics,
                "spectron_function_end": spectron.get("end_ea"),
                "spectron_string_refs": spectron.get("string_refs", []),
                "spectron_direct_call_names": spectron.get("direct_call_names", []),
                "proposed_name": "v18_jpeg_" + spec["role"],
                "confidence": "high",
                "match_kind": "manual-libjpeg-jmemmgr-role-anchor",
                "family": "libjpeg memory manager",
                "source_name": spec["role"],
                "source_role": spec["role"],
                "source_file": "jmemmgr.c",
                "source_component": "jinit_memory_mgr_jpeg_common_struct at 0x294d48",
                "target_component": "v18_jinit_memory_mgr_jpeg_common_struct at 0x2a21b8",
                "source_basis": "libjpeg %s body and memory-manager method installation"
                % spec["role"],
                "source_parent": "jinit_memory_mgr_jpeg_common_struct at 0x294d48",
                "target_parent": "v18_jinit_memory_mgr_jpeg_common_struct at 0x2a21b8",
                "target_context": spec["target_context"],
                "method_index": spec["method_index"],
                "target_install_sites": spec["target_install_sites"],
                "operation": spec["operation"],
                "normalized_shape_equal": normalized_equal,
                "full_metric_equal": not differences,
                "layout_change": spec["layout_difference"],
                "layout_difference_reason": spec.get("layout_difference_reason"),
                "metric_differences": differences,
                "semantic_match_already_present": False,
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_memory_manager_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for libjpeg jmemmgr memory-manager routines",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "source_controller": "jinit_memory_mgr_jpeg_common_struct at 0x294d48",
            "target_controller": "v18_jinit_memory_mgr_jpeg_common_struct at 0x2a21b8",
            "source_source_file": "jmemmgr.c",
            "target_source_file": "jmemmgr.c",
            "role_resolution": "standard libjpeg jmemmgr method contract, target method-table assignments, reviewed pseudocode, and complete or explicitly explained ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because both source and target functions retained default names",
            "reference_source": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jmemmgr.c",
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({a["spectron_ea"] for a in anchors}),
            "high_confidence_count": sum(a["confidence"] == "high" for a in anchors),
            "target_default_name_count": sum(a["spectron_default_name"] for a in anchors),
            "source_default_name_count": sum(a["original_default_name"] for a in anchors),
            "normalized_shape_exact_count": sum(a["normalized_shape_equal"] for a in anchors),
            "full_metric_exact_count": sum(a["full_metric_equal"] for a in anchors),
            "layout_difference_count": sum(a["layout_change"] for a in anchors),
            "register_detail_difference_count": sum(
                "register_detail_hash" in a["metric_differences"] for a in anchors
            ),
            "memory_manager_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed libjpeg role labels, not restored original debug symbols, because both source and target functions retained default names.",
            "The target memory-manager initializer preserves the source public method table and assigns the eleven allocation, virtual-array, pool, and teardown roles by slot.",
            "Nine rows match all normalized fields. Six rows also match register allocation detail. The two shape-difference rows retain identical decompiled pool logic and differ in the visible representation of allocator calls between the source PLT and target exports.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
