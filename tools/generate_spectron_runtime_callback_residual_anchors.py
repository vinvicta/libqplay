#!/usr/bin/env python3
"""Create reviewed anchors for the next small Spectron callback families.

This pass covers the four TStream callbacks that complete the target
``zlib_filefunc_def_s`` adapter, plus the default zlib and YAJL allocator
callbacks. The source and target bodies have identical recorded metrics. The
callback contracts and the target installation sites are kept in the artifact
so the names do not depend on address proximity alone.
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
        "family": "TStream zlib file callbacks",
        "original_ea": "0xf04ec",
        "original_name": "TStream_zipOpenFile",
        "target_ea": "0xf19c8",
        "target_name": "nullsub_2",
        "source_role": "zopen_file callback",
        "target_slot": "0x00",
        "evidence": [
            "The 1.8 native callback inventory assigns TStream_zipOpenFile to the zopen_file slot at offset 0.",
            "The target v18_TStream_fillZipFunctions_zlib_filefunc_def_s body stores nullsub_2 in the first callback slot at 0xf2374.",
            "Both callback bodies are the one-instruction no-op that preserves the opaque stream handle contract.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
        ],
    },
    {
        "family": "TStream zlib file callbacks",
        "original_ea": "0xf04f0",
        "original_name": "TStream_zipTellFile",
        "target_ea": "0xf19cc",
        "target_name": "sub_F19CC",
        "source_role": "ztell_file callback",
        "target_slot": "0x18",
        "evidence": [
            "The 1.8 native callback inventory assigns TStream_zipTellFile to the ztell_file slot at offset 24.",
            "The target fill function stores sub_F19CC at offset 0x18, and the target body returns the current stream position from the supplied state object.",
            "The target callback is referenced only by the target zlib adapter at 0xf2374, which supplies an independent installation-site identity check.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
        ],
    },
    {
        "family": "TStream zlib file callbacks",
        "original_ea": "0xf0548",
        "original_name": "TStream_zipCloseFile",
        "target_ea": "0xf1a24",
        "target_name": "sub_F1A24",
        "source_role": "zclose_file callback",
        "target_slot": "0x28",
        "evidence": [
            "The 1.8 native callback inventory assigns TStream_zipCloseFile to the zclose_file slot at offset 40.",
            "The target fill function stores sub_F1A24 at offset 0x28.",
            "The target body returns zero without taking ownership of the stream, matching the zlib close-callback contract.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
        ],
    },
    {
        "family": "TStream zlib file callbacks",
        "original_ea": "0xf0550",
        "original_name": "TStream_zipErrorFile",
        "target_ea": "0xf1a2c",
        "target_name": "sub_F1A2C",
        "source_role": "zerror_file callback",
        "target_slot": "0x30",
        "evidence": [
            "The 1.8 native callback inventory assigns TStream_zipErrorFile to the zerror_file slot at offset 48.",
            "The target fill function stores sub_F1A2C at offset 0x30.",
            "The target body returns zero, indicating no stream error, matching the source callback role.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
        ],
    },
    {
        "family": "zlib allocator callbacks",
        "original_ea": "0x289b80",
        "original_name": "zlib_zcalloc",
        "target_ea": "0x296ff0",
        "target_name": "sub_296FF0",
        "source_role": "zcalloc",
        "target_slot": "z_stream.opaque and zalloc",
        "evidence": [
            "The source static-library role audit identifies zlib_zcalloc as the default zcalloc callback implemented with malloc(items * size).",
            "The target body returns malloc(a2 * a3), and v18_deflateInit2 and v18_inflateInit2 install it when no custom allocator is present.",
            "The target installation sites write the callback address into the zlib allocator field, providing a direct role check.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
        ],
    },
    {
        "family": "zlib allocator callbacks",
        "original_ea": "0x289b88",
        "original_name": "zlib_zcfree",
        "target_ea": "0x296ff8",
        "target_name": "sub_296FF8",
        "source_role": "zcfree",
        "target_slot": "z_stream.zfree",
        "evidence": [
            "The source static-library role audit identifies zlib_zcfree as the default zcfree callback implemented with free(pointer).",
            "The target body forwards the supplied pointer to free, and v18_deflateInit2 and v18_inflateInit2 install it in the zfree field.",
            "The target installation sites are independent of the function-size match and identify the allocator role directly.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
        ],
    },
    {
        "family": "YAJL allocator callbacks",
        "original_ea": "0x2af788",
        "original_name": "yajl_internal_realloc",
        "target_ea": "0x2bcd0c",
        "target_name": "sub_2BCD0C",
        "source_role": "YAJL realloc callback",
        "target_slot": "yajl_alloc_funcs.realloc",
        "evidence": [
            "The source static-library role audit identifies yajl_internal_realloc as the allocator callback that calls realloc on the supplied pointer and size.",
            "The target v18_yajl_set_default_alloc_funcs_yajl_alloc_funcs routine stores sub_2BCD0C in the realloc slot at 0x2bcd44.",
            "The target body moves the pointer and size arguments into the platform realloc call and returns its result.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
        ],
    },
    {
        "family": "YAJL allocator callbacks",
        "original_ea": "0x2af794",
        "original_name": "yajl_internal_free",
        "target_ea": "0x2bcd18",
        "target_name": "sub_2BCD18",
        "source_role": "YAJL free callback",
        "target_slot": "yajl_alloc_funcs.free",
        "evidence": [
            "The source static-library role audit identifies yajl_internal_free as the allocator callback that calls free on the supplied pointer.",
            "The target v18_yajl_set_default_alloc_funcs_yajl_alloc_funcs routine stores sub_2BCD18 in the free slot at 0x2bcd38.",
            "The target body forwards the supplied pointer to free and ignores the allocator context.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
        ],
    },
    {
        "family": "YAJL allocator callbacks",
        "original_ea": "0x2af79c",
        "original_name": "yajl_internal_malloc",
        "target_ea": "0x2bcd20",
        "target_name": "sub_2BCD20",
        "source_role": "YAJL malloc callback",
        "target_slot": "yajl_alloc_funcs.malloc",
        "evidence": [
            "The source static-library role audit identifies yajl_internal_malloc as the allocator callback that calls malloc on the requested size.",
            "The target v18_yajl_set_default_alloc_funcs_yajl_alloc_funcs routine stores sub_2BCD20 in the malloc slot at 0x2bcd28.",
            "The target body forwards the requested byte count to malloc and ignores the allocator context.",
            "The complete recorded ARM64 metrics are identical across the source and target functions.",
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


def by_ea(document: dict) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in document["functions"]}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--native-callback-artifact", required=True, type=Path)
    parser.add_argument("--static-library-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original = by_ea(load(args.original_features))
    spectron = by_ea(load(args.spectron_features))
    semantic = load(args.semantic_map)
    semantic_sources = {
        int(row["original_ea"], 16) for row in semantic.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        source_ea = int(spec["original_ea"], 16)
        target_ea = int(spec["target_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % spec["original_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("unexpected source name at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("unexpected target name at %s" % spec["target_ea"])
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("callback is already in the broad semantic map at %s" % spec["target_ea"])
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        if source_metrics != target_metrics:
            raise ValueError("unexpected metric difference at %s" % spec["target_ea"])
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": source["name"],
                "original_function_end": source["end_ea"],
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["target_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_function_end": target["end_ea"],
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "family": spec["family"],
                "source_role": spec["source_role"],
                "target_installation_slot": spec["target_slot"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-runtime-callback-exact-anchor",
                "exact_metric_match": True,
                "source_basis": "%s: %s" % (spec["family"], spec["source_role"]),
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "semantic_match_already_present": False,
            }
        )

    target_eas = [row["spectron_ea"] for row in anchors]
    if len(set(target_eas)) != len(target_eas):
        raise ValueError("duplicate target callback in residual runtime anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_runtime_callback_residual_manual_translation_anchors_20260828",
        "scope": "reviewed exact-shape TStream, zlib, and YAJL callback anchors for Spectron",
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
            "native_callback_artifact": str(args.native_callback_artifact),
            "native_callback_artifact_sha256": sha256_path(args.native_callback_artifact),
            "static_library_artifact": str(args.static_library_artifact),
            "static_library_artifact_sha256": sha256_path(args.static_library_artifact),
        },
        "context": {
            "tstream_target_fill_function": "0xf2374",
            "tstream_target_callback_slots": "zopen=0x00, zread=0x08, zwrite=0x10, ztell=0x18, zseek=0x20, zclose=0x28, zerror=0x30",
            "zlib_target_installers": ["0x290edc v18_deflateInit2", "0x291484 v18_inflateInit2"],
            "yajl_target_install_function": "0x2bcd28 v18_yajl_set_default_alloc_funcs_yajl_alloc_funcs",
            "translation_boundary": "These are exact source-role callbacks with independent target installation-site evidence. The v18_ prefix identifies the readable source role while the target's current name and address remain in each row.",
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len(set(target_eas)),
            "high_confidence_count": len(anchors),
            "exact_metric_match_count": sum(row["exact_metric_match"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "tstream_count": sum(row["family"] == "TStream zlib file callbacks" for row in anchors),
            "zlib_count": sum(row["family"] == "zlib allocator callbacks" for row in anchors),
            "yajl_count": sum(row["family"] == "YAJL allocator callbacks" for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "The TStream names come from the callback slots populated by the target zlib adapter, not from address order alone.",
            "The zlib and YAJL names are source-role aliases supported by the target allocator installation sites and complete metric equality.",
            "All rows are high-confidence exact metric matches, and no row overlaps the broad semantic map.",
            "The addresses are valid only for the exact hashed Spectron library named in this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
