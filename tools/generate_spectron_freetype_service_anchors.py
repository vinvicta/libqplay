#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType SFNT service callbacks."""

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
NORMALIZED_FIELDS = METRIC_FIELDS[:-1]


SPECS = (
    {
        "source_ea": "0x254b98",
        "target_ea": "0x262008",
        "source_name": "tt_get_cmap_info",
        "proposed_name": "v18_tt_get_cmap_info",
        "role": "TT cmap information service callback",
        "source_file": "src/sfnt/ttcmap.c",
        "service_slot": "tt-cmaps.get_cmap_info",
        "source_data": "tt_service_get_cmap_info callback at 0x35e4c0",
        "target_data": "corresponding TT cmap service callback at 0x371240",
        "operation": "dispatches the TrueType cmap information request to the active cmap class",
        "expected_differences": [],
    },
    {
        "source_ea": "0x2579b4",
        "target_ea": "0x264e24",
        "source_name": "sfnt_get_ps_name",
        "proposed_name": "v18_sfnt_get_ps_name",
        "role": "PostScript font-name service callback",
        "source_file": "src/sfnt/sfdriver.c",
        "service_slot": "postscript-font-name.get_ps_font_name",
        "source_data": "sfnt_service_ps_name callback at 0x35e4c8",
        "target_data": "corresponding PostScript-name service callback in the stripped target",
        "operation": "returns the cached PostScript name or constructs it from the font name table",
        "expected_differences": [],
    },
    {
        "source_ea": "0x25663c",
        "target_ea": "0x263aac",
        "source_name": "tt_face_load_any",
        "proposed_name": "v18_tt_face_load_any",
        "role": "generic SFNT table loader",
        "source_file": "src/sfnt/ttload.c",
        "service_slot": "sfnt-table.load_table",
        "source_data": "sfnt_service_sfnt_table.load_table at 0x35e4d0",
        "target_data": "corresponding SFNT table-service load slot",
        "operation": "resolves a font table or the whole font file and reads the requested byte range",
        "expected_differences": [],
    },
    {
        "source_ea": "0x254d80",
        "target_ea": "0x2621f0",
        "source_name": "get_sfnt_table",
        "proposed_name": "v18_get_sfnt_table",
        "role": "SFNT in-memory table accessor",
        "source_file": "src/sfnt/sfdriver.c",
        "service_slot": "sfnt-table.get_table",
        "source_data": "sfnt_service_sfnt_table.get_table at 0x35e4d8",
        "target_data": "corresponding SFNT table-service get slot",
        "operation": "maps public SFNT table tags to the corresponding fields in the TrueType face object",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x25796c",
        "target_ea": "0x264ddc",
        "source_name": "sfnt_table_info",
        "proposed_name": "v18_sfnt_table_info",
        "role": "SFNT table-directory information callback",
        "source_file": "src/sfnt/sfdriver.c",
        "service_slot": "sfnt-table.table_info",
        "source_data": "sfnt_service_sfnt_table.table_info at 0x35e4e0",
        "target_data": "corresponding SFNT table-service info slot",
        "operation": "reports the table count or returns a directory entry's tag, offset, and length",
        "expected_differences": [],
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


def build_anchor(original: dict, spectron: dict, spec: dict) -> dict:
    original_metrics = metrics(original)
    spectron_metrics = metrics(spectron)
    differences = [
        field
        for field in METRIC_FIELDS
        if original_metrics[field] != spectron_metrics[field]
    ]
    if differences != spec["expected_differences"]:
        raise ValueError(
            "%s unexpectedly differs in %s (expected %s)"
            % (spec["source_name"], differences, spec["expected_differences"])
        )

    return {
        "original_ea": spec["source_ea"],
        "original_name": original["name"],
        "original_current_name": original["name"],
        "original_default_name": original.get("is_default_name", False),
        "original_metrics": original_metrics,
        "original_function_end": original.get("end_ea"),
        "original_string_refs": original.get("string_refs", []),
        "original_direct_call_names": original.get("direct_call_names", []),
        "spectron_ea": spec["target_ea"],
        "spectron_current_name": spectron["name"],
        "spectron_default_name": spectron.get("is_default_name", False),
        "spectron_metrics": spectron_metrics,
        "spectron_function_end": spectron.get("end_ea"),
        "spectron_string_refs": spectron.get("string_refs", []),
        "spectron_direct_call_names": spectron.get("direct_call_names", []),
        "proposed_name": spec["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-freetype-sfnt-service-role-anchor",
        "family": "FreeType SFNT services",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "service_slot": spec["service_slot"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType SFNT driver and cmap service layer",
        "target_component": "stripped Spectron FreeType SFNT service layer",
        "source_basis": "FreeType static helper name, service slot, and matching function body",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The original data records place these callbacks in the tt-cmaps, postscript-font-name, and sfnt-table service slots.",
            "The official FreeType SFNT sources define the corresponding helper names and service field roles.",
            "The source and target pseudocode match in dispatch, table selection, stream access, and return behavior.",
            "All normalized ARM64 feature metrics match; the only recorded variation is register allocation detail in get_sfnt_table.",
        ],
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original_by_ea = by_ea(load(args.original_features))
    spectron_by_ea = by_ea(load(args.spectron_features))
    anchors = []
    for spec in SPECS:
        original = original_by_ea[spec["source_ea"]]
        spectron = spectron_by_ea[spec["target_ea"]]
        if not original.get("is_default_name"):
            raise ValueError("source candidate is not a default name")
        if not spectron.get("is_default_name"):
            raise ValueError("target candidate is not a default name")
        anchors.append(build_anchor(original, spectron, spec))

    result = {
        "schema_version": 1,
        "artifact": "spectron_freetype_sfnt_service_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for five internal FreeType SFNT service callbacks",
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
            "source_data_window": "0x35e4c0 through 0x35e4e0 contains the three service records; the descriptors at 0x35e480 identify sfnt-table, postscript-font-name, and tt-cmaps",
            "target_data_window": "0x371240 through 0x371260 is the corresponding stripped service-record area",
            "role_resolution": "service-slot mapping, official FreeType source roles, matching pseudocode, and exact ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/75b4fbd0462ad4544ffc447213777d1f0d536c1a/src/sfnt/sfdriver.c",
                "https://android.googlesource.com/platform/external/freetype/+/f720f0db/src/sfnt/ttcmap.c",
                "https://android.googlesource.com/platform/external/freetype/+/3053d1b9db55099918843889e4809ce97483ca9f/src/sfnt/ttload.c",
                "https://android.googlesource.com/platform/external/freetype/+/79eda7da453415f23a3c6c6ddab2227389a180f0/include/freetype/internal/services/svttcmap.h",
            ],
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len({anchor["spectron_ea"] for anchor in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(
                anchor["spectron_default_name"] for anchor in anchors
            ),
            "source_default_name_count": sum(
                anchor["original_default_name"] for anchor in anchors
            ),
            "normalized_shape_exact_count": sum(
                anchor["normalized_shape_equal"] for anchor in anchors
            ),
            "full_metric_exact_count": sum(
                anchor["full_metric_equal"] for anchor in anchors
            ),
            "service_slot_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target callbacks had no surviving source names.",
            "The five functions are not a single class record. They are callbacks referenced by the SFNT service descriptors and are resolved by their service slots.",
            "tt_get_cmap_info forwards the public cmap information request to the active cmap class, while sfnt_get_ps_name owns PostScript-name construction and caching.",
            "tt_face_load_any, get_sfnt_table, and sfnt_table_info form the three operations of the SFNT table service object.",
            "The source and target bodies have identical normalized feature metrics in this batch; get_sfnt_table differs only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
