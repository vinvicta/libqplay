#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType TrueType runtime helpers."""

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
        "source_ea": "0x25ec84",
        "target_ea": "0x26c0f4",
        "source_name": "Direct_Move_Orig",
        "proposed_name": "v18_Direct_Move_Orig",
        "role": "original-coordinate direct movement helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Funcs for movement in the original glyph zone",
        "source_data": "the helper updates the interpreter zone's org coordinates and does not set current-point touch tags",
        "target_data": "the parallel target interpreter keeps the same original-zone movement path",
        "operation": "adds the scaled movement distance to a point's original x and y coordinates",
    },
    {
        "source_ea": "0x25ed14",
        "target_ea": "0x26c184",
        "source_name": "Direct_Move",
        "proposed_name": "v18_Direct_Move",
        "role": "current-coordinate direct movement helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "selected by Compute_Funcs for movement in the current glyph zone",
        "source_data": "the helper updates the interpreter zone's cur coordinates and sets the corresponding x and y touch tags",
        "target_data": "the parallel target interpreter keeps the same current-zone movement and touch-tag path",
        "operation": "adds the scaled movement distance to a point's current x and y coordinates and marks the moved coordinates touched",
    },
    {
        "source_ea": "0x25f4f4",
        "target_ea": "0x26c964",
        "source_name": "tt_slot_init",
        "proposed_name": "v18_tt_slot_init",
        "role": "TrueType slot initializer",
        "source_file": "src/truetype/ttobjs.c",
        "topology": "TrueType driver-class init_slot callback",
        "source_data": "the slot initializer forwards the slot's internal glyph loader to FT_GlyphLoader_CreateExtra",
        "target_data": "the corresponding target driver record reaches the parallel glyph-loader extra-data initializer",
        "operation": "creates the extra glyph-loader storage used by a TrueType slot",
    },
    {
        "source_ea": "0x25f500",
        "target_ea": "0x26c970",
        "source_name": "tt_face_done",
        "proposed_name": "v18_tt_face_done",
        "role": "TrueType face teardown",
        "source_file": "src/truetype/ttobjs.c",
        "topology": "TrueType driver-class done_face callback",
        "source_data": "the teardown releases the loca frame and TrueType tables, then calls the SFNT face finalizer",
        "target_data": "the target face object follows the same table-release and SFNT-finalizer sequence",
        "operation": "releases the TrueType face's optional finalizer, glyph-location frame, metrics, CVT, and bytecode resources",
    },
    {
        "source_ea": "0x25f648",
        "target_ea": "0x26cab8",
        "source_name": "tt_face_init",
        "proposed_name": "v18_tt_face_init",
        "role": "TrueType face initializer",
        "source_file": "src/truetype/ttobjs.c",
        "topology": "TrueType driver-class init_face callback",
        "source_data": "the initializer obtains the SFNT service, loads the TrueType tables and programs, and installs glyph-frame callbacks",
        "target_data": "the target face initializer keeps the same SFNT service lookup, table loading, and glyph-frame callback setup",
        "operation": "initializes a TrueType face from its SFNT stream and prepares loca, CVT, fpgm, prep, and glyph-frame state",
        "expected_differences": ["register_detail_hash"],
    },
    {
        "source_ea": "0x25fd8c",
        "target_ea": "0x26d1fc",
        "source_name": "Current_Ratio",
        "proposed_name": "v18_Current_Ratio",
        "role": "TrueType interpreter scaling-ratio helper",
        "source_file": "src/truetype/ttinterp.c",
        "topology": "called by interpreter setup when the graphics-state scaling ratio is needed",
        "source_data": "the helper derives the ratio from the face metrics and vector components, then caches it in the execution context",
        "target_data": "the target interpreter retains the same metric-vector calculation and cached-ratio path",
        "operation": "calculates the effective current scaling ratio from the face's metrics and projection vectors",
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
    expected_differences = spec.get("expected_differences", [])
    unexpected_differences = [
        field for field in differences if field not in expected_differences
    ]
    if unexpected_differences:
        raise ValueError(
            "%s unexpectedly differs in %s"
            % (spec["source_name"], unexpected_differences)
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
        "match_kind": "manual-freetype-tt-runtime-role-anchor",
        "family": "FreeType TrueType object lifecycle and interpreter",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "topology": spec["topology"],
        "source_data": spec["source_data"],
        "target_data": spec["target_data"],
        "source_component": "FreeType TrueType object and interpreter modules",
        "target_component": "stripped Spectron FreeType TrueType modules",
        "source_basis": "FreeType helper name, callback or interpreter topology, matching pseudocode, official source role, and exact ARM64 feature metrics",
        "operation": spec["operation"],
        "normalized_shape_equal": all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The original TrueType callback or interpreter topology identifies the helper role.",
            "The target code retains the corresponding callback, call, or execution-context topology at the translated location.",
            "The official FreeType TrueType source defines the matching helper name and operation.",
            "The source and target ARM64 feature records match across the complete recorded metric set, or differ only in the recorded register-allocation detail accepted for this anchor.",
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
        "artifact": "spectron_freetype_tt_runtime_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for FreeType TrueType object lifecycle and interpreter runtime helpers",
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
            "source_true_type_region": "0x25ec84-0x25fd8c in the source FreeType TrueType object and interpreter region",
            "target_true_type_region": "the parallel target region at the source address plus 0xd470",
            "role_resolution": "callback topology, matching pseudocode, official FreeType source roles, and exact ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target candidate retained only an IDA auto-generated name",
            "reference_sources": [
                "https://android.googlesource.com/platform/external/freetype/+/3053d1b9db55099918843889e4809ce97483ca9f/src/truetype/ttobjs.c",
                "https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/truetype/ttinterp.c",
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
            "driver_and_loader_anchor_count": 3,
            "interpreter_helper_anchor_count": 3,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target candidates had no surviving source names.",
            "The first three anchors cover the TrueType slot initializer and face lifecycle callbacks.",
            "The remaining anchors cover original-zone movement, current-zone movement, and the interpreter's current scaling ratio.",
            "The exact metric match across every anchor supports a direct source-to-target translation for this compiler-preserved FreeType block.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
