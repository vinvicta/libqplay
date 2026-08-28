#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's FreeType base cleanup helpers."""

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
        "source_ea": "0x250e94",
        "target_ea": "0x25e304",
        "source_name": "destroy_size",
        "proposed_name": "v18_destroy_size",
        "role": "destroy_size",
        "source_file": "src/base/ftobjs.c",
        "source_callers": [
            "destroy_face at 0x252e90 via FT_List_Finalize",
            "FT_Done_Face at 0x253508 via size-list teardown",
        ],
        "target_callers": [
            "destroy_face candidate at 0x260300 via FT_List_Finalize",
            "v18_FT_Done_Face at 0x260978 via size-list teardown",
        ],
        "operation": "runs the size finalizer and driver size destructor, then frees the size internal state and size object",
        "expected_differences": [],
    },
    {
        "source_ea": "0x252e90",
        "target_ea": "0x260300",
        "source_name": "destroy_face",
        "proposed_name": "v18_destroy_face",
        "role": "destroy_face",
        "source_file": "src/base/ftobjs.c",
        "source_callers": [
            "FT_Done_Face in ftobjs.c",
            "FT_Remove_Module at 0x252fd0",
        ],
        "target_callers": [
            "v18_FT_Done_Face at 0x260978",
            "v18_FT_Remove_Module at 0x260440",
        ],
        "operation": "destroys a FreeType face by releasing glyph slots, sizes, client and driver data, the stream, internal storage, and the face object",
        "expected_differences": ["register_detail_hash"],
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
            "%s unexpected metric differences: %s"
            % (spec["source_name"], differences)
        )
    normalized_equal = all(
        original_metrics[field] == spectron_metrics[field]
        for field in NORMALIZED_FIELDS
    )
    if not normalized_equal:
        raise ValueError("%s normalized metrics do not match" % spec["source_name"])

    return {
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
        "proposed_name": spec["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-freetype-base-cleanup-role-anchor",
        "family": "FreeType base cleanup",
        "source_name": spec["source_name"],
        "source_role": spec["role"],
        "source_file": spec["source_file"],
        "source_component": "FreeType base object lifecycle in ftobjs.c",
        "target_component": "stripped Spectron FreeType base object lifecycle",
        "source_basis": "FreeType %s static helper body and caller relationships"
        % spec["source_name"],
        "source_callers": spec["source_callers"],
        "target_callers": spec["target_callers"],
        "operation": spec["operation"],
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "semantic_match_already_present": False,
        "evidence": [
            "The official FreeType Donut ftobjs.c source gives this exact static helper name and cleanup role.",
            "The source and target pseudocode match in field offsets, callback dispatch, allocation cleanup, and return behavior.",
            "The target caller relationships preserve the same lifecycle use through the corresponding public face and glyph-slot routines.",
            "The source and target normalized ARM64 feature metrics match; any recorded difference is limited to compiler register allocation detail.",
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
        "artifact": "spectron_freetype_base_cleanup_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for two internal FreeType base cleanup helpers",
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
            "source_functions": "sub_250E94 and sub_252E90 in the original 1.8 FreeType base block",
            "target_functions": "sub_25E304 and sub_260300 in the stripped Spectron FreeType base block",
            "source_file": "src/base/ftobjs.c",
            "role_resolution": "official FreeType Donut source, matching pseudocode, matching caller relationships, and ARM64 feature metrics",
            "name_policy": "v18-prefixed semantic role because each target retained only an IDA auto-generated name",
            "reference_source": "https://android.googlesource.com/platform/external/freetype/+/donut-release/src/base/ftobjs.c",
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
            "register_detail_difference_count": sum(
                "register_detail_hash" in anchor["metric_differences"]
                for anchor in anchors
            ),
            "freetype_base_cleanup_role_count": len(anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed FreeType role labels, not restored original debug symbols, because the target static helpers had no surviving source names.",
            "destroy_size is the size-list destructor passed to FT_List_Finalize; its three-argument signature and size-internal cleanup distinguish it from the glyph-slot lifecycle helpers.",
            "destroy_face is the face-object destructor used by FT_Done_Face and driver/module teardown; it passes destroy_size to FT_List_Finalize while releasing the rest of the face state.",
            "The source and target normalized bodies match. The only non-normalized difference in this batch is target register allocation detail for destroy_face.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
