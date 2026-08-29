#!/usr/bin/env python3
"""Create reviewed role anchors for the next Spectron residual batch.

The four rows in this artifact are a JPEG marker-reader helper and three
General Polygon Clipper helpers.  The target names are analysis aliases.  They
are not claims that the stripped Spectron ELF retained the upstream names.
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
NORMALIZED_FIELDS = METRIC_FIELDS[:-1]


SPECS = (
    {
        "source_ea": "0xE0454",
        "target_ea": "0xDFAE4",
        "source_name": "examine_app14",
        "proposed_name": "v18_jpeg_examine_app14",
        "family": "libjpeg marker reader",
        "role": "examine_app14",
        "source_file": "jdmarker.c",
        "source_component": "JPEG decompressor marker reader",
        "target_component": "stripped Spectron JPEG decompressor marker reader",
        "operation": (
            "examines an APP14 Adobe marker, records the Adobe transform and "
            "marker flag in the decompressor state, and otherwise reports a "
            "non-Adobe APP14 marker"
        ),
        "source_basis": (
            "matching pseudocode, matching APP14 call sites in save_marker and "
            "get_interesting_appn, the official libjpeg-turbo jdmarker role, "
            "and exact ARM64 feature metrics"
        ),
        "reference": "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdmarker.c",
        "evidence": [
            "The source and target marker parsers call the candidate on the APP14 Adobe-marker path while the neighboring APP0 path calls examine_app0.",
            "The body reads the 12-byte APP14 payload, recognizes the ASCII Adobe signature, records the version, flags, and transform, and sets saw_Adobe_marker.",
            "The non-Adobe branch reports the APP14 marker without changing the Adobe state, matching the official jdmarker.c examine_app14 role.",
            "All recorded ARM64 feature metrics are exact, including the instruction, control-flow, call, string-reference, and register-detail fields.",
        ],
        "target_callers": [
            "v18_jpeg_save_marker at 0x29ac74",
            "v18_jpeg_get_interesting_appn at 0x29afac",
        ],
        "source_callers": [
            "save_marker at 0x28d804",
            "get_interesting_appn at 0x28db3c",
        ],
    },
    {
        "source_ea": "0x152200",
        "target_ea": "0x155028",
        "source_name": "free_sbtree",
        "proposed_name": "v18_gpc_free_sbtree",
        "family": "General Polygon Clipper scanbeam tree",
        "role": "free_sbtree",
        "source_file": "gpc.c",
        "source_component": "General Polygon Clipper scanbeam tree",
        "target_component": "stripped Spectron General Polygon Clipper scanbeam tree",
        "operation": (
            "recursively frees the less and more branches of a scanbeam tree "
            "and releases the tree nodes"
        ),
        "source_basis": (
            "matching recursively expanded pseudocode, matching GPC tree-node "
            "layout, the official gpc.c free_sbtree role, the shared 0x2e28 "
            "GPC-region displacement, and exact ARM64 feature metrics"
        ),
        "reference": "https://github.com/rickbrew/GeneralPolygonClipper/blob/main/gpc.c",
        "evidence": [
            "The source and target bodies recursively walk the two child pointers at node offsets 0x08 and 0x10, free each child, and clear the pointer after release.",
            "Both bodies then free the current node and clear the caller's root pointer, which is the official GPC free_sbtree contract.",
            "The source and target functions are in the same GPC region: target 0x155028 minus source 0x152200 equals 0x2e28, the displacement also used by the surrounding translated GPC routines.",
            "The compiler expanded the recursion into a large ARM64 body, but the complete feature metrics are exact.",
        ],
        "target_callers": [
            "v18_gpc_tristrip_clip_gpc_op_gpc_polygon_gpc_polygon_gpc_tristrip at 0x156544",
        ],
        "source_callers": [
            "gpc_tristrip_clip_gpc_op_gpc_polygon_gpc_polygon_gpc_tristrip at 0x15371c",
        ],
        "address_displacement": "0x2e28",
    },
    {
        "source_ea": "0x152898",
        "target_ea": "0x1556C0",
        "source_name": "build_sbt",
        "proposed_name": "v18_gpc_build_sbt",
        "family": "General Polygon Clipper scanbeam tree",
        "role": "build_sbt",
        "source_file": "gpc.c",
        "source_component": "General Polygon Clipper scanbeam tree",
        "target_component": "stripped Spectron General Polygon Clipper scanbeam tree",
        "operation": (
            "flattens the ordered scanbeam tree into the sorted scanbeam table "
            "while advancing the output entry count"
        ),
        "source_basis": (
            "matching in-order tree traversal pseudocode, matching GPC node "
            "layout, the official gpc.c build_sbt role, the shared 0x2e28 "
            "GPC-region displacement, and exact ARM64 feature metrics"
        ),
        "reference": "https://github.com/rickbrew/GeneralPolygonClipper/blob/main/gpc.c",
        "evidence": [
            "The source and target bodies visit the less subtree, write the current node's y value, increment the entry count, and then visit the more subtree.",
            "The target's unrolled depth-first loops and its fallback recursive call preserve the source build_sbt in-order traversal over the same three-field node layout.",
            "The source and target functions sit immediately before the translated gpc_build_lmt body at the same 0x2e28 GPC-region displacement.",
            "All recorded ARM64 feature metrics are exact, including the complete register-detail allocation.",
        ],
        "target_callers": [
            "v18_gpc_tristrip_clip_gpc_op_gpc_polygon_gpc_polygon_gpc_tristrip at 0x156544",
        ],
        "source_callers": [
            "gpc_tristrip_clip_gpc_op_gpc_polygon_gpc_polygon_gpc_tristrip at 0x15371c",
        ],
        "address_displacement": "0x2e28",
    },
    {
        "source_ea": "0xE01A0",
        "target_ea": "0xDF830",
        "source_name": "gpc_tristrip_node_malloc_failure",
        "proposed_name": "v18_gpc_tristrip_node_malloc_failure",
        "family": "General Polygon Clipper allocation diagnostics",
        "role": "tristrip node allocation failure path",
        "source_file": "gpc.c",
        "source_component": "General Polygon Clipper allocation macro path",
        "target_component": "stripped Spectron General Polygon Clipper allocation macro path",
        "operation": (
            "reports the GPC allocation failure for tristrip node creation and "
            "terminates the process"
        ),
        "source_basis": (
            "identical diagnostic string and exit behavior, matching call site "
            "in gpc_tristrip_clip, the official GPC MALLOC macro text, and "
            "normalized ARM64 feature metrics"
        ),
        "reference": "https://github.com/rickbrew/GeneralPolygonClipper/blob/main/gpc.c",
        "expected_differences": ["register_detail_hash"],
        "evidence": [
            "The source and target bodies are the same compiler-extracted failure path: fprintf writes gpc malloc failure: %s followed by tristrip node creation, then exit(0) terminates execution.",
            "The source and target gpc_tristrip_clip routines call the helper at the tristrip-node allocation failure site.",
            "This is a compiler-generated helper for the GPC MALLOC macro rather than a separately named upstream function, so the alias describes the literal failure role explicitly.",
            "All normalized ARM64 feature metrics match. The only recorded difference is register_detail_hash, which reflects allocation details rather than behavior.",
        ],
        "target_callers": [
            "v18_gpc_tristrip_clip_gpc_op_gpc_polygon_gpc_polygon_gpc_tristrip at 0x1567a0",
        ],
        "source_callers": [
            "gpc_tristrip_clip_gpc_op_gpc_polygon_gpc_polygon_gpc_tristrip at 0x153978",
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
        original = original_rows[spec["source_ea"].lower()]
        spectron = spectron_rows[spec["target_ea"].lower()]
        if not original.get("is_default_name"):
            raise ValueError(
                "source candidate is not a default name: %s" % spec["source_ea"]
            )
        if not spectron.get("is_default_name"):
            raise ValueError(
                "target candidate is not a default name: %s" % spec["target_ea"]
            )
        original_metrics = metrics(original)
        spectron_metrics = metrics(spectron)
        differences = [
            field
            for field in METRIC_FIELDS
            if original_metrics[field] != spectron_metrics[field]
        ]
        expected_differences = spec.get("expected_differences", [])
        if differences != expected_differences:
            raise ValueError(
                "unexpected metric differences for %s: %s"
                % (spec["role"], differences)
            )
        normalized_equal = all(
            original_metrics[field] == spectron_metrics[field]
            for field in NORMALIZED_FIELDS
        )
        if not normalized_equal:
            raise ValueError("normalized metrics do not match for %s" % spec["role"])
        anchor = {
            "original_ea": spec["source_ea"].lower(),
            "original_name": original["name"],
            "original_current_name": original["name"],
            "original_default_name": True,
            "original_metrics": original_metrics,
            "original_function_end": original.get("end_ea"),
            "original_string_refs": original.get("string_refs", []),
            "original_direct_call_names": original.get("direct_call_names", []),
            "spectron_ea": spec["target_ea"].lower(),
            "spectron_current_name": spectron["name"],
            "spectron_default_name": True,
            "spectron_metrics": spectron_metrics,
            "spectron_function_end": spectron.get("end_ea"),
            "spectron_string_refs": spectron.get("string_refs", []),
            "spectron_direct_call_names": spectron.get("direct_call_names", []),
            "proposed_name": spec["proposed_name"],
            "confidence": "high",
            "match_kind": "manual-jpeg-gpc-residual-role-anchor",
            "family": spec["family"],
            "source_name": spec["source_name"],
            "source_role": spec["role"],
            "source_file": spec["source_file"],
            "source_component": spec["source_component"],
            "target_component": spec["target_component"],
            "source_basis": spec["source_basis"],
            "operation": spec["operation"],
            "normalized_shape_equal": normalized_equal,
            "full_metric_equal": not differences,
            "metric_differences": differences,
            "semantic_match_already_present": False,
            "evidence": spec["evidence"],
            "reference_sources": [spec["reference"]],
            "name_action": "rename-with-v18-prefix",
            "target_callers": spec["target_callers"],
            "source_callers": spec["source_callers"],
        }
        if "address_displacement" in spec:
            anchor["address_displacement"] = spec["address_displacement"]
        anchors.append(anchor)

    result = {
        "schema_version": 1,
        "artifact": "spectron_jpeg_gpc_residual_manual_translation_anchors_20260828",
        "scope": (
            "reviewed 1.8-to-Spectron ARM64 anchors for the libjpeg APP14 "
            "marker examiner and General Polygon Clipper residual helpers"
        ),
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
            "source_jpeg_region": "0xE0454 through 0xE04D4",
            "target_jpeg_region": "0xDFAE4 through 0xDFB64",
            "source_gpc_regions": [
                "0x152200 through 0x152B0C",
                "0xE01A0 through 0xE01D0",
            ],
            "target_gpc_regions": [
                "0x155028 through 0x155934",
                "0xDF830 through 0xDF860",
            ],
            "gpc_address_displacement": "0x2e28",
            "role_resolution": (
                "matching pseudocode, caller topology, upstream source roles or "
                "literal macro diagnostics, and exact or normalized ARM64 feature metrics"
            ),
            "name_policy": (
                "v18-prefixed semantic role because every target candidate retained "
                "only an IDA auto-generated name"
            ),
            "reference_sources": [
                "https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdmarker.c",
                "https://github.com/rickbrew/GeneralPolygonClipper/blob/main/gpc.c",
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
            "register_detail_only_count": sum(
                anchor["metric_differences"] == ["register_detail_hash"]
                for anchor in anchors
            ),
            "jpeg_marker_reader_count": 1,
            "gpc_scanbeam_tree_count": 2,
            "gpc_allocation_diagnostic_count": 1,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed analysis aliases, not restored ELF debug symbols.",
            "The JPEG row is assigned from the APP14 call-site split and the official libjpeg-turbo marker-reader role.",
            "The two scanbeam rows are assigned from their exact GPC tree traversal and release behavior, while the failure row describes a compiler-extracted MALLOC diagnostic path.",
            "The three main GPC rows share the surrounding 0x2e28 cross-build displacement. The small diagnostic helper is outside that contiguous region but has the same literal body and call-site role.",
            "All four rows match normalized ARM64 shape. Three match the complete recorded feature set, while the diagnostic helper differs only in register-detail allocation.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
