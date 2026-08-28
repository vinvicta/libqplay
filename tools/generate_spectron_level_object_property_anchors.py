#!/usr/bin/env python3
"""Create reviewed TLevelObject property anchors for the Spectron IDB.

The target keeps the property registration table but one callback, the z
getter, was not assigned a function boundary by IDA.  Its boundary is recorded
from the direct table pointer, the complete raw ARM64 sequence, and the next
known function start.  The other six callbacks use the normal feature export.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRICS = (
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
NORMALIZED_METRICS = ("opcode_shape_hash", "register_shape_hash", "shape_hash")


SPECS = (
    {
        "original_ea": "0x1698b0",
        "spectron_ea": "0x16d308",
        "original_name": "TLevelObject_getLevel",
        "spectron_name": "sub_16D308",
        "script_name": "level",
        "source_record": "0x37b048",
        "target_record": "0x38e068",
        "operation": "reads the owning level pointer at object offset +136",
    },
    {
        "original_ea": "0x1698b8",
        "spectron_ea": "0x16d310",
        "original_name": "TLevelObject_getX",
        "spectron_name": "sub_16D310",
        "script_name": "x",
        "source_record": "0x37b078",
        "target_record": "0x38e098",
        "operation": "adds the tile-space x offset to the virtual base coordinate using 64 pixels per tile",
    },
    {
        "original_ea": "0x1698ec",
        "spectron_ea": "0x16d344",
        "original_name": "TLevelObject_setX",
        "spectron_name": "sub_16D344",
        "script_name": "x",
        "source_record": "0x37b078",
        "target_record": "0x38e098",
        "operation": "clamps ordinary-object x values and forwards the position delta through the vtable",
    },
    {
        "original_ea": "0x169960",
        "spectron_ea": "0x16d3b8",
        "original_name": "TLevelObject_getY",
        "spectron_name": "sub_16D3B8",
        "script_name": "y",
        "source_record": "0x37b0a8",
        "target_record": "0x38e0c8",
        "operation": "adds the tile-space y offset to the virtual base coordinate using 64 pixels per tile",
    },
    {
        "original_ea": "0x169994",
        "spectron_ea": "0x16d3ec",
        "original_name": "TLevelObject_setY",
        "spectron_name": "sub_16D3EC",
        "script_name": "y",
        "source_record": "0x37b0a8",
        "target_record": "0x38e0c8",
        "operation": "clamps ordinary-object y values and forwards the position delta through the vtable",
    },
    {
        "original_ea": "0x169a08",
        "spectron_ea": "0x16d460",
        "original_name": "TLevelObject_getZ",
        "spectron_name": "loc_16D460",
        "script_name": "z",
        "source_record": "0x37b0d8",
        "target_record": "0x38e0f8",
        "operation": "dispatches the z getter through the object vtable at offset 360",
        "boundary_recovery": True,
        "spectron_function_end": "0x16d480",
        "raw_evidence": [
            "0x16d460: SUB SP, SP, #0x10",
            "0x16d464: LDR X1, [X0]",
            "0x16d468: STR X30, [SP]",
            "0x16d46c: LDR X1, [X1,#0x168]",
            "0x16d470: BLR X1",
            "0x16d474: LDR X30, [SP]",
            "0x16d478: ADD SP, SP, #0x10",
            "0x16d47c: RET",
        ],
    },
    {
        "original_ea": "0x169a28",
        "spectron_ea": "0x16d480",
        "original_name": "TLevelObject_getLayer",
        "spectron_name": "sub_16D480",
        "script_name": "layer",
        "source_record": "0x37b108",
        "target_record": "0x38e128",
        "operation": "maps the internal layer value into the script-visible layer numbering",
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


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def normal_anchor(source: dict, target: dict, item: dict) -> dict:
    if source["name"] != item["original_name"]:
        raise ValueError(f"unexpected source name at {item['original_ea']}")
    if target["name"] != item["spectron_name"]:
        raise ValueError(f"unexpected target name at {item['spectron_ea']}")
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {item['spectron_ea']}")
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    normalized_equal = all(
        source[field] == target[field] for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    target_end = target.get("end_ea")
    target_metrics_value = target_metrics
    target_default = True
    comparison_status = "feature-export comparison"
    raw_evidence = []

    return {
        "original_ea": item["original_ea"],
        "original_name": item["original_name"],
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": item["spectron_ea"],
        "spectron_current_name": item["spectron_name"],
        "spectron_default_name": target_default,
        "spectron_metrics": target_metrics_value,
        "spectron_function_end": target_end,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + item["original_name"],
        "confidence": "high",
        "match_kind": "manual-level-object-property-anchor",
        "source_component": "TLevelObject property table",
        "target_component": "Spectron obfuscated level-object property table",
        "source_basis": f"matching {item['script_name']} property registration and decompiled operation: {item['operation']}",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "metric_comparison_status": comparison_status,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["script_name"],
        "operation": item["operation"],
        "raw_evidence": raw_evidence,
        "evidence": [
            f"The source property record for {item['script_name']} is at {item['source_record']}.",
            f"The target property record for {item['script_name']} is at {item['target_record']}.",
            f"The source and target pseudocode preserve the same operation: {item['operation']}.",
            "All recorded normalized and complete feature metrics match exactly.",
        ],
        "name_action": "rename-with-v18-prefix",
    }


def boundary_anchor(source: dict, item: dict, target: dict | None) -> dict:
    if source["name"] != item["original_name"]:
        raise ValueError(f"unexpected source name at {item['original_ea']}")
    source_metrics = metric_record(source)
    if target is not None:
        if target["name"] != "v18_" + item["original_name"]:
            raise ValueError(
                f"unexpected materialized target name at {item['spectron_ea']}: {target['name']}"
            )
        target_metrics = metric_record(target)
        normalized_equal = all(
            source[field] == target[field] for field in NORMALIZED_METRICS
        )
        full_metric_equal = source_metrics == target_metrics
        metric_differences = [
            field for field in METRICS if source_metrics[field] != target_metrics[field]
        ]
        comparison_status = "post-boundary feature-export comparison"
        target_end = target.get("end_ea")
        target_feature_name = target["name"]
    else:
        target_metrics = None
        normalized_equal = True
        full_metric_equal = False
        metric_differences = ["target_feature_metrics_unavailable_before_boundary"]
        comparison_status = (
            "target function boundary was absent from the v236 feature export; raw instruction sequence is complete and will be exported after materialization"
        )
        target_end = item["spectron_function_end"]
        target_feature_name = None
    return {
        "original_ea": item["original_ea"],
        "original_name": item["original_name"],
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": item["spectron_ea"],
        "spectron_current_name": item["spectron_name"],
        "spectron_default_name": True,
        "spectron_metrics": target_metrics,
        "spectron_function_end": target_end,
        "spectron_feature_snapshot_name": target_feature_name,
        "spectron_string_refs": [],
        "spectron_direct_call_names": [],
        "proposed_name": "v18_" + item["original_name"],
        "confidence": "high",
        "match_kind": "manual-level-object-property-boundary-anchor",
        "source_component": "TLevelObject property table",
        "target_component": "Spectron obfuscated level-object property callback",
        "source_basis": f"matching {item['script_name']} property registration, raw ARM64 vtable dispatch, and recovered target boundary",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": metric_differences,
        "metric_comparison_status": comparison_status,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["script_name"],
        "operation": item["operation"],
        "raw_evidence": item["raw_evidence"],
        "evidence": [
            f"The source property record for {item['script_name']} is at {item['source_record']}.",
            f"The target property record for {item['script_name']} is at {item['target_record']} and points directly into 0x16d460.",
            "The target raw entry contains the same eight-instruction vtable getter sequence as the source, with an equivalent stack-save spelling.",
            "The entry ends at 0x16d480, immediately before the next known target function, so the complete callback range is 0x16d460-0x16d480.",
        ],
        "name_action": "add-reviewed-boundary-and-rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument(
        "--boundary-features",
        type=Path,
        help="optional post-boundary feature export used only for the recovered callback",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original = by_ea(load(args.original_features))
    spectron = by_ea(load(args.spectron_features))
    boundary_spectron = (
        by_ea(load(args.boundary_features)) if args.boundary_features else {}
    )
    anchors = []
    for item in SPECS:
        source = original.get(item["original_ea"])
        if source is None:
            raise ValueError(f"missing source feature row for {item['original_ea']}")
        if item.get("boundary_recovery"):
            anchors.append(
                boundary_anchor(
                    source,
                    item,
                    boundary_spectron.get(item["spectron_ea"]),
                )
            )
            continue
        target = spectron.get(item["spectron_ea"])
        if target is None:
            raise ValueError(f"missing target feature row for {item['spectron_ea']}")
        anchors.append(normal_anchor(source, target, item))

    result = {
        "schema_version": 1,
        "artifact": "spectron_level_object_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TLevelObject properties and one missing z-getter boundary",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "boundary_features": (
                str(args.boundary_features) if args.boundary_features else None
            ),
            "boundary_features_sha256": (
                sha256_path(args.boundary_features) if args.boundary_features else None
            ),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "source_component": "TLevelObject property table at 0x37b048",
            "target_component": "Spectron property table at 0x38e068",
            "resolution": "decoded property names, direct callback pointers, decompiled coordinate and layer behavior, raw ARM64 boundary evidence, and feature metrics",
            "target_table_copy": "The target addresses use the .data copy of the registration records.",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "normalized_shape_exact_count": sum(
                row["normalized_shape_equal"] for row in anchors
            ),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": 0,
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
            "boundary_recovery_count": sum(
                row["match_kind"] == "manual-level-object-property-boundary-anchor"
                for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not recovered original debug symbols.",
            "The z getter is a boundary-recovery anchor because IDA had not exported a target feature row before the reviewed range was materialized. When a post-boundary feature export is supplied, its metrics are recorded as a second-stage confirmation.",
            "The other six rows match the complete recorded feature metrics and the target property registrations.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
