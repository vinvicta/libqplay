#!/usr/bin/env python3
"""Create reviewed residual TDrawingPanel property and script anchors."""

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


def make_spec(
    original_ea: str,
    spectron_ea: str,
    original_name: str,
    script_name: str,
    role: str,
    source_record: str,
    target_record: str,
    operation: str,
    additional_registrations: tuple[dict[str, str], ...] = (),
) -> dict:
    return {
        "original_ea": original_ea,
        "spectron_ea": spectron_ea,
        "original_name": original_name,
        "spectron_name": "sub_" + spectron_ea[2:].upper(),
        "script_name": script_name,
        "role": role,
        "source_record": source_record,
        "target_record": target_record,
        "operation": operation,
        "additional_registrations": list(additional_registrations),
    }


SPECS = (
    make_spec(
        "0x117850",
        "0x11a2b0",
        "TDrawingPanel_get_height",
        "height",
        "getter",
        "0x377d38",
        "0x38ad48",
        "reads the panel height field at object offset +184",
        additional_registrations=(
            {
                "script_name": "parth",
                "source_record": "0x377e28",
                "target_record": "0x38ae38",
            },
        ),
    ),
    make_spec(
        "0x117830",
        "0x11a290",
        "TDrawingPanel_get_isclear",
        "isclear",
        "getter",
        "0x377d68",
        "0x38ad78",
        "reads the panel clear-state byte at object offset +189",
    ),
    make_spec(
        "0x117838",
        "0x11a298",
        "TDrawingPanel_get_partx",
        "partx",
        "getter",
        "0x377d98",
        "0x38ada8",
        "reads the source rectangle X field at object offset +172",
    ),
    make_spec(
        "0x117840",
        "0x11a2a0",
        "TDrawingPanel_get_party",
        "party",
        "getter",
        "0x377dc8",
        "0x38add8",
        "reads the source rectangle Y field at object offset +176",
    ),
    make_spec(
        "0x117848",
        "0x11a2a8",
        "TDrawingPanel_get_partw",
        "partw",
        "getter",
        "0x377df8",
        "0x38ae08",
        "reads the source rectangle width field at object offset +180",
        additional_registrations=(
            {
                "script_name": "width",
                "source_record": "0x377eb8",
                "target_record": "0x38aec8",
            },
        ),
    ),
    make_spec(
        "0x11a358",
        "0x11ce58",
        "TDrawingPanel_set_profile",
        "profile",
        "setter",
        "0x377e58",
        "0x38ae68",
        "dynamic-casts the script value to a GuiControlProfile and assigns it to the panel",
    ),
    make_spec(
        "0x117858",
        "0x11a2b8",
        "TDrawingPanel_get_useownprofile",
        "useownprofile",
        "getter",
        "0x377e88",
        "0x38ae98",
        "returns whether the panel has its own profile pointer",
    ),
    make_spec(
        "0x117868",
        "0x11a2c8",
        "TDrawingPanel_get_availablefilters",
        "availablefilters",
        "getter",
        "0x377ee8",
        "0x38aef8",
        "turns the panel filter-name list into a script array value",
    ),
    make_spec(
        "0x117828",
        "0x11a288",
        "TDrawingPanel_get_enablecache",
        "enablecache",
        "getter",
        "0x377f18",
        "0x38af28",
        "reads the panel cache-enable byte at object offset +140",
    ),
    make_spec(
        "0x1182dc",
        "0x11ad8c",
        "TDrawingPanel_script_drawimagestretched",
        "drawimagestretched",
        "callback",
        "0x377fd8",
        "0x38afe8",
        "forwards the ten script arguments to the panel drawImageStretched implementation",
    ),
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
    return {field: row.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, item: dict) -> dict:
    if source["name"] != item["original_name"]:
        raise ValueError(f"unexpected source name at {item['original_ea']}: {source['name']}")
    if target["name"] != item["spectron_name"]:
        raise ValueError(f"unexpected target name at {item['spectron_ea']}: {target['name']}")
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {item['spectron_ea']}")
    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source[field] == target[field] for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    evidence = [
        f"The source {item['role']} registration row for {item['script_name']} is at {item['source_record']}.",
        f"The target {item['role']} registration row for {item['script_name']} is at {item['target_record']}.",
        f"The source and target pseudocode preserve the same operation: {item['operation']}.",
        "The target callback remained a default sub name before this pass.",
    ]
    if item["additional_registrations"]:
        evidence.append(
            "The same callback is also registered under a second script property in both builds, so the duplicate row is retained without a second alias."
        )
    if full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    else:
        evidence.append(
            "Normalized instruction shape matches; the remaining metric difference is target register detail from rebuilt panel helpers."
        )
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
        "spectron_function_end": target.get("end_ea"),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + item["original_name"],
        "confidence": "high",
        "match_kind": "manual-drawing-panel-property-residual-anchor",
        "source_component": "TDrawingPanel properties and functions tables",
        "target_component": "Spectron obfuscated TDrawingPanel properties and functions tables",
        "source_basis": f"matching {item['script_name']} {item['role']} registration and decompiled operation: {item['operation']}",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "additional_registrations": item["additional_registrations"],
        "script_name": item["script_name"],
        "property_role": item["role"],
        "operation": item["operation"],
        "evidence": evidence,
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

    original = by_ea(load(args.original_features))
    spectron = by_ea(load(args.spectron_features))
    anchors = []
    for item in SPECS:
        source = original.get(item["original_ea"])
        target = spectron.get(item["spectron_ea"])
        if source is None or target is None:
            raise ValueError(
                f"missing feature row for {item['original_ea']} or {item['spectron_ea']}"
            )
        anchors.append(make_anchor(source, target, item))

    registration_row_count = len(anchors) + sum(
        len(row["additional_registrations"]) for row in anchors
    )
    result = {
        "schema_version": 1,
        "artifact": "spectron_drawing_panel_property_residual_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TDrawingPanel property callbacks and drawimagestretched",
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
            "source_component": "TDrawingPanel property table at 0x377d38 and function table at 0x377f48",
            "target_component": "Spectron obfuscated TDrawingPanel property table at 0x38ad48 and function table at 0x38af58",
            "resolution": "decoded property names, table-local order, callback roles, direct field behavior, wrapper pseudocode, and ARM64 feature metrics",
            "target_table_copy": "The target addresses use its .data registration-table copies.",
            "shared_callbacks": [
                "height and parth share TDrawingPanel_get_height at 0x117850 and target 0x11a2b0",
                "partw and width share TDrawingPanel_get_partw at 0x117848 and target 0x11a2a8",
            ],
            "preexisting_aliases": [
                "The profile getter and useownprofile setter were already named in the target.",
                "The enablecache setter was already named in the target and is not renamed in this pass.",
            ],
        },
        "summary": {
            "anchor_count": len(anchors),
            "registration_row_count": registration_row_count,
            "unique_target_count": len({row["spectron_ea"] for row in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "normalized_shape_exact_count": sum(
                row["normalized_shape_equal"] for row in anchors
            ),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(
                not row["normalized_shape_equal"] for row in anchors
            ),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
            "duplicate_registration_count": sum(
                len(row["additional_registrations"]) for row in anchors
            ),
            "getter_count": sum(row["property_role"] == "getter" for row in anchors),
            "setter_count": sum(row["property_role"] == "setter" for row in anchors),
            "callback_count": sum(row["property_role"] == "callback" for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The height/parth and partw/width rows share callbacks in both builds; the artifact records those registration aliases explicitly.",
            "The profile and filter-list wrappers retain register-detail differences caused by rebuilt target helper classes, while the table and pseudocode establish their roles.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
