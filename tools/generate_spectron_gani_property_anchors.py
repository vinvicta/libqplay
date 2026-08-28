#!/usr/bin/env python3
"""Create reviewed TGaniObject property anchors for Spectron."""

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
    spectron_name: str,
    script_name: str,
    source_record: str,
    target_record: str,
    operation: str,
    additional_registrations: tuple[dict[str, str], ...] = (),
) -> dict:
    return {
        "original_ea": original_ea,
        "spectron_ea": spectron_ea,
        "original_name": original_name,
        "spectron_name": spectron_name,
        "script_name": script_name,
        "source_record": source_record,
        "target_record": target_record,
        "operation": operation,
        "additional_registrations": list(additional_registrations),
    }


SPECS = (
    make_spec(
        "0x15da98",
        "0x160cf0",
        "TGaniParam_getStringField304",
        "sub_160CF0",
        "aniparams",
        "0x37a5e0",
        "0x38d600",
        "copies the TGaniParam string field at object offset +304 into the script result",
    ),
    make_spec(
        "0x15d4d8",
        "0x160568",
        "TGaniObject_getField292",
        "sub_160568",
        "anistep",
        "0x37a610",
        "0x38d630",
        "reads the TGaniObject dword field at object offset +292",
    ),
    make_spec(
        "0x15d51c",
        "0x1605ac",
        "TGaniObject_getField320",
        "sub_1605AC",
        "attr",
        "0x37a6d0",
        "0x38d6f0",
        "reads the TGaniObject field at object offset +320",
    ),
    make_spec(
        "0x15da68",
        "0x160cc0",
        "TGaniParam_getStringField376",
        "sub_160CC0",
        "body",
        "0x37a700",
        "0x38d720",
        "copies the TGaniParam string field at object offset +376 into the script result",
        additional_registrations=(
            {
                "script_name": "bodyimg",
                "source_record": "0x37a730",
                "target_record": "0x38d750",
            },
        ),
    ),
    make_spec(
        "0x15d524",
        "0x1605b4",
        "TGaniObject_getField448",
        "sub_1605B4",
        "colors",
        "0x37a760",
        "0x38d780",
        "reads the TGaniObject field at object offset +448",
    ),
    make_spec(
        "0x15d590",
        "0x160620",
        "TGaniObject_getField576",
        "sub_160620",
        "gmap",
        "0x37a7c0",
        "0x38d7e0",
        "reads the TGaniObject field at object offset +576",
    ),
    make_spec(
        "0x15d4b0",
        "0x160540",
        "TGaniObject_getEnableMovieReposition",
        "sub_160540",
        "enableganimoviereposition",
        "0x37ab50",
        "0x38db70",
        "reads the global enableganimoviereposition flag",
    ),
    make_spec(
        "0x15d4c0",
        "0x160550",
        "TGaniObject_setEnableMovieReposition",
        "sub_160550",
        "enableganimoviereposition",
        "0x37ab50",
        "0x38db70",
        "stores the incoming value in the global enableganimoviereposition flag",
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
        f"The source property registration row for {item['script_name']} is at {item['source_record']}.",
        f"The target property registration row for {item['script_name']} is at {item['target_record']}.",
        f"The source and target pseudocode preserve the same operation: {item['operation']}.",
        "The target row remains in the matching TGaniObject property block and began as a default sub name.",
    ]
    if item["additional_registrations"]:
        evidence.append(
            "The same getter is also registered under bodyimg in both builds, so the duplicate row is recorded without a second alias."
        )
    if full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; the remaining difference is recorded as target register detail."
        )
    else:
        evidence.append(
            "The target global-access wrapper uses a different relocated instruction form, and the metric differences are retained explicitly."
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
        "match_kind": "manual-gani-property-table-anchor",
        "source_component": "TGaniObject property table",
        "target_component": "Spectron obfuscated TGaniObject property table",
        "source_basis": f"matching {item['script_name']} property registration and decompiled operation: {item['operation']}",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "additional_registrations": item["additional_registrations"],
        "script_name": item["script_name"],
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

    result = {
        "schema_version": 1,
        "artifact": "spectron_gani_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TGaniObject and TGaniParam property callbacks",
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
            "source_component": "TGaniObjectProperties and TGaniObject_initStaticScriptVars",
            "target_component": "Spectron obfuscated TGaniObject property tables",
            "resolution": "decoded property names, table-local order, direct callback pointers, decompiled field behavior, and ARM64 feature metrics",
            "target_table_copy": "The target addresses use its .data registration-table copy.",
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
            "layout_change_count": sum(
                not row["normalized_shape_equal"] for row in anchors
            ),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
            "duplicate_registration_count": sum(
                len(row["additional_registrations"]) for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The body and bodyimg rows share one callback in both builds; the artifact records that registration alias explicitly.",
            "The field-offset names in the 1.8 IDB are retained because they describe the proven native operation without pretending that the stripped target kept source-level names.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
