#!/usr/bin/env python3
"""Create reviewed anchors for the remaining GuiStretchCtrl property callbacks."""

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
    ("0x1c522c", "0x1c9d08", "GuiStretchCtrl_get_clientextent", "clientextent", "getter", "0x382090", "0x3950f0", "converts the point at object offset +384 into the script point result"),
    ("0x1c5118", "0x1c9bf4", "GuiStretchCtrl_get_clientheight", "clientheight", "getter", "0x3820c0", "0x395120", "reads the client-height integer at object offset +388"),
    ("0x1c5164", "0x1c9c40", "GuiStretchCtrl_get_clientwidth", "clientwidth", "getter", "0x3820f0", "0x395150", "reads the client-width integer at object offset +384"),
    ("0x1c5bfc", "0x1ca6d8", "GuiTextCtrl_get_maxchars", "maxchars", "getter", "0x382120", "0x395180", "reads the maximum-character count at object offset +464"),
    ("0x1c5c04", "0x1ca6e0", "GuiTextCtrl_set_maxchars", "maxchars", "setter", "0x382120", "0x395180", "stores the maximum-character count at object offset +464"),
    ("0x1c5c0c", "0x1ca6e8", "GuiTextCtrl_get_text", "text", "getter", "0x382150", "0x3951b0", "forwards to the control text getter virtual slot"),
    ("0x1c5c34", "0x1ca710", "GuiTextCtrl_set_text", "text", "setter", "0x382150", "0x3951b0", "forwards to the control text setter virtual slot"),
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


def make_anchor(source: dict, target: dict, item: tuple[str, ...]) -> dict:
    original_ea, spectron_ea, original_name, script_name, role, source_record, target_record, operation = item
    expected_target_name = "sub_" + spectron_ea[2:].upper()
    if source["name"] != original_name:
        raise ValueError(f"unexpected source name at {original_ea}: {source['name']}")
    if target["name"] != expected_target_name:
        raise ValueError(f"unexpected target name at {spectron_ea}: {target['name']}")
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {spectron_ea}")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source_metrics[field] == target_metrics[field]
        for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    evidence = [
        f"The source {role} registration row for {script_name} is at {source_record}.",
        f"The target {role} registration row for {script_name} is at {target_record}.",
        f"The source and target pseudocode preserve the same operation: {operation}.",
        "The target callback remained a default sub name before this pass.",
    ]
    if normalized_equal and full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; remaining differences are recorded explicitly."
        )
    else:
        evidence.append(
            "The target wrapper has a shape change, so the metric difference is retained explicitly."
        )

    return {
        "original_ea": original_ea,
        "original_name": original_name,
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": spectron_ea,
        "spectron_current_name": target["name"],
        "spectron_default_name": True,
        "spectron_metrics": target_metrics,
        "spectron_function_end": target.get("end_ea"),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + original_name,
        "confidence": "high",
        "match_kind": "manual-guistretchctrl-property-anchor",
        "source_component": "GuiStretchCtrl and inherited GuiTextCtrl property tables",
        "target_component": "Spectron obfuscated GuiStretchCtrl property table",
        "source_basis": f"matching the {script_name} {role} registration and decompiled operation",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": source_record,
        "target_script_table_record": target_record,
        "script_name": script_name,
        "property_role": role,
        "operation": operation,
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
        source = original.get(item[0])
        target = spectron.get(item[1])
        if source is None or target is None:
            raise ValueError(f"missing feature row for {item[0]} or {item[1]}")
        anchors.append(make_anchor(source, target, item))

    result = {
        "schema_version": 1,
        "artifact": "spectron_guistretchctrl_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for remaining GuiStretchCtrl and inherited GuiTextCtrl property callbacks",
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
            "source_component": "GuiStretchCtrl property table at 0x382090 with inherited GuiTextCtrl rows at 0x382120 and 0x382150",
            "target_component": "Spectron obfuscated GuiStretchCtrl property table at 0x3950f0",
            "resolution": "decoded property names, table-local order, callback roles, direct field behavior, pseudocode, and ARM64 feature metrics",
            "record_size": "0x30 bytes",
            "callback_offsets": {"getter": "0x10", "setter": "0x18"},
            "preexisting_target_callbacks": [
                "The clientextent, clientheight, and clientwidth setters already had reviewed target names."
            ],
            "inheritance_note": "The maxchars and text rows use GuiTextCtrl source callback names because the 1.8 registration metadata points to the inherited GuiTextCtrl property callbacks."
        },
        "summary": {
            "anchor_count": len(anchors),
            "registration_row_count": len(anchors),
            "unique_target_count": len({row["spectron_ea"] for row in anchors}),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "normalized_shape_exact_count": sum(row["normalized_shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(not row["normalized_shape_equal"] for row in anchors),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
            "getter_count": sum(row["property_role"] == "getter" for row in anchors),
            "setter_count": sum(row["property_role"] == "setter" for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source and target property tables preserve the same five property rows and callback roles for this batch.",
            "The inherited maxchars and text rows retain their original GuiTextCtrl callback names because that is how the source registration table identifies them.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
