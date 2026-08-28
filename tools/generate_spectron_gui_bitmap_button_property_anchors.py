#!/usr/bin/env python3
"""Create reviewed residual GuiBitmapButtonCtrl and GuiButtonBaseCtrl anchors."""

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


def spec(
    original_ea: str,
    spectron_ea: str,
    original_name: str,
    script_name: str,
    role: str,
    source_record: str,
    target_record: str,
    operation: str,
    component: str,
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
        "component": component,
    }


SPECS = (
    spec(
        "0x1abf1c",
        "0x1b00dc",
        "GuiBitmapButtonCtrl_get_mouseoverbitmap",
        "mouseoverbitmap",
        "getter",
        "0x380190",
        "0x3931f0",
        "copies the mouse-over bitmap string from object offset +504",
        "GuiBitmapButtonCtrl",
    ),
    spec(
        "0x1abeec",
        "0x1b00ac",
        "GuiBitmapButtonCtrl_get_normalbitmap",
        "normalbitmap",
        "getter",
        "0x3801c0",
        "0x393220",
        "copies the normal bitmap string from object offset +488",
        "GuiBitmapButtonCtrl",
    ),
    spec(
        "0x1abebc",
        "0x1b007c",
        "GuiBitmapButtonCtrl_get_pressedbitmap",
        "pressedbitmap",
        "getter",
        "0x3801f0",
        "0x393250",
        "copies the pressed bitmap string from object offset +520",
        "GuiBitmapButtonCtrl",
    ),
    spec(
        "0x1ac6c4",
        "0x1b0884",
        "GuiBitmapButtonCtrl_set_mouseoverbitmap",
        "mouseoverbitmap",
        "setter",
        "0x380190",
        "0x3931f0",
        "forwards the bitmap string to the shared setter with mode 1",
        "GuiBitmapButtonCtrl",
    ),
    spec(
        "0x1ac6bc",
        "0x1b087c",
        "GuiBitmapButtonCtrl_set_normalbitmap",
        "normalbitmap",
        "setter",
        "0x3801c0",
        "0x393220",
        "forwards the bitmap string to the shared setter with mode 0",
        "GuiBitmapButtonCtrl",
    ),
    spec(
        "0x1ac6b4",
        "0x1b0874",
        "GuiBitmapButtonCtrl_set_pressedbitmap",
        "pressedbitmap",
        "setter",
        "0x3801f0",
        "0x393250",
        "forwards the bitmap string to the shared setter with mode 2",
        "GuiBitmapButtonCtrl",
    ),
    spec(
        "0x1ad278",
        "0x1b1438",
        "GuiButtonBaseCtrl_get_buttontype",
        "buttontype",
        "getter",
        "0x3803a0",
        "0x393400",
        "looks up the button-type index at +468 and copies its name into the script result",
        "GuiButtonBaseCtrl",
    ),
    spec(
        "0x1ad2b8",
        "0x1b1478",
        "GuiButtonBaseCtrl_set_buttontype",
        "buttontype",
        "setter",
        "0x3803a0",
        "0x393400",
        "scans the button-type names and stores the matching index at +468",
        "GuiButtonBaseCtrl",
    ),
    spec(
        "0x1ad268",
        "0x1b1428",
        "GuiButtonBaseCtrl_get_groupnum",
        "groupnum",
        "getter",
        "0x380400",
        "0x393460",
        "reads the group number at object offset +472",
        "GuiButtonBaseCtrl",
    ),
    spec(
        "0x1ad270",
        "0x1b1430",
        "GuiButtonBaseCtrl_set_groupnum",
        "groupnum",
        "setter",
        "0x380400",
        "0x393460",
        "stores the group number at object offset +472",
        "GuiButtonBaseCtrl",
    ),
    spec(
        "0x1ad53c",
        "0x1b16fc",
        "GuiButtonBaseCtrl_get_text",
        "text",
        "getter",
        "0x380430",
        "0x393490",
        "forwards the control text getter into the script result",
        "GuiButtonBaseCtrl",
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
        raise ValueError(
            f"unexpected source name at {item['original_ea']}: {source['name']}"
        )
    if target["name"] != item["spectron_name"]:
        raise ValueError(
            f"unexpected target name at {item['spectron_ea']}: {target['name']}"
        )
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
    if normalized_equal and full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; the remaining difference is recorded as target register-detail allocation."
        )
    else:
        evidence.append(
            "The target wrapper has a shape change, so the metric difference is retained explicitly."
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
        "match_kind": "manual-gui-bitmap-button-property-residual-anchor",
        "source_component": item["component"] + " property table",
        "target_component": "Spectron obfuscated " + item["component"] + " property table",
        "source_basis": f"matching the {item['script_name']} {item['role']} registration and decompiled operation",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["script_name"],
        "property_role": item["role"],
        "operation": item["operation"],
        "component": item["component"],
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
        "artifact": "spectron_gui_bitmap_button_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual GuiBitmapButtonCtrl and GuiButtonBaseCtrl property callbacks",
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
            "source_components": [
                "GuiBitmapButtonCtrl property rows at 0x380190, 0x3801c0, and 0x3801f0",
                "GuiButtonBaseCtrl property table at 0x3803a0",
            ],
            "target_components": [
                "Spectron GuiBitmapButtonCtrl property rows at 0x3931f0, 0x393220, and 0x393250",
                "Spectron GuiButtonBaseCtrl property table at 0x393400",
            ],
            "resolution": "decoded property names, table-local order, callback roles, direct field behavior, pseudocode, and ARM64 feature metrics",
            "record_size": "0x30 bytes",
            "callback_offsets": {"getter": "0x10", "setter": "0x18"},
            "preexisting_target_callbacks": [
                "The GuiButtonBaseCtrl checked getter and setter already had target ABI names.",
                "The GuiButtonBaseCtrl text setter already had a target ABI name.",
            ],
        },
        "summary": {
            "anchor_count": len(anchors),
            "registration_row_count": len(anchors),
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
            "getter_count": sum(row["property_role"] == "getter" for row in anchors),
            "setter_count": sum(row["property_role"] == "setter" for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The GuiBitmapButtonCtrl image rows preserve their three mode values, while GuiButtonBaseCtrl preserves the button-type list, group number, and text getter roles.",
            "The two button-type rows differ only in target register-detail metadata; all other selected rows match the complete recorded feature set.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
