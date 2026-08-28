#!/usr/bin/env python3
"""Create reviewed anchors for the remaining named short property runs."""

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
    ("0x1adfe8", "0x1b21a8", "GuiButtonCtrl_get_stylesection", "stylesection", "getter", "0x3804f0", "0x393550", "copies the style-section string from object offset +504 into the script result"),
    ("0x1adfe0", "0x1b21a0", "GuiButtonCtrl_set_stylesection", "stylesection", "setter", "0x3804f0", "0x393550", "assigns the style-section string at object offset +504"),
    ("0x224540", "0x22cba0", "TScriptProperty_get_scriptlogwritetoreadonly", "scriptlogwritetoreadonly", "getter", "0x387d90", "0x39aee0", "returns the script-log-write-to-read-only global flag"),
    ("0x224550", "0x22cbb0", "TScriptProperty_set_scriptlogwritetoreadonly", "scriptlogwritetoreadonly", "setter", "0x387d90", "0x39aee0", "stores the script-log-write-to-read-only global flag"),
    ("0x22f2bc", "0x238eb0", "TTiles_get_waterheight", "waterheight", "getter", "0x387e78", "0x39afc8", "returns the water-height double from the TTiles static field"),
    ("0x22f2cc", "0x238ec0", "TTiles_set_waterheight", "waterheight", "setter", "0x387e78", "0x39afc8", "stores the water-height double into the TTiles static field"),
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
            "Normalized instruction shape matches; the remaining difference is register allocation detail."
        )
    else:
        evidence.append(
            "The target implementation has a rebuilt wrapper shape, so the metric differences are retained explicitly."
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
        "match_kind": "manual-residual-property-anchor",
        "source_component": "short residual script property table",
        "target_component": "Spectron obfuscated short residual script property table",
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
        "artifact": "spectron_residual_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for named short residual property runs",
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
                "GuiButtonCtrl property table at 0x3804f0",
                "TScriptProperty property table at 0x387d60",
                "TTiles property table at 0x387e78",
            ],
            "target_components": [
                "Spectron GuiButtonCtrl property row at 0x393550",
                "Spectron TScriptProperty property rows at 0x39aeb0",
                "Spectron TTiles property row at 0x39afc8",
            ],
            "resolution": "decoded property names, table-local order, callback roles, direct field or static-global behavior, pseudocode, and ARM64 feature metrics",
            "record_size": "0x30 bytes",
            "callback_offsets": {"getter": "0x10", "setter": "0x18"},
            "preexisting_target_callbacks": [
                "The scriptcallobject getter already had a reviewed target name.",
                "The remaining callbacks in the surrounding server, tile, and script-property blocks already had reviewed target names."
            ],
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
            "The decoded short property rows identify three named residual groups outside the longer property-table runs.",
            "All six selected rows preserve normalized ARM64 shape. The style-section pair is an exact metric match, while the script-log and water-height pairs differ only in register-detail hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
