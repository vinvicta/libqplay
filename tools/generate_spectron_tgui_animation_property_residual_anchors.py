#!/usr/bin/env python3
"""Create reviewed residual TGUIAnimation property anchors."""

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
    }


SPECS = (
    spec(
        "0x1c9718",
        "0x1ce298",
        "TGUIAnimation_get_currenttime",
        "currenttime",
        "getter",
        "0x3823c0",
        "0x395420",
        "reads the animation current-time float at object offset +120",
    ),
    spec(
        "0x1c9720",
        "0x1ce2a0",
        "TGUIAnimation_set_currenttime",
        "currenttime",
        "setter",
        "0x3823c0",
        "0x395420",
        "stores the animation current-time float at object offset +120",
    ),
    spec(
        "0x1c9708",
        "0x1ce288",
        "TGUIAnimation_get_amplitude",
        "amplitude",
        "getter",
        "0x382420",
        "0x395480",
        "reads the animation amplitude float at object offset +144",
    ),
    spec(
        "0x1c9710",
        "0x1ce290",
        "TGUIAnimation_set_amplitude",
        "amplitude",
        "setter",
        "0x382420",
        "0x395480",
        "stores the animation amplitude float at object offset +144",
    ),
    spec(
        "0x1c9f00",
        "0x1cea80",
        "TGUIAnimation_get_bounds",
        "bounds",
        "getter",
        "0x382450",
        "0x3954b0",
        "converts the animation rectangle returned by getBounds into a script value",
    ),
    spec(
        "0x1c9fd0",
        "0x1ceb50",
        "TGUIAnimation_set_bounds",
        "bounds",
        "setter",
        "0x382450",
        "0x3954b0",
        "parses a script rectangle and forwards it to setBounds",
    ),
    spec(
        "0x1c9728",
        "0x1ce2a8",
        "TGUIAnimation_get_delay",
        "delay",
        "getter",
        "0x382480",
        "0x3954e0",
        "reads the animation delay float at object offset +136",
    ),
    spec(
        "0x1c9730",
        "0x1ce2b0",
        "TGUIAnimation_set_delay",
        "delay",
        "setter",
        "0x382480",
        "0x3954e0",
        "stores the animation delay float at object offset +136",
    ),
    spec(
        "0x1c9738",
        "0x1ce2b8",
        "TGUIAnimation_get_duration",
        "duration",
        "getter",
        "0x3824b0",
        "0x395510",
        "reads the animation duration float at object offset +140",
    ),
    spec(
        "0x1c9740",
        "0x1ce2c0",
        "TGUIAnimation_set_duration",
        "duration",
        "setter",
        "0x3824b0",
        "0x395510",
        "stores the animation duration float at object offset +140",
    ),
    spec(
        "0x1c9748",
        "0x1ce2c8",
        "TGUIAnimation_get_interval",
        "interval",
        "getter",
        "0x3824e0",
        "0x395540",
        "reads the animation interval float at object offset +148",
    ),
    spec(
        "0x1c9750",
        "0x1ce2d0",
        "TGUIAnimation_set_interval",
        "interval",
        "setter",
        "0x3824e0",
        "0x395540",
        "stores the animation interval float at object offset +148",
    ),
    spec(
        "0x1c9780",
        "0x1ce300",
        "TGUIAnimation_get_sound",
        "sound",
        "getter",
        "0x382540",
        "0x3955a0",
        "copies the animation sound string from object offset +168",
    ),
    spec(
        "0x1c9770",
        "0x1ce2f0",
        "TGUIAnimation_get_tabfirstonshow",
        "tabfirstonshow",
        "getter",
        "0x382570",
        "0x3955d0",
        "reads the tab-first-on-show byte at object offset +152",
    ),
    spec(
        "0x1c9778",
        "0x1ce2f8",
        "TGUIAnimation_set_tabfirstonshow",
        "tabfirstonshow",
        "setter",
        "0x382570",
        "0x3955d0",
        "stores the tab-first-on-show byte at object offset +152",
    ),
    spec(
        "0x1c9bc4",
        "0x1ce744",
        "TGUIAnimation_get_timing",
        "timing",
        "getter",
        "0x3825a0",
        "0x395600",
        "returns the timing function as a script string",
    ),
    spec(
        "0x1c9b1c",
        "0x1ce69c",
        "TGUIAnimation_get_transition",
        "transition",
        "getter",
        "0x3825d0",
        "0x395630",
        "returns the transition type as a script string",
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
        f"Both pseudocodes preserve the same operation: {item['operation']}.",
        "The target callback remained a default sub name before this pass.",
    ]
    if normalized_equal and full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; remaining differences are recorded explicitly as target register or call-detail changes."
        )
    else:
        evidence.append(
            "The target wrapper uses rebuilt animation helpers, so the shape difference is retained explicitly rather than treated as byte identity."
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
        "match_kind": "manual-tgui-animation-property-residual-anchor",
        "source_component": "TGUIAnimationProperties property table",
        "target_component": "Spectron obfuscated TGUIAnimationProperties property table",
        "source_basis": f"matching the {item['script_name']} {item['role']} registration and decompiled operation",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
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

    result = {
        "schema_version": 1,
        "artifact": "spectron_tgui_animation_property_residual_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TGUIAnimation property callbacks",
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
            "source_component": "TGUIAnimationProperties property table at 0x3823c0",
            "target_component": "Spectron TGUIAnimationProperties property table at 0x395420",
            "resolution": "decoded table order, property role, decompiled field or wrapper behavior, and ARM64 feature metrics",
            "record_size": "0x30 bytes",
            "callback_offsets": {"getter": "0x10", "setter": "0x18"},
            "table_property_order": [
                "currenttime",
                "alpha",
                "amplitude",
                "bounds",
                "delay",
                "duration",
                "interval",
                "rotation",
                "sound",
                "tabfirstonshow",
                "timing",
                "transition",
            ],
            "preexisting_target_callbacks": [
                "The alpha getter and rotation getter were already translated in earlier passes.",
                "The sound setter was already translated in an earlier pass.",
                "The alpha, rotation, timing, and transition setters retain target ABI jump names and are not assigned duplicate aliases here.",
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
            "The source and target tables retain the same twelve property names and order; this artifact records only target callbacks that were still default names.",
            "The target's rectangle, timing, and transition wrappers use obfuscated rebuilt helpers, while their table roles and decompiled operations remain clear.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
