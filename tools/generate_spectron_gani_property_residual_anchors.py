#!/usr/bin/env python3
"""Create reviewed residual TGaniObject and TGaniParam property anchors."""

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
        "0x15d4d0",
        "0x160560",
        "TGaniObject_getField280",
        "ani",
        "getter",
        "0x37a5b0",
        "0x38d5d0",
        "returns the TGaniObject field at object offset +280",
    ),
    make_spec(
        "0x15d514",
        "0x1605a4",
        "TGaniObject_getChildField144",
        "attachedtoobject",
        "getter",
        "0x37a6a0",
        "0x38d6c0",
        "returns the child pointer at object offset +144",
    ),
    make_spec(
        "0x15d52c",
        "0x1605bc",
        "TGaniObject_callVirtual504",
        "dir",
        "getter",
        "0x37a790",
        "0x38d7b0",
        "invokes the receiver virtual method at vtable offset +504",
    ),
    make_spec(
        "0x15da38",
        "0x160c90",
        "TGaniParam_getStringField384",
        "head",
        "getter",
        "0x37a7f0",
        "0x38d810",
        "copies the TGaniParam string field at object offset +384 into the script result",
        additional_registrations=(
            {
                "script_name": "headimg",
                "source_record": "0x37a820",
                "target_record": "0x38d840",
            },
        ),
    ),
    make_spec(
        "0x15da08",
        "0x160c60",
        "TGaniParam_getStringField392",
        "shield",
        "getter",
        "0x37a880",
        "0x38d8a0",
        "copies the TGaniParam string field at object offset +392 into the script result",
    ),
    make_spec(
        "0x15d9d0",
        "0x160a58",
        "TGaniParam_setStringField392",
        "shield",
        "setter",
        "0x37a880",
        "0x38d8a0",
        "assigns a string to the TGaniParam field at object offset +392",
    ),
    make_spec(
        "0x15d9d8",
        "0x160c30",
        "TGaniParam_getStringField400",
        "sword",
        "getter",
        "0x37a8b0",
        "0x38d8d0",
        "copies the TGaniParam string field at object offset +400 into the script result",
    ),
    make_spec(
        "0x15d9c8",
        "0x160a50",
        "TGaniParam_setStringField400",
        "sword",
        "setter",
        "0x37a8b0",
        "0x38d8d0",
        "assigns a string to the TGaniParam field at object offset +400",
    ),
    make_spec(
        "0x15d598",
        "0x160628",
        "TGaniObject_getFloatField460",
        "rotation",
        "getter",
        "0x37a8e0",
        "0x38d900",
        "reads the rotation float, at +460 in 1.8 and the relocated corresponding field in Spectron",
    ),
    make_spec(
        "0x15d5a0",
        "0x160630",
        "TGaniObject_setFloatField460",
        "rotation",
        "setter",
        "0x37a8e0",
        "0x38d900",
        "writes the rotation float, at +460 in 1.8 and the relocated corresponding field in Spectron",
    ),
    make_spec(
        "0x15db90",
        "0x160c0c",
        "TGaniParam_getPointField476",
        "rotationcenter",
        "getter",
        "0x37a910",
        "0x38d930",
        "serializes the point field at object offset +476, relocated to the corresponding target field",
    ),
    make_spec(
        "0x15db60",
        "0x160be0",
        "TGaniParam_setPointField476",
        "rotationcenter",
        "setter",
        "0x37a910",
        "0x38d930",
        "parses a point string and stores it at object offset +476, relocated to the corresponding target field",
    ),
    make_spec(
        "0x15d5a8",
        "0x160638",
        "TGaniObject_getFloatField464",
        "stretchx",
        "getter",
        "0x37a940",
        "0x38d960",
        "reads the stretch-X float field",
    ),
    make_spec(
        "0x15d5b0",
        "0x160640",
        "TGaniObject_setFloatField464",
        "stretchx",
        "setter",
        "0x37a940",
        "0x38d960",
        "writes the stretch-X float field",
    ),
    make_spec(
        "0x15d5b8",
        "0x160648",
        "TGaniObject_getFloatField468",
        "stretchy",
        "getter",
        "0x37a970",
        "0x38d990",
        "reads the stretch-Y float field",
    ),
    make_spec(
        "0x15d5c0",
        "0x160650",
        "TGaniObject_setFloatField468",
        "stretchy",
        "setter",
        "0x37a970",
        "0x38d990",
        "writes the stretch-Y float field",
    ),
    make_spec(
        "0x15d5c8",
        "0x160658",
        "TGaniObject_getByteField472",
        "useowncenter",
        "getter",
        "0x37a9a0",
        "0x38d9c0",
        "reads the animation center byte field",
    ),
    make_spec(
        "0x15d5d0",
        "0x160660",
        "TGaniObject_setByteField472",
        "useowncenter",
        "setter",
        "0x37a9a0",
        "0x38d9c0",
        "writes the animation center byte field",
    ),
    make_spec(
        "0x15d5d8",
        "0x160668",
        "TGaniObject_getFloatField456",
        "zoom",
        "getter",
        "0x37a9d0",
        "0x38d9f0",
        "reads the zoom value, decoded from the target's encoded backing storage",
    ),
    make_spec(
        "0x15d5e0",
        "0x161530",
        "TGaniObject_setFloatField456",
        "zoom",
        "setter",
        "0x37a9d0",
        "0x38d9f0",
        "stores the zoom value through the target's encoded backing storage",
    ),
    make_spec(
        "0x15d638",
        "0x160708",
        "TGaniObject_getFloatField484",
        "red",
        "getter",
        "0x37aa00",
        "0x38da20",
        "reads the red color-effect float field",
    ),
    make_spec(
        "0x15d640",
        "0x160710",
        "TGaniObject_setFloatField484Clamped",
        "red",
        "setter",
        "0x37aa00",
        "0x38da20",
        "writes the red color-effect float after clamping it to 0 through 1",
    ),
    make_spec(
        "0x15d66c",
        "0x16073c",
        "TGaniObject_getFloatField488",
        "green",
        "getter",
        "0x37aa30",
        "0x38da50",
        "reads the green color-effect float field",
    ),
    make_spec(
        "0x15d674",
        "0x160744",
        "TGaniObject_setFloatField488Clamped",
        "green",
        "setter",
        "0x37aa30",
        "0x38da50",
        "writes the green color-effect float after clamping it to 0 through 1",
    ),
    make_spec(
        "0x15d6a0",
        "0x160770",
        "TGaniObject_getFloatField492",
        "blue",
        "getter",
        "0x37aa60",
        "0x38da80",
        "reads the blue color-effect float field",
    ),
    make_spec(
        "0x15d6a8",
        "0x160778",
        "TGaniObject_setFloatField492Clamped",
        "blue",
        "setter",
        "0x37aa60",
        "0x38da80",
        "writes the blue color-effect float after clamping it to 0 through 1",
    ),
    make_spec(
        "0x15d6d4",
        "0x1607a4",
        "TGaniObject_getFloatField496",
        "alpha",
        "getter",
        "0x37aa90",
        "0x38dab0",
        "reads the alpha color-effect float field",
    ),
    make_spec(
        "0x15d6dc",
        "0x1607ac",
        "TGaniObject_setFloatField496Clamped",
        "alpha",
        "setter",
        "0x37aa90",
        "0x38dab0",
        "writes the alpha color-effect float after clamping it to 0 through 1",
    ),
    make_spec(
        "0x15d61c",
        "0x1606ec",
        "TGaniObject_getByteField500",
        "mode",
        "getter",
        "0x37aac0",
        "0x38dae0",
        "reads the animation effect-mode byte field",
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
        "The target callback remained a default sub name before this pass.",
    ]
    if item["additional_registrations"]:
        evidence.append(
            "The same getter is also registered under headimg in both builds, so the duplicate row is retained without a second alias."
        )
    if full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized instruction shape matches; the remaining metric difference is target register detail."
        )
    else:
        evidence.append(
            "The target uses a rebuilt or encoded implementation form; the semantic correspondence is anchored by the table row and pseudocode, and all metric differences are retained explicitly."
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
        "match_kind": "manual-gani-property-residual-anchor",
        "source_component": "TGaniObject and TGaniParam property tables",
        "target_component": "Spectron obfuscated TGaniObject and TGaniParam property tables",
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
        "artifact": "spectron_gani_property_residual_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining TGaniObject and TGaniParam property callbacks",
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
            "source_component": "TGaniObjectProperties table at 0x37a5b0",
            "target_component": "Spectron obfuscated TGaniObject property table at 0x38d5d0",
            "resolution": "decoded property names, table-local order, getter/setter roles, direct callback pointers, decompiled behavior, and ARM64 feature metrics",
            "target_table_copy": "The target addresses use its .data registration-table copy.",
            "shared_callbacks": [
                "head and headimg share TGaniParam_getStringField384 at 0x15da38 and target 0x160c90",
            ],
            "target_layout_notes": [
                "The rotation, rotationcenter, stretch, center, and color fields move in the rebuilt target object layout.",
                "The target zoom field is stored in an encoded backing allocation, so its getter and setter are larger than the direct 1.8 float accessors.",
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
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The head and headimg rows share one getter in both builds; the artifact records that registration alias explicitly.",
            "The field-offset names in the 1.8 IDB are retained where they describe the proven source operation. The target layout and encoded zoom representation are called out rather than silently treated as identical.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
