#!/usr/bin/env python3
"""Create target-only labels for the Spectron Quattro zoom-culling property.

The target adds a TPlayer property whose name is a readable C++ rendering
string rather than an encoded 1.8 script name. The source inventory and
source binary contain no matching property record or literal, so these labels
remain explicitly target-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


TARGET_RECORD = 0x38EE08
TARGET_NAME_POINTER = 0x2E27C0
TARGET_PROPERTY_NAME = "Quattro::Rendering::Quattro2D::useQuattroZoomFactorCulling"
TARGET_FLAGS = 0x6200

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


LABEL_SPECS = (
    {
        "target_ea": "0x170334",
        "current_name": "sub_170334",
        "function_end": "0x170344",
        "property_role": "getter",
        "proposed_name": "spectron_TPlayer_get_useQuattroZoomFactorCulling",
        "operation": "returns the byte stored in W6NzgawMJy::SdZ4Lar7N3",
    },
    {
        "target_ea": "0x170344",
        "current_name": "sub_170344",
        "function_end": "0x170354",
        "property_role": "setter",
        "proposed_name": "spectron_TPlayer_set_useQuattroZoomFactorCulling",
        "operation": "stores the incoming byte in W6NzgawMJy::SdZ4Lar7N3 and returns it",
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


def va_to_offset(va: int) -> int:
    return va - 0x10000 if va >= 0x35D210 else va


def qword(binary: bytes, va: int) -> int:
    offset = va_to_offset(va)
    if offset < 0 or offset + 8 > len(binary):
        raise ValueError("address outside target binary: 0x%x" % va)
    return struct.unpack_from("<Q", binary, offset)[0]


def literal(binary: bytes, va: int) -> str:
    offset = va_to_offset(va)
    end = binary.find(b"\0", offset)
    if offset < 0 or end < 0:
        raise ValueError("target property literal is not terminated")
    return binary[offset:end].decode("ascii")


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def source_has_name(inventory: dict, name: str) -> bool:
    return any(
        record.get("script_name") == name
        for table in inventory.get("tables", [])
        for record in table.get("records", [])
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--spectron-binary", required=True, type=Path)
    parser.add_argument("--original-binary", required=True, type=Path)
    parser.add_argument("--source-inventory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256", required=True)
    parser.add_argument("--original-binary-sha256", required=True)
    args = parser.parse_args()

    spectron_document = load(args.spectron_features)
    spectron = {
        int(row["ea"], 16): row for row in spectron_document["functions"]
    }
    binary = args.spectron_binary.read_bytes()
    original_binary = args.original_binary.read_bytes()
    inventory = load(args.source_inventory)

    if literal(binary, TARGET_NAME_POINTER) != TARGET_PROPERTY_NAME:
        raise ValueError("target property literal changed")
    if TARGET_PROPERTY_NAME.encode("ascii") in original_binary:
        raise ValueError("source binary unexpectedly contains target property literal")
    if source_has_name(inventory, TARGET_PROPERTY_NAME):
        raise ValueError("source inventory unexpectedly contains target property name")
    if qword(binary, TARGET_RECORD) != TARGET_NAME_POINTER:
        raise ValueError("target property record name pointer changed")
    if qword(binary, TARGET_RECORD + 0x08) != TARGET_FLAGS:
        raise ValueError("target property flags changed")
    if qword(binary, TARGET_RECORD + 0x10) != int(LABEL_SPECS[0]["target_ea"], 16):
        raise ValueError("target getter pointer changed")
    if qword(binary, TARGET_RECORD + 0x18) != int(LABEL_SPECS[1]["target_ea"], 16):
        raise ValueError("target setter pointer changed")

    labels = []
    for spec in LABEL_SPECS:
        target_ea = int(spec["target_ea"], 16)
        target = spectron.get(target_ea)
        if target is None:
            raise ValueError("missing target feature at %s" % spec["target_ea"])
        if target.get("name") != spec["current_name"]:
            raise ValueError("unexpected target name at %s" % spec["target_ea"])
        if target.get("end_ea") != spec["function_end"]:
            raise ValueError("unexpected target boundary at %s" % spec["target_ea"])
        if not target.get("is_default_name"):
            raise ValueError("target is not a default name at %s" % spec["target_ea"])
        labels.append(
            {
                "target_ea": spec["target_ea"],
                "current_name": target["name"],
                "function_end": target["end_ea"],
                "proposed_name": spec["proposed_name"],
                "target_default_name": target["is_default_name"],
                "target_metrics": metrics(target),
                "target_string_refs": target.get("string_refs", []),
                "target_direct_call_names": target.get("direct_call_names", []),
                "script_name": TARGET_PROPERTY_NAME,
                "property_name": TARGET_PROPERTY_NAME,
                "property_role": spec["property_role"],
                "target_property_table_record": "0x%x" % TARGET_RECORD,
                "target_property_name_pointer": "0x%x" % TARGET_NAME_POINTER,
                "target_property_flags": "0x%x" % TARGET_FLAGS,
                "target_property_callback_field": "0x%x"
                % (TARGET_RECORD + (0x10 if spec["property_role"] == "getter" else 0x18)),
                "target_class": "W6NzgawMJy, the obfuscated TPlayer property class",
                "operation": spec["operation"],
                "source_counterpart": None,
                "source_counterpart_status": "not-demonstrated",
                "confidence": "high",
                "match_kind": "reviewed-spectron-target-only-property-label",
                "evidence": [
                    "The target TPlayer initialization path at 0x17d854 registers the property table containing record 0x38ee08.",
                    "The target property record stores the readable name pointer at 0x38ee08 and the 0x6200 property flags at 0x38ee10.",
                    "The getter and setter fields at 0x38ee18 and 0x38ee20 point to the reviewed target functions.",
                    "Target pseudocode shows that it %s." % spec["operation"],
                    "The 1.8 source binary has no matching literal and the source table inventory has no matching property record, so no source counterpart is claimed.",
                ],
                "name_action": "rename-with-spectron-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tplayer_quattro_zoom_property_target_only_labels_20260828",
        "scope": "target-only labels for the Spectron TPlayer Quattro zoom-culling property",
        "network_contacted": False,
        "inputs": {
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "original_binary": str(args.original_binary),
            "original_binary_sha256": args.original_binary_sha256,
            "source_inventory": str(args.source_inventory),
            "source_inventory_sha256": sha256_path(args.source_inventory),
        },
        "context": {
            "target_class": "W6NzgawMJy, the obfuscated target TPlayer property class",
            "target_property_table_record": "0x%x" % TARGET_RECORD,
            "target_property_name_pointer": "0x%x" % TARGET_NAME_POINTER,
            "target_property_flags": "0x%x" % TARGET_FLAGS,
            "source_counterpart_policy": "The source inventory and source binary were checked for the exact target property name. Neither contains it.",
            "mapping_boundary": "These labels describe a target-added property and are excluded from the 1.8-to-Spectron mapping count.",
        },
        "summary": {
            "label_count": len(labels),
            "high_confidence_count": len(labels),
            "target_default_name_count": sum(row["target_default_name"] for row in labels),
            "source_counterpart_count": sum(row["source_counterpart"] is not None for row in labels),
            "getter_count": sum(row["property_role"] == "getter" for row in labels),
            "setter_count": sum(row["property_role"] == "setter" for row in labels),
        },
        "labels": labels,
        "interpretation": [
            "The spectron_ prefix marks a target-specific property label rather than a recovered 1.8 symbol.",
            "The pair shares one target property record and one obfuscated byte-sized global, with distinct getter and setter callbacks.",
            "The lack of a source literal or source inventory record is recorded as evidence, not as proof that a future source build could never contain an equivalent property.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
