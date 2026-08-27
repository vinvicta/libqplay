#!/usr/bin/env python3
"""Create reviewed anchors from the complete TShowImg property table.

The 1.8 and Spectron TShowImgProperties tables expose the same 48 decoded
property names in the same order. Each record stores its getter and setter
callback directly, which makes the table a stronger source of identity than
class-local address proximity. This generator records every non-null callback
slot, skips rows already present in the semantic map, and preserves shared
target implementations as context instead of renaming them twice.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path


DEFAULT_ORIGINAL_BINARY = Path(
    "/home/v/Desktop/graal-decomp/GraalOnline+Classic_1.8_APKPure/"
    "lib/arm64-v8a/libqplay.so"
)
DEFAULT_SPECTRON_BINARY = Path(
    "/tmp/spectron-libqplay-inspect/lib/arm64-v8a/libqplay.so"
)
DATA_VA_FILE_DELTA = 0x10000
DATA_VA_FILE_THRESHOLD = 0x35D210
PROPERTY_TABLE_BASES = {"original": 0x389FA0, "spectron": 0x39D0F0}
PROPERTY_RECORD_SIZE = 0x30
PROPERTY_COUNT = 48
TARGET_CLASS = "eODlJaQ5OL"

PROPERTY_NAMES = [
    "actor",
    "ani",
    "dir",
    "playerlook",
    "image",
    "polygon",
    "dimension",
    "font",
    "shadowoffset",
    "shadowcolor",
    "style",
    "text",
    "textshadow",
    "alpha",
    "blue",
    "code",
    "green",
    "height",
    "imageindex",
    "layer",
    "mode",
    "parth",
    "partw",
    "partx",
    "party",
    "position",
    "red",
    "rotation",
    "rotationcenter",
    "spin",
    "stretchx",
    "stretchy",
    "useowncenter",
    "width",
    "x",
    "y",
    "z",
    "zoom",
    "attachoffset",
    "attachtoowner",
    "emitter",
    "uniqueparticle",
    "angle",
    "lifetime",
    "movementvector",
    "speed",
    "zangle",
    "sound",
]

METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)

GENERAL_EVIDENCE = [
    "The 1.8 and Spectron TShowImgProperties tables decode to the same 48 property names in the same order. The corresponding record therefore identifies the target callback by property role and slot, even where the target linker reordered the implementation bodies.",
    "Each 0x30-byte record stores the getter at offset 0x10 and the setter at offset 0x18. The artifact retains both records, their flags, encoded-name pointers, common metadata pointers, and callback addresses.",
    "The readable v18_ alias preserves the 1.8 symbol role while the evidence row keeps the target's original obfuscated or default name. Addresses are valid only for the hashed Spectron library recorded in the artifact.",
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(functions: list[dict]) -> dict[int, dict]:
    return {int(function["ea"], 16): function for function in functions}


def metrics(function: dict) -> dict:
    return {field: function.get(field) for field in METRIC_FIELDS}


def hex_ea(value: int) -> str:
    return "0x%x" % value


def va_to_offset(va: int) -> int:
    return va - DATA_VA_FILE_DELTA if va >= DATA_VA_FILE_THRESHOLD else va


def read_u64(binary: bytes, va: int) -> int:
    offset = va_to_offset(va)
    if offset < 0 or offset + 8 > len(binary):
        raise ValueError("address is outside the binary: %s" % hex_ea(va))
    return struct.unpack_from("<Q", binary, offset)[0]


def read_encoded_string(binary: bytes, va: int) -> bytes:
    offset = va_to_offset(va)
    if offset < 0 or offset >= len(binary):
        raise ValueError("string address is outside the binary: %s" % hex_ea(va))
    end = binary.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated table string at %s" % hex_ea(va))
    return binary[offset:end]


def decode_script_name(binary: bytes, va: int) -> str:
    raw = read_encoded_string(binary, va)
    decoded = []
    length = len(raw)
    for index, encoded in enumerate(raw):
        signed_encoded = encoded if encoded < 0x80 else encoded - 0x100
        value = -11 - signed_encoded - length
        sentinel_test = ((value >> 2) & 0x3F) | ((value & 3) << 6)
        if sentinel_test == index:
            signed_encoded = 0
        value = -11 - signed_encoded - length
        decoded.append(((value << 6) - index + ((value >> 2) & 0x3F)) & 0xFF)
    try:
        return bytes(decoded).decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("could not decode table string at %s" % hex_ea(va)) from error


def table_record(binary: bytes, base: int, index: int) -> dict:
    record_ea = base + index * PROPERTY_RECORD_SIZE
    name_pointer = read_u64(binary, record_ea)
    return {
        "index": index,
        "record_ea": hex_ea(record_ea),
        "name_pointer": hex_ea(name_pointer),
        "name": decode_script_name(binary, name_pointer),
        "flags": hex_ea(read_u64(binary, record_ea + 0x8)),
        "getter_ea": read_u64(binary, record_ea + 0x10),
        "setter_ea": read_u64(binary, record_ea + 0x18),
        "common_pointer": hex_ea(read_u64(binary, record_ea + 0x20)),
        "trailing": hex_ea(read_u64(binary, record_ea + 0x28)),
    }


def load_table(binary: bytes, base: int) -> list[dict]:
    return [table_record(binary, base, index) for index in range(PROPERTY_COUNT)]


def callback(record: dict, slot: str) -> int:
    if slot == "getter":
        return record["getter_ea"]
    if slot == "setter":
        return record["setter_ea"]
    raise ValueError("unsupported property callback slot: %s" % slot)


def table_evidence(
    source_record: dict,
    target_record: dict,
    property_name: str,
    slot: str,
) -> dict:
    return {
        "table_kind": "TShowImgProperties",
        "record_size": hex_ea(PROPERTY_RECORD_SIZE),
        "property_index": source_record["index"],
        "property_name": property_name,
        "slot": slot,
        "source_record": source_record,
        "target_record": target_record,
        "callback_field": "record+0x10" if slot == "getter" else "record+0x18",
    }


def existing_context_row(
    source: dict,
    target: dict,
    source_record: dict,
    target_record: dict,
    property_name: str,
    slot: str,
    semantic_row: dict | None,
    shared: bool,
) -> dict:
    source_ea = int(source["ea"], 16)
    target_ea = int(target["ea"], 16)
    row = {
        "context_kind": "shared-target-implementation" if shared else "already-translated",
        "original_ea": source["ea"],
        "original_name": source["name"],
        "spectron_ea": target["ea"],
        "spectron_current_name": target["name"],
        "property_name": property_name,
        "slot": slot,
        "target_delta": "+0x%x" % (target_ea - source_ea),
        "table_evidence": table_evidence(source_record, target_record, property_name, slot),
        "evidence": GENERAL_EVIDENCE,
    }
    if semantic_row is not None:
        row["semantic_target_original_ea"] = semantic_row["original_ea"]
        row["semantic_target_original_name"] = semantic_row["original_name"]
    if shared:
        row["target_name_action"] = "preserve-existing-semantic-alias"
        row["role"] = "code property setter registration callback"
        row["evidence"] = GENERAL_EVIDENCE + [
            "The 1.8 code setter record points to a TShowImg wrapper, while the Spectron record points to the already labeled TGaniParam string-writing implementation. The existing target alias is preserved so one target body is not renamed twice.",
        ]
    return row


def anchor_row(
    source: dict,
    target: dict,
    source_record: dict,
    target_record: dict,
    property_name: str,
    slot: str,
    context_order: int,
) -> dict:
    source_ea = int(source["ea"], 16)
    target_ea = int(target["ea"], 16)
    shape_equal = metrics(source) == metrics(target)
    evidence = GENERAL_EVIDENCE + [
        "The source and target property records point directly to these callback bodies for the same decoded property and getter or setter slot.",
    ]
    row = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target["ea"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-showimg-property-exact-anchor"
        if shape_equal
        else "manual-showimg-property-layout-change-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TShowImgProperties record %d (%s) %s callback"
        % (source_record["index"], property_name, slot),
        "context_group": "TShowImg property callback table",
        "context_order": context_order,
        "property_name": property_name,
        "property_slot": slot,
        "target_delta": "+0x%x" % (target_ea - source_ea),
        "role": "show-image %s %s" % (property_name, slot),
        "evidence": evidence,
        "table_evidence": table_evidence(
            source_record, target_record, property_name, slot
        ),
        "name_action": "rename-with-v18-prefix",
        "shape_equal": shape_equal,
    }
    if shape_equal:
        row["evidence"].append(
            "The complete normalized feature metrics, including instruction shape and string-reference digest, match exactly across the two callback bodies."
        )
    else:
        row["layout_change_reason"] = (
            "The target keeps the code property getter slot and the same virtual getter dispatch, but adds target-side string extraction and cleanup around the returned value."
            if property_name == "code" and slot == "getter"
            else "The target preserves the registration role but changes the callback body layout."
        )
        row["evidence"].append(
            "This row is a reviewed layout-change anchor. The property record, virtual dispatch role, and target pseudocode establish identity even though the normalized body hashes differ."
        )
    return row


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary", type=Path, default=DEFAULT_ORIGINAL_BINARY)
    parser.add_argument("--spectron-binary", type=Path, default=DEFAULT_SPECTRON_BINARY)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_rows = {
        int(row["spectron_ea"], 16): row
        for row in semantic_document.get("matches", [])
    }
    original_binary = args.original_binary.read_bytes()
    spectron_binary = args.spectron_binary.read_bytes()
    original_table = load_table(
        original_binary, PROPERTY_TABLE_BASES["original"]
    )
    spectron_table = load_table(
        spectron_binary, PROPERTY_TABLE_BASES["spectron"]
    )
    original_names = [record["name"] for record in original_table]
    spectron_names = [record["name"] for record in spectron_table]
    if original_names != PROPERTY_NAMES:
        raise ValueError("unexpected 1.8 TShowImg property order")
    if spectron_names != PROPERTY_NAMES:
        raise ValueError("unexpected Spectron TShowImg property order")

    anchors = []
    existing_context = []
    exact_count = 0
    layout_count = 0
    context_order = 0
    seen_target_eas: set[int] = set()
    non_null_count = 0
    for index, property_name in enumerate(PROPERTY_NAMES):
        source_record = original_table[index]
        target_record = spectron_table[index]
        for slot in ("getter", "setter"):
            source_ea = callback(source_record, slot)
            target_ea = callback(target_record, slot)
            if source_ea == 0 or target_ea == 0:
                if source_ea != target_ea:
                    raise ValueError(
                        "null callback mismatch at property %s %s" % (property_name, slot)
                    )
                continue
            non_null_count += 1
            source = original.get(source_ea)
            target = spectron.get(target_ea)
            if source is None or target is None:
                raise ValueError(
                    "missing callback feature for %s %s: %s -> %s"
                    % (property_name, slot, hex_ea(source_ea), hex_ea(target_ea))
                )
            if source_ea in semantic_source_eas:
                existing_context.append(
                    existing_context_row(
                        source,
                        target,
                        source_record,
                        target_record,
                        property_name,
                        slot,
                        semantic_target_rows.get(target_ea),
                        False,
                    )
                )
                continue
            if target_ea in semantic_target_rows:
                if not (
                    property_name == "code"
                    and slot == "setter"
                    and source["name"] == "TShowImg_set_code"
                    and target["name"] == "v18_TGaniParam_writeFloat_double"
                ):
                    raise ValueError(
                        "unexpected semantic target overlap for %s %s"
                        % (property_name, slot)
                    )
                existing_context.append(
                    existing_context_row(
                        source,
                        target,
                        source_record,
                        target_record,
                        property_name,
                        slot,
                        semantic_target_rows[target_ea],
                        True,
                    )
                )
                continue
            if target_ea in seen_target_eas:
                raise ValueError("duplicate target callback at %s" % hex_ea(target_ea))
            if target.get("end_ea") is None:
                raise ValueError("missing target function boundary at %s" % hex_ea(target_ea))
            context_order += 1
            row = anchor_row(
                source,
                target,
                source_record,
                target_record,
                property_name,
                slot,
                context_order,
            )
            anchors.append(row)
            seen_target_eas.add(target_ea)
            if row["shape_equal"]:
                exact_count += 1
            else:
                layout_count += 1

    if non_null_count != 93:
        raise ValueError("unexpected non-null callback count: %d" % non_null_count)
    if len(anchors) != 85:
        raise ValueError("unexpected new anchor count: %d" % len(anchors))
    if len(existing_context) != 8:
        raise ValueError("unexpected existing-context count: %d" % len(existing_context))
    if exact_count != 84 or layout_count != 1:
        raise ValueError(
            "unexpected shape counts: exact=%d layout=%d" % (exact_count, layout_count)
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_showimg_property_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for all non-null TShowImg property callbacks",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary": str(args.original_binary),
            "original_binary_sha256": args.original_binary_sha256
            or sha256_path(args.original_binary),
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256
            or sha256_path(args.spectron_binary),
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "summary": {
            "property_count": PROPERTY_COUNT,
            "non_null_callback_count": non_null_count,
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": len(existing_context),
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": exact_count,
            "layout_change_anchor_count": layout_count,
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "existing_context_count": len(existing_context),
            "shared_target_context_count": sum(
                row["context_kind"] == "shared-target-implementation"
                for row in existing_context
            ),
            "address_delta_groups": dict(
                sorted(Counter(row["target_delta"] for row in anchors).items())
            ),
        },
        "context": {
            "source_class": "TShowImg",
            "target_class": TARGET_CLASS,
            "source_property_table": hex_ea(PROPERTY_TABLE_BASES["original"]),
            "target_property_table": hex_ea(PROPERTY_TABLE_BASES["spectron"]),
            "record_size": hex_ea(PROPERTY_RECORD_SIZE),
            "getter_offset": "0x10",
            "setter_offset": "0x18",
            "property_names": PROPERTY_NAMES,
            "null_slots": [
                {"property": "actor", "slot": "setter"},
                {"property": "imageindex", "slot": "setter"},
                {"property": "emitter", "slot": "setter"},
            ],
        },
        "anchors": anchors,
        "existing_context": existing_context,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The table establishes the property and callback slot. Exact normalized metrics provide the strongest confirmation for 84 new rows; the code getter is recorded separately as a high-confidence layout-change row.",
            "Seven callbacks were already translated by earlier semantic or manual passes. The code setter points to the existing TGaniParam writeFloat alias in the target and is preserved as shared context rather than renamed twice.",
            "The v18_ aliases are scoped to the exact hashed Spectron library in the inputs. They are an analysis overlay and do not modify the APK.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
