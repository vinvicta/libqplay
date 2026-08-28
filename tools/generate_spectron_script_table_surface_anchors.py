#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron script-table callback anchors.

The target keeps the script names in encoded 0x30-byte records, even though
many of the callback symbols are default IDA names. This generator joins the
decoded target record with the readable 1.8 callback and the current feature
exports. It also records a correction to the earlier popdialog assignment:
the target row at 0x3935d0 is pushdialog, while the separate row at 0x393600
is popdialog.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


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
NORMALIZED_FIELDS = ("opcode_shape_hash", "register_shape_hash", "shape_hash")
DATA_VA_THRESHOLD = 0x35D210
DATA_VA_FILE_DELTA = 0x10000
TARGET_DATA_START = 0x370070
TARGET_DATA_END = 0x39FEC0
TARGET_TEXT_START = 0xDF800
TARGET_TEXT_END = 0x2DB070
TARGET_RECORD_SIZE = 0x30


SPECS = (
    {
        "original_ea": "0x1b1a24",
        "original_name": "GuiCanvas_script_pushdialog",
        "script_name": "pushdialog",
        "source_basis": "GuiCanvas pushdialog script callback",
        "evidence": [
            "The source function table registers pushdialog at 0x380580 and its callback cell is 0x380598.",
            "The target encoded table row at 0x3935d0 decodes to pushdialog and its callback cell points to 0x1b5cf8.",
            "The earlier label on 0x1b5cf8 used the popdialog name, but the target table proves that this row is pushdialog. The correction is kept explicit in this artifact.",
            "The reviewed target body is the rebuilt dialog-opening path and includes the MessageBoxDialog and MessageBoxDialog_Window state transitions.",
        ],
        "target_ea": "0x1b5cf8",
        "expected_current_names": ["v18_GuiCanvas_script_popdialog"],
        "corrected_from": "v18_GuiCanvas_script_popdialog",
        "correction_reason": "The target script table row at 0x3935e0 decodes to pushdialog, not popdialog.",
    },
    {
        "original_ea": "0x1b15f0",
        "original_name": "GuiCanvas_script_popdialog",
        "script_name": "popdialog",
        "source_basis": "GuiCanvas popdialog script callback",
        "evidence": [
            "The source function table registers popdialog at 0x3805b0 and its callback cell is 0x3805c8.",
            "The target encoded table row at 0x393600 decodes to popdialog and its callback cell points to 0x1b58c4.",
            "The target body is the compact dialog-pop loop that walks the canvas list and invokes the target pop-dialog helper, matching the source role.",
            "Keeping this row separate from 0x1b5cf8 prevents the push and pop callbacks from sharing one label.",
        ],
        "target_ea": "0x1b58c4",
    },
    {
        "original_ea": "0x1af0cc",
        "original_name": "GuiCanvas_script_iscursoron",
        "script_name": "iscursoron",
        "source_basis": "GuiCanvas cursor-state query callback",
        "evidence": [
            "Both callbacks are registered under the exact decoded script name iscursoron in the GuiCanvas table.",
            "Both return the cursor-on byte from the canvas singleton when present and return zero when it is absent.",
            "The normalized ARM64 feature records match; the remaining difference is target register allocation.",
        ],
        "target_ea": "0x1b3284",
    },
    {
        "original_ea": "0x1b8a9c",
        "original_name": "GuiControl_script_makeFirstResponder",
        "script_name": "makefirstresponder",
        "source_basis": "GuiControl first-responder script callback",
        "evidence": [
            "Both callbacks are registered under makefirstresponder in the GuiControl function table.",
            "Both choose the first-responder setter for a true argument and the clear-first-responder path for false.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x1bd324",
    },
    {
        "original_ea": "0x1b7470",
        "original_name": "GuiControl_script_repaint",
        "script_name": "repaint",
        "source_basis": "GuiControl repaint script callback",
        "evidence": [
            "Both callbacks are registered under repaint in the GuiControl function table.",
            "Both forward to the invalid-rectangle operation with a false argument.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x1bbc30",
    },
    {
        "original_ea": "0x1c198c",
        "original_name": "GuiScrollCtrl_script_scrolltobottom",
        "script_name": "scrolltobottom",
        "source_basis": "GuiScrollCtrl scroll-to-bottom script callback",
        "evidence": [
            "The source GuiScrollCtrl table registers scrolltobottom at 0x382000.",
            "The target row at 0x395050 decodes to scrolltobottom and points to 0x1c6468.",
            "Both call the scroll operation with a zero start and 0x7fffffff end bound.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x1c6468",
    },
    {
        "original_ea": "0x1c1980",
        "original_name": "GuiScrollCtrl_script_scrolltotop",
        "script_name": "scrolltotop",
        "source_basis": "GuiScrollCtrl scroll-to-top script callback",
        "evidence": [
            "The source GuiScrollCtrl table registers scrolltotop at 0x382030.",
            "The target row at 0x395080 decodes to scrolltotop and points to 0x1c645c.",
            "Both call the scroll operation with zero for both bounds.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x1c645c",
    },
    {
        "original_ea": "0x20d59c",
        "original_name": "TGraalVar_script_ignoreevent",
        "script_name": "ignoreevent",
        "source_basis": "TGraalVar single-event ignore callback",
        "evidence": [
            "Both callbacks are registered under ignoreevent in the TGraalVar script-function table.",
            "Both check the script-space pointer at object offset 80 and forward the two string arguments when it is present.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x2139c8",
    },
    {
        "original_ea": "0x20d58c",
        "original_name": "TGraalVar_script_ignoreevents",
        "script_name": "ignoreevents",
        "source_basis": "TGraalVar event-family ignore callback",
        "evidence": [
            "Both callbacks are registered under ignoreevents in the TGraalVar script-function table.",
            "Both check the script-space pointer at object offset 80 and forward the event-name string when it is present.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x2139b8",
    },
    {
        "original_ea": "0x20dd34",
        "original_name": "TGraalVar_script_objecttype",
        "script_name": "objecttype",
        "source_basis": "TGraalVar object-type script callback",
        "evidence": [
            "Both callbacks are registered under objecttype in the TGraalVar script-function table.",
            "Both use the callback return slot at X8 and call the class method that produces the variable type string.",
            "The target method is the retained G0gxgajWBw::nqc9LaT3l7 implementation, so the obfuscated target helper is preserved in the call evidence.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x2141e4",
    },
    {
        "original_ea": "0x210ce0",
        "original_name": "TGraalVar_script_sortascending",
        "script_name": "sortascending",
        "source_basis": "TGraalVar ascending-sort script callback",
        "evidence": [
            "The target row at 0x39ad20 decodes to sortascending and points to 0x21743c.",
            "Both callbacks forward to the variable sort method with a true ascending flag.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x21743c",
    },
    {
        "original_ea": "0x210cd8",
        "original_name": "TGraalVar_script_sortdescending",
        "script_name": "sortdescending",
        "source_basis": "TGraalVar descending-sort script callback",
        "evidence": [
            "The target row at 0x39ad50 decodes to sortdescending and points to 0x217434.",
            "Both callbacks forward to the variable sort method with a false ascending flag.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x217434",
    },
    {
        "original_ea": "0x20eea4",
        "original_name": "TGraalVar_script_timershow",
        "script_name": "timershow",
        "source_basis": "TGraalVar timer-display script callback",
        "evidence": [
            "Both callbacks are registered under timershow in the TGraalVar script-function table.",
            "Both forward to the show-timer setter with a true flag.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x215370",
    },
    {
        "original_ea": "0x22f2dc",
        "original_name": "TTiles_script_gettileset",
        "script_name": "gettileset",
        "source_basis": "TTiles tileset-file script callback",
        "evidence": [
            "The target row at 0x39afe8 decodes to gettileset and its callback cell points to 0x238edc.",
            "Both bodies return a string copy of the shared TTiles tiles-file value through the callback return slot.",
            "The target uses CanTfaz6bZ and C8THgaTQxF conversion and cleanup around the rebuilt string representation, explaining the larger body.",
        ],
        "target_ea": "0x238edc",
    },
    {
        "original_ea": "0x22f2ac",
        "original_name": "TTiles_script_gettilesettype",
        "script_name": "gettilesettype",
        "source_basis": "TTiles tileset-type script callback",
        "evidence": [
            "The target row at 0x39b018 decodes to gettilesettype and its callback cell points to 0x238ea0.",
            "Both return the shared TTiles tileset-type integer.",
            "The normalized body shape is retained; only target register allocation differs.",
        ],
        "target_ea": "0x238ea0",
    },
    {
        "original_ea": "0x230034",
        "original_name": "TTiles_script_addtiledef",
        "script_name": "addtiledef",
        "source_basis": "TTiles addtiledef script callback",
        "evidence": [
            "The target row at 0x39b078 decodes to addtiledef and its callback cell points to 0x239d60.",
            "Both pass the two string arguments, two zero default coordinates, and the supplied integer to the shared tile-definition method.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x239d60",
    },
    {
        "original_ea": "0x230020",
        "original_name": "TTiles_script_addtiledef2",
        "script_name": "addtiledef2",
        "source_basis": "TTiles addtiledef2 script callback",
        "evidence": [
            "The target row at 0x39b0a8 decodes to addtiledef2 and its callback cell points to 0x239d4c.",
            "Both pass the supplied image name and coordinates through the shared tile-definition method with the same repeated coordinate argument.",
            "All recorded function metrics match exactly.",
        ],
        "target_ea": "0x239d4c",
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


def feature_map(document: dict) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in document["functions"]}


def va_to_offset(va: int) -> int:
    return va - DATA_VA_FILE_DELTA if va >= DATA_VA_THRESHOLD else va


def read_u64(binary: bytes, va: int) -> int:
    offset = va_to_offset(va)
    if offset < 0 or offset + 8 > len(binary):
        raise ValueError("address outside target binary: 0x%x" % va)
    return struct.unpack_from("<Q", binary, offset)[0]


def encoded_string(binary: bytes, va: int) -> bytes:
    offset = va_to_offset(va)
    if offset < 0 or offset >= len(binary):
        raise ValueError("string address outside target binary: 0x%x" % va)
    end = binary.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated target table string at 0x%x" % va)
    return binary[offset:end]


def decode_script_name(raw: bytes) -> str:
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
        raise ValueError("target table name is not ASCII") from error


def find_target_record(binary: bytes, target_ea: int, script_name: str) -> dict:
    found = []
    for base in range(TARGET_DATA_START, TARGET_DATA_END, 8):
        try:
            callback = read_u64(binary, base + 0x28)
            name_pointer = read_u64(binary, base + 0x10)
            raw = encoded_string(binary, name_pointer)
            decoded = decode_script_name(raw)
        except (ValueError, UnicodeDecodeError):
            continue
        if callback != target_ea or decoded != script_name:
            continue
        found.append(
            {
                "record": base,
                "name_pointer": name_pointer,
                "callback_xref": base + 0x28,
                "raw": raw,
            }
        )
    if len(found) != 1:
        raise ValueError(
            "expected one target table row for %s at 0x%x, found %d"
            % (script_name, target_ea, len(found))
        )
    return found[0]


def find_source_record(inventory: dict, source_ea: int, script_name: str) -> dict:
    found = []
    for table in inventory.get("tables", []):
        if table.get("kind") != "functions":
            continue
        for record in table.get("records", []):
            if record.get("script_name") != script_name:
                continue
            if record.get("callback_va") != "0x%x" % source_ea:
                continue
            record_va = int(record["record_va"], 16)
            found.append(
                {
                    "record": record_va,
                    "callback_xref": record_va + 0x18,
                    "table": table,
                }
            )
    if len(found) != 1:
        raise ValueError(
            "expected one source table row for %s at 0x%x, found %d"
            % (script_name, source_ea, len(found))
        )
    return found[0]


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def make_anchor(
    spec: dict,
    source: dict,
    target: dict,
    source_record: dict,
    target_record: dict,
) -> dict:
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    differences = [
        field
        for field in METRIC_FIELDS
        if source_metrics.get(field) != target_metrics.get(field)
    ]
    anchor = {
        "original_ea": spec["original_ea"],
        "original_name": source["name"],
        "original_function_end": source["end_ea"],
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "original_script_table_record": "0x%x" % source_record["record"],
        "original_callback_xref": "0x%x" % source_record["callback_xref"],
        "spectron_ea": spec["target_ea"],
        "spectron_function_end": target["end_ea"],
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_script_table_record": "0x%x" % target_record["record"],
        "spectron_callback_xref": "0x%x" % target_record["callback_xref"],
        "spectron_name_pointer": "0x%x" % target_record["name_pointer"],
        "spectron_name_raw_hex": target_record["raw"].hex(),
        "script_name": spec["script_name"],
        "source_basis": spec["source_basis"],
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-script-table-surface-anchor",
        "normalized_shape_equal": all(
            source_metrics.get(field) == target_metrics.get(field)
            for field in NORMALIZED_FIELDS
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "source_table_context": source_record["table"].get("caller_name"),
        "target_table_context": "target encoded 0x30-byte script-function row",
        "evidence": spec["evidence"],
        "name_action": "rename-with-v18-prefix",
    }
    if spec.get("expected_current_names"):
        anchor["accepted_current_names"] = spec["expected_current_names"]
    if spec.get("corrected_from"):
        anchor["corrected_from"] = spec["corrected_from"]
        anchor["correction_reason"] = spec["correction_reason"]
    return anchor


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--source-inventory", required=True, type=Path)
    parser.add_argument("--spectron-binary", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    parser.add_argument("--semantic-map", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    inventory = load(args.source_inventory)
    original = feature_map(original_document)
    spectron = feature_map(spectron_document)
    binary = args.spectron_binary.read_bytes()
    anchors = []
    for spec in SPECS:
        source_ea = int(spec["original_ea"], 16)
        target_ea = int(spec["target_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing feature row for %s or %s" % (spec["original_ea"], spec["target_ea"]))
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at %s" % spec["original_ea"])
        if target.get("name") in {"", None}:
            raise ValueError("target has no current name at %s" % spec["target_ea"])
        source_record = find_source_record(inventory, source_ea, spec["script_name"])
        target_record = find_target_record(binary, target_ea, spec["script_name"])
        anchors.append(make_anchor(spec, source, target, source_record, target_record))

    target_names = [row["spectron_ea"] for row in anchors]
    if len(set(target_names)) != len(target_names):
        raise ValueError("duplicate target callback in script-table surface anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_script_table_surface_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron callback anchors for the remaining decoded script-table surface",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "source_inventory": str(args.source_inventory),
            "source_inventory_sha256": sha256_path(args.source_inventory),
            "semantic_map": None if args.semantic_map is None else str(args.semantic_map),
            "semantic_map_sha256": None if args.semantic_map is None else sha256_path(args.semantic_map),
        },
        "context": {
            "target_record_size": "0x30",
            "target_name_field_offset": "0x10",
            "target_callback_field_offset": "0x28",
            "source_callback_field_offset": "0x18",
            "correction": "The earlier 0x1b5cf8 label is corrected from popdialog to pushdialog. The separate target row at 0x393600 points to 0x1b58c4 for popdialog.",
            "translation_boundary": "These are reviewed callback correspondences. The v18_ prefix records the readable 1.8 role while the obfuscated target helper names and exact table cells remain in the evidence.",
        },
        "summary": {
            "anchor_count": len(anchors),
            "unique_target_count": len(set(target_names)),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "correction_count": sum("corrected_from" in row for row in anchors),
            "normalized_shape_exact_count": sum(row["normalized_shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(not row["normalized_shape_equal"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "The target script names are decoded from the library's static registration records, not guessed from address order.",
            "The pushdialog and popdialog rows are deliberately separate. The correction records why the earlier target label was wrong.",
            "Exact metric matches are still checked, while wrapper and string-representation changes are recorded instead of being hidden.",
            "These labels are valid only for the supplied hashed Spectron library.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
