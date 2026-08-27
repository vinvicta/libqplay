#!/usr/bin/env python3
"""Create reviewed anchors for the final seven TServerPlayer methods.

This tail is intentionally kept separate from the registration-table batch.
The attachment setter has a direct property-table pointer, while the other
rows are identified by exact normalized shape and their class-local lifecycle
or initialization sequence.
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
PROPERTY_TABLE_BASES = {"original": 0x37CE00, "spectron": 0x38FE60}
PROPERTY_RECORD_SIZE = 0x30
TARGET_NAME_CLASS = "MpGzgariDy"
PROPERTY_INDEX_ATTACHED_TO_OBJECT = 3

SOURCE_SPECS = [
    {
        "source_ea": 0x18CA40,
        "source_name": "TServerPlayer_setAttachedToObject",
        "target_ea": 0x1912F0,
        "target_name": "sub_1912F0",
        "target_default": True,
        "role": "attached-to-object property setter",
        "match_kind": "manual-tserverplayer-tail-property-exact-anchor",
        "context_group": "TServerPlayer attachment and lifecycle tail",
        "source_basis": "attachedtoobject property record index 3 setter pointer",
        "table_kind": "property",
    },
    {
        "source_ea": 0x18DC58,
        "source_name": "TServerPlayer_clearNickWrapped_void",
        "target_ea": 0x192558,
        "target_name": "_ZN10MpGzgariDy10Zb7rwaMFgVEv",
        "target_default": False,
        "role": "nickname text-token cleanup wrapper",
        "match_kind": "manual-tserverplayer-tail-lifecycle-exact-anchor",
        "context_group": "TServerPlayer attachment and lifecycle tail",
        "source_basis": "draw-to-destructor lifecycle sequence and exact normalized shape",
        "table_kind": "sequence",
    },
    {
        "source_ea": 0x18DE80,
        "source_name": "TServerPlayer_TServerPlayer__2",
        "target_ea": 0x192780,
        "target_name": "_ZN10MpGzgariDyD0Ev",
        "target_default": False,
        "role": "D0 deleting destructor",
        "match_kind": "manual-tserverplayer-tail-lifecycle-exact-anchor",
        "context_group": "TServerPlayer attachment and lifecycle tail",
        "source_basis": "source D0 destructor symbol, following clearNickWrapped and calling the D1 destructor",
        "table_kind": "sequence",
        "source_symbol": "_ZN13TServerPlayerD0Ev",
        "source_demangled_role": "TServerPlayer::~TServerPlayer() [D0]",
    },
    {
        "source_ea": 0x1906E8,
        "source_name": "TServerPlayer_initStaticVars_void",
        "target_ea": 0x195118,
        "target_name": "_Z10HFtL2aJzyWv",
        "target_default": False,
        "role": "static variable initializer",
        "match_kind": "manual-tserverplayer-tail-static-exact-anchor",
        "context_group": "TServerPlayer property runtime tail",
        "source_basis": "exact static-initializer pair immediately before property accessors",
        "table_kind": "sequence",
    },
    {
        "source_ea": 0x19072C,
        "source_name": "TServerPlayer_initStaticScriptVars_void",
        "target_ea": 0x19515C,
        "target_name": "_Z10O36P2aSys_v",
        "target_default": False,
        "role": "static script-variable initializer",
        "match_kind": "manual-tserverplayer-tail-static-exact-anchor",
        "context_group": "TServerPlayer property runtime tail",
        "source_basis": "exact static-script initializer pair immediately before property accessors",
        "table_kind": "sequence",
    },
    {
        "source_ea": 0x1908B8,
        "source_name": "TServerPlayer_setlocalx_double_bool",
        "target_ea": 0x1952E8,
        "target_name": "_ZN10MpGzgariDy10yizVgakj2QEdb",
        "target_default": False,
        "role": "local X setter",
        "match_kind": "manual-tserverplayer-tail-coordinate-exact-anchor",
        "context_group": "TServerPlayer local-coordinate setters",
        "source_basis": "paired local-coordinate setter sequence",
        "table_kind": "sequence",
    },
    {
        "source_ea": 0x1909F0,
        "source_name": "TServerPlayer_setlocaly_double_bool",
        "target_ea": 0x195420,
        "target_name": "_ZN10MpGzgariDy10rysVgaGDXQEdb",
        "target_default": False,
        "role": "local Y setter",
        "match_kind": "manual-tserverplayer-tail-coordinate-exact-anchor",
        "context_group": "TServerPlayer local-coordinate setters",
        "source_basis": "paired local-coordinate setter sequence",
        "table_kind": "sequence",
    },
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

EVIDENCE = [
    "The attachment setter is the callback stored in the source and target attachedtoobject property record at index 3. The target pointer resolves to 0x1912f0, so the label does not depend on the nearby attachToNPC body.",
    "The nickname cleanup body sits between the large draw method and the TServerPlayer destructor in both class-local layouts. It removes the encoded text token, releases the related object through the virtual path, and clears the member. Its complete normalized feature metrics match exactly.",
    "The source row named TServerPlayer_TServerPlayer__2 is the original D0 destructor symbol _ZN13TServerPlayerD0Ev, not a second constructor. The target _ZN10MpGzgariDyD0Ev occupies the corresponding deleting-destructor role and calls the target D1 destructor.",
    "The static variable and static script-variable initializers are an adjacent exact-shape pair immediately before the TServerPlayer property accessors in both builds. The local X and Y setters are another exact-shape pair with the same +0x4a30 relocation and the same 0x10-byte gap after the first setter.",
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


def property_record(binary: bytes, base: int, index: int) -> dict:
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


def make_property_evidence(
    original_binary: bytes,
    spectron_binary: bytes,
    source_ea: int,
    target_ea: int,
) -> dict:
    source = property_record(
        original_binary,
        PROPERTY_TABLE_BASES["original"],
        PROPERTY_INDEX_ATTACHED_TO_OBJECT,
    )
    target = property_record(
        spectron_binary,
        PROPERTY_TABLE_BASES["spectron"],
        PROPERTY_INDEX_ATTACHED_TO_OBJECT,
    )
    if source["name"] != "attachedtoobject" or target["name"] != "attachedtoobject":
        raise ValueError("attachedtoobject property name mismatch")
    if source["setter_ea"] != source_ea or target["setter_ea"] != target_ea:
        raise ValueError("attachedtoobject setter pointer mismatch")
    return {
        "table_kind": "TServerPlayerProperties",
        "record_size": hex_ea(PROPERTY_RECORD_SIZE),
        "property_index": PROPERTY_INDEX_ATTACHED_TO_OBJECT,
        "property_name": "attachedtoobject",
        "slot": "setter",
        "source_record": source,
        "target_record": target,
        "source_callback_ea": hex_ea(source_ea),
        "target_callback_ea": hex_ea(target_ea),
    }


def make_row(
    source: dict,
    target: dict,
    spec: dict,
    index: int,
    table_evidence: dict,
    semantic_source_eas: set[int],
    semantic_target_eas: set[int],
) -> dict:
    source_ea = int(source["ea"], 16)
    target_ea = int(target["ea"], 16)
    if source_ea in semantic_source_eas or target_ea in semantic_target_eas:
        raise ValueError("tail row is already in the semantic map at %s" % source["ea"])
    if source.get("name") != spec["source_name"]:
        raise ValueError("unexpected source name at %s" % source["ea"])
    if target.get("name") != spec["target_name"]:
        raise ValueError("unexpected target name at %s" % target["ea"])
    if bool(target.get("is_default_name")) != spec["target_default"]:
        raise ValueError("unexpected target default-name state at %s" % target["ea"])
    if metrics(source) != metrics(target):
        raise ValueError("TServerPlayer tail feature mismatch at %s" % source["ea"])
    if target.get("end_ea") is None:
        raise ValueError("missing target function boundary at %s" % target["ea"])
    return {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target["ea"],
        "spectron_function_end": target["end_ea"],
        "spectron_current_name": target["name"],
        "spectron_default_name": target["is_default_name"],
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": spec["match_kind"],
        "semantic_match_already_present": False,
        "source_basis": spec["source_basis"],
        "context_group": spec["context_group"],
        "context_order": index + 1,
        "target_delta": "+0x%x" % (target_ea - source_ea),
        "role": spec["role"],
        "evidence": EVIDENCE,
        "table_evidence": table_evidence,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": True,
        **{
            key: spec[key]
            for key in ("source_symbol", "source_demangled_role")
            if key in spec
        },
    }


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
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    original_binary = args.original_binary.read_bytes()
    spectron_binary = args.spectron_binary.read_bytes()

    anchors = []
    for index, spec in enumerate(SOURCE_SPECS):
        source = original.get(spec["source_ea"])
        target = spectron.get(spec["target_ea"])
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % hex_ea(spec["source_ea"]))
        if spec["table_kind"] == "property":
            table = make_property_evidence(
                original_binary,
                spectron_binary,
                spec["source_ea"],
                spec["target_ea"],
            )
        elif spec["source_ea"] == 0x18DE80:
            table = {
                "table_kind": "TServerPlayer destructor lifecycle",
                "source_symbol": spec["source_symbol"],
                "source_demangled_role": spec["source_demangled_role"],
                "source_predecessor": "0x18dc58 TServerPlayer_clearNickWrapped_void",
                "target_predecessor": "0x192558 _ZN10MpGzgariDy10Zb7rwaMFgVEv",
                "source_d1_call": "0x18dc98 TServerPlayer_TServerPlayer",
                "target_d1_call": "0x192598 v18_TServerPlayer_TServerPlayer",
            }
        elif spec["source_ea"] in (0x1906E8, 0x19072C):
            table = {
                "table_kind": "TServerPlayer property-runtime sequence",
                "source_predecessor": "0x19004c TServerPlayer_setWeaponImgs_TString_const",
                "target_predecessor": "0x194a54 v18_TServerPlayer_setWeaponImgs_TString_const",
                "source_following_accessor": "0x19075c TServerPlayer_getProperty_TString_const_TGraalVar",
                "target_following_accessor": "0x19518c v18_TServerPlayer_getProperty_TString_const_TGraalVar",
                "pair_order": "initStaticVars, initStaticScriptVars",
            }
        elif spec["source_ea"] in (0x1908B8, 0x1909F0):
            table = {
                "table_kind": "TServerPlayer local-coordinate setter sequence",
                "source_pair": "0x1908b8 setlocalx, 0x1909f0 setlocaly",
                "target_pair": "0x1952e8 setlocalx, 0x195420 setlocaly",
                "source_gap_after_first_setter": hex_ea(0x1909F0 - 0x1909E0),
                "target_gap_after_first_setter": hex_ea(0x195420 - 0x195410),
                "target_class": TARGET_NAME_CLASS,
            }
        else:
            table = {
                "table_kind": "TServerPlayer class-local lifecycle sequence",
                "source_predecessor": "0x18c7ec TServerPlayer_attachToNPC_TServerNPC",
                "target_predecessor": "0x19109c v18_TServerPlayer_attachToNPC_TServerNPC",
                "target_class": TARGET_NAME_CLASS,
            }
        anchors.append(
            make_row(
                source,
                target,
                spec,
                index,
                table,
                semantic_source_eas,
                semantic_target_eas,
            )
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tserverplayer_tail_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the final seven named TServerPlayer residual methods",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary": str(args.original_binary),
            "original_binary_sha256": args.original_binary_sha256 or sha256_path(args.original_binary),
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256 or sha256_path(args.spectron_binary),
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "boundary_anchor_count": 0,
            "address_delta_groups": dict(
                sorted(Counter(row["target_delta"] for row in anchors).items())
            ),
        },
        "context": {
            "source_class": "TServerPlayer",
            "target_class": TARGET_NAME_CLASS,
            "source_attachment_property_table": hex_ea(PROPERTY_TABLE_BASES["original"]),
            "target_attachment_property_table": hex_ea(PROPERTY_TABLE_BASES["spectron"]),
            "attachment_property_index": PROPERTY_INDEX_ATTACHED_TO_OBJECT,
            "source_range": "0x18ca40 through 0x190b18",
            "target_range": "0x1912f0 through 0x195548",
            "source_property_accessor_following_tail": "0x19075c through 0x19084c",
            "target_property_accessor_following_tail": "0x19518c through 0x1952e8",
            "target_default_name_note": "Only the attachment setter target was a default sub_ name. The six other targets retained obfuscated or existing non-default names.",
        },
        "shared_context": [],
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ aliases preserve the readable 1.8 roles while the artifact records the target names, complete normalized metrics, and class-local sequence evidence.",
            "The source label TServerPlayer_TServerPlayer__2 is documented as the D0 deleting destructor because its original symbol is _ZN13TServerPlayerD0Ev.",
            "All seven pairs are exact normalized-shape matches. The address deltas are recorded per row and are not generalized into one class-wide relocation rule.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
