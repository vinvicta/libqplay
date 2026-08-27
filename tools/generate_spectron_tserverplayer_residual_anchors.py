#!/usr/bin/env python3
"""Create reviewed TServerPlayer anchors from the two registration tables.

The Spectron build reordered several TServerPlayer methods, so address
proximity alone is not enough for this group. The 1.8 and target property
tables contain the same decoded names and point directly at their callbacks.
The six-entry script-function table supplies the remaining script callbacks.
This tool records that evidence without modifying either binary or IDA.
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
PROPERTY_RECORD_SIZE = 0x30
PROPERTY_TABLE_BASES = {"original": 0x37CE00, "spectron": 0x38FE60}
FUNCTION_TABLE_BASES = {"original": 0x37D7C0, "spectron": 0x390820}
PROPERTY_COUNT = 52
FUNCTION_COUNT = 6
TARGET_NAME_CLASS = "MpGzgariDy"

PROPERTY_NAMES = [
    "account",
    "ap",
    "attached",
    "attachedtoobject",
    "bombs",
    "isbuddy",
    "chat",
    "communityname",
    "chatoffset",
    "darts",
    "fullhearts",
    "glovepower",
    "gralats",
    "guild",
    "head",
    "headimg",
    "headset",
    "hearts",
    "horseimg",
    "hp",
    "id",
    "isadmin",
    "isblocking",
    "ischannel",
    "ischannelopen",
    "ischanneluser",
    "isexternal",
    "isfemale",
    "isignored",
    "isignoring",
    "isloggedin",
    "ismale",
    "language",
    "languagedomain",
    "levelname",
    "maxhp",
    "messagebubble",
    "mp",
    "nick",
    "paused",
    "platform",
    "playerlisticon",
    "playersindex",
    "rating",
    "ratingd",
    "rupees",
    "shieldimg",
    "shieldpower",
    "swordimg",
    "swordpower",
    "x",
    "y",
]

FUNCTION_NAMES = [
    "isguildpm",
    "ismasspm",
    "pmswaiting",
    "openexternalhistory",
    "openexternalpm",
    "showprofile",
]

# The list is kept in source address order. The target callbacks are derived
# from the table records below instead of being copied from address order.
PROPERTY_SPECS = [
    ("TServerPlayer_setSwordImg", "swordimg", "setter", "sword image setter"),
    ("TServerPlayer_setShieldImg", "shieldimg", "setter", "shield image setter"),
    ("TServerPlayer_setHorseImg", "horseimg", "setter", "horse image setter"),
    ("TServerPlayer_getSwordImg", "swordimg", "getter", "sword image getter"),
    ("TServerPlayer_getShieldImg", "shieldimg", "getter", "shield image getter"),
    ("TServerPlayer_getPlatform", "platform", "getter", "platform getter"),
    ("TServerPlayer_getLevelName", "levelname", "getter", "level name getter"),
    ("TServerPlayer_getLanguage", "language", "getter", "language getter"),
    ("TServerPlayer_getHorseImg", "horseimg", "getter", "horse image getter"),
    (
        "TServerPlayer_getHeadOrHeadImg",
        ("head", "headimg"),
        "getter",
        "head and head image getter",
    ),
    ("TServerPlayer_getGuild", "guild", "getter", "guild getter"),
    ("TServerPlayer_getCommunityName", "communityname", "getter", "community name getter"),
    ("TServerPlayer_getAccount", "account", "getter", "account getter"),
    ("TServerPlayer_getChat", "chat", "getter", "chat getter"),
    ("TServerPlayer_getNick", "nick", "getter", "nickname getter"),
    ("TServerPlayer_getLanguageDomain", "languagedomain", "getter", "language domain getter"),
    ("TServerPlayer_getHeadset", "headset", "getter", "headset getter"),
    ("TServerPlayer_setChatOffset", "chatoffset", "setter", "chat offset setter"),
    ("TServerPlayer_getChatOffset", "chatoffset", "getter", "chat offset getter"),
    ("TServerPlayer_script_showProfile", "showprofile", "function", "profile window callback"),
    ("TServerPlayer_setDarts", "darts", "setter", "darts setter"),
    ("TServerPlayer_setBombs", "bombs", "setter", "bombs setter"),
]

SCRIPT_SPECS = [
    ("TServerPlayer_script_PMsWaiting", "pmswaiting", 2, "pending private-message callback"),
    (
        "TServerPlayer_script_openExternalHistory",
        "openexternalhistory",
        3,
        "external history callback",
    ),
    (
        "TServerPlayer_script_openExternalPM",
        "openexternalpm",
        4,
        "external private-message callback",
    ),
]

SHARED_CONTEXT_SPECS = [
    (
        "TServerPlayer_getPlayersIndex",
        "playersindex",
        "getter",
        42,
        0x18AD58,
        0x18F588,
        "v18_TServerNPC_getNPCsIndex",
        "shared NPC/player index implementation",
    ),
    (
        "TServerPlayer_getLogName_void",
        None,
        "shared",
        None,
        0x18AF54,
        0x18F804,
        "v18_TGraalAni_getLogName_void",
        "shared animation log-name implementation",
    ),
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
    "The 1.8 and Spectron TServerPlayer property tables each contain the same 52 decoded names in the same order. Each table record stores the getter and setter callback directly, so target method reordering does not weaken the correspondence.",
    "The six-entry script-function tables also contain the same decoded names. The pending-message, external-history, and external-private-message callbacks are the three target bodies that needed explicit IDA function boundaries before they could be labeled.",
    "Twenty-three selected rows retain identical complete normalized feature metrics. The headset and showprofile callbacks keep their registration slots and readable roles but grow in the target because the stripped build adds wrapper work and helper calls.",
    "The player-index and log-name rows point to target bodies already labeled through shared TServerNPC and TGraalAni implementations. They are recorded as context and are deliberately not renamed a second time.",
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
        "setter_or_callback_ea": read_u64(binary, record_ea + 0x18),
        "common_pointer": hex_ea(read_u64(binary, record_ea + 0x20)),
        "trailing": hex_ea(read_u64(binary, record_ea + 0x28)),
    }


def load_table(binary: bytes, base: int, count: int) -> list[dict]:
    return [table_record(binary, base, index) for index in range(count)]


def normalize_callback(record: dict, slot: str) -> int:
    if slot == "getter":
        return record["getter_ea"]
    if slot in ("setter", "function"):
        return record["setter_or_callback_ea"]
    raise ValueError("unsupported callback slot: %s" % slot)


def property_evidence(
    source_table: list[dict],
    target_table: list[dict],
    names: tuple[str, ...],
    slot: str,
    source_ea: int,
    target_ea: int,
) -> dict:
    records = []
    for name in names:
        index = PROPERTY_NAMES.index(name)
        source_record = source_table[index]
        target_record = target_table[index]
        if source_record["name"] != name or target_record["name"] != name:
            raise ValueError("property table name mismatch at index %d" % index)
        source_callback = normalize_callback(source_record, slot)
        target_callback = normalize_callback(target_record, slot)
        if source_callback != source_ea or target_callback != target_ea:
            raise ValueError(
                "property callback mismatch for %s: %s/%s versus %s/%s"
                % (
                    name,
                    hex_ea(source_callback),
                    hex_ea(source_ea),
                    hex_ea(target_callback),
                    hex_ea(target_ea),
                )
            )
        records.append(
            {
                "index": index,
                "name": name,
                "source_record_ea": source_record["record_ea"],
                "target_record_ea": target_record["record_ea"],
                "source_callback_ea": hex_ea(source_callback),
                "target_callback_ea": hex_ea(target_callback),
                "source_flags": source_record["flags"],
                "target_flags": target_record["flags"],
            }
        )
    return {
        "table_kind": "TServerPlayerProperties",
        "record_size": hex_ea(PROPERTY_RECORD_SIZE),
        "slot": slot,
        "records": records,
    }


def function_evidence(
    source_table: list[dict],
    target_table: list[dict],
    index: int,
    source_ea: int,
    target_ea: int,
) -> dict:
    source_record = source_table[index]
    target_record = target_table[index]
    if source_record["name"] != FUNCTION_NAMES[index] or target_record["name"] != FUNCTION_NAMES[index]:
        raise ValueError("script-function table name mismatch at index %d" % index)
    source_callback = source_record["setter_or_callback_ea"]
    target_callback = target_record["setter_or_callback_ea"]
    if source_callback != source_ea or target_callback != target_ea:
        raise ValueError("script callback mismatch at index %d" % index)
    return {
        "table_kind": "TServerPlayerFunctions",
        "record_size": hex_ea(PROPERTY_RECORD_SIZE),
        "index": index,
        "name": FUNCTION_NAMES[index],
        "source_record_ea": source_record["record_ea"],
        "target_record_ea": target_record["record_ea"],
        "source_callback_ea": hex_ea(source_callback),
        "target_callback_ea": hex_ea(target_callback),
        "source_flags": source_record["flags"],
        "target_flags": target_record["flags"],
    }


def make_common_row(
    source: dict,
    target: dict,
    source_ea: int,
    target_ea: int,
    role: str,
    context_order: int,
    table_evidence: dict,
    match_kind: str,
    shape_equal: bool,
    layout_change_reason: str | None = None,
) -> dict:
    if source_ea in semantic_source_eas or target_ea in semantic_target_eas:
        raise ValueError("residual row is already in the semantic map at %s" % source["ea"])
    target_name = target.get("name", "")
    if not target.get("is_default_name", False) or not target_name.startswith("sub_"):
        raise ValueError("expected a default target name at %s" % target["ea"])
    if target.get("end_ea") is None:
        raise ValueError("missing target function boundary at %s" % target["ea"])
    row = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target["ea"],
        "spectron_function_end": target["end_ea"],
        "spectron_current_name": target_name,
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": match_kind,
        "semantic_match_already_present": False,
        "source_basis": "TServerPlayer registration table: %s" % source["name"],
        "context_group": "TServerPlayer property and script registration residuals",
        "context_order": context_order,
        "target_delta": "+0x%x" % (target_ea - source_ea),
        "role": role,
        "evidence": EVIDENCE,
        "table_evidence": table_evidence,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": shape_equal,
    }
    if layout_change_reason is not None:
        row["layout_change_reason"] = layout_change_reason
    return row


def shared_context_row(
    source: dict,
    target: dict,
    source_ea: int,
    target_ea: int,
    target_alias: str,
    role: str,
    table_evidence: dict,
    semantic_target_row: dict,
) -> dict:
    if target_ea not in semantic_target_eas:
        raise ValueError("shared target is not already in the semantic map at %s" % target["ea"])
    if target.get("name") != target_alias:
        raise ValueError("shared target alias mismatch at %s" % target["ea"])
    if metrics(source) != metrics(target):
        raise ValueError("shared implementation feature mismatch at %s" % source["ea"])
    return {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_metrics": metrics(source),
        "spectron_ea": target["ea"],
        "spectron_current_name": target["name"],
        "spectron_metrics": metrics(target),
        "semantic_match_already_present": True,
        "semantic_target_original_ea": semantic_target_row["original_ea"],
        "semantic_target_original_name": semantic_target_row["original_name"],
        "target_name_action": "preserve-existing-shared-target-alias",
        "target_delta": "+0x%x" % (target_ea - source_ea),
        "role": role,
        "table_evidence": table_evidence,
        "evidence": EVIDENCE,
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
    global semantic_source_eas, semantic_target_eas
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_by_target = {
        int(row["spectron_ea"], 16): row for row in semantic_document.get("matches", [])
    }

    original_binary = args.original_binary.read_bytes()
    spectron_binary = args.spectron_binary.read_bytes()
    original_properties = load_table(original_binary, PROPERTY_TABLE_BASES["original"], PROPERTY_COUNT)
    spectron_properties = load_table(spectron_binary, PROPERTY_TABLE_BASES["spectron"], PROPERTY_COUNT)
    original_functions = load_table(original_binary, FUNCTION_TABLE_BASES["original"], FUNCTION_COUNT)
    spectron_functions = load_table(spectron_binary, FUNCTION_TABLE_BASES["spectron"], FUNCTION_COUNT)
    if [row["name"] for row in original_properties] != PROPERTY_NAMES:
        raise ValueError("unexpected 1.8 property table name order")
    if [row["name"] for row in spectron_properties] != PROPERTY_NAMES:
        raise ValueError("unexpected Spectron property table name order")
    if [row["name"] for row in original_functions] != FUNCTION_NAMES:
        raise ValueError("unexpected 1.8 script-function table name order")
    if [row["name"] for row in spectron_functions] != FUNCTION_NAMES:
        raise ValueError("unexpected Spectron script-function table name order")

    anchors = []
    exact_count = 0
    layout_count = 0
    context_order = 0

    for source_name, table_name, table_index, role in SCRIPT_SPECS:
        context_order += 1
        source_ea = next(
            row["setter_or_callback_ea"]
            for row in original_functions
            if row["index"] == table_index
        )
        target_ea = next(
            row["setter_or_callback_ea"]
            for row in spectron_functions
            if row["index"] == table_index
        )
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None or source.get("name") != source_name:
            raise ValueError("unexpected script callback feature for %s" % source_name)
        if source.get("end_ea") != hex_ea(source_ea + source["size"]):
            raise ValueError("source feature boundary mismatch at %s" % source["ea"])
        table = function_evidence(
            original_functions,
            spectron_functions,
            table_index,
            source_ea,
            target_ea,
        )
        if metrics(source) != metrics(target):
            raise ValueError("script callback feature mismatch at %s" % source["ea"])
        anchors.append(
            make_common_row(
                source,
                target,
                source_ea,
                target_ea,
                role,
                context_order,
                table,
                "manual-tserverplayer-script-table-exact-anchor",
                True,
            )
        )
        exact_count += 1

    for source_name, property_spec, slot, role in PROPERTY_SPECS:
        context_order += 1
        if slot == "function":
            function_index = FUNCTION_NAMES.index(property_spec)
            source_ea = original_functions[function_index]["setter_or_callback_ea"]
            target_ea = spectron_functions[function_index]["setter_or_callback_ea"]
            names = ()
        else:
            names = (property_spec,) if isinstance(property_spec, str) else tuple(property_spec)
            index = PROPERTY_NAMES.index(names[0])
            source_ea = normalize_callback(original_properties[index], slot)
            target_ea = normalize_callback(spectron_properties[index], slot)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None or source.get("name") != source_name:
            raise ValueError("unexpected property callback feature for %s" % source_name)
        table = (
            property_evidence(
                original_properties,
                spectron_properties,
                names,
                slot,
                source_ea,
                target_ea,
            )
            if slot != "function"
            else function_evidence(
                original_functions,
                spectron_functions,
                function_index,
                source_ea,
                target_ea,
            )
        )
        shape_equal = metrics(source) == metrics(target)
        if source_name in ("TServerPlayer_getHeadset", "TServerPlayer_script_showProfile"):
            if shape_equal:
                raise ValueError("expected a layout change for %s" % source_name)
            layout_count += 1
            reason = {
                "TServerPlayer_getHeadset": "The target retains the headset property getter slot and the same head string reference, but adds wrapper calls and conditional work.",
                "TServerPlayer_script_showProfile": "The target retains the showprofile function-table slot and profile-event role, but adds target-side argument and helper handling.",
            }[source_name]
            match_kind = "manual-tserverplayer-registration-layout-change-anchor"
        else:
            if not shape_equal:
                raise ValueError("unexpected exact-shape mismatch for %s" % source_name)
            exact_count += 1
            reason = None
            match_kind = "manual-tserverplayer-registration-exact-anchor"
        anchors.append(
            make_common_row(
                source,
                target,
                source_ea,
                target_ea,
                role,
                context_order,
                table,
                match_kind,
                shape_equal,
                reason,
            )
        )

    shared_context = []
    for (
        source_name,
        property_name,
        slot,
        property_index,
        source_ea,
        target_ea,
        target_alias,
        role,
    ) in SHARED_CONTEXT_SPECS:
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None or source.get("name") != source_name:
            raise ValueError("unexpected shared-context feature for %s" % source_name)
        if property_name is None:
            table = {
                "table_kind": "shared implementation context",
                "source_ea": hex_ea(source_ea),
                "target_ea": hex_ea(target_ea),
            }
        else:
            table = property_evidence(
                original_properties,
                spectron_properties,
                (property_name,),
                slot,
                source_ea,
                target_ea,
            )
        semantic_target_row = semantic_by_target.get(target_ea)
        if semantic_target_row is None:
            raise ValueError("missing semantic target row for %s" % source_name)
        shared_context.append(
            shared_context_row(
                source,
                target,
                source_ea,
                target_ea,
                target_alias,
                role,
                table,
                semantic_target_row,
            )
        )

    if len(anchors) != 25 or exact_count != 23 or layout_count != 2:
        raise ValueError("unexpected residual anchor totals")

    result = {
        "schema_version": 1,
        "artifact": "spectron_tserverplayer_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining TServerPlayer registration callbacks",
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
            "exact_shape_anchor_count": exact_count,
            "layout_change_anchor_count": layout_count,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "shared_context_count": len(shared_context),
            "shared_context_target_already_labeled_count": sum(
                row["semantic_match_already_present"] for row in shared_context
            ),
            "boundary_anchor_count": sum(
                row["spectron_ea"] in {"0x18f2c8", "0x18f2e8", "0x18f2f0"}
                for row in anchors
            ),
            "address_delta_groups": dict(
                sorted(Counter(row["target_delta"] for row in anchors).items())
            ),
        },
        "context": {
            "source_class": "TServerPlayer",
            "target_class": TARGET_NAME_CLASS,
            "source_property_table": hex_ea(PROPERTY_TABLE_BASES["original"]),
            "target_property_table": hex_ea(PROPERTY_TABLE_BASES["spectron"]),
            "source_function_table": hex_ea(FUNCTION_TABLE_BASES["original"]),
            "target_function_table": hex_ea(FUNCTION_TABLE_BASES["spectron"]),
            "property_record_size": hex_ea(PROPERTY_RECORD_SIZE),
            "property_count": PROPERTY_COUNT,
            "function_count": FUNCTION_COUNT,
            "property_table_names_match": True,
            "function_table_names_match": True,
            "source_range": "0x18aa68 through 0x18b1c8",
            "target_range": "0x18f2c8 through 0x18fa94",
            "method_order_note": "The property records resolve callback identity directly. The target method order is not assumed to match source address order.",
        },
        "table_inventory": {
            "property_names": PROPERTY_NAMES,
            "function_names": FUNCTION_NAMES,
            "source_property_table": original_properties,
            "target_property_table": spectron_properties,
            "source_function_table": original_functions,
            "target_function_table": spectron_functions,
        },
        "shared_context": shared_context,
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The v18_ aliases preserve the readable 1.8 roles while the artifact records the default target names, callback table records, and per-row address deltas.",
            "The same 52 property names and six script-function names appear in both builds. Direct callback pointers resolve the target reorder without relying on adjacent function order.",
            "The two layout-change rows are high-confidence role matches even though their normalized bodies grew in the target.",
            "Shared target implementations are documented in shared_context and retain their existing v18_ aliases.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
