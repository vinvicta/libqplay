#!/usr/bin/env python3
"""Create a reviewed anchor for the TClient static-string initializer.

The source callback clears eleven named TClient string globals. Spectron keeps
the same order and fields under its obfuscated client class, while adding one
CanTfaz6bZ string whose initialization and cleanup are visible in the target
callback pair.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
    "register_detail_hash",
    "shape_hash",
    "string_refs_hash",
)


SOURCE_EA = 0xE0A2C
TARGET_EA = 0xE1118
SOURCE_NAME = "sub_E0A2C"
TARGET_NAME = "sub_E1118"
SOURCE_TABLE_EA = "0x35d298"
TARGET_TABLE_EA = "0x36fb40"


FIELDS = [
    {
        "source_name": "data_TClient_serverlevelname",
        "source_address": "0x38fd10",
        "target_name": "_ZN10w6qzgacqqy10vCpGxa09hXE",
        "target_address": "0x3a3748",
    },
    {
        "source_name": "data_TClient_bigfilename",
        "source_address": "0x38fd08",
        "target_name": "_ZN10w6qzgacqqy10jzxGxaoRoXE",
        "target_address": "0x3a3740",
    },
    {
        "source_name": "data_TClient_lastdownloadfile",
        "source_address": "0x38fcf8",
        "target_name": "_ZN10w6qzgacqqy10OC8FxajS3WE",
        "target_address": "0x3a3730",
    },
    {
        "source_name": "data_TClient_serverwarpdestination",
        "source_address": "0x38fcf0",
        "target_name": "_ZN10w6qzgacqqy10ehlrLaawCwE",
        "target_address": "0x3a3728",
    },
    {
        "source_name": "data_TClient_lastserverwarp",
        "source_address": "0x38fc90",
        "target_name": "_ZN10w6qzgacqqy10YAQDxaTR7UE",
        "target_address": "0x3a36c8",
    },
    {
        "source_name": "data_TClient_requestedmapwarp",
        "source_address": "0x38fc88",
        "target_name": "_ZN10w6qzgacqqy10Mc0JxapNj_E",
        "target_address": "0x3a36c0",
    },
    {
        "source_name": "data_TClient_ghostmessage",
        "source_address": "0x38fc70",
        "target_name": "_ZN10w6qzgacqqy10tUy3LadZB2E",
        "target_address": "0x3a36a8",
    },
    {
        "source_name": "data_TClient_disconnectreason",
        "source_address": "0x38fc68",
        "target_name": "_ZN10w6qzgacqqy10PHoeLaxoJlE",
        "target_address": "0x3a36a0",
    },
    {
        "source_name": "data_TClient_currentdownloadfile",
        "source_address": "0x38fc58",
        "target_name": "_ZN10w6qzgacqqy10I3HIxaSGdZE",
        "target_address": "0x3a3690",
    },
    {
        "source_name": "data_TClient_currentdownloadpackage",
        "source_address": "0x38fc50",
        "target_name": "_ZN10w6qzgacqqy10IKcIxaXkOYE",
        "target_address": "0x3a3688",
    },
    {
        "source_name": "data_TClient_loginaccountname",
        "source_address": "0x38fc40",
        "target_name": "_ZN10w6qzgacqqy10l5qdLa5oVkE",
        "target_address": "0x3a3678",
    },
]


EVIDENCE = [
    "The source callback sub_E0A2C at 0xe0a2c is referenced by source static-initializer table slot 0x35d298 and clears eleven named TClient string globals in a fixed order.",
    "The source order is serverlevelname, bigfilename, lastdownloadfile, serverwarpdestination, lastserverwarp, requestedmapwarp, ghostmessage, disconnectreason, currentdownloadfile, currentdownloadpackage, and loginaccountname.",
    "The target callback sub_E1118 at 0xe1118 is referenced by target static-initializer table slot 0x36fb40 and clears eleven w6qzgacqqy fields in the same order.",
    "The target w6qzgacqqy class is independently established as the Spectron TClient family by the already translated client reset, connection, script, and static cleanup methods.",
    "The source cleanup callback TClient_clearStaticStrings at 0xe05ec clears the same eleven source fields. The already translated target v18_TClient_clearStaticStrings at 0xe0128 clears the same eleven w6qzgacqqy fields and then clears target-only qword_3A3670.",
    "The target initializer first initializes qword_3A3670 through CanTfaz6bZ::operator=(const char *) before clearing the eleven client fields. That extra target-only lifetime explains the larger target body.",
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


def delta_text(target_ea: int, source_ea: int) -> str:
    delta = target_ea - source_ea
    sign = "+" if delta >= 0 else "-"
    return "%s0x%x" % (sign, abs(delta))


def existing_manual_sources(artifact_root: Path, output: Path) -> set[int]:
    result = set()
    for path in artifact_root.glob("spectron_*_manual_translation_anchors_*.json"):
        if path.resolve() == output.resolve():
            continue
        try:
            document = load(path)
        except (OSError, json.JSONDecodeError):
            continue
        for anchor in document.get("anchors", []):
            value = anchor.get("original_ea")
            if isinstance(value, str):
                try:
                    result.add(int(value, 16))
                except ValueError:
                    pass
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    source = original.get(SOURCE_EA)
    target = spectron.get(TARGET_EA)
    if source is None or target is None:
        raise ValueError("missing source or target feature row")
    if source.get("name") != SOURCE_NAME:
        raise ValueError("unexpected source name at 0x%x" % SOURCE_EA)
    if target.get("name") != TARGET_NAME:
        raise ValueError("unexpected target name at 0x%x" % TARGET_EA)
    if not source.get("is_default_name") or not target.get("is_default_name"):
        raise ValueError("source and target must retain default IDA names")

    semantic_sources = {
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    if SOURCE_EA in semantic_sources or TARGET_EA in semantic_targets:
        raise ValueError("TClient static-string initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("TClient static-string initializer is already manually anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    if source.get("direct_call_names", []):
        raise ValueError("unexpected source direct calls")
    if target.get("direct_call_names", []) != ["._ZN10CanTfaz6bZaSEPKc"]:
        raise ValueError("unexpected target direct call set")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    metric_differences = [
        field
        for field in METRIC_FIELDS
        if source_metrics[field] != target_metrics[field]
    ]
    expected_differences = {
        "size",
        "instruction_count",
        "branch_count",
        "call_count",
        "mnemonic_hash",
        "opcode_shape_hash",
        "register_shape_hash",
        "register_detail_hash",
        "shape_hash",
    }
    if set(metric_differences) != expected_differences:
        raise ValueError(
            "unexpected metric differences: %s" % ", ".join(metric_differences)
        )

    anchor = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "original_static_initializer_table_ea": SOURCE_TABLE_EA,
        "spectron_ea": target["ea"],
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_static_initializer_table_ea": TARGET_TABLE_EA,
        "proposed_name": "v18_TClient_initializeStaticStrings",
        "confidence": "high",
        "match_kind": "manual-tclient-static-strings-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TClient static string initializer",
        "context_group": "TClient string state and static cleanup",
        "target_class": "w6qzgacqqy",
        "target_class_translation": "TClient",
        "field_order_preserved": True,
        "field_map": FIELDS,
        "source_cleanup": {
            "ea": "0xe05ec",
            "name": "TClient_clearStaticStrings",
            "table_ea": "0x35d2e8",
        },
        "spectron_cleanup": {
            "ea": "0xe0128",
            "name": "v18_TClient_clearStaticStrings",
            "table_ea": "0x36ff18",
        },
        "target_only_field": {
            "name": "qword_3A3670",
            "address": "0x3a3670",
            "type": "CanTfaz6bZ",
            "role": "additional target TClient string initialized before the eleven shared fields and cleared during static cleanup",
        },
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-reviewed-role",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_tclient_static_strings_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TClient static-string initializer",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "summary": {
            "anchor_count": 1,
            "high_confidence_count": 1,
            "already_in_semantic_map": 0,
            "new_context_anchor_count": 1,
            "exact_shape_anchor_count": 0,
            "layout_change_anchor_count": 1,
            "target_default_name_count": 1,
            "field_count": len(FIELDS),
        },
        "context": {
            "source_class": "TClient",
            "target_class": "w6qzgacqqy",
            "target_class_translation": "TClient",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_cleanup": "TClient_clearStaticStrings",
            "spectron_cleanup": "v18_TClient_clearStaticStrings",
            "resolution": "matching eleven-field order, source and target static callback slots, independently translated cleanup pair, target client class context, and one documented target-only string lifetime",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The source and target callbacks clear the same eleven TClient string fields in the same order.",
            "The target adds qword_3A3670 as a CanTfaz6bZ string, which is initialized by this callback and cleared by the independently translated target static cleanup method.",
            "The v18_ alias describes the recovered role while the evidence retains the default names, field mapping, static-table slots, cleanup pair, target-only field, and metric differences.",
            "The alias is valid only for the exact hashed Spectron library recorded in this artifact. It changes the IDA analysis copy only; no APK or native library is modified.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
