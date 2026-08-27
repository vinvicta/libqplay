#!/usr/bin/env python3
"""Create a reviewed anchor for the TSocket static-string initializer.

The source callback clears two named TSocket string globals. Spectron keeps
the same pair under its obfuscated socket class and initializes one additional
CanTfaz6bZ string in the same callback. The separately translated cleanup
callbacks confirm the field correspondence and lifetime.
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

SOURCE_EA = 0xE0AB4
TARGET_EA = 0xE12DC
SOURCE_NAME = "sub_E0AB4"
TARGET_NAME = "sub_E12DC"
SOURCE_TABLE_EA = "0x35d2a0"
TARGET_TABLE_EA = "0x36fb88"


FIELDS = [
    {
        "source_name": "data_TSocket_allowedsocketsconnect",
        "source_address": "0x390b18",
        "target_name": "_ZN10XJLBgarMnA10DcjBgagM_zE",
        "target_address": "0x3a4db8",
        "role": "first shared TSocket string cleared by the source initializer",
    },
    {
        "source_name": "data_TSocket_allowedportsbind",
        "source_address": "0x390b10",
        "target_name": "_ZN10XJLBgarMnA10gwjBgaP1_zE",
        "target_address": "0x3a4db0",
        "role": "second shared TSocket string and initializer return value",
    },
]


EVIDENCE = [
    "The source callback sub_E0AB4 at 0xe0ab4 is referenced by source static-initializer table slot 0x35d2a0.",
    "The source body clears data_TSocket_allowedsocketsconnect at 0x390b18, clears data_TSocket_allowedportsbind at 0x390b10, and returns the address of the latter field.",
    "The source cleanup callback TSocket_clearStaticStrings at 0xe0680 is referenced by cleanup table slot 0x35d2f0 and calls TString::clear on the same two fields in reverse order.",
    "The target callback sub_E12DC at 0xe12dc is referenced by target static-initializer table slot 0x36fb88 and clears XJLBgarMnA::DcjBgagM_z at 0x3a4db8 and XJLBgarMnA::gwjBgaP1_z at 0x3a4db0, returning the latter address.",
    "The target cleanup callback v18_TSocket_clearStaticStrings at 0xe0258 is referenced by cleanup table slot 0x36ff60 and clears the same two XJLBgarMnA fields through C8THgaTQxF::clear.",
    "The target callback first initializes qword_3A4D90 at 0x3a4d90 through CanTfaz6bZ::operator=(const char *). The target cleanup callback clears this additional string after the shared socket fields, explaining the larger body without changing the two-field correspondence.",
    "The normalized metrics preserve one basic block and one return with no literal string references. Spectron adds one branch, one direct string-construction call, and the associated body and fingerprint changes for qword_3A4D90.",
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
        raise ValueError("TSocket static initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("TSocket static initializer is already manually anchored")
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
        "proposed_name": "v18_TSocket_initializeStaticStrings",
        "confidence": "high",
        "match_kind": "manual-tsocket-static-strings-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TSocket static string initializer",
        "context_group": "TSocket connection and bind policy state",
        "target_class": "XJLBgarMnA",
        "target_class_translation": "TSocket",
        "field_order_preserved": True,
        "field_map": FIELDS,
        "source_cleanup": {
            "ea": "0xe0680",
            "name": "TSocket_clearStaticStrings",
            "table_ea": "0x35d2f0",
        },
        "spectron_cleanup": {
            "ea": "0xe0258",
            "name": "v18_TSocket_clearStaticStrings",
            "table_ea": "0x36ff60",
        },
        "target_only_field": {
            "name": "qword_3A4D90",
            "address": "0x3a4d90",
            "type": "CanTfaz6bZ",
            "role": "additional target socket string initialized before the two shared fields and cleared during static cleanup",
        },
        "metric_differences": metric_differences,
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-reviewed-role",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_tsocket_static_state_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TSocket static-string initializer",
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
            "source_class": "TSocket",
            "target_class": "XJLBgarMnA",
            "target_class_translation": "TSocket",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_cleanup": "TSocket_clearStaticStrings",
            "spectron_cleanup": "v18_TSocket_clearStaticStrings",
            "resolution": "matching two-field order, source and target static callback slots, independently translated cleanup pair, target socket class context, and one documented target-only string lifetime",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The source and target callbacks initialize the same two TSocket string fields in the same order and return the second field address.",
            "The target adds qword_3A4D90 as a CanTfaz6bZ string, which is initialized by this callback and cleared by the independently translated target static cleanup method.",
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
