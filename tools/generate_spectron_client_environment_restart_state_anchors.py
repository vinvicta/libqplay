#!/usr/bin/env python3
"""Create a reviewed anchor for the client-environment restart-state cleanup.

The source helper clears three saved-restart TString pointers. Spectron keeps
the same three logical fields in the obfuscated a7qxJaHqKV class and adds one
target-only string cleanup to the callback.
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
    "shape_hash",
    "string_refs_hash",
)


ANCHOR_SPEC = {
    "original_ea": 0xE0814,
    "original_name": "TClientEnvironment_clearRestartState",
    "spectron_ea": 0xDFDB4,
    "spectron_name": "sub_DFDB4",
    "source_callback_table": "0x35d248",
    "spectron_callback_table": "0x36fd90",
    "target_class": "a7qxJaHqKV",
    "target_initializer_ea": "0xe0970",
    "source_fields": [
        {
            "name": "fullexepath",
            "address": "0x38d4d8",
            "role": "application path",
        },
        {
            "name": "servername_saveforrestart",
            "address": "0x38d4c0",
            "role": "saved server name",
        },
        {
            "name": "serveraddr_saveforrestart",
            "address": "0x38d4b8",
            "role": "saved server address",
        },
    ],
    "target_fields": [
        {
            "name": "pZk1wamgKo",
            "address": "0x3a0d60",
            "role": "application path",
        },
        {
            "name": "We1hLalFMo",
            "address": "0x3a0d40",
            "role": "saved server name",
        },
        {
            "name": "t7xiLaUjdp",
            "address": "0x3a0d48",
            "role": "saved server address",
        },
    ],
}


EVIDENCE = [
    "The source function is the named TClientEnvironment_clearRestartState callback at static cleanup-table slot 0x35d248. Its body clears fullexepath, servername_saveforrestart, and serveraddr_saveforrestart.",
    "The target function sub_DFDB4 occupies the corresponding static cleanup-table slot at 0x36fd90 and belongs to the a7qxJaHqKV client-environment global family.",
    "The target body clears a7qxJaHqKV::We1hLalFMo, a7qxJaHqKV::t7xiLaUjdp, and a7qxJaHqKV::pZk1wamgKo. The target restartApplication method uses We1hLalFMo and t7xiLaUjdp for the saved server name and address, while pZk1wamgKo is the third application-path field initialized with them by sub_E0970.",
    "The target initializer sub_E0970 at 0xe0970 sets the same three a7qxJaHqKV fields to zero, preserving the source restart-state initialization relationship.",
    "After clearing the three corresponding fields, the target callback clears one additional CanTfaz6bZ object at qword_3A0D30, represented by the target-only tail of the callback. This is a target layout change rather than a role mismatch.",
    "The source and target use different string implementations and therefore do not have an exact normalized shape. The field set, static-table position, target class, initializer, and existing restartApplication use provide the identity evidence.",
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    source_ea = ANCHOR_SPEC["original_ea"]
    target_ea = ANCHOR_SPEC["spectron_ea"]
    source = original.get(source_ea)
    target = spectron.get(target_ea)
    if source is None or target is None:
        raise ValueError("missing source or target feature row")
    if source.get("name") != ANCHOR_SPEC["original_name"]:
        raise ValueError("source name mismatch")
    if target.get("name") != ANCHOR_SPEC["spectron_name"]:
        raise ValueError("target name mismatch")
    if not target.get("is_default_name"):
        raise ValueError("target is not a default IDA name")
    semantic_sources = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    if source_ea in semantic_sources or target_ea in semantic_targets:
        raise ValueError("restart-state row is already in the semantic map")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics == target_metrics:
        raise ValueError("restart-state row unexpectedly has an exact shape")
    metric_differences = [
        field
        for field in METRIC_FIELDS
        if source_metrics[field] != target_metrics[field]
    ]
    anchor = {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_function_end": source.get("end_ea"),
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": "0x%x" % target_ea,
        "spectron_function_end": target.get("end_ea"),
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-client-environment-restart-state-layout-anchor",
        "semantic_match_already_present": False,
        "source_basis": "TClientEnvironment saved-restart state cleanup",
        "context_group": "client-environment restart-state initialization and cleanup",
        "source_callback_table_ea": ANCHOR_SPEC["source_callback_table"],
        "spectron_callback_table_ea": ANCHOR_SPEC["spectron_callback_table"],
        "target_class": ANCHOR_SPEC["target_class"],
        "target_initializer_ea": ANCHOR_SPEC["target_initializer_ea"],
        "source_fields": ANCHOR_SPEC["source_fields"],
        "spectron_fields": ANCHOR_SPEC["target_fields"],
        "target_only_cleanup": "CanTfaz6bZ::clear at qword_3A0D30 after the three a7qxJaHqKV fields",
        "metric_differences": metric_differences,
        "target_delta": delta_text(target_ea, source_ea),
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": False,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_client_environment_restart_state_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TClientEnvironment saved-restart state cleanup callback",
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
        },
        "context": {
            "source_class": "TClientEnvironment",
            "target_class": "a7qxJaHqKV",
            "source_callback_table": "0x35d248",
            "spectron_callback_table": "0x36fd90",
            "target_initializer": "sub_E0970 at 0xe0970",
            "resolution": "corresponding saved-restart fields, target initializer, static cleanup-table slot, and target-only cleanup tail",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The target body is larger because the 2.2 build clears one additional target-only string object and uses the C8THgaTQxF and CanTfaz6bZ string implementations.",
            "The v18_ alias preserves the readable source role while the evidence retains the obfuscated target class, fields, and default name.",
            "The alias is valid only for the exact hashed Spectron library recorded in this artifact. It is an IDA analysis overlay only; no APK or native library was modified.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
