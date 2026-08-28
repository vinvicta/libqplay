#!/usr/bin/env python3
"""Create the reviewed TBodyPanel bodycacheperplayer anchor."""

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
    args = parser.parse_args()

    original = by_ea(load(args.original_features))["0x23bf5c"]
    spectron = by_ea(load(args.spectron_features))["0x245e0c"]
    if original["name"] != "TBodyPanel_get_bodycacheperplayer":
        raise ValueError("unexpected source name")
    if spectron["name"] != "sub_245E0C" or not spectron.get("is_default_name"):
        raise ValueError("unexpected target name")

    original_metrics = metrics(original)
    spectron_metrics = metrics(spectron)
    normalized_equal = all(
        original_metrics[field] == spectron_metrics[field]
        for field in NORMALIZED_METRICS
    )
    full_metric_equal = original_metrics == spectron_metrics
    differences = [
        field for field in METRICS if original_metrics[field] != spectron_metrics[field]
    ]
    anchor = {
        "original_ea": "0x23bf5c",
        "original_name": original["name"],
        "original_metrics": original_metrics,
        "original_function_end": original.get("end_ea"),
        "original_string_refs": original.get("string_refs", []),
        "original_direct_call_names": original.get("direct_call_names", []),
        "spectron_ea": "0x245e0c",
        "spectron_current_name": spectron["name"],
        "spectron_default_name": True,
        "spectron_metrics": spectron_metrics,
        "spectron_function_end": spectron.get("end_ea"),
        "spectron_string_refs": spectron.get("string_refs", []),
        "spectron_direct_call_names": spectron.get("direct_call_names", []),
        "proposed_name": "v18_TBodyPanel_get_bodycacheperplayer",
        "confidence": "high",
        "match_kind": "manual-tbodypanel-property-anchor",
        "source_component": "TBodyPanel property table",
        "target_component": "Spectron obfuscated TBodyPanel property table",
        "source_basis": "matching the bodycacheperplayer getter registration and static-field operation",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": "0x38af98",
        "target_script_table_record": "0x39e0e8",
        "script_name": "bodycacheperplayer",
        "property_role": "getter",
        "operation": "returns the panels-per-player static integer",
        "evidence": [
            "The source bodycacheperplayer getter is registered at 0x38af98.",
            "The target bodycacheperplayer getter is registered at 0x39e0e8.",
            "The source and target pseudocode both return the panels-per-player static integer.",
            "The target callback remained a default sub name before this pass.",
            "Normalized instruction shape matches; the only difference is register allocation detail.",
        ],
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_tbodypanel_bodycacheperplayer_manual_translation_anchor_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the TBodyPanel bodycacheperplayer getter",
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
            "source_component": "TBodyPanel property table at 0x38af98",
            "target_component": "Spectron obfuscated TBodyPanel property table at 0x39e0e8",
            "resolution": "decoded property name, table-local order, getter role, static-field behavior, pseudocode, and ARM64 feature metrics",
            "record_size": "0x30 bytes",
            "callback_offsets": {"getter": "0x10", "setter": "0x18"},
            "preexisting_target_callbacks": [
                "The bodycacheperplayer setter and the remaining server-object callbacks already had target names."
            ],
        },
        "summary": {
            "anchor_count": 1,
            "registration_row_count": 1,
            "unique_target_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": 1,
            "normalized_shape_exact_count": int(normalized_equal),
            "full_metric_exact_count": int(full_metric_equal),
            "layout_change_count": int(not normalized_equal),
            "register_detail_difference_count": int("register_detail_hash" in differences),
            "getter_count": 1,
            "setter_count": 0,
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The property row resolves the remaining default getter in the TBodyPanel and server-object registration block.",
            "The target preserves normalized instruction shape and differs only in register allocation detail.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
