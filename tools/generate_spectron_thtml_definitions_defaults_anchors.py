#!/usr/bin/env python3
"""Create a reviewed anchor for the THTMLDefinitions default initializer.

The source callback is default-named, but its stores target named
THTMLDefinitions fields that are read by the HTML renderer and tag executor.
Spectron keeps the same stores and consumers under an obfuscated class name.
The normalized body shape is exact; only IDA's register-detail fingerprint
differs between the two databases.
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

# Register-detail fingerprints can change when IDA derives different operand
# or liveness details from relocated C++ names. The remaining body metrics are
# the exact-shape comparison used by this anchor.
SHAPE_METRIC_FIELDS = tuple(
    field for field in METRIC_FIELDS if field != "register_detail_hash"
)

SOURCE_EA = 0xE09F4
TARGET_EA = 0xE0FC4
SOURCE_NAME = "sub_E09F4"
TARGET_NAME = "sub_E0FC4"
SOURCE_TABLE_EA = "0x35d290"
TARGET_TABLE_EA = "0x36fae0"


EVIDENCE = [
    "The source callback sub_E09F4 at 0xe09f4 is referenced by source static-initializer table slot 0x35d290 and has no direct calls or literal string references.",
    "The source body stores defaultbitmapindent = 5 at data_THTMLDefinitions_defaultbitmapindent (0x38fa90), clears dword_38FA94, and stores the four bytes 0x40, 0x40, 0x40, and 0xff at data_THTMLDefinitions_horizontallinecolor (0x38fa88) and its adjacent color bytes.",
    "The source horizontal-line color bytes are read by THTMLPage_render_TPoint_const at 0x1d095c, while the bitmap-indent word and adjacent zero field are read by THTMLPage_executeTag_html_tag_THTMLTagName_int at 0x1d3c88.",
    "The target callback sub_E0FC4 at 0xe0fc4 is referenced by target static-initializer table slot 0x36fae0 and has the same no-call, no-string body profile.",
    "The target body writes yyt3gaHtxY = 5 at 0x3a3460, clears dword_3A3464, and stores the same four color bytes at D2x4gaXfrZ::xYeSgaycfO (0x3a3458) and its adjacent bytes.",
    "The target fields are read by v18_THTMLPage_render_TPoint_const at 0x1d55b0 and v18_THTMLPage_executeTag_html_tag_THTMLTagName_int at 0x1d88e0, the corresponding translated HTML consumers.",
    "All normalized function metrics match exactly: size 56, 14 instructions, one basic block, one branch, zero calls, one return, and matching mnemonic, opcode, register-shape, overall-shape, and string-reference hashes. Only register_detail_hash differs.",
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


def shape_metrics(function: dict) -> dict:
    return {field: function.get(field) for field in SHAPE_METRIC_FIELDS}


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
        raise ValueError("THTMLDefinitions default initializer is already in the semantic map")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("THTMLDefinitions default initializer is already manually anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal string references")
    if source.get("direct_call_names", []) or target.get("direct_call_names", []):
        raise ValueError("unexpected direct calls")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    source_shape = shape_metrics(source)
    target_shape = shape_metrics(target)
    if source_shape != target_shape:
        raise ValueError("THTMLDefinitions default initializer does not have an exact normalized shape")
    metric_differences = [
        field
        for field in METRIC_FIELDS
        if source_metrics[field] != target_metrics[field]
    ]
    if metric_differences != ["register_detail_hash"]:
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
        "proposed_name": "v18_THTMLDefinitions_initializeDefaults",
        "confidence": "high",
        "match_kind": "manual-thtml-definitions-defaults-exact-shape-anchor",
        "semantic_match_already_present": False,
        "source_basis": "THTMLDefinitions default-value initializer",
        "context_group": "HTML page rendering and tag layout defaults",
        "target_class": "D2x4gaXfrZ",
        "target_class_translation": "THTMLDefinitions",
        "shape_metric_fields": list(SHAPE_METRIC_FIELDS),
        "shape_equal": True,
        "metric_differences": metric_differences,
        "source_fields": [
            {
                "name": "data_THTMLDefinitions_horizontallinecolor",
                "address": "0x38fa88",
                "role": "first byte of horizontal-line RGBA color",
                "value": 64,
            },
            {
                "name": "byte_38FA89",
                "address": "0x38fa89",
                "role": "second byte of horizontal-line RGBA color",
                "value": 64,
            },
            {
                "name": "byte_38FA8A",
                "address": "0x38fa8a",
                "role": "third byte of horizontal-line RGBA color",
                "value": 64,
            },
            {
                "name": "byte_38FA8B",
                "address": "0x38fa8b",
                "role": "fourth byte of horizontal-line RGBA color",
                "value": 255,
            },
            {
                "name": "data_THTMLDefinitions_defaultbitmapindent",
                "address": "0x38fa90",
                "role": "default bitmap indent",
                "value": 5,
            },
            {
                "name": "dword_38FA94",
                "address": "0x38fa94",
                "role": "adjacent HTML layout state cleared by initializer",
                "value": 0,
            },
        ],
        "spectron_fields": [
            {
                "name": "_ZN10D2x4gaXfrZ10xYeSgaycfOE",
                "address": "0x3a3458",
                "role": "first byte of horizontal-line RGBA color",
                "value": 64,
            },
            {
                "name": "byte_3A3459",
                "address": "0x3a3459",
                "role": "second byte of horizontal-line RGBA color",
                "value": 64,
            },
            {
                "name": "byte_3A345A",
                "address": "0x3a345a",
                "role": "third byte of horizontal-line RGBA color",
                "value": 64,
            },
            {
                "name": "byte_3A345B",
                "address": "0x3a345b",
                "role": "fourth byte of horizontal-line RGBA color",
                "value": 255,
            },
            {
                "name": "_ZN10D2x4gaXfrZ10yyt3gaHtxYE",
                "address": "0x3a3460",
                "role": "default bitmap indent",
                "value": 5,
            },
            {
                "name": "dword_3A3464",
                "address": "0x3a3464",
                "role": "adjacent HTML layout state cleared by initializer",
                "value": 0,
            },
        ],
        "source_consumers": [
            {
                "ea": "0x1d095c",
                "name": "THTMLPage_render_TPoint_const",
                "fields": ["0x38fa88", "0x38fa89", "0x38fa8a", "0x38fa8b"],
            },
            {
                "ea": "0x1d3c88",
                "name": "THTMLPage_executeTag_html_tag_THTMLTagName_int",
                "fields": ["0x38fa90", "0x38fa94"],
            },
        ],
        "spectron_consumers": [
            {
                "ea": "0x1d55b0",
                "name": "v18_THTMLPage_render_TPoint_const",
                "fields": ["0x3a3458", "0x3a3459", "0x3a345a", "0x3a345b"],
            },
            {
                "ea": "0x1d88e0",
                "name": "v18_THTMLPage_executeTag_html_tag_THTMLTagName_int",
                "fields": ["0x3a3460", "0x3a3464"],
            },
        ],
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-reviewed-role",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_thtml_definitions_defaults_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the THTMLDefinitions default initializer",
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
            "exact_shape_anchor_count": 1,
            "layout_change_anchor_count": 0,
            "register_detail_only_difference_count": 1,
            "target_default_name_count": 1,
        },
        "context": {
            "source_class": "THTMLDefinitions",
            "target_class": "D2x4gaXfrZ",
            "target_class_translation": "THTMLDefinitions",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_consumers": [
                "THTMLPage_render_TPoint_const",
                "THTMLPage_executeTag_html_tag_THTMLTagName_int",
            ],
            "spectron_consumers": [
                "v18_THTMLPage_render_TPoint_const",
                "v18_THTMLPage_executeTag_html_tag_THTMLTagName_int",
            ],
            "resolution": "matching horizontal-line RGBA bytes, bitmap-indent and adjacent state stores, exact normalized body shape, static-table slots, and translated HTML consumers",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The source and target callbacks initialize the same HTML rendering defaults and feed the corresponding HTML page methods.",
            "The normalized function body is exact. The only differing recorded fingerprint is register_detail_hash, which is retained in the artifact instead of being silently discarded.",
            "The v18_ alias describes the recovered role while the evidence retains the default names, obfuscated target class, field ranges, static-table slots, consumer addresses, and exact default values.",
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
