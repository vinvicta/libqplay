#!/usr/bin/env python3
"""Create reviewed anchors for the small Spectron THTMLPage method family.

These methods are below the normal semantic-matcher size threshold, so they
are recorded separately.  Every pair has an exact normalized feature match,
and all eight target names share the same obfuscated class prefix.  The
generator keeps that evidence explicit and does not modify an IDA database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SPECTRON_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
TARGET_CLASS_PREFIX = "_ZN10AS80gaE4zW"

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

ANCHOR_SPECS = [
    {
        "original_ea": "0x1cf818",
        "original_name": "THTMLPage_clearFontPointers_void",
        "spectron_ea": "0x1d446c",
        "target_name": "_ZN10AS80gaE4zW10pMwQgakbOMEv",
        "role": "THTMLPage clear cached font pointers",
        "source_table_ea": "0x36ff60",
        "spectron_table_ea": "0x383e08",
        "evidence": [
            "Both bodies walk the page font list at object offset +200, clear each cached font pointer at +136, and follow the next-link at +152.",
            "The target name belongs to the same AS80gaE4zW class prefix as the other seven mapped THTMLPage methods.",
            "The source and target method references are 0x36ff60 and 0x383e08, respectively.",
        ],
    },
    {
        "original_ea": "0x1d037c",
        "original_name": "THTMLPage_setDirty_void",
        "spectron_ea": "0x1d4fd0",
        "target_name": "_ZN10AS80gaE4zW10FOVQgamf8MEv",
        "role": "THTMLPage dirty-state setter",
        "source_table_ea": "0x373df8",
        "spectron_table_ea": "0x384298",
        "evidence": [
            "Both bodies set the page dirty byte at object offset +360 when it is not already set and return the receiver.",
            "The target class prefix matches the setWordWrap and setParseTags methods that call this helper in the rebuilt class.",
            "The source and target method references are 0x373df8 and 0x384298, respectively.",
        ],
    },
    {
        "original_ea": "0x1d03c0",
        "original_name": "THTMLPage_setWordWrap_bool",
        "spectron_ea": "0x1d5014",
        "target_name": "_ZN10AS80gaE4zW10ZMSSgaUHMOEb",
        "role": "THTMLPage word-wrap setter",
        "source_table_ea": "0x370a80",
        "spectron_table_ea": "0x3854b0",
        "evidence": [
            "Both bodies compare and update the word-wrap byte at object offset +256, then call the page dirty-state helper only when the value changes.",
            "The target pseudocode calls AS80gaE4zW::FOVQgamf8M, the target counterpart of THTMLPage::setDirty.",
            "The source and target method references are 0x370a80 and 0x3854b0, respectively.",
        ],
    },
    {
        "original_ea": "0x1d03f4",
        "original_name": "THTMLPage_setParseTags_bool_TStringList",
        "spectron_ea": "0x1d5048",
        "target_name": "_ZN10AS80gaE4zW10wEiPgaIiMLEbP10vuuHgangcF",
        "role": "THTMLPage parse-tags and tag-list setter",
        "source_table_ea": "0x371ff0",
        "spectron_table_ea": "0x383ea8",
        "evidence": [
            "Both bodies write the parse-tags byte at object offset +257, store the tag list at object offset +264, and mark the page dirty.",
            "The obfuscated target signature carries the rebuilt vuuHgangcF list type while preserving the same receiver fields and helper call.",
            "The source and target method references are 0x371ff0 and 0x383ea8, respectively.",
        ],
    },
    {
        "original_ea": "0x1d043c",
        "original_name": "THTMLPage_setSelection_bool_uint_uint",
        "spectron_ea": "0x1d5090",
        "target_name": "_ZN10AS80gaE4zW10F1pSga8voOEbjj",
        "role": "THTMLPage selection range setter",
        "source_table_ea": "0x370bd8",
        "spectron_table_ea": "0x3845b8",
        "evidence": [
            "Both bodies write the selection-enabled byte at +296 and the two selection indices at +300 and +304 before returning the receiver.",
            "The target uses the same three field offsets and the same bool-plus-two-integer calling shape.",
            "The source and target method references are 0x370bd8 and 0x3845b8, respectively.",
        ],
    },
    {
        "original_ea": "0x1d1280",
        "original_name": "THTMLPage_initURLs_void",
        "spectron_ea": "0x1d5ed4",
        "target_name": "_ZN10AS80gaE4zW10TdfRgasqpNEv",
        "role": "THTMLPage URL-state initializer",
        "source_table_ea": "0x36ed68",
        "spectron_table_ea": "0x382c18",
        "evidence": [
            "Both bodies clear the three URL-related fields at receiver offsets +112, +128, and +368 and return the receiver.",
            "The target class prefix matches the page methods around the rebuilt URL and line initialization cluster.",
            "The source and target method references are 0x36ed68 and 0x382c18, respectively.",
        ],
    },
    {
        "original_ea": "0x1d1324",
        "original_name": "THTMLPage_setTabStop_int_int",
        "spectron_ea": "0x1d5f78",
        "target_name": "_ZN10AS80gaE4zW10BPX6ga8Ws0Eii",
        "role": "THTMLPage tab-stop replacement helper",
        "source_table_ea": "0x371fe8",
        "spectron_table_ea": "0x385690",
        "evidence": [
            "Both bodies load the tab-stop list at receiver offset +152, replace the entry when the list exists, and return the list result.",
            "The target's rebuilt list type is different, but the receiver field, two integer arguments, and conditional Replace call are unchanged.",
            "The source and target method references are 0x371fe8 and 0x385690, respectively.",
        ],
    },
    {
        "original_ea": "0x1d1d9c",
        "original_name": "THTMLPage_initLines_void",
        "spectron_ea": "0x1d69f0",
        "target_name": "_ZN10AS80gaE4zW10In6QgaHZhNEv",
        "role": "THTMLPage line-list initializer",
        "source_table_ea": "0x36f2b0",
        "spectron_table_ea": "0x384300",
        "evidence": [
            "Both bodies clear the line-list head at receiver offset +336, then point the line-list cursor at that field through receiver offset +88.",
            "The target preserves the same two stores and receiver return despite the obfuscated class and rebuilt surrounding code.",
            "The source and target method references are 0x36f2b0 and 0x384300, respectively.",
        ],
    },
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
    parser.add_argument("--original-binary-sha256", default=SOURCE_BINARY_SHA256)
    parser.add_argument("--spectron-binary-sha256", default=SPECTRON_BINARY_SHA256)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_sources = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    previous_sources = existing_manual_sources(args.artifact_root, args.output)

    anchors = []
    seen_targets: set[int] = set()
    for spec in ANCHOR_SPECS:
        source_ea = int(spec["original_ea"], 16)
        target_ea = int(spec["spectron_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target row at 0x%x" % source_ea)
        if source.get("name") != spec["original_name"]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != spec["target_name"]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if not target["name"].startswith(TARGET_CLASS_PREFIX):
            raise ValueError("target is outside the AS80gaE4zW class family")
        if source_ea in semantic_sources or source_ea in previous_sources:
            raise ValueError("source is already represented by another translation")
        if target_ea in semantic_targets:
            raise ValueError("target is already present in the semantic map")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string reference at 0x%x" % source_ea)
        if source.get("direct_call_names", []) or target.get("direct_call_names", []):
            raise ValueError("unexpected direct call at 0x%x" % source_ea)
        differing = [
            field
            for field in METRIC_FIELDS
            if source.get(field) != target.get(field)
        ]
        if differing:
            raise ValueError(
                "feature mismatch at 0x%x: %s"
                % (source_ea, ", ".join(differing))
            )

        anchors.append(
            {
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
                "match_kind": "manual-html-page-exact-small-method",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "source_component": "THTMLPage",
                "target_component": "AS80gaE4zW",
                "source_table_ea": spec["source_table_ea"],
                "spectron_table_ea": spec["spectron_table_ea"],
                "metric_differences": [],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_html_page_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for eight small THTMLPage methods",
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
        "method": {
            "selection": "reviewed class-local pairing plus exact size, instruction, block, branch, call, return, normalized mnemonic, opcode, register, and string-reference metrics",
            "size_note": "the eight methods are below the normal 32-byte semantic-matcher threshold",
            "class_evidence": "all target names share the AS80gaE4zW obfuscated class prefix",
            "address_policy": "both build-specific addresses are retained; no original address is copied into Spectron",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "new_context_anchor_count": len(anchors),
            "exact_normalized_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The exact normalized feature match is supported by the shared target class prefix and the receiver-field behavior recorded for each row.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
