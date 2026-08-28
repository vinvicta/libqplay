#!/usr/bin/env python3
"""Create reviewed anchors for the small Spectron GuiTextListCtrl family.

The normal matcher omits these methods because they are shorter than 32 bytes.
This generator records exact normalized feature matches together with the
obfuscated target class and the preserved script-table or call-site context.
It does not modify an IDA database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SPECTRON_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
TARGET_CLASS_PREFIX = "_ZN10u0eyga1eqx"

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
        "original_ea": "0x1d8fec",
        "original_name": "GuiTextListCtrl_getCellSize_TPoint",
        "spectron_ea": "0x1ddd28",
        "target_name": "_ZN10u0eyga1eqx10H8ZnobYTN7ER10eY2wgaf6pw",
        "role": "GuiTextListCtrl cell-size getter",
        "source_context": ["0x367298", "0x3687f8"],
        "spectron_context": ["0x37a068", "0x37b5c8"],
        "evidence": [
            "Both bodies read the cell-size value at receiver offset +472, write it to the TPoint result pointer, and return the value.",
            "The target pseudocode identifies the same u0eyga1eqx class family used by the list and sorting methods below.",
            "The source and target class-context references are 0x367298, 0x3687f8 and 0x37a068, 0x37b5c8.",
        ],
    },
    {
        "original_ea": "0x1dc960",
        "original_name": "GuiTextListCtrl_set_sortcolumn",
        "spectron_ea": "0x1e06fc",
        "target_name": "sub_1E06FC",
        "role": "GuiTextListCtrl sort-column property setter",
        "source_context": ["0x383698"],
        "spectron_context": ["0x3966f8"],
        "evidence": [
            "Both bodies write the sort-column value to receiver offset +552 and return the receiver.",
            "The source and target pointers occur in the corresponding GuiTextListCtrl property table records for sortcolumn.",
            "The source and target property-table references are 0x383698 and 0x3966f8.",
        ],
    },
    {
        "original_ea": "0x1de504",
        "original_name": "GuiTextListCtrl_script_clearrows",
        "spectron_ea": "0x1e22a0",
        "target_name": "sub_1E22A0",
        "role": "GuiTextListCtrl clear-rows script wrapper",
        "source_context": ["0x383758"],
        "spectron_context": ["0x3967b8"],
        "evidence": [
            "Both wrappers test the same guard byte at receiver offset +204 and call the class clear method only when the control is not in the guarded state.",
            "The source and target pointers occur in the matching GuiTextListCtrl script-function table entry for clearrows.",
            "The source and target script-table references are 0x383758 and 0x3967b8.",
        ],
    },
    {
        "original_ea": "0x1de6c8",
        "original_name": "GuiTextListCtrl_script_sort",
        "spectron_ea": "0x1e2464",
        "target_name": "sub_1E2464",
        "role": "GuiTextListCtrl default sort script wrapper",
        "source_context": ["0x383c98"],
        "spectron_context": ["0x396cf8"],
        "evidence": [
            "Both wrappers set the default sort mode field at receiver offset +540 when it is zero, then call the class sort method.",
            "The source and target pointers occur in the matching GuiTextListCtrl script-function table entry for sort.",
            "The source and target script-table references are 0x383c98 and 0x396cf8.",
        ],
    },
    {
        "original_ea": "0x1de6dc",
        "original_name": "GuiTextListCtrl_sort_int_bool",
        "spectron_ea": "0x1e2478",
        "target_name": "_ZN10u0eyga1eqx4sortEib",
        "role": "GuiTextListCtrl text sort setter",
        "source_context": ["0x22510"],
        "spectron_context": ["0x1c428"],
        "evidence": [
            "Both bodies set sort mode 2 at +540, invert the requested direction into +544, store the requested column at +552, and call the common sort method.",
            "The target ABI name and pseudocode identify the u0eyga1eqx sort overload with the same int and bool arguments.",
            "The corresponding call-site references are 0x22510 in the source and 0x1c428 in Spectron.",
        ],
    },
    {
        "original_ea": "0x1de6f8",
        "original_name": "GuiTextListCtrl_sortNumerical_int_bool",
        "spectron_ea": "0x1e2494",
        "target_name": "_ZN10u0eyga1eqx10_ThCQaUFPSEib",
        "role": "GuiTextListCtrl numerical sort setter",
        "source_context": ["0x2c350"],
        "spectron_context": ["0x210a8"],
        "evidence": [
            "Both bodies set numerical sort mode 1 at +540, invert the requested direction into +544, store the requested column at +552, and call the common sort method.",
            "The target ABI name and pseudocode identify the matching u0eyga1eqx numerical-sort overload.",
            "The corresponding call-site references are 0x2c350 in the source and 0x210a8 in Spectron.",
        ],
    },
    {
        "original_ea": "0x1df564",
        "original_name": "GuiTextListCtrl_script_removerowbyid",
        "spectron_ea": "0x1e33a8",
        "target_name": "sub_1E33A8",
        "role": "GuiTextListCtrl remove-row script wrapper",
        "source_context": ["0x383ab8"],
        "spectron_context": ["0x396b18"],
        "evidence": [
            "Both wrappers test the guard byte at receiver offset +204 and call removeEntry with the row identifier only when the guard is clear.",
            "The source and target pointers occur in the matching GuiTextListCtrl script-function table entry for removerowbyid.",
            "The source and target script-table references are 0x383ab8 and 0x396b18.",
        ],
    },
    {
        "original_ea": "0x1df690",
        "original_name": "GuiTextListCtrl_addColumnOffset_int",
        "spectron_ea": "0x1e34d4",
        "target_name": "_ZN10u0eyga1eqx10_jHwgaC36vEi",
        "role": "GuiTextListCtrl column-offset append helper",
        "source_context": ["0x374008"],
        "spectron_context": ["0x382ea8"],
        "evidence": [
            "Both bodies load the column-offset list from receiver offset +520 and append the integer argument through the list Add method.",
            "The target ABI name and pseudocode identify the same u0eyga1eqx class and rebuilt list type.",
            "The source and target class-context references are 0x374008 and 0x382ea8.",
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


def existing_manual_addresses(artifact_root: Path, output: Path) -> tuple[set[int], set[int]]:
    source_addresses: set[int] = set()
    target_addresses: set[int] = set()
    for path in artifact_root.glob("spectron_*_manual_translation_anchors_*.json"):
        if path.resolve() == output.resolve():
            continue
        try:
            document = load(path)
        except (OSError, json.JSONDecodeError):
            continue
        for anchor in document.get("anchors", []):
            for key, result in (("original_ea", source_addresses), ("spectron_ea", target_addresses)):
                value = anchor.get(key)
                if isinstance(value, str):
                    try:
                        result.add(int(value, 16))
                    except ValueError:
                        pass
    return source_addresses, target_addresses


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
    previous_sources, previous_targets = existing_manual_addresses(args.artifact_root, args.output)

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
        if not (
            target["name"].startswith(TARGET_CLASS_PREFIX)
            or target["name"].startswith("sub_")
        ):
            raise ValueError("target is outside the u0eyga1eqx class family")
        if source_ea in semantic_sources or source_ea in previous_sources:
            raise ValueError("source is already represented by another translation")
        if target_ea in semantic_targets or target_ea in previous_targets:
            raise ValueError("target is already represented by another translation")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string reference at 0x%x" % source_ea)
        if source.get("direct_call_names", []) or target.get("direct_call_names", []):
            raise ValueError("unexpected direct call at 0x%x" % source_ea)
        differing = [field for field in METRIC_FIELDS if source.get(field) != target.get(field)]
        if differing:
            raise ValueError(
                "feature mismatch at 0x%x: %s" % (source_ea, ", ".join(differing))
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
                "match_kind": "manual-gui-text-list-exact-small-method",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "source_component": "GuiTextListCtrl",
                "target_component": "u0eyga1eqx",
                "source_context": spec["source_context"],
                "spectron_context": spec["spectron_context"],
                "metric_differences": [],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_text_list_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for eight small GuiTextListCtrl methods",
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
            "class_evidence": "all target ABI names belong to the u0eyga1eqx obfuscated class family or its IDA-demangled form",
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
            "The exact feature match is supported by the shared target class family, receiver-field behavior, and preserved script-table or call-site context.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
