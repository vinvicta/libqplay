#!/usr/bin/env python3
"""Create reviewed anchors for the compact T2DMatrixManager method block.

The source names survive in the 1.8 build.  Spectron keeps the same method
block under the named AUzMgaePtJ class, while the list helper type and direct
call names are rebuilt.  This script records the class-local context and the
normalized ARM64 shape without modifying an IDA database.
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
SHAPE_FIELDS = tuple(field for field in METRIC_FIELDS if field != "register_detail_hash")

SOURCE_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SPECTRON_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"


ANCHOR_SPECS = [
    {
        "original_ea": "0xfd1e4",
        "original_name": "T2DMatrixManager_isActivated_void",
        "spectron_ea": "0xff800",
        "target_name": "_ZN10AUzMgaePtJ10t5AMgadPuJEv",
        "source_context": ["0x373750"],
        "spectron_context": ["0x3810b8"],
        "source_component": "T2DMatrixManager",
        "target_component": "AUzMgaePtJ",
        "role": "2D matrix manager activation getter",
        "behavior": "return whether the matrix list exists and has at least one entry",
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The target ABI name places the method in the AUzMgaePtJ class, and the target body reads AUzMgaePtJ::UuAMgaMjuJ.",
            "The source and target bodies perform the same global-list presence and positive-count test.",
            "The source and target class-local references are 0x373750 and 0x3810b8.",
        ],
    },
    {
        "original_ea": "0xfd20c",
        "original_name": "T2DMatrixManager_getTop_void",
        "spectron_ea": "0xff828",
        "target_name": "_ZN10AUzMgaePtJ10dGBMgabjvJEv",
        "source_context": ["0x36e3c0"],
        "spectron_context": ["0x383c90"],
        "source_component": "T2DMatrixManager",
        "target_component": "AUzMgaePtJ",
        "role": "2D matrix manager top-entry getter",
        "behavior": "return the final matrix-list entry when the list is nonempty, otherwise null",
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The target ABI name places the method in the same AUzMgaePtJ class as the activation getter.",
            "Both bodies check the list count, subtract one, call the list index operator, and return the stored matrix pointer.",
            "The source and target class-local references are 0x36e3c0 and 0x383c90.",
        ],
    },
    {
        "original_ea": "0xfd258",
        "original_name": "T2DMatrixManager_clear_void",
        "spectron_ea": "0xff874",
        "target_name": "_ZN10AUzMgaePtJ5clearEv",
        "source_context": ["0x370cb0"],
        "spectron_context": ["0x386728"],
        "source_component": "T2DMatrixManager",
        "target_component": "AUzMgaePtJ",
        "role": "2D matrix manager clear operation",
        "behavior": "delete each stored matrix and clear the backing list when initialized",
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The target ABI name and surrounding method block identify the AUzMgaePtJ clear method.",
            "Both bodies walk the list, delete each stored matrix, and call the list Clear method after the loop.",
            "The source and target class-local references are 0x370cb0 and 0x386728.",
        ],
    },
    {
        "original_ea": "0xfd478",
        "original_name": "T2DMatrixManager_pop_void",
        "spectron_ea": "0xffa94",
        "target_name": "_ZN10AUzMgaePtJ3popEv",
        "source_context": ["0x374608"],
        "spectron_context": ["0x383e00"],
        "source_component": "T2DMatrixManager",
        "target_component": "AUzMgaePtJ",
        "role": "2D matrix manager pop operation",
        "behavior": "remove and delete the final matrix entry when the list is nonempty",
        "expected_metric_differences": {"register_detail_hash"},
        "evidence": [
            "The target ABI name places the method in the same AUzMgaePtJ class as the other three rows.",
            "Both bodies read the final list entry, delete that list position, and then delete the removed matrix object.",
            "The source and target class-local references are 0x374608 and 0x383e00.",
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
        if source_ea in semantic_sources or source_ea in previous_sources:
            raise ValueError("source is already represented at 0x%x" % source_ea)
        if target_ea in semantic_targets or target_ea in seen_targets:
            raise ValueError("target is already represented at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string reference at 0x%x" % source_ea)

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differing = {
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        }
        if differing != spec["expected_metric_differences"]:
            raise ValueError(
                "unexpected metric differences at 0x%x: %s"
                % (source_ea, ", ".join(sorted(differing)))
            )
        if any(source_metrics[field] != target_metrics[field] for field in SHAPE_FIELDS):
            raise ValueError("normalized shape mismatch at 0x%x" % source_ea)

        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_context": spec["source_context"],
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_context": spec["spectron_context"],
                "source_component": spec["source_component"],
                "target_component": spec["target_component"],
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-t2d-matrix-manager-class-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "behavior": spec["behavior"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "target_delta_decimal": target_ea - source_ea,
                "metric_differences": sorted(differing),
                "evidence": spec["evidence"]
                + [
                    "The source and target direct-call lists are retained so the rebuilt TList helper names can be audited separately.",
                    "All normalized shape fields match; the register-detail difference is recorded as a target register-allocation change.",
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
                "layout_change": False,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_t2d_matrix_manager_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the compact T2DMatrixManager method block",
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
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(
                not row["metric_differences"] for row in anchors
            ),
            "layout_change_anchor_count": 0,
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"]
                for row in anchors
            ),
            "source_default_name_count": sum(
                row["original_name"].startswith("sub_") for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "context": {
            "source_class": "T2DMatrixManager",
            "target_class": "AUzMgaePtJ",
            "target_list_helper": "vy1JgaKVkH",
            "resolution": "contiguous class-local method block, target ABI class name, matching pseudocode, helper-call role, and normalized ARM64 shape",
        },
        "deferred_review": [
            {
                "original_ea": "0xfd4e0",
                "original_name": "T2DMatrixManager_initStaticVars_void",
                "reason": "Its compact static-initializer shape matches several unrelated target initializers; the target AUzMgaePtJ global initializer needs a separate global-reference proof before renaming.",
            }
        ],
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "All four rows preserve the matrix-list tests, indexing, deletion, and clear behavior. The rebuilt target uses the obfuscated AUzMgaePtJ and vy1JgaKVkH names, which are kept in the target fields alongside the readable aliases.",
            "The four rows differ only in register_detail_hash. Direct-call names differ because the target list helper is rebuilt, but those calls are recorded rather than treated as a behavior mismatch.",
            "The T2DMatrixManager static initializer remains explicitly deferred because shape alone is not enough to choose among several target static initializers.",
            "The v18_ aliases are scoped to the exact hashed Spectron library in the inputs and are an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
