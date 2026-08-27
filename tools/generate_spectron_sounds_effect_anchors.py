#!/usr/bin/env python3
"""Create reviewed anchors for the TSounds sound-effect object path.

The source sound-effect constructor was previously left unmatched because
Spectron adds an obfuscated helper-string construction to the body. The
adjacent lookup method is also shape-compatible with several other hash-list
lookups. This artifact keeps the object family, field behavior, cleanup, and
direct-call roles together so the two translations remain auditable.
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

SOURCE_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SPECTRON_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"


ANCHOR_SPECS = [
    {
        "original_ea": "0xe0dc0",
        "original_name": "TSoundEffect_TSoundEffect_TString_const",
        "spectron_ea": "0xe1970",
        "target_name": "_ZN10fEVMgax6LJC2ERK10C8THgaTQxF",
        "proposed_name": "v18_TSoundEffect_TSoundEffect_TString_const",
        "source_basis": "TSoundEffect constructor from a TString",
        "target_component": "fEVMgax6LJ sound-effect object",
        "source_direct_calls": [
            "plt_TFiles_lowerCaseFilename_TString_const",
            "plt_THashListObject_THashListObject_TString_const",
            "plt_TString_clear_void",
            "plt_TString_operator_assign_TString_const",
        ],
        "target_direct_calls": [
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10C8THgaTQxFaSERKS_",
            "._ZN10CanTfaz6bZ5clearEv",
            "._ZN10CanTfaz6bZaSERK10C8THgaTQxF",
            "._ZN10J7zOgaf09KC2ERK10CanTfaz6bZ",
            "._ZN10wiULgacZUI10RUnvgavJ0uERK10C8THgaTQxF",
        ],
        "expected_metric_differences": {
            "size",
            "instruction_count",
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
            "register_shape_hash",
            "register_detail_hash",
            "shape_hash",
        },
        "shape_equal": False,
        "evidence": [
            "The source constructor lowercases the filename, constructs the hash-list base, clears the temporary TString, installs the TSoundEffect vtable, copies the original filename, and initializes the playback fields.",
            "The Spectron constructor performs the same filename normalization and object initialization through C8THgaTQxF, then constructs and clears a target-only CanTfaz6bZ helper before initializing the fEVMgax6LJ object.",
            "The target fEVMgax6LJ method family at 0xe3714 through 0xe3744 exposes the sound-effect accessors and mutators, independently identifying the constructor's class role.",
            "The target sound-effect Java constructor at 0xe4098 calls this constructor, linking the translated TSounds lookup result to the same object family.",
        ],
    },
    {
        "original_ea": "0xe0e48",
        "original_name": "TSounds_getSoundEffect_TString_const",
        "spectron_ea": "0xe1a1c",
        "target_name": "_ZN10IUKzgam4Gy10adFVZaKh7HERK10C8THgaTQxF",
        "proposed_name": "v18_TSounds_getSoundEffect_TString_const",
        "source_basis": "TSounds case-insensitive sound-effect hash lookup",
        "target_component": "IUKzgam4Gy sound-effects cache",
        "source_direct_calls": [
            "plt_TFiles_lowerCaseFilename_TString_const",
            "plt_THashList_getHashcode_TString_const",
            "plt_THashList_getObjectIgnoreCase_uint_TString_const",
            "plt_TString_clear_void",
        ],
        "target_direct_calls": [
            "._ZN10C8THgaTQxF5clearEv",
            "._ZN10KKhLga4xoI10g4ouMaaIbpERK10C8THgaTQxF",
            "._ZN10KKhLga4xoI10sZ8vgajaFvEjRK10C8THgaTQxF",
            "._ZN10wiULgacZUI10RUnvgavJ0uERK10C8THgaTQxF",
        ],
        "expected_metric_differences": {"register_detail_hash"},
        "shape_equal": True,
        "evidence": [
            "The source reads the TSounds sound-effects hash list, lowercases the requested filename, computes its hash, performs a case-insensitive object lookup, and clears the temporary string.",
            "The Spectron body reads IUKzgam4Gy::fqEVZaFC6H, performs the same lowercasing, hash, lookup, and temporary-string cleanup sequence through the obfuscated C8THgaTQxF and KKhLga4xoI helpers.",
            "The returned object is the fEVMgax6LJ sound-effect family constructed by the adjacent target constructor at 0xe1970.",
            "Other target rows with the same normalized shape belong to separate hash-list classes, while this row is fixed by the IUKzgam4Gy sound-effects global and its position beside the translated sound wrappers.",
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
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
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
        if source_ea in semantic_sources or target_ea in semantic_targets:
            raise ValueError("sound-effect row is already in the semantic map")
        if source_ea in previous_sources:
            raise ValueError("sound-effect source is already manually anchored")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string references")
        if source.get("direct_call_names", []) != spec["source_direct_calls"]:
            raise ValueError("unexpected source direct calls at 0x%x" % source_ea)
        if target.get("direct_call_names", []) != spec["target_direct_calls"]:
            raise ValueError("unexpected target direct calls at 0x%x" % target_ea)
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
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-sounds-effect-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "source_component": "TSounds and TSoundEffect",
                "target_component": spec["target_component"],
                "metric_differences": sorted(differing),
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": spec["shape_equal"],
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_sounds_effect_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the TSounds sound-effect constructor and cache lookup",
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
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "layout_change_anchor_count": sum(
                not row["shape_equal"] for row in anchors
            ),
            "source_default_name_count": sum(
                row["original_name"].startswith("sub_") for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "context": {
            "source_classes": ["TSounds", "TSoundEffect"],
            "target_class_clusters": ["IUKzgam4Gy", "fEVMgax6LJ"],
            "resolution": "sound-effects global, constructor class family, direct-call roles, adjacent sound-wrapper order, and complete normalized ARM64 features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The constructor is recorded as a layout-change anchor because Spectron adds a CanTfaz6bZ helper-string construction and associated cleanup.",
            "The cache lookup retains the source normalized shape; its target direct calls are obfuscated class methods and its register-detail fingerprint differs.",
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
