#!/usr/bin/env python3
"""Create reviewed anchors for the 1.8 random-generator family.

The source build exposes readable MRandomGenerator, MRandomLCG, and
MRandomR250 names. Spectron keeps the same contiguous class block under the
obfuscated o3AZxayNqc, Vx2_xajLEd, and ZwL1xarB5e classes. This script records
the class order, lifecycle roles, static-generator global, and normalized
ARM64 features without modifying an IDA database.
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


def spec(
    original_ea: str,
    original_name: str,
    spectron_ea: str,
    target_name: str,
    source_component: str,
    target_component: str,
    role: str,
    behavior: str,
    source_context: list[str],
    spectron_context: list[str],
    expected_metric_differences: set[str] | frozenset[str] = frozenset(
        {"register_detail_hash"}
    ),
    allow_semantic_match: bool = False,
) -> dict:
    return {
        "original_ea": original_ea,
        "original_name": original_name,
        "spectron_ea": spectron_ea,
        "target_name": target_name,
        "source_component": source_component,
        "target_component": target_component,
        "role": role,
        "behavior": behavior,
        "source_context": source_context,
        "spectron_context": spectron_context,
        "expected_metric_differences": set(expected_metric_differences),
        "allow_semantic_match": allow_semantic_match,
    }


ANCHOR_SPECS = [
    spec(
        "0x1e3b88",
        "MRandomGenerator_initStaticVars_void",
        "0x1e7a58",
        "_Z10Byh1xaKnHev",
        "MRandomGenerator",
        "Vx2_xajLEd",
        "MRandomGenerator static generator initializer",
        "allocate and retain the process-wide LCG generator, then remove it from the garbage collector",
        ["0x36ead8"],
        ["0x383268"],
        allow_semantic_match=True,
    ),
    spec(
        "0x1e3574",
        "MRandomGenerator_MRandomGenerator_TString_const",
        "0x1e7444",
        "_ZN10o3AZxayNqcC1ERK10C8THgaTQxF",
        "MRandomGenerator",
        "o3AZxayNqc",
        "MRandomGenerator string constructor",
        "initialize the base static-variable object from a string and call initObject",
        ["0x3713f0"],
        ["0x380540"],
    ),
    spec(
        "0x1e35a4",
        "MRandomGenerator_MRandomGenerator_void",
        "0x1e7474",
        "_ZN10o3AZxayNqcC1Ev",
        "MRandomGenerator",
        "o3AZxayNqc",
        "MRandomGenerator default constructor",
        "construct the default generator name, initialize the base static-variable object, and call initObject",
        ["0xb7e8", "0x1f0a8"],
        ["0xe268", "0x18888"],
    ),
    spec(
        "0x1e36d0",
        "MRandomLCG_initObject_int",
        "0x1e75a0",
        "_ZN10Vx2_xajLEd10j9gLgaw2nIEi",
        "MRandomLCG",
        "Vx2_xajLEd",
        "MRandomLCG integer initializer",
        "set the initialized flags, install the LCG property table, and dispatch the base virtual initializer",
        ["0x373748"],
        ["0x381f48"],
    ),
    spec(
        "0x1e3710",
        "MRandomLCG_MRandomLCG_TString_const",
        "0x1e75e0",
        "_ZN10Vx2_xajLEdC1ERK10C8THgaTQxF",
        "MRandomLCG",
        "Vx2_xajLEd",
        "MRandomLCG string constructor",
        "construct the MRandomGenerator base, advance the shared seed, install the LCG vtable, and initialize it",
        ["0x36ea20"],
        ["0x380540"],
    ),
    spec(
        "0x1e3760",
        "MRandomLCG_create_TString_const",
        "0x1e7630",
        "_Z20Vx2_xajLEdE7Bm2aaHDBRK10C8THgaTQxF",
        "MRandomLCG",
        "Vx2_xajLEd",
        "MRandomLCG factory",
        "allocate a 0x90-byte LCG object and invoke its string constructor",
        ["0x375098"],
        ["0x387a20"],
        expected_metric_differences=set(),
    ),
    spec(
        "0x1e3790",
        "MRandomLCG_MRandomLCG_void",
        "0x1e7660",
        "_ZN10Vx2_xajLEdC2Ev",
        "MRandomLCG",
        "Vx2_xajLEd",
        "MRandomLCG default constructor",
        "construct the default base name, advance the shared seed, install the LCG vtable, and initialize it",
        ["0x372860"],
        ["0x386a18"],
    ),
    spec(
        "0x1e3814",
        "MRandomLCG_MRandomLCG_int",
        "0x1e76e4",
        "_ZN10Vx2_xajLEdC2Ei",
        "MRandomLCG",
        "Vx2_xajLEd",
        "MRandomLCG integer constructor",
        "construct the default base name, install the LCG vtable, and initialize it with the supplied seed",
        ["0x36fa50"],
        ["0x383cd8"],
    ),
    spec(
        "0x1e39d8",
        "MRandomR250_initObject_int",
        "0x1e78a8",
        "_ZN10ZwL1xarB5e10j9gLgaw2nIEi",
        "MRandomR250",
        "ZwL1xarB5e",
        "MRandomR250 integer initializer",
        "set the initialized flags, install the R250 property table, and dispatch the base virtual initializer",
        ["0x36f318"],
        ["0x385108"],
    ),
    spec(
        "0x1e3a18",
        "MRandomR250_MRandomR250_TString_const",
        "0x1e78e8",
        "_ZN10ZwL1xarB5eC1ERK10C8THgaTQxF",
        "MRandomR250",
        "ZwL1xarB5e",
        "MRandomR250 string constructor",
        "construct the MRandomGenerator base, advance the shared seed, install the R250 vtable, and initialize it",
        ["0x373a58"],
        ["0x382f40"],
    ),
    spec(
        "0x1e3a68",
        "MRandomR250_create_TString_const",
        "0x1e7938",
        "_Z20ZwL1xarB5eE7Bm2aaHDBRK10C8THgaTQxF",
        "MRandomR250",
        "ZwL1xarB5e",
        "MRandomR250 factory",
        "allocate a 0x478-byte R250 object and invoke its string constructor",
        ["0x3758e0"],
        ["0x387a70"],
        expected_metric_differences=set(),
    ),
    spec(
        "0x1e3a98",
        "MRandomR250_MRandomR250_void",
        "0x1e7968",
        "_ZN10ZwL1xarB5eC1Ev",
        "MRandomR250",
        "ZwL1xarB5e",
        "MRandomR250 default constructor",
        "construct the default base name, advance the shared seed, install the R250 vtable, and initialize it",
        ["0xcdf0", "0x28918"],
        ["0xac08", "0x25608"],
    ),
    spec(
        "0x1e3b1c",
        "MRandomR250_MRandomR250_int",
        "0x1e79ec",
        "_ZN10ZwL1xarB5eC2Ei",
        "MRandomR250",
        "ZwL1xarB5e",
        "MRandomR250 integer constructor",
        "construct the default base name, install the R250 vtable, and initialize it with the supplied seed",
        ["0x168d0", "0x20f98"],
        ["0x16db8", "0x1d178"],
    ),
    spec(
        "0x1e3cb8",
        "MRandomGeneratorProperties_MRandomGeneratorProperties",
        "0x1e7b88",
        "_ZN20o3AZxayNqcPropertiesD2Ev",
        "MRandomGeneratorProperties",
        "o3AZxayNqcProperties",
        "MRandomGeneratorProperties complete destructor",
        "install both property vtables and destroy the shared property base",
        ["0x3693d0"],
        ["0x37c1a0"],
    ),
    spec(
        "0x1e3cd4",
        "non_virtual_thunk_to_MRandomGeneratorProperties_MRandomGeneratorProperties",
        "0x1e7ba4",
        "_ZThn16_N20o3AZxayNqcPropertiesD1Ev",
        "MRandomGeneratorProperties",
        "o3AZxayNqcProperties",
        "MRandomGeneratorProperties non-virtual destructor thunk",
        "adjust the secondary property subobject by 16 bytes and call the complete destructor",
        ["0x369408"],
        ["0x37c1d8"],
        expected_metric_differences=set(),
    ),
    spec(
        "0x1e3cdc",
        "MRandomLCGProperties_MRandomLCGProperties",
        "0x1e7bac",
        "_ZN20Vx2_xajLEdPropertiesD1Ev",
        "MRandomLCGProperties",
        "Vx2_xajLEdProperties",
        "MRandomLCGProperties complete destructor",
        "install both LCG-property vtables and destroy the shared property base",
        ["0x369430"],
        ["0x37c200"],
    ),
    spec(
        "0x1e3cf8",
        "non_virtual_thunk_to_MRandomLCGProperties_MRandomLCGProperties",
        "0x1e7bc8",
        "_ZThn16_N20Vx2_xajLEdPropertiesD1Ev",
        "MRandomLCGProperties",
        "Vx2_xajLEdProperties",
        "MRandomLCGProperties non-virtual destructor thunk",
        "adjust the secondary property subobject by 16 bytes and call the complete destructor",
        ["0x369468"],
        ["0x37c238"],
        expected_metric_differences=set(),
    ),
    spec(
        "0x1e3d00",
        "MRandomR250Properties_MRandomR250Properties",
        "0x1e7bd0",
        "_ZN20ZwL1xarB5ePropertiesD1Ev",
        "MRandomR250Properties",
        "ZwL1xarB5eProperties",
        "MRandomR250Properties complete destructor",
        "install both R250-property vtables and destroy the shared property base",
        ["0x369490"],
        ["0x37c260"],
    ),
    spec(
        "0x1e3d1c",
        "non_virtual_thunk_to_MRandomR250Properties_MRandomR250Properties",
        "0x1e7bec",
        "_ZThn16_N20ZwL1xarB5ePropertiesD1Ev",
        "MRandomR250Properties",
        "ZwL1xarB5eProperties",
        "MRandomR250Properties non-virtual destructor thunk",
        "adjust the secondary property subobject by 16 bytes and call the complete destructor",
        ["0x3694c8"],
        ["0x37c298"],
        expected_metric_differences=set(),
    ),
    spec(
        "0x1e3d24",
        "MRandomGeneratorProperties_MRandomGeneratorProperties__2",
        "0x1e7bf4",
        "_ZN20o3AZxayNqcPropertiesD0Ev",
        "MRandomGeneratorProperties",
        "o3AZxayNqcProperties",
        "MRandomGeneratorProperties deleting destructor",
        "install both property vtables, destroy the shared property base, and delete the object",
        ["0x3693d8"],
        ["0x37c1a8"],
    ),
    spec(
        "0x1e3d5c",
        "non_virtual_thunk_to_MRandomGeneratorProperties_MRandomGeneratorProperties__2",
        "0x1e7c2c",
        "_ZThn16_N20o3AZxayNqcPropertiesD0Ev",
        "MRandomGeneratorProperties",
        "o3AZxayNqcProperties",
        "MRandomGeneratorProperties deleting-destructor thunk",
        "adjust the secondary property subobject by 16 bytes and call the deleting destructor",
        ["0x369410"],
        ["0x37c1e0"],
        expected_metric_differences=set(),
    ),
    spec(
        "0x1e3d64",
        "MRandomLCGProperties_MRandomLCGProperties__2",
        "0x1e7c34",
        "_ZN20Vx2_xajLEdPropertiesD0Ev",
        "MRandomLCGProperties",
        "Vx2_xajLEdProperties",
        "MRandomLCGProperties deleting destructor",
        "install both LCG-property vtables, destroy the shared property base, and delete the object",
        ["0x369438"],
        ["0x37c208"],
    ),
    spec(
        "0x1e3d9c",
        "non_virtual_thunk_to_MRandomLCGProperties_MRandomLCGProperties__2",
        "0x1e7c6c",
        "_ZThn16_N20Vx2_xajLEdPropertiesD0Ev",
        "MRandomLCGProperties",
        "Vx2_xajLEdProperties",
        "MRandomLCGProperties deleting-destructor thunk",
        "adjust the secondary property subobject by 16 bytes and call the deleting destructor",
        ["0x369470"],
        ["0x37c240"],
        expected_metric_differences=set(),
    ),
    spec(
        "0x1e3da4",
        "MRandomR250Properties_MRandomR250Properties__2",
        "0x1e7c74",
        "_ZN20ZwL1xarB5ePropertiesD0Ev",
        "MRandomR250Properties",
        "ZwL1xarB5eProperties",
        "MRandomR250Properties deleting destructor",
        "install both R250-property vtables, destroy the shared property base, and delete the object",
        ["0x369498"],
        ["0x37c268"],
    ),
    spec(
        "0x1e3ddc",
        "non_virtual_thunk_to_MRandomR250Properties_MRandomR250Properties__2",
        "0x1e7cac",
        "_ZThn16_N20ZwL1xarB5ePropertiesD0Ev",
        "MRandomR250Properties",
        "ZwL1xarB5eProperties",
        "MRandomR250Properties deleting-destructor thunk",
        "adjust the secondary property subobject by 16 bytes and call the deleting destructor",
        ["0x3694d0"],
        ["0x37c2a0"],
        expected_metric_differences=set(),
    ),
    spec(
        "0x1e3de4",
        "MRandomLCG_MRandomLCG",
        "0x1e7cb4",
        "_ZN10Vx2_xajLEdD2Ev",
        "MRandomLCG",
        "Vx2_xajLEd",
        "MRandomLCG complete destructor",
        "restore the base static-variable vtable and destroy the MRandomGenerator base",
        ["0x3694f0"],
        ["0x37c2c0"],
    ),
    spec(
        "0x1e3df8",
        "MRandomLCG_MRandomLCG__2",
        "0x1e7cc8",
        "_ZN10Vx2_xajLEdD0Ev",
        "MRandomLCG",
        "Vx2_xajLEd",
        "MRandomLCG deleting destructor",
        "restore the base static-variable vtable, destroy the MRandomGenerator base, and delete the object",
        ["0x3694f8"],
        ["0x37c2c8"],
    ),
    spec(
        "0x1e3e28",
        "MRandomR250_MRandomR250",
        "0x1e7cf8",
        "_ZN10ZwL1xarB5eD2Ev",
        "MRandomR250",
        "ZwL1xarB5e",
        "MRandomR250 complete destructor",
        "restore the base static-variable vtable and destroy the MRandomGenerator base",
        ["0x369650"],
        ["0x37c420"],
        expected_metric_differences={"register_detail_hash"},
    ),
    spec(
        "0x1e3e3c",
        "MRandomR250_MRandomR250__2",
        "0x1e7d0c",
        "_ZN10ZwL1xarB5eD0Ev",
        "MRandomR250",
        "ZwL1xarB5e",
        "MRandomR250 deleting destructor",
        "restore the base static-variable vtable, destroy the MRandomGenerator base, and delete the object",
        ["0x369658"],
        ["0x37c428"],
    ),
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


def existing_manual_rows(artifact_root: Path, output: Path) -> list[dict]:
    rows = []
    for path in artifact_root.glob("spectron_*_manual_translation_anchors_*.json"):
        if path.resolve() == output.resolve():
            continue
        try:
            document = load(path)
        except (OSError, json.JSONDecodeError):
            continue
        rows.extend(row for row in document.get("anchors", []) if isinstance(row, dict))
    return rows


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
    semantic_by_source = {
        int(row["original_ea"], 16): row
        for row in semantic_document.get("matches", [])
    }
    semantic_by_target = {
        int(row["spectron_ea"], 16): row
        for row in semantic_document.get("matches", [])
    }
    previous_rows = existing_manual_rows(args.artifact_root, args.output)
    previous_sources = {
        int(row["original_ea"], 16)
        for row in previous_rows
        if isinstance(row.get("original_ea"), str)
    }
    previous_targets = {
        int(row["spectron_ea"], 16)
        for row in previous_rows
        if isinstance(row.get("spectron_ea"), str)
    }

    anchors = []
    seen_sources: set[int] = set()
    seen_targets: set[int] = set()
    for item in ANCHOR_SPECS:
        source_ea = int(item["original_ea"], 16)
        target_ea = int(item["spectron_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target row at 0x%x" % source_ea)
        if source.get("name") != item["original_name"]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != item["target_name"]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in previous_sources or source_ea in seen_sources:
            raise ValueError("source is already represented at 0x%x" % source_ea)
        if target_ea in previous_targets or target_ea in seen_targets:
            raise ValueError("target is already represented at 0x%x" % target_ea)
        seen_sources.add(source_ea)
        seen_targets.add(target_ea)

        semantic_source = semantic_by_source.get(source_ea)
        semantic_target = semantic_by_target.get(target_ea)
        semantic_match_already_present = semantic_source is not None or semantic_target is not None
        if semantic_match_already_present and not item["allow_semantic_match"]:
            raise ValueError("unexpected semantic-map overlap at 0x%x" % source_ea)
        if semantic_match_already_present:
            if semantic_source is None or semantic_source.get("spectron_ea") != item["spectron_ea"]:
                raise ValueError("semantic source overlap points to another target at 0x%x" % source_ea)
            if semantic_source.get("confidence") != "medium":
                raise ValueError("expected the static initializer overlap to be medium confidence")

        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string reference at 0x%x" % source_ea)

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differing = {
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        }
        expected = item["expected_metric_differences"]
        if differing != expected:
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
                "original_context": item["source_context"],
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_context": item["spectron_context"],
                "source_component": item["source_component"],
                "target_component": item["target_component"],
                "proposed_name": "v18_" + item["original_name"],
                "confidence": "high",
                "match_kind": "manual-mrandom-family-class-anchor",
                "semantic_match_already_present": semantic_match_already_present,
                "source_basis": item["role"],
                "behavior": item["behavior"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "target_delta_decimal": target_ea - source_ea,
                "metric_differences": sorted(differing),
                "evidence": [
                    "The source and target rows occupy the same contiguous random-generator family block after the shared color and point helpers.",
                    "The class-local context and target ABI name identify the corresponding o3AZxayNqc, Vx2_xajLEd, or ZwL1xarB5e component.",
                    item["behavior"].capitalize() + ".",
                    "All normalized shape fields match; any register-detail difference is recorded as a target register-allocation change.",
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
                "layout_change": False,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_mrandom_family_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the MRandomGenerator, MRandomLCG, and MRandomR250 class block",
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
            "already_in_semantic_map": sum(
                row["semantic_match_already_present"] for row in anchors
            ),
            "new_context_anchor_count": sum(
                not row["semantic_match_already_present"] for row in anchors
            ),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(
                not row["metric_differences"] for row in anchors
            ),
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
            "source_classes": [
                "MRandomGenerator",
                "MRandomLCG",
                "MRandomR250",
                "MRandomGeneratorProperties",
                "MRandomLCGProperties",
                "MRandomR250Properties",
            ],
            "target_classes": [
                "o3AZxayNqc",
                "Vx2_xajLEd",
                "ZwL1xarB5e",
                "o3AZxayNqcProperties",
                "Vx2_xajLEdProperties",
                "ZwL1xarB5eProperties",
            ],
            "resolution": "contiguous class-local order, matching constructor and destructor roles, static-generator global reference, target ABI class names, allocator sizes, and normalized ARM64 shape",
            "static_generator_global": {
                "source": "gRandGen",
                "target": "Lry_xa0Aed",
            },
        },
        "deferred_review": [],
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The random-generator block is resolved by class order and lifecycle role, not by size alone. The LCG and R250 constructors use different object sizes and different target vtables, while their shared base constructors map to o3AZxayNqc.",
            "The static initializer was a medium-confidence feature match before review. Its target body allocates the 0x90-byte Vx2_xajLEd LCG, stores it in Lry_xa0Aed, and calls the target garbage-collector removal helper, which resolves the earlier collision with unrelated static initializers.",
            "The target ABI names and direct-call names are retained in the evidence rows alongside the readable v18_ aliases.",
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
