#!/usr/bin/env python3
"""Create reviewed anchors for the remaining TSounds tail methods.

The stop-SFX wrapper and script pitch bridge are exact normalized ARM64
matches.  The adjacent static initializer keeps the same compiler-generated
one-block sequence and class-local order, but its second target container is
larger in Spectron, so that row is recorded as a layout-change anchor.
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
        "original_ea": "0xe0ea4",
        "original_name": "TSounds_stopSFX_TString_const",
        "spectron_ea": "0xe1a78",
        "target_name": "_ZN10IUKzgam4Gy10jIWZZaS_ILERK10C8THgaTQxF",
        "proposed_name": "v18_TSounds_stopSFX_TString_const",
        "source_callback_table_ea": "0x376120",
        "spectron_callback_table_ea": "0x389120",
        "source_class": "TSounds",
        "target_class": "IUKzgam4Gy",
        "role": "TSounds stop one sound effect by filename",
        "source_direct_calls": ["plt_TSounds_getSoundEffect_TString_const"],
        "target_direct_calls": [
            "._ZN10IUKzgam4Gy10adFVZaKh7HERK10C8THgaTQxF"
        ],
        "expected_metric_differences": set(),
        "shape_equal": True,
        "semantic_confidence": "medium",
        "evidence": [
            "The existing semantic matcher had already proposed the same target at medium confidence from the compact shape, but the row was not yet applied to the IDA copy.",
            "The source resolves the requested sound effect through TSounds::getSoundEffect and calls the returned object's virtual stop method at offset +112 when the lookup succeeds.",
            "The Spectron body makes the corresponding IUKzgam4Gy::adFVZaKh7H lookup and calls the same +112 virtual stop slot.",
            "The source callback-table reference at 0x376120 and target reference at 0x389120 place both rows in the TSounds sound-effect wrapper table.",
            "All normalized feature fields match, including register detail, and the target lookup is the already reviewed sound-effect cache method at 0xe1a1c.",
        ],
    },
    {
        "original_ea": "0xe2a7c",
        "original_name": "TSounds_script_setSoundPitch",
        "spectron_ea": "0xe366c",
        "target_name": "sub_E366C",
        "proposed_name": "v18_TSounds_script_setSoundPitch",
        "source_callback_table_ea": "0x376450",
        "spectron_callback_table_ea": "0x389450",
        "source_class": "TSounds",
        "target_class": "IUKzgam4Gy",
        "role": "TSounds script set-sound-pitch bridge",
        "source_direct_calls": [],
        "target_direct_calls": [],
        "expected_metric_differences": set(),
        "shape_equal": True,
        "semantic_confidence": "high",
        "evidence": [
            "The source callback receives the script value in a TString-shaped argument, loads its double payload into the floating-point argument register, and forwards it to TSounds::setSoundPitch.",
            "The Spectron body has the identical three-instruction bridge and forwards the same payload to IUKzgam4Gy::wgG1Zawa1N.",
            "The source callback-table reference at 0x376450 and target reference at 0x389450 identify the corresponding script function entry.",
            "All normalized feature fields match, including register detail, and the row sits directly before the corresponding static initializer in both TSounds class-local clusters.",
        ],
    },
    {
        "original_ea": "0xe2a88",
        "original_name": "TSounds_initStaticVars_void",
        "spectron_ea": "0xe3678",
        "target_name": "_Z10WACL2aR4FWv",
        "proposed_name": "v18_TSounds_initStaticVars_void",
        "source_class": "TSounds",
        "target_class": "IUKzgam4Gy",
        "role": "TSounds sound-cache static initializer",
        "source_static_xrefs": ["0x2f8c0", "0x374108"],
        "spectron_static_xrefs": ["0x1daa8", "0x383a50"],
        "source_direct_calls": [
            "plt_THashList_THashList_void__2",
            "plt_TStringList_TStringList_void",
            "plt_operator_new_ulong__2",
        ],
        "target_direct_calls": [
            "._ZN10KKhLga4xoIC1Ev",
            "._ZN10vuuHgangcFC2Ev",
            "._Znwm",
        ],
        "expected_metric_differences": {
            "opcode_shape_hash",
            "register_shape_hash",
            "register_detail_hash",
            "shape_hash",
        },
        "shape_equal": False,
        "semantic_confidence": "high",
        "evidence": [
            "The source allocates a 0x28-byte THashList for the TSounds sound-effects cache, constructs it, then allocates and constructs the disabled-sound-effects TStringList before storing both static pointers.",
            "The target keeps the same one-block instruction sequence, allocation order, four-call count, return convention, and class-local position after the script pitch bridge.",
            "The target first container is the 0x28-byte KKhLga4xoI object stored in IUKzgam4Gy::fqEVZaFC6H, the renamed sound-effects cache global used by the adjacent sound methods.",
            "The target second container is the vuuHgangcF object stored in IUKzgam4Gy::mDUVZaIfkI. Its allocation is 0x20 bytes instead of the source TStringList allocation of 0x18 bytes, which explains the immediate and register-shape changes.",
            "The source static registration references at 0x2f8c0 and 0x374108 correspond to target references at 0x1daa8 and 0x383a50. The source and target feature differences are limited to the recorded shape fields caused by the changed target helper types.",
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
    semantic_by_source = {
        int(row["original_ea"], 16): row
        for row in semantic_document.get("matches", [])
    }
    semantic_by_target = {
        int(row["spectron_ea"], 16): row
        for row in semantic_document.get("matches", [])
    }
    previous_sources = existing_manual_sources(args.artifact_root, args.output)
    anchors = []
    seen_targets: set[int] = set()
    overlap_count = 0
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
        if source_ea in previous_sources:
            raise ValueError("sound tail source is already manually anchored")
        if target_ea in seen_targets:
            raise ValueError("duplicate target address at 0x%x" % target_ea)
        seen_targets.add(target_ea)

        semantic_source = semantic_by_source.get(source_ea)
        semantic_target = semantic_by_target.get(target_ea)
        if semantic_source is not None or semantic_target is not None:
            if semantic_source is None or semantic_target is None:
                raise ValueError("incomplete semantic-map sound-tail row at 0x%x" % source_ea)
            if semantic_source is not semantic_target:
                raise ValueError("source and target semantic rows disagree at 0x%x" % source_ea)
            if semantic_source.get("confidence") != spec["semantic_confidence"]:
                raise ValueError("unexpected semantic confidence at 0x%x" % source_ea)
            proposed_name = semantic_source["alias_name"]
            semantic_present = True
            overlap_count += 1
        else:
            proposed_name = spec["proposed_name"]
            semantic_present = False

        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string references at 0x%x" % source_ea)
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
        if spec["shape_equal"] and differing:
            raise ValueError("exact sound-tail row is not exact at 0x%x" % source_ea)
        if not spec["shape_equal"] and not any(
            source_metrics[field] != target_metrics[field] for field in SHAPE_FIELDS
        ):
            raise ValueError("layout-change row has no shape evidence at 0x%x" % source_ea)

        anchor = {
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
            "proposed_name": proposed_name,
            "confidence": "high",
            "match_kind": "manual-sounds-tail-context-anchor",
            "semantic_match_already_present": semantic_present,
            "source_basis": spec["role"],
            "source_component": spec["source_class"],
            "target_component": spec["target_class"],
            "metric_differences": sorted(differing),
            "target_delta": "+0x%x" % (target_ea - source_ea),
            "evidence": spec["evidence"],
            "name_action": "rename-with-v18-prefix",
            "shape_equal": spec["shape_equal"],
        }
        for key in (
            "source_callback_table_ea",
            "spectron_callback_table_ea",
            "source_static_xrefs",
            "spectron_static_xrefs",
        ):
            if key in spec:
                anchor[key] = spec[key]
        anchors.append(anchor)

    result = {
        "schema_version": 1,
        "artifact": "spectron_sounds_tail_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TSounds stop-SFX, script pitch, and static sound-cache initialization",
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
            "already_in_semantic_map": overlap_count,
            "new_context_anchor_count": len(anchors) - overlap_count,
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(
                not row["metric_differences"] for row in anchors
            ),
            "layout_change_anchor_count": sum(
                not row["shape_equal"] for row in anchors
            ),
            "source_default_name_count": sum(
                row["original_name"].startswith("sub_") for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"]
                for row in anchors
            ),
        },
        "context": {
            "source_class": "TSounds",
            "target_class_cluster": "IUKzgam4Gy",
            "resolution": "sound-effect callback table, class-local script order, static global ownership, allocation sequence, target helper types, and complete normalized ARM64 features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The stop-SFX row upgrades an existing medium-confidence shape candidate because the target lookup and virtual stop call are now confirmed in the sound class cluster.",
            "The script pitch bridge is an exact callback-table and class-order match.",
            "The static initializer is a high-confidence layout-change anchor. Its changed second helper type explains the shape-field differences, while its allocation order, global ownership, function order, and registration references remain consistent.",
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
