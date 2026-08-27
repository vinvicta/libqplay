#!/usr/bin/env python3
"""Create a reviewed anchor for the particle-emitter script-property initializer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from generate_spectron_gsfunctions_client_exact_residual_anchors import (
    existing_manual_sources,
)


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


SOURCE_EA = 0x23B348
TARGET_EA = 0x2451F4
SOURCE_NAME = "TParticleEmitter_initStaticScriptVars_void"
TARGET_NAME = "_Z10L7ezIahlg6v"
SOURCE_TABLE_EA = "0x36f068"
TARGET_TABLE_EA = "0x383fc8"


EVIDENCE = [
    "The source callback is TParticleEmitter_initStaticScriptVars_void at 0x23b348. It allocates and constructs TParticleModifierProperties and TParticleEmitterProperties, then stores the two objects in the corresponding static property pointers.",
    "The target function at 0x2451f4 is the exact normalized-shape counterpart. It allocates and constructs ULeBJaZ1WYProperties and pdnkJaZ8KKProperties, then stores them in ULeBJaZ1WYOnln2aNBfC and pdnkJaZ8KKOnln2aNBfC.",
    "The target property constructors were independently translated from TParticleModifierProperties_TParticleModifierProperties_void and TParticleEmitterProperties_TParticleEmitterProperties_void. Their constructor bodies identify ULeBJaZ1WYProperties as the modifier-property class and pdnkJaZ8KKProperties as the emitter-property class.",
    "The target function is in the same particle-emitter cluster: it follows the already translated v18_TParticleEmitter_initStaticVars_void at 0x245114 and immediately precedes the already translated v18_TParticleEmitter_emit_T3DFloatPoint_const_uint_bool at 0x245240.",
    "The source and target rows are both one-block, 76-byte, 19-instruction initializers with five branches, four calls, one return, and identical normalized mnemonic, opcode, register, shape, and string-reference hashes.",
    "The callback pointer is referenced from the source static-initializer table at 0x36f068 and the target static-initializer table at 0x383fc8. The target table entry is also reached through the target initialization wrapper at 0x1fad0.",
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
    if target.get("is_default_name"):
        raise ValueError("target initializer unexpectedly has a default name")
    semantic_sources = {
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    if SOURCE_EA in semantic_sources or TARGET_EA in semantic_targets:
        raise ValueError("particle-emitter script initializer is already mapped")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("source particle-emitter script initializer is already anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal strings in the initializer")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics != target_metrics:
        raise ValueError("particle-emitter script initializer shape changed")
    expected_target_calls = {
        "._ZN20ULeBJaZ1WYPropertiesC1Ev",
        "._ZN20pdnkJaZ8KKPropertiesC1Ev",
        "._Znwm",
    }
    if set(target.get("direct_call_names", [])) != expected_target_calls:
        raise ValueError("unexpected target property-constructor call set")
    expected_source_calls = {
        "plt_TParticleModifierProperties_TParticleModifierProperties_void",
        "plt_TParticleEmitterProperties_TParticleEmitterProperties_void",
        "plt_operator_new_ulong__2",
    }
    if set(source.get("direct_call_names", [])) != expected_source_calls:
        raise ValueError("unexpected source property-constructor call set")

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
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "manual-particle-emitter-script-property-initializer-exact-shape",
        "semantic_match_already_present": False,
        "source_basis": "particle-emitter script-property static initializer",
        "context_group": "particle-emitter static variable and script-property initialization",
        "target_property_classes": {
            "modifier_properties": {
                "source_class": "TParticleModifierProperties",
                "target_class": "ULeBJaZ1WYProperties",
                "target_constructor_ea": "0x242588",
                "target_static_pointer": "ULeBJaZ1WYOnln2aNBfC",
            },
            "emitter_properties": {
                "source_class": "TParticleEmitterProperties",
                "target_class": "pdnkJaZ8KKProperties",
                "target_constructor_ea": "0x242b18",
                "target_static_pointer": "pdnkJaZ8KKOnln2aNBfC",
            },
        },
        "target_neighbors": {
            "previous_ea": "0x245114",
            "previous_name": "v18_TParticleEmitter_initStaticVars_void",
            "next_ea": "0x245240",
            "next_name": "v18_TParticleEmitter_emit_T3DFloatPoint_const_uint_bool",
        },
        "target_initialization_wrapper_ea": "0x1fad0",
        "target_delta": "+0x11ec",
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": True,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_particle_emitter_script_vars_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the particle-emitter script-property static initializer",
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
            "target_default_name_count": 0,
        },
        "context": {
            "source_cluster": "0x23b274 through 0x23b394",
            "spectron_cluster": "0x245114 through 0x245700",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_class": "TParticleEmitter",
            "target_class": "pdnkJaZ8KK",
            "resolution": "exact normalized initializer shape, independently translated target property constructors, static table references, and class-local neighbors",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The target keeps an obfuscated but structurally corresponding initializer name. The proposed v18_ alias preserves the readable source role while the evidence retains the target name.",
            "The exact normalized shape is supported by the target constructor call set and the independently translated target property classes.",
            "The alias is valid only for the exact hashed Spectron library named in this artifact. It changes the IDA analysis copy only; no APK or native library is modified.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
