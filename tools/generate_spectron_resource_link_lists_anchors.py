#!/usr/bin/env python3
"""Create a reviewed anchor for the resource link-list initializer."""

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


SOURCE_EA = 0xE070C
TARGET_EA = 0xE0564
SOURCE_NAME = "TResource_initializeLinkLists"
TARGET_NAME = "sub_E0564"
SOURCE_TABLE_EA = "0x35d218"
TARGET_TABLE_EA = "0x36f8d8"


EVIDENCE = [
    "The source callback is TResource_initializeLinkLists at 0xe070c. It allocates two 0x28-byte THashList objects, constructs each list, stores the first in TResourceFileLink::links, stores the second in TResourceObjectLink::links, and returns the second static pointer.",
    "The target function sub_E0564 at 0xe0564 has the exact normalized shape. It allocates two 0x28-byte KKhLga4xoI objects, constructs each object, stores the first in OOmzgapOmy::IYlQSaJ5EK, stores the second in H4zIGaBY6x::IYlQSaJ5EK, and returns the second static pointer.",
    "The target class OOmzgapOmy is already identified as the resource-file-link class from its one-string constructor and update-dispatch method. The target class H4zIGaBY6x is already identified as the resource-object-link class from its pointer-taking constructor and link lookup method.",
    "The source callback pointer is referenced from the source static-initializer table at 0x35d218. The target callback pointer is referenced from the target static-initializer table at 0x36f8d8, placing both functions in the same startup-initialization role.",
    "Both rows are one-block, 76-byte, 19-instruction initializers with five branches, four calls, one return, and identical normalized mnemonic, opcode, register, shape, and string-reference hashes.",
    "The same exact shape initially collided with a particle-emitter initializer candidate at target 0x2451f4. That candidate is now assigned to the particle script-property initializer because it constructs ULeBJaZ1WYProperties and pdnkJaZ8KKProperties. The target 0xe0564 call set and static fields instead identify the resource link-list initializer.",
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
    if not target.get("is_default_name"):
        raise ValueError("target initializer is no longer a default name")

    semantic_sources = {
        int(row["original_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16)
        for row in semantic_document.get("matches", [])
    }
    if SOURCE_EA in semantic_sources or TARGET_EA in semantic_targets:
        raise ValueError("resource link-list initializer is already mapped")
    if SOURCE_EA in existing_manual_sources(args.artifact_root, args.output):
        raise ValueError("source resource link-list initializer is already anchored")
    if source.get("string_refs", []) or target.get("string_refs", []):
        raise ValueError("unexpected literal strings in the initializer")

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    if source_metrics != target_metrics:
        raise ValueError("resource link-list initializer shape changed")
    expected_source_calls = {
        "plt_THashList_THashList_void__2",
        "plt_operator_new_ulong__2",
    }
    if set(source.get("direct_call_names", [])) != expected_source_calls:
        raise ValueError("unexpected source resource-list call set")
    expected_target_calls = {
        "._ZN10KKhLga4xoIC1Ev",
        "._Znwm",
    }
    if set(target.get("direct_call_names", [])) != expected_target_calls:
        raise ValueError("unexpected target resource-list call set")

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
        "match_kind": "manual-resource-link-list-initializer-exact-shape",
        "semantic_match_already_present": False,
        "source_basis": "resource file-link and object-link list static initializer",
        "context_group": "resource link-list global initialization",
        "target_link_classes": {
            "file_link": {
                "source_class": "TResourceFileLink",
                "target_class": "OOmzgapOmy",
                "target_static_pointer": "OOmzgapOmy::IYlQSaJ5EK",
                "target_constructor_ea": "0xf03ec",
                "target_constructor_alias": "v18_TResourceFileLink_TResourceFileLink_TString_const",
            },
            "object_link": {
                "source_class": "TResourceObjectLink",
                "target_class": "H4zIGaBY6x",
                "target_static_pointer": "H4zIGaBY6x::IYlQSaJ5EK",
                "target_constructor_ea": "0xf06d8",
                "target_constructor_alias": "v18_TResourceObjectLink_TResourceObjectLink_void",
            },
        },
        "target_collision_resolution": {
            "particle_candidate_ea": "0x2451f4",
            "particle_candidate_alias": "v18_TParticleEmitter_initStaticScriptVars_void",
            "particle_candidate_resolution": "accepted for the particle script-property initializer because it constructs ULeBJaZ1WYProperties and pdnkJaZ8KKProperties",
            "resource_candidate_resolution": "accepted here because it constructs KKhLga4xoI objects stored in the two already identified resource-link static lists",
        },
        "target_delta": delta_text(TARGET_EA, SOURCE_EA),
        "evidence": EVIDENCE,
        "name_action": "rename-with-v18-prefix",
        "shape_equal": True,
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_resource_link_lists_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the resource file-link and object-link list static initializer",
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
            "target_default_name_count": 1,
        },
        "context": {
            "source_cluster": "0xe070c resource initializer",
            "spectron_cluster": "0xe0564 resource initializer",
            "source_static_initializer_table": SOURCE_TABLE_EA,
            "spectron_static_initializer_table": TARGET_TABLE_EA,
            "source_classes": ["TResourceFileLink", "TResourceObjectLink"],
            "target_classes": ["OOmzgapOmy", "H4zIGaBY6x"],
            "resolution": "exact normalized initializer shape, startup-table references, independently identified resource-link classes and static fields, and explicit resolution of the particle-emitter collision",
        },
        "anchors": [anchor],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The target default name is replaced with a v18_ analysis alias while the obfuscated name, class fields, call set, and startup-table location remain recorded as evidence.",
            "The exact normalized shape is supported by the two independently identified resource-link classes and their static list pointers.",
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
