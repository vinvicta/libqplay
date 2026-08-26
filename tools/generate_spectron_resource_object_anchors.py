#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for resource-object helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0xed260",
        "original_name": "TResourceFunctions_insertResourceObject_TResourceObject",
        "spectron_ea": "0xee230",
        "target_name_fragment": "EP10bNZvga2Awv",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource insertion and alternative selection",
        "evidence": [
            "The source and target hash the resource filename, look up an existing resource, and either add the new object as an alternative or insert it into the global resource list.",
            "Both invoke the emoticon-file check after a new object is inserted, and both retain the same short five-block decision structure.",
            "The target signature takes the corresponding resource-object pointer in the f6WHgaQkAF resource-function class.",
        ],
    },
    {
        "original_ea": "0xef030",
        "original_name": "resourceobjects_filenamecompare_void_const_void_const",
        "spectron_ea": "0xf0244",
        "target_name_fragment": "PKvS0_",
        "match_kind": "changed-size-comparator-context",
        "source_basis": "resource filename comparator",
        "evidence": [
            "The source comparator orders resource objects first by extension, then by filename, and finally by modification time.",
            "Spectron's target is the comparator passed by its resource-list sorter and preserves the same three-stage ordering, with explicit normalized-string helper calls added by the rebuilt library.",
            "The target sits in the same resource-object cluster and is referenced directly by the reviewed getMatchingResourceObjects correspondence.",
        ],
    },
    {
        "original_ea": "0xef184",
        "original_name": "TResourceFileLink_TResourceFileLink_TString_const",
        "spectron_ea": "0xf03ec",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource-file link constructor from filename",
        "evidence": [
            "Both constructors normalize the supplied filename, initialize the hash-list object base, allocate the linked-list container, and register the link in the global file-link list.",
            "The target preserves the one-string constructor signature and the same resource-file-link class position, while its body is larger because of the target string wrapper calls.",
        ],
    },
    {
        "original_ea": "0xef270",
        "original_name": "TResourceFileLink_invokeUpdate_TString_const",
        "spectron_ea": "0xf04f4",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource-file link update dispatch",
        "evidence": [
            "The source resolves the file link, walks its registered objects from the end of the list, and invokes each object's update method with the changed filename.",
            "Spectron's target performs the same reverse list walk and virtual update dispatch in the adjacent OOmzgapOmy resource-file-link class.",
        ],
    },
    {
        "original_ea": "0xef428",
        "original_name": "TResourceObjectLink_TResourceObjectLink_void",
        "spectron_ea": "0xf06d8",
        "target_name_fragment": "EPv",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource-object link constructor",
        "evidence": [
            "Both constructors convert the linked object pointer to a hash-list key, initialize the link container, and register the object link in its global list.",
            "The target retains the pointer-taking constructor signature and the corresponding H4zIGaBY6x resource-object-link class context.",
        ],
    },
    {
        "original_ea": "0xef5a0",
        "original_name": "TEncodedFileKey_TEncodedFileKey_TString_const",
        "spectron_ea": "0xf086c",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "match_kind": "changed-size-class-context",
        "source_basis": "encoded-file key constructor",
        "evidence": [
            "The source and target initialize a hash-list object from the supplied filename, clear the linked resource pointer, set the key length sentinel to -1, and clear the active flag.",
            "The target has the matching one-string constructor and the corresponding encoded-file-key vtable, despite rebuilt string-wrapper calls changing the size.",
        ],
    },
    {
        "original_ea": "0xef610",
        "original_name": "TResourceObject_TResourceObject_TString_const",
        "spectron_ea": "0xf0904",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource object constructor",
        "evidence": [
            "Both constructors initialize the hash-list object base, clear the alternative metadata pointer and size field, install the resource-object vtable, and leave the extended metadata pointer null.",
            "The target retains the one-string constructor in the corresponding bNZvga2Awv resource-object class.",
        ],
    },
    {
        "original_ea": "0xef7ec",
        "original_name": "TResourceObject_getSize_void",
        "spectron_ea": "0xf0b08",
        "target_name_fragment": "10DlUjZaW0lcEv",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource size query",
        "evidence": [
            "Both return the cached size from the active alternative when it is available, otherwise compose the stored path and filename and query the file size.",
            "The target is the const resource-object method immediately before addZipFile and preserves the same fallback behavior with target string-path helpers.",
        ],
    },
    {
        "original_ea": "0xefbc4",
        "original_name": "TResourceObject_addAlternative_TResourceObject",
        "spectron_ea": "0xf0f1c",
        "target_name_fragment": "10QoawgaFmGvEPS_",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource alternative selection and ordering",
        "evidence": [
            "The source and target compare resource alternatives by active state, .wba preference, file size, and modification time.",
            "Both exchange the primary object when the new alternative wins, create the alternative list on demand, append the object, and sort it with the modification-time comparator.",
            "The target is the corresponding bNZvga2Awv method and preserves the full 31-block decision structure.",
        ],
    },
    {
        "original_ea": "0xefe7c",
        "original_name": "TResourceObject_getStream_void",
        "spectron_ea": "0xf11f0",
        "target_name_fragment": "10L5bygaBNnxEv",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource stream materialization",
        "evidence": [
            "Both materialize a fresh stream, handle cached and zip-backed resources, read the selected file entry, and apply .gani or encoded-resource decryption when required.",
            "The target preserves the same resource-object class method role and the same major branches, including the empty-stream and unavailable-resource paths.",
            "The larger target body reflects Spectron's rebuilt zip, stream, and encryption wrappers rather than a different resource operation.",
        ],
    },
    {
        "original_ea": "0xf03a0",
        "original_name": "TResourceObject_canBeLoaded_void",
        "spectron_ea": "0xf1860",
        "target_name_fragment": "10rGpygapdzxEv",
        "match_kind": "changed-size-class-context",
        "source_basis": "resource loadability predicate",
        "evidence": [
            "The source and target return true for ordinary resources, inspect the active alternative's download state for remote resources, and trigger a download update when the resource is not ready.",
            "The target is the corresponding short bNZvga2Awv loadability method and preserves the same nested-resource and direct-resource branches.",
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
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "mnemonic_hash",
            "register_shape_hash",
            "shape_hash",
        )
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        target_name = target.get("name", "")
        if spec["target_name_fragment"] not in target_name:
            raise ValueError(
                "target %s does not retain expected signature fragment: %s"
                % (spec["spectron_ea"], spec["target_name_fragment"])
            )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target_name,
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": spec["match_kind"],
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in resource-object anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_resource_object_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for resource-object comparison, links, alternatives, and stream materialization",
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
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": sum(
                row["semantic_match_already_present"] for row in anchors
            ),
            "new_context_anchor_count": sum(
                not row["semantic_match_already_present"] for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated 2.2 name in the evidence row.",
            "Simple constructor and destructor families with multiple identical candidates remain unassigned unless class-local behavior resolves them.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
