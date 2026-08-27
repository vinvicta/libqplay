#!/usr/bin/env python3
"""Create reviewed anchors for residual update-package wrapper helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source rows are the remaining update-package failure, containment, force-wrapper, and download-complete helpers at 0x209260, 0x209310, 0x209414, 0x20993c, 0x209944, and 0x20a798. Their corresponding target roles occur at 0x20f3f8, 0x20f4e4, 0x20f5e8, 0x20fb10, 0x20fb18, and 0x210958.",
    "updatePackageFailed and updatePackageDownloaded both check the active client for a .gupd download, then notify the game environment with the onPackagesDownloaded event when appropriate. Spectron keeps that behavior through C8THgaTQxF, w6qzgacqqy, QYZugaRKGu, and G0gxgajWBw wrappers; the download-complete form also loads the selected package first.",
    "The two containment helpers lowercase the requested filename, walk either the downloadingpackages or privilegedpackages list, inspect each package file list, compare normalized paths, and return the matching package. Their target bodies retain the same nested iteration and cleanup sequence through vy1JgaKVkH, vuuHgangcF, and wiULgacZUI wrappers.",
    "The no-force and force script wrappers forward to TUpdatePackage_update_bool with false and true respectively. Spectron exposes the same immediate constants through RH6ygazf9x::mP6ygaUl9x.",
    "The failure and download-complete rows grow from 176/42/7/12/7 to 236/57/7/16/11 and from 196/47/7/14/9 to 256/62/7/18/13. The two containment rows and both boolean wrappers have exact normalized shapes.",
]


SOURCE_TARGETS = {
    0x209260: 0x20F3F8,
    0x209310: 0x20F4E4,
    0x209414: 0x20F5E8,
    0x20993C: 0x20FB10,
    0x209944: 0x20FB18,
    0x20A798: 0x210958,
}

EXPECTED_SOURCE_NAMES = {
    0x209260: "updatePackageFailed_TString_const",
    0x209310: "getContainingUpdatePackage_TString_const",
    0x209414: "getContainingPrivilegedPackage_TString_const",
    0x20993C: "TUpdatePackage_updateNoForce",
    0x209944: "TUpdatePackage_updateForce",
    0x20A798: "updatePackageDownloaded_TString_const",
}

EXPECTED_TARGET_NAMES = {
    0x20F3F8: "_Z10PPxXSam4HQRK10C8THgaTQxF",
    0x20F4E4: "_Z10e3y_Sao6eTRK10C8THgaTQxF",
    0x20F5E8: "_Z10k1gxobOWBfRK10C8THgaTQxF",
    0x20FB10: "sub_20FB10",
    0x20FB18: "sub_20FB18",
    0x210958: "_Z10by20SakLuURK10C8THgaTQxF",
}

EXACT_SHAPE_SOURCE_EAS = {0x209310, 0x209414, 0x20993C, 0x209944}


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
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
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
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for order, (source_ea, target_ea) in enumerate(SOURCE_TARGETS.items(), 1):
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at 0x%x" % source_ea)
        if source.get("name") != EXPECTED_SOURCE_NAMES[source_ea]:
            raise ValueError("unexpected source name at 0x%x" % source_ea)
        if target.get("name") != EXPECTED_TARGET_NAMES[target_ea]:
            raise ValueError("unexpected target name at 0x%x" % target_ea)
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: 0x%x" % source_ea)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: 0x%x" % target_ea)
        shape_equal = all(source.get(field) == target.get(field) for field in metrics(source))
        expected_shape_equal = source_ea in EXACT_SHAPE_SOURCE_EAS
        if shape_equal != expected_shape_equal:
            raise ValueError("unexpected update-package wrapper shape result at 0x%x" % source_ea)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": "0x%x" % target_ea,
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-update-package-wrapper-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "update-package wrapper %s" % source["name"],
                "context_group": "TUpdatePackage package-event and lookup residual block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_update_package_wrapper_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual update-package event and lookup wrappers",
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
            "layout_change_anchor_count": sum(not row["shape_equal"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_sequence": "0x209260 updatePackageFailed, 0x209310 and 0x209414 containment lookups, 0x20993c and 0x209944 boolean wrappers, and 0x20a798 updatePackageDownloaded",
            "target_sequence": "0x20f3f8 failure event, 0x20f4e4 and 0x20f5e8 containment lookups, 0x20fb10 and 0x20fb18 boolean wrappers, and 0x210958 download event",
            "source_class": "TClient and TUpdatePackage",
            "target_class": "w6qzgacqqy, RH6ygazf9x, and related obfuscated helpers",
            "target_only_boundaries": ["0x20f1b8 requestUpdate already mapped", "0x20f6ec TUpdatePackageProperties constructor already mapped", "0x20f79c TUpdatePackage constructor already mapped", "0x210a58 getdownloadingpackage already mapped"],
            "following_target_boundary": "0x210a84 TUpdatePackage script lookup helper already mapped",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source package roles while retaining the target obfuscated or default names in the evidence rows.",
            "The failure and download-event bodies are layout-change anchors because Spectron expands the temporary string and event-wrapper sequence. The two containment helpers and both boolean wrappers are exact normalized-shape matches.",
            "The force and no-force rows are the only default target names in this batch, so they are the only rows that reduce the database default-name count.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
