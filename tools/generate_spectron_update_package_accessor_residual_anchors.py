#!/usr/bin/env python3
"""Create reviewed anchors for the residual update-package accessor block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source rows form one ordered accessor block from 0x208a70 through 0x208be8. Spectron preserves the same order at 0x20ec08 through 0x20ed80, which makes the block boundary and one-to-one pairing unusually strong.",
    "The first two rows return the global base-package pointer and the downloading-package list count. The next twelve rows return the same TUpdatePackage byte, dword, double, qword, and nested-list fields at the same offsets shown by the source decompilation.",
    "The final six rows copy the platform, name, mode, auxiliary string, filename, and description TString fields. Each target uses C8THgaTQxF::operator= in the same 48-byte wrapper shape as the source TString assignment helper.",
    "Every pair has identical size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, and overall shape. The ordered block and matching field offsets provide the semantic distinction between the otherwise repetitive accessors.",
    "All twenty target entries were still default sub_ names. These aliases therefore reduce the database default-name count while preserving the original target address and the evidence needed to audit each field role.",
]


SOURCE_TARGETS = {
    0x208A70: 0x20EC08,
    0x208A80: 0x20EC18,
    0x208A94: 0x20EC2C,
    0x208A9C: 0x20EC34,
    0x208AA4: 0x20EC3C,
    0x208AB0: 0x20EC48,
    0x208AB8: 0x20EC50,
    0x208AC0: 0x20EC58,
    0x208AC8: 0x20EC60,
    0x208AD0: 0x20EC68,
    0x208AD8: 0x20EC70,
    0x208AE0: 0x20EC78,
    0x208AE8: 0x20EC80,
    0x208AF0: 0x20EC88,
    0x208AF8: 0x20EC90,
    0x208B28: 0x20ECC0,
    0x208B58: 0x20ECF0,
    0x208B88: 0x20ED20,
    0x208BB8: 0x20ED50,
    0x208BE8: 0x20ED80,
}

EXPECTED_SOURCE_NAMES = {
    0x208A70: "TClient_getBasePackage",
    0x208A80: "TClient_getDownloadingPackageCount",
    0x208A94: "TUpdatePackage_getDownloadComplete",
    0x208A9C: "TUpdatePackage_getDownloadBytesField228",
    0x208AA4: "TUpdatePackage_getFileCount",
    0x208AB0: "TUpdatePackage_getDwordField236",
    0x208AB8: "TUpdatePackage_getDwordField232",
    0x208AC0: "TUpdatePackage_getByteField249",
    0x208AC8: "TUpdatePackage_getDoubleField216",
    0x208AD0: "TUpdatePackage_getQwordField128",
    0x208AD8: "TUpdatePackage_getProtectOverwrite",
    0x208AE0: "TUpdatePackage_getTotalBytesField224",
    0x208AE8: "TUpdatePackage_getUseChecksum",
    0x208AF0: "TUpdatePackage_getVersion",
    0x208AF8: "TUpdatePackage_getPlatform",
    0x208B28: "TUpdatePackage_getName",
    0x208B58: "TUpdatePackage_getMode",
    0x208B88: "TUpdatePackage_getStringField240",
    0x208BB8: "TUpdatePackage_getFilename",
    0x208BE8: "TUpdatePackage_getDescription",
}

EXPECTED_TARGET_NAMES = {
    0x20EC08: "sub_20EC08",
    0x20EC18: "sub_20EC18",
    0x20EC2C: "sub_20EC2C",
    0x20EC34: "sub_20EC34",
    0x20EC3C: "sub_20EC3C",
    0x20EC48: "sub_20EC48",
    0x20EC50: "sub_20EC50",
    0x20EC58: "sub_20EC58",
    0x20EC60: "sub_20EC60",
    0x20EC68: "sub_20EC68",
    0x20EC70: "sub_20EC70",
    0x20EC78: "sub_20EC78",
    0x20EC80: "sub_20EC80",
    0x20EC88: "sub_20EC88",
    0x20EC90: "sub_20EC90",
    0x20ECC0: "sub_20ECC0",
    0x20ECF0: "sub_20ECF0",
    0x20ED20: "sub_20ED20",
    0x20ED50: "sub_20ED50",
    0x20ED80: "sub_20ED80",
}


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
        if not shape_equal:
            raise ValueError("unexpected update-package accessor shape result at 0x%x" % source_ea)
        if not target.get("is_default_name", False):
            raise ValueError("target is unexpectedly non-default at 0x%x" % target_ea)
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
                "match_kind": "manual-update-package-accessor-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "ordered update-package accessor %s" % source["name"],
                "context_group": "TClient and TUpdatePackage accessor residual block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_update_package_accessor_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TClient and TUpdatePackage accessor block",
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
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "source_sequence": "0x208a70 TClient_getBasePackage through 0x208be8 TUpdatePackage_getDescription",
            "target_sequence": "0x20ec08 through 0x20ed80 in the ordered default accessor block",
            "source_class": "TClient and TUpdatePackage",
            "target_class": "w6qzgacqqy and RH6ygazf9x",
            "target_only_boundaries": ["0x20edb0 aggregate download-complete helper", "0x20ee2c package progress helper", "0x20eea0 package aggregate helper"],
            "following_target_boundary": "0x20ef40 TUpdatePackage constructor or destructor boundary",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source accessor roles while retaining the original target sub_ names in the evidence rows.",
            "All twenty pairs are exact normalized-shape matches. The ordered block and identical field offsets support the individual getter assignments.",
            "The source field names ending in Field are deliberately conservative where the original member name was not recovered.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
