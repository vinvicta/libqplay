#!/usr/bin/env python3
"""Create reviewed anchors for the update-package-properties lifecycle block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source rows are the uninstall jump thunk and the complete or deleting TUpdatePackageProperties destructor family at 0x20aab8 through 0x20ab18. Spectron preserves the same local family at 0x210cb4 through 0x210d14.",
    "The uninstall thunk forwards to TUpdatePackage_uninstall_void, while the target jump thunk forwards to RH6ygazf9x::TrDxob8NUf. Both are one-instruction jump wrappers with the same normalized shape.",
    "The source constructor-like TUpdatePackageProperties label carries the alternative symbol name _ZN24TUpdatePackagePropertiesD2Ev and restores two vtable fields before calling the TProperties base cleanup. Spectron's RH6ygazf9xProperties D2 destructor performs the same work through c76BgaJBGA.",
    "The deleting destructor variants repeat the vtable and base cleanup and then call operator delete. Each 16-byte non-virtual thunk subtracts 16 from the object pointer before forwarding to its corresponding destructor in both builds.",
    "All five pairs have identical size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, and overall shape. Every target name was already non-default.",
]


SOURCE_TARGETS = {
    0x20AAB8: 0x210CB4,
    0x20AABC: 0x210CB8,
    0x20AAD8: 0x210CD4,
    0x20AAE0: 0x210CDC,
    0x20AB18: 0x210D14,
}

EXPECTED_SOURCE_NAMES = {
    0x20AAB8: "jump_TUpdatePackage_uninstall_void",
    0x20AABC: "TUpdatePackageProperties_TUpdatePackageProperties",
    0x20AAD8: "non_virtual_thunk_to_TUpdatePackageProperties_TUpdatePackageProperties",
    0x20AAE0: "TUpdatePackageProperties_TUpdatePackageProperties__2",
    0x20AB18: "non_virtual_thunk_to_TUpdatePackageProperties_TUpdatePackageProperties__2",
}

EXPECTED_TARGET_NAMES = {
    0x210CB4: "j_._ZN10RH6ygazf9x10TrDxob8NUfEv",
    0x210CB8: "_ZN20RH6ygazf9xPropertiesD2Ev",
    0x210CD4: "_ZThn16_N20RH6ygazf9xPropertiesD1Ev",
    0x210CDC: "_ZN20RH6ygazf9xPropertiesD0Ev",
    0x210D14: "_ZThn16_N20RH6ygazf9xPropertiesD0Ev",
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
            raise ValueError("unexpected update-package-properties shape result at 0x%x" % source_ea)
        if target.get("is_default_name", False):
            raise ValueError("target is unexpectedly default at 0x%x" % target_ea)
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
                "match_kind": "manual-update-package-properties-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "update-package-properties lifecycle method %s" % source["name"],
                "context_group": "TUpdatePackageProperties destructor and uninstall residual block",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_update_package_properties_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TUpdatePackageProperties lifecycle block",
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
            "source_sequence": "0x20aab8 uninstall jump thunk through 0x20ab18 TUpdatePackageProperties deleting-destructor thunk",
            "target_sequence": "0x210cb4 uninstall jump thunk through 0x210d14 RH6ygazf9xProperties deleting-destructor thunk",
            "source_class": "TUpdatePackageProperties",
            "target_class": "RH6ygazf9xProperties",
            "target_only_boundaries": ["0x210bc8 RH6ygazf9x uninstall implementation", "0x210d1c TSocketConnection certificate helper"],
            "following_target_boundary": "0x210d1c TSocketConnection_setVerifyGraalWebCert_void",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source lifecycle roles while retaining the target obfuscated names in the evidence rows.",
            "The source constructor-like labels have alternative D2 and D0 destructor names. The decompilation and vtable or base cleanup sequence establish their destructor roles.",
            "All five pairs are exact normalized-shape matches and all target names were already non-default.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
