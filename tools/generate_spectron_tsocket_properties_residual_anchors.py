#!/usr/bin/env python3
"""Create reviewed anchors for the residual TSocketProperties destructors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The source TSocketProperties destructor family is the four-function block at 0x205e94, 0x205eb0, 0x205eb8, and 0x205ef0. Spectron keeps the corresponding XJLBgarMnAProperties D1, non-virtual D1 thunk, D0, and non-virtual D0 thunk at 0x20bfa0, 0x20bfbc, 0x20bfc4, and 0x20bffc.",
    "The complete destructor writes both source vtable fields, then calls the TProperties base cleanup. The target D1 destructor writes the two XJLBgarMnAProperties vtable fields and calls the c76BgaJBGA base destructor. The deleting destructor adds the same operator-delete step in both builds.",
    "Each non-virtual thunk adjusts the this pointer by 16 bytes and forwards to the corresponding complete or deleting destructor. The thunk bodies remain separate functions in both IDA databases.",
    "All four pairs have exact size, instruction, block, branch, call, mnemonic, opcode-shape, register-shape, and overall-shape matches. The source and target rows are adjacent within their respective destructor families and have no string references.",
]


SOURCE_TARGETS = {
    0x205E94: 0x20BFA0,
    0x205EB0: 0x20BFBC,
    0x205EB8: 0x20BFC4,
    0x205EF0: 0x20BFFC,
}

EXPECTED_SOURCE_NAMES = {
    0x205E94: "TSocketProperties_TSocketProperties",
    0x205EB0: "non_virtual_thunk_to_TSocketProperties_TSocketProperties",
    0x205EB8: "TSocketProperties_TSocketProperties__2",
    0x205EF0: "non_virtual_thunk_to_TSocketProperties_TSocketProperties__2",
}

EXPECTED_TARGET_NAMES = {
    0x20BFA0: "_ZN20XJLBgarMnAPropertiesD1Ev",
    0x20BFBC: "_ZThn16_N20XJLBgarMnAPropertiesD1Ev",
    0x20BFC4: "_ZN20XJLBgarMnAPropertiesD0Ev",
    0x20BFFC: "_ZThn16_N20XJLBgarMnAPropertiesD0Ev",
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
            raise ValueError("destructor metrics differ at 0x%x" % source_ea)
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
                "match_kind": "manual-tsocket-properties-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": "TSocketProperties destructor family %s" % source["name"],
                "context_group": "TSocketProperties residual destructor family",
                "context_order": order,
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_tsocket_properties_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TSocketProperties destructor family",
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
            "source_sequence": "0x205e94 through 0x205ef0 in the TSocketProperties destructor family",
            "target_sequence": "0x20bfa0 through 0x20bffc in the XJLBgarMnAProperties destructor family",
            "source_class": "TSocketProperties",
            "target_class": "XJLBgarMnAProperties",
            "target_delta": "+0x612c",
            "following_target_boundary": "0x20c008",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable source destructor and thunk roles while retaining the target class names in the evidence rows.",
            "The complete and deleting destructor pairs are resolved by vtable writes, base cleanup, operator-delete behavior, thunk adjustment, class-local order, and exact normalized metrics.",
            "All four pairs are exact normalized-shape matches and the target names were already non-default.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
