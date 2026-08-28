#!/usr/bin/env python3
"""Create reviewed anchors for compact encryption and TGraalVar helpers.

The source names survive in the 1.8 database, while Spectron keeps an
obfuscated property-registration bridge and a named G0gxgajWBw class.  The
artifact records exact normalized feature matches and the relevant static or
property-table context without modifying an IDA database.
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
        "original_ea": "0xe6b7c",
        "original_name": "TEncryption_initStaticScriptVars_void",
        "spectron_ea": "0xe7764",
        "target_name": "_Z10mYk6FatfX1v",
        "source_context": ["0x36f320"],
        "spectron_context": ["0x380748"],
        "source_component": "TEncryption",
        "target_component": "cWWYfaxbT2 property-registration bridge",
        "role": "TEncryption script-property initializer",
        "behavior": "register the 15-entry encryption property table",
        "evidence": [
            "Both bodies forward a null receiver, a static property-table pointer, and the count 15 to the script-property registration routine.",
            "The source and target static table references are 0x36f320 and 0x380748, respectively.",
            "The target pseudocode calls cWWYfaxbT2::DpbOGacdQC, the rebuilt counterpart of TScriptProperty::addFuncs.",
        ],
    },
    {
        "original_ea": "0xe6b90",
        "original_name": "TGraalVar_isPaused_void",
        "spectron_ea": "0xe7778",
        "target_name": "_ZN10G0gxgajWBw10DGtmMaBAwiEv",
        "source_context": ["0x35ef98", "0x35f9b8", "0x35ff08"],
        "spectron_context": ["0x371d18", "0x372758", "0x372cc8"],
        "source_component": "TGraalVar",
        "target_component": "G0gxgajWBw",
        "role": "TGraalVar paused-state getter",
        "behavior": "return the paused byte at receiver offset +17",
        "evidence": [
            "Both are direct two-instruction getters that return the byte at receiver offset +17.",
            "The target ABI name identifies the G0gxgajWBw class, the obfuscated counterpart of TGraalVar in this compact helper cluster.",
            "Representative source and target references preserve the same repeated property or callback context: 0x35ef98, 0x35f9b8, 0x35ff08 and 0x371d18, 0x372758, 0x372cc8.",
        ],
    },
    {
        "original_ea": "0xe6b98",
        "original_name": "TGraalVar_setProtectedObject_int",
        "spectron_ea": "0xe7780",
        "target_name": "_ZN10G0gxgajWBw10wjnCga8dUAEi",
        "source_context": ["0x35efa8", "0x35f9c8", "0x35ff18"],
        "spectron_context": ["0x371d28", "0x372768", "0x372cd8"],
        "source_component": "TGraalVar",
        "target_component": "G0gxgajWBw",
        "role": "TGraalVar protected-object setter",
        "behavior": "store the supplied byte at receiver offset +18 and return the receiver",
        "evidence": [
            "Both are direct two-instruction setters that write the supplied byte to receiver offset +18 and return the receiver pointer.",
            "The target ABI name places the setter beside the matched G0gxgajWBw paused-state getter.",
            "Representative source and target references preserve the same repeated property or callback context: 0x35efa8, 0x35f9c8, 0x35ff18 and 0x371d28, 0x372768, 0x372cd8.",
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
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
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
        if source_ea in semantic_sources or source_ea in previous_sources:
            raise ValueError("source is already represented at 0x%x" % source_ea)
        if target_ea in semantic_targets or target_ea in seen_targets:
            raise ValueError("target is already represented at 0x%x" % target_ea)
        seen_targets.add(target_ea)
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected literal string reference at 0x%x" % source_ea)
        if source.get("direct_call_names", []) or target.get("direct_call_names", []):
            raise ValueError("unexpected direct call at 0x%x" % source_ea)

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differing = [
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        ]
        if differing:
            raise ValueError(
                "feature mismatch at 0x%x: %s"
                % (source_ea, ", ".join(differing))
            )

        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_context": spec["source_context"],
                "spectron_ea": target["ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_context": spec["spectron_context"],
                "source_component": spec["source_component"],
                "target_component": spec["target_component"],
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-encryption-graalvar-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "behavior": spec["behavior"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "metric_differences": [],
                "evidence": spec["evidence"]
                + [
                    "All recorded ARM64 features match exactly, including register detail and string-reference hash."
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_encryption_graalvar_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the compact TEncryption initializer and TGraalVar state helpers",
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
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": len(anchors),
            "full_metric_exact_count": len(anchors),
            "layout_change_anchor_count": 0,
            "source_default_name_count": sum(
                row["original_name"].startswith("sub_") for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "context": {
            "source_class_cluster": "TEncryption and TGraalVar",
            "target_class_cluster": "cWWYfaxbT2 property bridge and G0gxgajWBw",
            "resolution": "exact normalized ARM64 features, target ABI class names, static or property-table context, and direct receiver-field behavior",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "All three rows match every recorded feature and have no literal string references or direct call names in the feature export.",
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
