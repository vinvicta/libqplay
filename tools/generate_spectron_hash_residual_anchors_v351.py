#!/usr/bin/env python3
"""Create reviewed anchors for the remaining Spectron hash helpers.

The earlier hash passes covered the main lookup, lifecycle, and container
families.  This pass records the wrapper overloads and the remaining
THashStrings methods that were already readable in the copied target IDB but
were still absent from the source-backed semantic map.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ARTIFACT = "spectron_hash_residual_manual_translation_anchors_20260829"
METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)

GENERAL_EVIDENCE = [
    "The source and target methods sit in the corresponding THashList/KKhLga4xoI and THashStrings/yL3_IaDMFt class-local clusters.",
    "The target uses C8THgaTQxF and CanTfaz6bZ string wrappers where the 1.8 source uses TString. Wrapper expansion changes some instruction and control-flow metrics, so those rows are recorded as layout-aware rather than exact-shape matches.",
    "The target addresses and names are valid only for the exact hashed Spectron ARM64 library recorded in the feature export. The v18_ names are analysis aliases, not claims that the stripped target retained 1.8 debug symbols.",
]

ANCHOR_SPECS = [
    {
        "original_ea": "0xeac64",
        "original_name": "THashList_addObject_THashListObject_TString_const",
        "spectron_ea": "0xeb904",
        "target_name": "_ZN10KKhLga4xoI9addObjectEP10J7zOgaf09KRK10C8THgaTQxF",
        "proposed_name": "v18_THashList_addObject_THashListObject_TString_const",
        "source_category": "ambiguous",
        "exact_shape": True,
        "source_basis": "THashList add wrapper that hashes a string key",
        "target_evidence_terms": ["g4ouMaaIbp", "addObject", "C8THgaTQxF"],
        "evidence": [
            "The source hashes the supplied string and forwards the object plus hash to the integer overload.",
            "The target performs the same two-step wrapper through KKhLga4xoI::g4ouMaaIbp and KKhLga4xoI::addObject, with C8THgaTQxF as the rebuilt string wrapper.",
            "All recorded normalized feature fields match, resolving the parent ambiguity against the adjacent encoded overloads and the remove wrappers.",
        ],
    },
    {
        "original_ea": "0xeacd4",
        "original_name": "THashList_addObjectEncoded_THashListObject",
        "spectron_ea": "0xeb934",
        "target_name": "_ZN10KKhLga4xoI9addObjectEP10J7zOgaf09KRK10CanTfaz6bZ",
        "proposed_name": "v18_THashList_addObjectEncoded_THashListObject",
        "source_category": "unmatched",
        "exact_shape": False,
        "source_basis": "THashList add wrapper that hashes an encoded key",
        "target_evidence_terms": ["g4ouMaaIbp", "addObject", "CanTfaz6bZ"],
        "evidence": [
            "The source computes the encoded key hash inline with the three-byte XOR key, lowercases ASCII letters, and forwards the result to the integer add overload.",
            "The target exposes the same role as a short overload that delegates to KKhLga4xoI::g4ouMaaIbp for CanTfaz6bZ and then calls the integer add overload.",
            "The target stores the encoded hash calculation in a shared helper, so its wrapper is shorter than the source inline implementation. This is a semantic correspondence, not an exact-shape claim.",
        ],
    },
    {
        "original_ea": "0xeb844",
        "original_name": "THashList_removeObject_THashListObject_TString_const",
        "spectron_ea": "0xec570",
        "target_name": "_ZN10KKhLga4xoI10g6yvgaX89uEP10J7zOgaf09KRK10C8THgaTQxF",
        "proposed_name": "v18_THashList_removeObject_THashListObject_TString_const",
        "source_category": "ambiguous",
        "exact_shape": True,
        "source_basis": "THashList remove wrapper that hashes a string key",
        "target_evidence_terms": ["g4ouMaaIbp", "g6yvgaX89u", "C8THgaTQxF"],
        "evidence": [
            "The source hashes the supplied string and forwards the object plus hash to the integer remove overload.",
            "The target performs the same two-step wrapper through KKhLga4xoI::g4ouMaaIbp and KKhLga4xoI::g6yvgaX89u, with C8THgaTQxF as the rebuilt string wrapper.",
            "All recorded normalized feature fields match, resolving the parent ambiguity against the add and encoded remove overloads.",
        ],
    },
    {
        "original_ea": "0xeb8c0",
        "original_name": "THashList_removeObjectEncoded_THashListObject",
        "spectron_ea": "0xec5a0",
        "target_name": "_ZN10KKhLga4xoI10g6yvgaX89uEP10J7zOgaf09KRK10CanTfaz6bZ",
        "proposed_name": "v18_THashList_removeObjectEncoded_THashListObject",
        "source_category": "unmatched",
        "exact_shape": False,
        "source_basis": "THashList remove wrapper that hashes an encoded key",
        "target_evidence_terms": ["g4ouMaaIbp", "g6yvgaX89u", "CanTfaz6bZ"],
        "evidence": [
            "The source computes the encoded key hash inline with the three-byte XOR key, lowercases ASCII letters, and forwards the result to the integer remove overload.",
            "The target exposes the same role as a short overload that delegates to KKhLga4xoI::g4ouMaaIbp for CanTfaz6bZ and then calls the integer remove overload.",
            "The target stores the encoded hash calculation in a shared helper, so its wrapper is shorter than the source inline implementation. This is a semantic correspondence, not an exact-shape claim.",
        ],
    },
    {
        "original_ea": "0xeade4",
        "original_name": "THashStrings_getObject_TString_const",
        "spectron_ea": "0xeba30",
        "target_name": "v18_THashStrings_getObject_TString_const",
        "proposed_name": "v18_THashStrings_getObject_TString_const",
        "source_category": "unmatched",
        "exact_shape": False,
        "source_basis": "THashStrings key lookup",
        "target_evidence_terms": ["g4ouMaaIbp", "operator==", "C8THgaTQxF"],
        "evidence": [
            "Both reject an empty table, select a bucket using the key hash, follow the collision chain, and return the matching hash-string object.",
            "The target makes temporary C8THgaTQxF copies explicit around the equality test and uses the rebuilt KKhLga4xoI hash helper. The added wrapper operations explain the changed layout.",
        ],
    },
    {
        "original_ea": "0xeb358",
        "original_name": "THashStrings_setValue_TString_const_TString_const",
        "spectron_ea": "0xebfcc",
        "target_name": "v18_THashStrings_setValue_TString_const_TString_const",
        "proposed_name": "v18_THashStrings_setValue_TString_const_TString_const",
        "source_category": "unmatched",
        "exact_shape": False,
        "source_basis": "THashStrings key/value update",
        "target_evidence_terms": ["TBCvgay5cv", "juVsfa5YWC", "g6yvgaX89u", "addObject"],
        "evidence": [
            "Both find an existing key, insert a new hash-string object when the value is nonempty and capacity permits, replace a changed value, and remove the object when the new value is empty.",
            "The target preserves those three branches through yL3_IaDMFt and NYF9TaOVKR helpers, with explicit temporary C8THgaTQxF comparison and cleanup.",
        ],
    },
    {
        "original_ea": "0xebea0",
        "original_name": "THashStrings_listStrings_void",
        "spectron_ea": "0xecc58",
        "target_name": "v18_THashStrings_listStrings_void",
        "proposed_name": "v18_THashStrings_listStrings_void",
        "source_category": "unmatched",
        "exact_shape": False,
        "source_basis": "THashStrings name/value list serialization",
        "target_evidence_terms": ["Zb7cUaSFEU", "vuuHgangcF", "operator<<", "=", "clear"],
        "evidence": [
            "Both iterate the hash-string table, emit name=value for nonempty values, emit the name alone for empty values, and append each result to a string list.",
            "The target expands the same temporary-string sequence through C8THgaTQxF and returns a vuuHgangcF list. The target retains seven basic blocks while adding wrapper instructions and calls.",
        ],
    },
    {
        "original_ea": "0xebff0",
        "original_name": "THashStrings_GetCommaText2_void",
        "spectron_ea": "0xecde8",
        "target_name": "v18_THashStrings_GetCommaText2_void",
        "proposed_name": "v18_THashStrings_GetCommaText2_void",
        "source_category": "unmatched",
        "exact_shape": False,
        "source_basis": "THashStrings comma-text serialization",
        "target_evidence_terms": ["Zb7cUaSFEU", "Z1ceJasAzF", "operator<<", "=", "clear"],
        "evidence": [
            "Both initialize an output string, iterate the hash-string table, join entries with commas, emit name=value or a quoted name, and escape each completed entry.",
            "The target preserves the same empty-value branch and escaped serialization through C8THgaTQxF and Z1ceJasAzF. Additional wrapper temporaries account for the larger body.",
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


def by_ea(rows: list[dict]) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in rows}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-parent", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--original-binary-sha256",
        default="9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8",
    )
    parser.add_argument(
        "--spectron-binary-sha256",
        default="f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    parent = load(args.semantic_parent)
    target_evidence_document = load(args.target_evidence)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    evidence_rows = by_ea(target_evidence_document.get("targets", []))

    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected semantic-map parent artifact")
    if parent.get("network_contacted") is not False:
        raise ValueError("semantic-map parent is not offline")
    if target_evidence_document.get("network_contacted", False):
        raise ValueError("target evidence is marked as networked")

    ambiguous = {row["original_ea"]: row for row in parent.get("ambiguous", [])}
    unmatched = {row["original_ea"] for row in parent.get("unmatched", [])}
    semantic_targets = {row["spectron_ea"] for row in parent.get("matches", [])}
    anchors = []
    seen_sources: set[int] = set()
    seen_targets: set[int] = set()
    for spec in ANCHOR_SPECS:
        source_ea = int(spec["original_ea"], 16)
        target_ea = int(spec["spectron_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        evidence = evidence_rows.get(target_ea)
        if source is None or target is None or evidence is None:
            raise ValueError("missing source, target, or evidence row for %s" % spec["original_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: %s" % (spec["spectron_ea"], target.get("name"))
            )
        if source_ea in seen_sources or target_ea in seen_targets:
            raise ValueError("duplicate source or target anchor")
        seen_sources.add(source_ea)
        seen_targets.add(target_ea)

        category = spec["source_category"]
        if category == "ambiguous":
            parent_row = ambiguous.get(spec["original_ea"])
            if parent_row is None:
                raise ValueError("source row is not an unresolved parent ambiguity")
            if spec["spectron_ea"] not in parent_row.get("candidate_spectron_eas", []):
                raise ValueError("target is not in the parent ambiguity candidates")
        elif category == "unmatched":
            if spec["original_ea"] not in unmatched:
                raise ValueError("source row is not an unresolved parent unmatched row")
        else:
            raise ValueError("unknown source category: %s" % category)
        if spec["spectron_ea"] in semantic_targets:
            raise ValueError("target is already present in the parent semantic map")

        pseudocode = evidence.get("pseudocode") or ""
        missing_terms = [term for term in spec["target_evidence_terms"] if term not in pseudocode]
        if missing_terms:
            raise ValueError(
                "target pseudocode evidence is missing for %s: %s"
                % (spec["spectron_ea"], ", ".join(missing_terms))
            )

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        changed_fields = [
            field for field in METRIC_FIELDS if source_metrics[field] != target_metrics[field]
        ]
        if spec["exact_shape"] and changed_fields:
            raise ValueError(
                "expected exact metrics for %s -> %s: %s"
                % (spec["original_ea"], spec["spectron_ea"], ", ".join(changed_fields))
            )
        if not spec["exact_shape"] and not changed_fields:
            raise ValueError("layout-aware row unexpectedly has exact metrics")

        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target.get("name"),
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-hash-residual-exact-anchor"
                if spec["exact_shape"]
                else "manual-hash-residual-layout-anchor",
                "semantic_match_already_present": False,
                "source_category": category,
                "source_basis": spec["source_basis"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "changed_metric_fields": changed_fields,
                "target_evidence_terms": spec["target_evidence_terms"],
                "evidence": GENERAL_EVIDENCE + spec["evidence"],
                "name_action": "rename-with-v18-prefix"
                if target.get("name") != spec["proposed_name"]
                else "retain-existing-v18-alias-and-add-reviewed-comment",
                "shape_equal": spec["exact_shape"],
            }
        )

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for THashList add/remove overloads and THashStrings lookup and serialization helpers",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "semantic_map_parent": str(args.semantic_parent),
            "semantic_map_parent_sha256": sha256_path(args.semantic_parent),
            "target_pseudocode_evidence": str(args.target_evidence),
            "target_pseudocode_evidence_sha256": sha256_path(args.target_evidence),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "layout_change_anchor_count": sum(not row["shape_equal"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "address_delta_groups": dict(
                sorted(Counter(row["target_delta"] for row in anchors).items())
            ),
            "resolved_ambiguous_count": sum(
                row["source_category"] == "ambiguous" for row in anchors
            ),
            "promoted_unmatched_count": sum(
                row["source_category"] == "unmatched" for row in anchors
            ),
        },
        "context": {
            "source_classes": ["THashList", "THashStrings"],
            "target_class_clusters": ["KKhLga4xoI", "yL3_IaDMFt", "C8THgaTQxF", "CanTfaz6bZ"],
            "resolution": "source pseudocode, target pseudocode, overload signatures, class-local order, exact normalized features where available, and explicit wrapper-layout deltas",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The normal add and remove string wrappers are exact normalized matches. The encoded overloads and the remaining THashStrings routines are high-confidence semantic matches with documented wrapper-layout changes.",
            "The target aliases preserve the readable 1.8 roles while the artifact retains the original obfuscated target names and the direct pseudocode evidence.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
