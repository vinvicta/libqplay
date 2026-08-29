#!/usr/bin/env python3
"""Create reviewed layout-aware anchors for the remaining sound routines.

The v350 rows are behaviorally strong source-to-target correspondences, but
their target wrapper layouts differ enough that an exact normalized feature
claim would be false.  The artifact records the changed metrics and requires
direct target pseudocode terms before it emits an anchor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ARTIFACT = "spectron_sounds_layout_manual_translation_anchors_20260829"
ORIGINAL_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8"
SPECTRON_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
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
LAYOUT_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
)

ANCHOR_SPECS = [
    {
        "original_ea": "0xe2a88",
        "original_name": "TSounds_initStaticVars_void",
        "spectron_ea": "0xe3678",
        "target_name": "v18_TSounds_initStaticVars_void",
        "source_category": "ambiguous",
        "source_basis": "TSounds sound-cache static initializer",
        "target_evidence_terms": [
            "KKhLga4xoI",
            "vuuHgangcF",
            "fqEVZaFC6H",
            "mDUVZaIfkI",
        ],
        "evidence": [
            "Both allocate and construct the global sound-effects collection and the disabled-sound-effects collection, then return the address of the second global.",
            "The target replaces source THashList and TStringList with KKhLga4xoI and vuuHgangcF. The allocation sizes and one-block initializer shape remain stable, but the wrapper types and shape hashes change.",
        ],
    },
    {
        "original_ea": "0xe0dc0",
        "original_name": "TSoundEffect_TSoundEffect_TString_const",
        "spectron_ea": "0xe1970",
        "target_name": "v18_TSoundEffect_TSoundEffect_TString_const",
        "source_category": "unmatched",
        "source_basis": "TSoundEffect constructor from a TString",
        "target_evidence_terms": [
            "CanTfaz6bZ",
            "J7zOgaf09K",
            "RUnvgavJ0u",
            "C8THgaTQxF::clear",
        ],
        "evidence": [
            "Both lowercase the supplied name, initialize the base sound-effect object, copy the original name, and initialize the loaded, duration, volume, pan, and playback fields.",
            "The target inserts a CanTfaz6bZ encoded-string bridge and a J7zOgaf09K base-constructor call before initializing the same visible fields. This adds nine instructions and two calls without changing the one-block constructor role.",
        ],
    },
    {
        "original_ea": "0xe135c",
        "original_name": "TSounds_play_impl_TString_const_bool_bool_double_double",
        "spectron_ea": "0xe1f34",
        "target_name": "v18_TSounds_play_impl_TString_const_bool_bool_double_double",
        "source_category": "unmatched",
        "source_basis": "sound extension classification, cache, and playback state machine",
        "target_evidence_terms": [
            "ZHZxfaHwcH",
            "zO9xgagSlx",
            "mP6ygaUl9x",
            "adFVZaKh7H",
            "wNLMganPDJ",
            ".mid",
            ".mp2 .mp3 .ogg .wma .asf",
        ],
        "evidence": [
            "Both reject invalid sound state, honor the disabled-effects list, classify .mid, .wav, and compressed extensions, clamp volume and pan, check player capabilities, request missing files, and reuse or create a sound-effect object before playback.",
            "The target retains the same 72 basic blocks and the same two string references. Its C8THgaTQxF, vuuHgangcF, and IUKzgam4Gy wrappers add two calls and four instructions while preserving the source state-machine decisions.",
        ],
    },
    {
        "original_ea": "0xe2858",
        "original_name": "TSounds_script_setSoundPitchByNote",
        "spectron_ea": "0xe3440",
        "target_name": "v18_TSounds_script_setSoundPitchByNote",
        "source_category": "unmatched",
        "source_basis": "note-name parsing and sound pitch calculation",
        "target_evidence_terms": [
            "an,as,bn,cn,cs,dn,ds,en,fn,fs,gn,gs",
            "powf",
            "wgG1Zawa1N",
            "Msu4gaSeoZ",
            "vuuHgangcF",
        ],
        "evidence": [
            "Both validate three-character note strings, lazily build the twelve-note table, parse the octave, calculate the semitone delta, and apply powf(2.0, delta / 12.0) through the sound-pitch helper.",
            "The target replaces TString and TStringList wrappers with C8THgaTQxF and vuuHgangcF, adding two instructions while retaining 21 blocks, 26 calls, the note literal, and the same semantic calculation.",
        ],
    },
    {
        "original_ea": "0xe31d0",
        "original_name": "TSoundEffectJava_play_void",
        "spectron_ea": "0xe3dc0",
        "target_name": "v18_TSoundEffectJava_play_void",
        "source_category": "unmatched",
        "source_basis": "Java sound-effect playback and rate limiting",
        "target_evidence_terms": [
            "startSound",
            "fEtHgarybF",
            "CallStaticVoidMethod",
            "TASMgaIxJJ",
            "C8THgaTQxF::clear",
        ],
        "evidence": [
            "Both enforce a 0.2-second playback interval, resolve the startSound Java method, choose a path relative to the base-data folder when applicable, create a byte-array argument, invoke the static Java method, release the local reference, and update loaded and timestamp state.",
            "The source has a separate steps-prefix branch that the target no longer contains. The target therefore has one fewer block, four fewer branches, three fewer calls, and a body 44 bytes shorter while retaining the core Java playback path.",
        ],
    },
]

GENERAL_EVIDENCE = [
    "This artifact records layout-aware semantic correspondences for the exact hashed original 1.8 and Spectron ARM64 builds in the inputs.",
    "The target names are analysis aliases. They are not presented as readable debug symbols recovered from the stripped target.",
    "A row is accepted only when its source and target metrics match the recorded structural comparison and the direct target pseudocode contains the expected role-specific terms.",
    "These rows are intentionally separate from the v349 exact-shape artifact. A changed wrapper layout is evidence of a corresponding routine, not evidence of byte-for-byte identity.",
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


def selected_metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def layout_metrics(row: dict) -> dict:
    return {field: row.get(field) for field in LAYOUT_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-parent", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", default=ORIGINAL_BINARY_SHA256)
    parser.add_argument("--spectron-binary-sha256", default=SPECTRON_BINARY_SHA256)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    parent = load(args.semantic_parent)
    target_evidence = load(args.target_evidence)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    target_evidence_rows = by_ea(target_evidence.get("targets", []))

    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected semantic-map parent artifact")
    if parent.get("network_contacted") is not False:
        raise ValueError("semantic-map parent is not offline")

    ambiguous = {row["original_ea"]: row for row in parent.get("ambiguous", [])}
    unmatched = {row["original_ea"] for row in parent.get("unmatched", [])}
    anchors = []
    seen_sources: set[int] = set()
    seen_targets: set[int] = set()
    for spec in ANCHOR_SPECS:
        source_ea = int(spec["original_ea"], 16)
        target_ea = int(spec["spectron_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        evidence = target_evidence_rows.get(target_ea)
        if source is None or target is None or evidence is None:
            raise ValueError("missing source, target, or target evidence row for %s" % spec["original_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at %s: %s" % (spec["spectron_ea"], target.get("name")))
        if source_ea in seen_sources or target_ea in seen_targets:
            raise ValueError("duplicate source or target anchor")
        seen_sources.add(source_ea)
        seen_targets.add(target_ea)

        category = spec["source_category"]
        if category == "ambiguous":
            parent_row = ambiguous.get(spec["original_ea"])
            if parent_row is None:
                raise ValueError("expected ambiguous source row is missing: %s" % spec["original_ea"])
        elif category == "unmatched":
            if spec["original_ea"] not in unmatched:
                raise ValueError("expected unmatched source row is missing: %s" % spec["original_ea"])
        else:
            raise ValueError("unknown source category: %s" % category)

        pseudocode = evidence.get("pseudocode", "")
        missing_terms = [term for term in spec["target_evidence_terms"] if term not in pseudocode]
        if missing_terms:
            raise ValueError(
                "target pseudocode evidence is missing for %s: %s"
                % (spec["spectron_ea"], ", ".join(missing_terms))
            )

        source_metrics = selected_metrics(source)
        target_metrics = selected_metrics(target)
        changed_fields = [
            field for field in METRIC_FIELDS if source_metrics[field] != target_metrics[field]
        ]
        if not changed_fields:
            raise ValueError("layout anchor unexpectedly has exact metrics: %s" % spec["original_ea"])

        source_layout = layout_metrics(source)
        target_layout = layout_metrics(target)
        layout_delta = {
            field: target_layout[field] - source_layout[field]
            for field in LAYOUT_FIELDS
        }
        anchor = {
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
            "proposed_name": spec["target_name"],
            "confidence": "high",
            "match_kind": "manual-sounds-layout-anchor",
            "semantic_match_already_present": False,
            "source_category": category,
            "source_basis": spec["source_basis"],
            "target_delta": "+0x%x" % (target_ea - source_ea),
            "evidence": GENERAL_EVIDENCE + spec["evidence"],
            "target_pseudocode_terms": spec["target_evidence_terms"],
            "target_xrefs_to": evidence.get("xrefs_to", []),
            "name_action": "retain-existing-v18-alias-and-add-reviewed-comment",
            "shape_equal": False,
            "layout_change": True,
            "changed_metric_fields": changed_fields,
            "layout_metrics_source": source_layout,
            "layout_metrics_target": target_layout,
            "layout_metric_delta": layout_delta,
            "string_refs_equal": source.get("string_refs", []) == target.get("string_refs", []),
        }
        anchors.append(anchor)

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed layout-aware 1.8-to-Spectron anchors for the remaining TSounds and Java-audio routines",
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
            "exact_shape_anchor_count": 0,
            "layout_change_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "address_delta_groups": dict(sorted(Counter(row["target_delta"] for row in anchors).items())),
        },
        "context": {
            "source_classes": ["TSounds", "TSoundEffect", "TSoundEffectJava"],
            "target_class_clusters": ["IUKzgam4Gy", "J7zOgaf09K", "QPh5pbnC3y", "vuuHgangcF"],
            "resolution": "direct pseudocode role, preserved literals, caller context, class-local order, and explicit metric deltas",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not recovered target debug symbols.",
            "The target rows keep the source behavior but change object wrappers or remove a source-only branch. The changed metric fields are recorded per row so the aliases are not confused with exact binary-shape matches.",
            "The v350 pass promotes one previously ambiguous source row and four previously unmatched source rows. It does not alter the v349 exact-shape count.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
