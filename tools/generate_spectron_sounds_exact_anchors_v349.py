#!/usr/bin/env python3
"""Create reviewed exact-shape anchors for the Spectron sound wrappers.

The v349 pass reconciles ten source-backed rows that already had readable
``v18_`` names in the target IDA database but were still unresolved in the
semantic cross-build map.  The rows are deliberately limited to exact
normalized feature matches.  Larger sound routines whose layout changed in
the target are recorded separately in the research notes and are not claimed
by this artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ARTIFACT = "spectron_sounds_exact_manual_translation_anchors_20260829"
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

ANCHOR_SPECS = [
    {
        "original_ea": "0xe0af8",
        "original_name": "TSounds_isMusicPlaying",
        "spectron_ea": "0xe16a8",
        "target_name": "v18_TSounds_isMusicPlaying",
        "source_basis": "TSounds music-playing state getter",
        "evidence": [
            "Both check the global sound-player pointer, return false when it is absent, and otherwise dispatch the sound-player vtable slot at offset 56.",
            "The source and target rows have the same complete normalized ARM64 feature record. Their class and register names differ only because the target was rebuilt with obfuscated wrappers.",
        ],
    },
    {
        "original_ea": "0xe0b3c",
        "original_name": "TSounds_getMusicPos_void",
        "spectron_ea": "0xe16ec",
        "target_name": "v18_TSounds_getMusicPos_void",
        "source_basis": "TSounds music-position getter",
        "evidence": [
            "Both return -1.0 when the global sound player is absent and otherwise dispatch the sound-player vtable position slot at offset 80.",
            "The adjacent target getter at 0xe172c is the same-shaped length getter, so the source method order and the distinct vtable slot resolve the pair.",
        ],
    },
    {
        "original_ea": "0xe0b7c",
        "original_name": "TSounds_getMusicLen_void",
        "spectron_ea": "0xe172c",
        "target_name": "v18_TSounds_getMusicLen_void",
        "source_basis": "TSounds music-length getter",
        "evidence": [
            "Both return -1.0 when the global sound player is absent and otherwise dispatch the sound-player vtable length slot at offset 88.",
            "The target immediately follows the position getter at 0xe16ec, preserving the source order while the vtable slot distinguishes the two identical-shape rows.",
        ],
    },
    {
        "original_ea": "0xe0c84",
        "original_name": "TSounds_getDisabledSoundEffects",
        "spectron_ea": "0xe1834",
        "target_name": "v18_TSounds_getDisabledSoundEffects",
        "source_basis": "TSounds disabled-sound-effects getter",
        "evidence": [
            "Both return the comma-text representation of the global disabled-sound-effects list through the native callback result convention.",
            "The target calls the obfuscated vuuHgangcF comma-text getter, which is the target wrapper for the source TStringList operation, and sits in the matching disabled-effects cluster.",
        ],
    },
    {
        "original_ea": "0xe0e48",
        "original_name": "TSounds_getSoundEffect_TString_const",
        "spectron_ea": "0xe1a1c",
        "target_name": "v18_TSounds_getSoundEffect_TString_const",
        "source_basis": "TSounds case-insensitive sound-effect lookup",
        "evidence": [
            "Both lowercase the requested name, compute the hash, look up the object case-insensitively in the global sound-effects collection, and clear the temporary string.",
            "The target C8TH, wiULgacZUI, and KKhLga4xoI calls are the obfuscated string, lowercase, and hash-list wrappers for the same four-call source flow.",
        ],
    },
    {
        "original_ea": "0xe1060",
        "original_name": "TSounds_stopMidi_void",
        "spectron_ea": "0xe1c34",
        "target_name": "v18_TSounds_stopMidi_void",
        "source_basis": "TSounds MIDI stop dispatch",
        "evidence": [
            "Both check the global sound-player pointer and dispatch the stop-MIDI vtable slot at offset 72 when a player exists.",
            "The target 0xe1c34 row is in the same ordered stop/free sound cluster as the source method, while the same-shaped updateMusic wrapper is later at 0xe2470.",
        ],
    },
    {
        "original_ea": "0xe1888",
        "original_name": "TSounds_updateMusic_void",
        "spectron_ea": "0xe2470",
        "target_name": "v18_TSounds_updateMusic_void",
        "source_basis": "TSounds music update dispatch",
        "evidence": [
            "Both check the global sound-player pointer and dispatch the music-update vtable slot at offset 48 when a player exists.",
            "The target sits at the end of the larger TSounds playback block, and the vtable slot distinguishes it from the earlier stop-MIDI wrapper with the same normalized shape.",
        ],
    },
    {
        "original_ea": "0xe2b58",
        "original_name": "TSoundPlayerJava_stopMidi_void",
        "spectron_ea": "0xe3748",
        "target_name": "v18_TSoundPlayerJava_stopMidi_void",
        "source_basis": "TSoundPlayerJava MIDI stop wrapper",
        "evidence": [
            "Both are the compact Java sound-player wrapper that tests the receiver and dispatches the native stop-MIDI implementation through the object vtable.",
            "The complete normalized ARM64 feature records are identical, and the target row is the first method in the matching Java sound-player helper cluster.",
        ],
    },
    {
        "original_ea": "0xe2b78",
        "original_name": "TSoundPlayerJava_setMusicVolumeAndPan_int_int",
        "spectron_ea": "0xe3768",
        "target_name": "v18_TSoundPlayerJava_setMusicVolumeAndPan_int_int",
        "source_basis": "TSoundPlayerJava music volume and pan wrapper",
        "evidence": [
            "Both are the compact Java sound-player wrapper that forwards the two integer controls through the receiver vtable.",
            "The target method immediately follows the target stop-MIDI wrapper, and the complete normalized ARM64 feature records match exactly.",
        ],
    },
    {
        "original_ea": "0xe2c14",
        "original_name": "TSoundEffectJava_TSoundEffectJava__2",
        "spectron_ea": "0xe3804",
        "target_name": "v18_TSoundEffectJava_TSoundEffectJava__2",
        "source_basis": "TSoundEffectJava copy/base constructor wrapper",
        "evidence": [
            "Both are the two-block constructor wrapper that invokes the sound-effect base constructor and preserves the Java sound-effect object lifecycle.",
            "The target QPh5pbnC3y destructor call is the obfuscated replacement for the source base-constructor path, and the full normalized ARM64 feature records match.",
        ],
    },
]

GENERAL_EVIDENCE = [
    "This is a reviewed source-backed translation overlay for the exact hashed 1.8 and Spectron ARM64 feature exports recorded in the artifact.",
    "Every row matches size, instruction count, control-flow counts, mnemonic, opcode, register, overall-shape, and string-reference feature fields. The target register and helper names may still differ because of the later obfuscated rebuild.",
    "These rows were unresolved semantic-map ambiguities even though the target IDA database already carried the corresponding v18_ display names from earlier analysis passes. v349 records the source-to-target relationship explicitly and adds review comments to the copied IDA database.",
    "The five larger TSounds rows with changed layout are intentionally excluded from this exact-shape artifact. They remain documented as high-confidence layout-change candidates pending a separate pass.",
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-parent", required=True, type=Path)
    parser.add_argument("--target-evidence", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    parent = load(args.semantic_parent)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])

    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected semantic-map parent artifact")
    if parent.get("network_contacted") is not False:
        raise ValueError("semantic-map parent is not offline")

    ambiguous = {
        row["original_ea"]: row for row in parent.get("ambiguous", [])
    }
    anchors = []
    seen_sources: set[int] = set()
    seen_targets: set[int] = set()
    for spec in ANCHOR_SPECS:
        source_ea = int(spec["original_ea"], 16)
        target_ea = int(spec["spectron_ea"], 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing feature row for %s -> %s" % (spec["original_ea"], spec["spectron_ea"]))
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
        if spec["original_ea"] not in ambiguous:
            raise ValueError("source row is not an unresolved parent ambiguity: %s" % spec["original_ea"])
        if spec["spectron_ea"] not in ambiguous[spec["original_ea"]].get("candidate_spectron_eas", []):
            raise ValueError("target is not in the parent ambiguity candidates: %s" % spec["spectron_ea"])

        source_metrics = selected_metrics(source)
        target_metrics = selected_metrics(target)
        if source_metrics != target_metrics:
            differing = [field for field in METRIC_FIELDS if source_metrics[field] != target_metrics[field]]
            raise ValueError(
                "expected exact metrics for %s -> %s, differing fields: %s"
                % (spec["original_ea"], spec["spectron_ea"], ", ".join(differing))
            )

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
                "proposed_name": spec["target_name"],
                "confidence": "high",
                "match_kind": "manual-sounds-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "evidence": GENERAL_EVIDENCE + spec["evidence"],
                "name_action": "retain-existing-v18-alias-and-add-reviewed-comment",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed exact-shape 1.8-to-Spectron anchors for TSounds, TSoundPlayerJava, and TSoundEffectJava",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "semantic_map_parent": str(args.semantic_parent),
            "semantic_map_parent_sha256": sha256_path(args.semantic_parent),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "address_delta_groups": dict(sorted(Counter(row["target_delta"] for row in anchors).items())),
        },
        "context": {
            "source_classes": ["TSounds", "TSoundPlayerJava", "TSoundEffectJava"],
            "target_class_clusters": ["IUKzgam4Gy", "QPh5pbnC3y", "vuuHgangcF"],
            "resolution": "exact normalized ARM64 features, source/target pseudocode, vtable slot or wrapper role, and class-local method order",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not claims that the target's obfuscated names are original 1.8 debug symbols.",
            "The target rows already use v18_ aliases in the copied IDA database. The v349 pass makes the source-backed relationships explicit in the semantic map and records the review basis without inventing a new target-only symbol.",
            "The exact-shape result does not settle the five larger sound routines whose target layout changed. Those routines are kept as separate layout-change research candidates.",
        ],
    }
    if args.target_evidence:
        result["inputs"]["target_pseudocode_evidence"] = str(args.target_evidence)
        result["inputs"]["target_pseudocode_evidence_sha256"] = sha256_path(args.target_evidence)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
