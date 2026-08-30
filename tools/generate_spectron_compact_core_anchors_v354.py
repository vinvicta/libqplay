#!/usr/bin/env python3
"""Create reviewed anchors for the v354 compact core residual pass.

This pass covers small filesystem, identification, logging, profiling, and
input routines whose 2.2 bodies remain recognizable after the target rebuild.
One Android cleanup row carries forward an earlier reviewed role correction.
The source and target addresses are kept separate because the target library
was rebuilt and its C++ symbols were stripped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ARTIFACT = "spectron_compact_core_manual_translation_anchors_20260830"
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
TARGET_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
SOURCE_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8"


GENERAL_EVIDENCE = [
    "The source and target rows were selected from the corresponding class-local regions of the exact hashed ARM64 builds.",
    "The target addresses and v18_ names are analysis aliases. They are not claims that the stripped 2.2 library retained the readable 1.8 debug symbols.",
    "The target wrappers use rebuilt C8THgaTQxF, CanTfaz6bZ, vuuHgangcF, and obfuscated class names. Changed metrics are therefore recorded as layout changes rather than exact binary matches.",
    "Each selected target body was reviewed through fresh offline Hex-Rays pseudocode evidence and checked against the current target feature export.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0xe06a8",
        "original_name": "TServerFlying_clearStaticStrings",
        "spectron_ea": "0xe0438",
        "target_name": "v18_Android_TapJoy_video_clearStaticStrings",
        "proposed_name": "v18_Android_TapJoy_video_clearStaticStrings",
        "source_basis": "Android TapJoy and video static-string cleanup callback",
        "source_semantics": "Clears the three source Android or video TString globals registered in the cleanup table. The old TServerFlying label was corrected by the earlier TapJoy and video state audit.",
        "target_evidence_terms": ["C8THgaTQxF::clear", "CanTfaz6bZ::clear", "qword_3A58D8", "qword_3A5920"],
        "match_kind": "manual-compact-core-role-correction",
        "prior_artifact": "artifacts/spectron_android_tapjoy_video_state_manual_translation_anchors_20260827.json",
        "evidence": [
            "The earlier Android and video state audit ties the source cleanup callback to the source static cleanup table and to the translated JNI and video state fields.",
            "The target cleanup callback is registered in the corresponding target cleanup table and clears the three matching target string fields plus one target-only string lifetime.",
            "The target already carries the reviewed v18_Android_TapJoy_video_clearStaticStrings alias, so this pass adds explicit source-backed provenance without renaming it again.",
        ],
    },
    {
        "original_ea": "0xe8338",
        "original_name": "TFiles_initStaticVars_void",
        "spectron_ea": "0xe8f20",
        "target_name": "_Z10mw80JaPMzkv",
        "proposed_name": "v18_TFiles_initStaticVars_void",
        "source_basis": "TFiles static path, filename-character, and archive-extension initializer",
        "source_semantics": "Lazily creates the slash separator string, allowed filename character string, and archive extension list used by TFiles.",
        "target_evidence_terms": ["/\\\\", "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", ".gpake,.gpak,.zip,.wba,.mdt,.apk", "vuuHgangcF"],
        "match_kind": "manual-compact-core-layout-anchor",
        "evidence": [
            "Both bodies lazily allocate the separator and allowed-character strings, then construct the archive extension list from the same six extensions.",
            "The target uses C8THgaTQxF and vuuHgangcF in place of the source TString and TStringList wrappers, accounting for the small layout change.",
        ],
    },
    {
        "original_ea": "0xe85a8",
        "original_name": "TFileNameScan_readLevelPaths_TString_const",
        "spectron_ea": "0xe9194",
        "target_name": "_ZN10CDPvgaY2nv10Ael5MaUt6UERK10C8THgaTQxF",
        "proposed_name": "v18_TFileNameScan_readLevelPaths_TString_const",
        "source_basis": "recursive resource-directory scanner",
        "source_semantics": "Initializes the ignored directory and extension lists, normalizes a directory path, recurses through non-ignored directories, and registers eligible regular files as resource objects.",
        "target_evidence_terms": ["opendir", "readdir", "stat", "ignore,cache,offline,_CodeSignature", ".code", "iwUvgaL9rv"],
        "match_kind": "manual-compact-core-layout-anchor",
        "evidence": [
            "Both bodies initialize the same ignored directory list and .code suffix, normalize the directory separator, enumerate with opendir and readdir, stat each entry, recurse into permitted directories, and forward regular files to the resource registration helper.",
            "The target's resource and string wrapper names changed, and the rebuilt helper takes a different register-level signature, but the directory traversal and filtering role is preserved.",
        ],
    },
    {
        "original_ea": "0xec290",
        "original_name": "TIdentification_getCookieFilename_void",
        "spectron_ea": "0xed0d8",
        "target_name": "_ZN10NiVAFatPFB10NcxWQawyR8Ev",
        "proposed_name": "v18_TIdentification_getCookieFilename_void",
        "source_basis": "cookie creation-time filename selection",
        "source_semantics": "Builds basedatafolder/cache/creationtime.dat, returns it when present, and otherwise falls back to basedatafolder/files/creationtime.dat.",
        "target_evidence_terms": ["cache", "files", "creationtime.dat", "PhVLgaLOVI"],
        "match_kind": "manual-compact-core-layout-anchor",
        "evidence": [
            "The target begins with the same cache/creationtime.dat path and checks it through the target file-existence helper.",
            "When the cache path is absent, the target preserves the files/creationtime.dat fallback and adds two older fallback variants visible in the target pseudocode.",
        ],
    },
    {
        "original_ea": "0xec6f8",
        "original_name": "TIdentification_getSystemID_int",
        "spectron_ea": "0xed6b4",
        "target_name": "_ZN10NiVAFatPFB10qstsLaCozxEi",
        "proposed_name": "v18_TIdentification_getSystemID_int",
        "source_basis": "system-identifier selector",
        "source_semantics": "Selects dc:id2, hard-disk, network, operating-system, or Android identifiers by selector and returns an empty string for unsupported values.",
        "target_evidence_terms": ["dc:id2", "d_f_Qa03Zb", "FWw_Qa_jdc", "VlsAFa7shB", "_Sn_GaYH5M"],
        "match_kind": "manual-compact-core-layout-anchor",
        "evidence": [
            "The target keeps the selector cases for dc:id2, hard-disk, network, operating-system, and Android identifiers, with the same empty default output.",
            "The target adds one selector case for a newer identifier source, which explains the extra block and return shape without changing the original cases.",
        ],
    },
    {
        "original_ea": "0xf85fc",
        "original_name": "TLogActions_getTopScripts_TStringList_bool",
        "spectron_ea": "0xfa5f8",
        "target_name": "_ZN10qjQMgaXCHJ10c4RmLa65QsEv",
        "proposed_name": "v18_TLogActions_getTopScripts_TStringList_bool",
        "source_basis": "top script CPU profile report",
        "source_semantics": "Appends a top-N CPU report, formats each profiled NPC script with its percentage, optionally dumps function profiles, and emits (none) when the list is empty.",
        "target_evidence_terms": ["BRcLgaJqkI", "c_H_fa_Cm4", "sfffs", "vy1JgaKVkH", "fpnoLaVi7t"],
        "match_kind": "manual-compact-core-layout-anchor",
        "evidence": [
            "The target builds the same top-script report, iterates the profiler list, formats percentage and script name fields, optionally resolves the script and emits function profiles, and handles the empty-list case.",
            "The target stores profile entries in the rebuilt list and script classes, so the body is shorter and its normalized metrics differ even though the report role remains clear.",
        ],
    },
    {
        "original_ea": "0xfa17c",
        "original_name": "TProfiler_hashPop_void",
        "spectron_ea": "0xfc7ac",
        "target_name": "_ZN10esKIvakHfi10bCpNvaN9amEv",
        "proposed_name": "v18_TProfiler_hashPop_void",
        "source_basis": "profiler stack-pop and timing accumulation",
        "source_semantics": "Pops a profiler frame, reports underflow, handles disabled markers and nested counts, stops the timer, accumulates inclusive and exclusive timing, and restarts the root timer when needed.",
        "target_evidence_terms": ["Echo: stack underflow in profiler", "cWQMgaD8HJ", "gfBEFaqXLE", "FYcZgaMw6T"],
        "match_kind": "manual-compact-core-layout-anchor",
        "evidence": [
            "The target decrements the same profiler depth field, preserves the underflow diagnostic, and updates nested counts and timing fields through the rebuilt profiler tree.",
            "The target retains the source branch topology around disabled markers, parent propagation, root cleanup, and timer restart, with only wrapper and helper identities changed.",
        ],
    },
    {
        "original_ea": "0x168bc4",
        "original_name": "TControlBinding_TControlBinding_TString_const",
        "spectron_ea": "0x16c59c",
        "target_name": "_ZN10IoTkgardbmC1ERK10C8THgaTQxF",
        "proposed_name": "v18_TControlBinding_TControlBinding_TString_const",
        "source_basis": "control binding string constructor",
        "source_semantics": "Constructs the TGraalVar-backed binding from a string, initializes the keycode and slot fields to -1, sets default flags, and installs the control-binding vtable and property pointer.",
        "target_evidence_terms": ["CanTfaz6bZ::operator=", "G0gxgajWBw::G0gxgajWBw", "IoTkgardbmOnln2aNBfC"],
        "match_kind": "manual-compact-core-layout-anchor",
        "evidence": [
            "The target copies the string through CanTfaz6bZ, constructs the rebuilt TGraalVar base, initializes the same sentinel binding fields, and installs the target control-binding vtable and callback.",
            "The target constructor is larger because the encoded string wrapper and rebuilt base class require explicit lifetime operations.",
        ],
    },
    {
        "original_ea": "0x169720",
        "original_name": "TInput_initStaticVars_void",
        "spectron_ea": "0x16d174",
        "target_name": "_Z10x3PsfaBpSCv",
        "proposed_name": "v18_TInput_initStaticVars_void",
        "source_basis": "input control-binding and key-description static initializer",
        "source_semantics": "Allocates the control-binding list, builds the complete comma-separated key description table, and creates the second list used for key text lookup.",
        "target_evidence_terms": ["Backspace", "Left Windows", "Numpad0", "vuuHgangcF"],
        "match_kind": "manual-compact-core-layout-anchor",
        "evidence": [
            "The target allocates the same two list objects, assigns the first to the control-binding static, builds the long key description table, and constructs the second list from it.",
            "The target keeps recognizable entries including Backspace, Left Windows, and Numpad0; its four-byte size difference is wrapper overhead only.",
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


def by_ea(rows: list[dict]) -> dict[str, dict]:
    return {row["ea"]: row for row in rows}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-parent", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--prior-role-artifact", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    parent = load(args.semantic_parent)
    target_evidence_document = load(args.target_evidence)
    prior_role = load(args.prior_role_artifact)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    evidence_rows = by_ea(target_evidence_document.get("targets", []))

    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected semantic-map parent artifact")
    if parent.get("network_contacted") is not False:
        raise ValueError("semantic-map parent is not offline")
    if spectron_document.get("function_count") != 11707:
        raise ValueError("unexpected target function count")
    if spectron_document.get("network_contacted") is not False:
        raise ValueError("target feature export is not offline")
    if target_evidence_document.get("network_contacted") is not False:
        raise ValueError("target evidence is not offline")
    if prior_role.get("artifact") != "spectron_android_tapjoy_video_state_manual_translation_anchors_20260827":
        raise ValueError("unexpected prior role artifact")

    unmatched = {row["original_ea"] for row in parent.get("unmatched", [])}
    parent_targets = {row["spectron_ea"] for row in parent.get("matches", [])}
    anchors = []
    seen_sources: set[str] = set()
    seen_targets: set[str] = set()
    for spec in ANCHOR_SPECS:
        source_ea = spec["original_ea"]
        target_ea = spec["spectron_ea"]
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        evidence = evidence_rows.get(target_ea)
        if source is None or target is None or evidence is None:
            raise ValueError("missing source, target, or evidence row for %s" % source_ea)
        if source.get("name") != spec["original_name"]:
            raise ValueError("source name mismatch at %s" % source_ea)
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: %s" % (target_ea, target.get("name"))
            )
        if source_ea not in unmatched:
            raise ValueError("source is not parent-unmatched: %s" % source_ea)
        if target_ea in parent_targets:
            raise ValueError("target is already mapped: %s" % target_ea)
        if source_ea in seen_sources or target_ea in seen_targets:
            raise ValueError("duplicate source or target anchor")
        seen_sources.add(source_ea)
        seen_targets.add(target_ea)
        if target.get("is_default_name"):
            raise ValueError("target unexpectedly has a default name: %s" % target_ea)

        pseudocode = evidence.get("pseudocode") or ""
        missing_terms = [term for term in spec["target_evidence_terms"] if term not in pseudocode]
        if missing_terms:
            raise ValueError(
                "target pseudocode evidence is missing for %s: %s"
                % (target_ea, ", ".join(missing_terms))
            )

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        changed_fields = [
            field for field in METRIC_FIELDS if source_metrics[field] != target_metrics[field]
        ]
        if not changed_fields:
            raise ValueError("compact core row unexpectedly has exact metrics: %s" % source_ea)

        prior_provenance = []
        if source_ea == "0xe06a8":
            prior_provenance = [
                {
                    "artifact": str(args.prior_role_artifact),
                    "artifact_sha256": sha256_path(args.prior_role_artifact),
                    "target_ea": target_ea,
                    "proposed_name": spec["proposed_name"],
                }
            ]

        anchors.append(
            {
                "original_ea": source_ea,
                "original_name": spec["original_name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": target_ea,
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target.get("name"),
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": spec["match_kind"],
                "semantic_match_already_present": False,
                "source_category": "unmatched",
                "source_basis": spec["source_basis"],
                "source_semantics": spec["source_semantics"],
                "target_delta": (
                    "+0x%x" % (int(target_ea, 16) - int(source_ea, 16))
                    if int(target_ea, 16) >= int(source_ea, 16)
                    else "-0x%x" % (int(source_ea, 16) - int(target_ea, 16))
                ),
                "changed_metric_fields": changed_fields,
                "target_evidence_terms": spec["target_evidence_terms"],
                "source_pseudocode_basis": "Fresh direct source Hex-Rays review was summarized in source_semantics; source metrics come from the offline source feature export.",
                "target_pseudocode": pseudocode,
                "target_xrefs_to": evidence.get("xrefs_to", []),
                "prior_provenance": prior_provenance,
                "evidence": GENERAL_EVIDENCE + spec["evidence"],
                "name_action": (
                    "retain-existing-v18-alias-and-add-reviewed-comment"
                    if target.get("name") == spec["proposed_name"]
                    else "rename-with-v18-prefix"
                ),
                "shape_equal": False,
                "layout_change": True,
                "layout_metric_delta": {
                    field: {
                        "original": source_metrics.get(field),
                        "spectron": target_metrics.get(field),
                    }
                    for field in changed_fields
                },
            }
        )

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact filesystem, identity, logging, profiling, and input residuals",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": SOURCE_BINARY_SHA256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": TARGET_BINARY_SHA256,
            "semantic_map_parent": str(args.semantic_parent),
            "semantic_map_parent_sha256": sha256_path(args.semantic_parent),
            "target_pseudocode_evidence": str(args.target_evidence),
            "target_pseudocode_evidence_sha256": sha256_path(args.target_evidence),
            "prior_role_artifact": str(args.prior_role_artifact),
            "prior_role_artifact_sha256": sha256_path(args.prior_role_artifact),
            "database_before_application": str(args.database),
            "database_before_application_sha256": sha256_path(args.database),
        },
        "method": {
            "selection": "fresh source role review, target role pseudocode review, class-local order, target feature verification, and explicit wrapper-layout deltas",
            "address_policy": "source and target addresses remain separate fields; no address is copied between builds",
            "name_policy": "the target receives a v18_ analysis prefix, except for the existing reviewed Android cleanup alias",
            "confidence_policy": "high confidence requires direct role continuity; changed sizes and wrapper identities are recorded rather than hidden",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": 0,
            "layout_change_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "address_delta_groups": dict(
                sorted(Counter(row["target_delta"] for row in anchors).items())
            ),
            "promoted_unmatched_count": len(anchors),
            "existing_alias_role_correction_count": sum(
                row["name_action"] == "retain-existing-v18-alias-and-add-reviewed-comment"
                for row in anchors
            ),
        },
        "context": {
            "source_classes": [
                "TFiles",
                "TFileNameScan",
                "TIdentification",
                "TLogActions",
                "TProfiler",
                "TControlBinding",
                "TInput",
            ],
            "target_class_clusters": [
                "wiULgacZUI",
                "CDPvgaY2nv",
                "NiVAFatPFB",
                "qjQMgaXCHJ",
                "esKIvakHfi",
                "IoTkgardbm",
                "GaA2gaD2MX",
            ],
            "resolution": "compact source and target roles are preserved even when the target adds fallback cases, changes wrapper classes, or stores profiler and input state in rebuilt layouts",
        },
        "anchors": sorted(anchors, key=lambda row: int(row["original_ea"], 16)),
        "interpretation": [
            "These rows are reviewed semantic correspondences, not restored original debug symbols.",
            "The Android cleanup row is a source-backed promotion of a prior role correction. Its existing target alias is retained and provenance is made explicit.",
            "The remaining eight rows are high-confidence layout-aware translations. Their target code is unchanged by the artifact; only the later IDA application adds readable aliases and comments.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
