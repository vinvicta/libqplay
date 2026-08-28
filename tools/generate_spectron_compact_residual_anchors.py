#!/usr/bin/env python3
"""Create reviewed anchors for compact residual 1.8 to Spectron helpers.

The broad semantic matcher deliberately skips many functions shorter than its
cutoff.  This batch covers the remaining small property, wrapper, handler,
cache, and script helpers whose target roles are recoverable from matching
property or handler tables and normalized ARM64 features.
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
SHAPE_FIELDS = tuple(field for field in METRIC_FIELDS if field != "register_detail_hash")

SOURCE_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
SPECTRON_BINARY_SHA256 = "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"


ANCHOR_SPECS = [
    {
        "original_ea": "0x15d4e0",
        "original_name": "TGaniObject_getChildField748",
        "spectron_ea": "0x160570",
        "target_name": "sub_160570",
        "source_context": ["0x37a650"],
        "spectron_context": ["0x38d670"],
        "source_component": "TGaniObject",
        "target_component": "Spectron TGaniObject child-property cluster",
        "role": "TGaniObject child field 748 getter",
        "behavior": "return the unsigned child field at offset +748, or zero when the child object is absent",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": True,
        "evidence": [
            "The source and target entries are the first callbacks in the corresponding child-property tables at 0x37a638 and 0x38d658.",
            "Both bodies load the child pointer from receiver offset +144, test it, and return one unsigned child field or zero.",
            "The target field is at +772 rather than +748, documenting a target layout shift while preserving the getter role and control flow.",
        ],
    },
    {
        "original_ea": "0x16c5a4",
        "original_name": "TPlayer_get_online",
        "spectron_ea": "0x17015c",
        "target_name": "sub_17015C",
        "source_context": ["0x37b998"],
        "spectron_context": ["0x38e9c8"],
        "source_component": "TPlayer",
        "target_component": "Spectron TPlayer property cluster",
        "role": "TPlayer online-state getter",
        "behavior": "return whether the process-wide client object is present",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "The source and target entries are the first callbacks in corresponding TPlayer property tables.",
            "Both bodies return a nonzero test of the client singleton, with no arguments, calls, or literal references.",
            "The following target property entries are the already translated paused and reading getters, preserving the TPlayer table identity.",
        ],
    },
    {
        "original_ea": "0x1e0078",
        "original_name": "GuiDrawingPanel_set_enablecache",
        "spectron_ea": "0x1e3f6c",
        "target_name": "sub_1E3F6C",
        "source_context": ["0x383de8"],
        "spectron_context": ["0x396e48"],
        "source_component": "GuiDrawingPanel",
        "target_component": "Spectron V8fxgahcBw drawing-panel cluster",
        "role": "drawing-panel cache enable setter",
        "behavior": "store the enable flag in the drawing panel and clear its cache when disabling it",
        "expected_metric_differences": set(),
        "layout_change": False,
        "evidence": [
            "Both bodies read the panel pointer from receiver offset +464 and write the flag at panel offset +140.",
            "Both clear the panel cache only when the requested flag is false, then return the panel pointer.",
            "The target pseudocode identifies the renamed class-local clear-cache method as the counterpart of TDrawingPanel::clearCache.",
        ],
    },
    {
        "original_ea": "0x1eb8a0",
        "original_name": "TClient_deleteWeapon",
        "spectron_ea": "0x1eff78",
        "target_name": "sub_1EFF78",
        "source_context": ["0x369988", "0x384938"],
        "spectron_context": ["0x37c758", "0x397998"],
        "source_component": "TClient inbound handler table",
        "target_component": "Spectron TClient inbound handler table",
        "role": "client delete-weapon inbound wrapper",
        "behavior": "forward the delete-weapon string to the active player when the player exists",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "The source and target functions occupy handler-table index 5, at 0x369988 and 0x37c758.",
            "The same source and target property-table slots also point to these functions at 0x384938 and 0x397998.",
            "Both bodies guard the active player singleton and forward the one string argument before returning the guarded pointer.",
        ],
    },
    {
        "original_ea": "0x1eb91c",
        "original_name": "TClient_clearInDataHandlers",
        "spectron_ea": "0x1efff4",
        "target_name": "sub_1EFFF4",
        "source_context": ["0x3845a8"],
        "spectron_context": ["0x397608"],
        "source_component": "TClient inbound handler state",
        "target_component": "Spectron client inbound handler state",
        "role": "client inbound-handler table clear",
        "behavior": "clear the 256-entry inbound handler array when it has been initialized",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "Both bodies guard a global handler-table pointer and zero exactly 0x800 bytes with memset.",
            "The source and target references occur in the corresponding client handler-state context.",
            "The target global is the obfuscated client singleton field replacing data_TClient_indatahandlers.",
        ],
    },
    {
        "original_ea": "0x1fa50c",
        "original_name": "TCachedStream_set_minfilecachesize",
        "spectron_ea": "0x1ffcbc",
        "target_name": "sub_1FFCBC",
        "source_context": ["0x385630"],
        "spectron_context": ["0x3986f0"],
        "source_component": "TCachedStream cache-size properties",
        "target_component": "Spectron SDrvgadS3u cache-size properties",
        "role": "minimum file-cache-size setter",
        "behavior": "clamp a signed cache-size argument at zero and store it in the minimum cache-size global",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "Both bodies use the same signed-negative clamp, unsigned conversion, global store, and return value.",
            "The source and target property references are 0x385630 and 0x3986f0.",
            "The target function precedes the matched maximum-cache-size setter in the same property cluster.",
        ],
    },
    {
        "original_ea": "0x1fa534",
        "original_name": "TCachedStream_set_maxramcachesize",
        "spectron_ea": "0x1ffce4",
        "target_name": "sub_1FFCE4",
        "source_context": ["0x385660"],
        "spectron_context": ["0x398720"],
        "source_component": "TCachedStream cache-size properties",
        "target_component": "Spectron SDrvgadS3u cache-size properties",
        "role": "maximum RAM-cache-size setter",
        "behavior": "clamp a signed cache-size argument at zero and store it in the maximum RAM-cache-size global",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "Both bodies use the same signed-negative clamp, unsigned conversion, global store, and return value.",
            "The source and target property references are 0x385660 and 0x398720.",
            "The target function follows the matched minimum-cache-size setter, preserving the source property order.",
        ],
    },
    {
        "original_ea": "0x1fbbc8",
        "original_name": "TFileDownload_clearFilesToIgnore_void",
        "spectron_ea": "0x2014c0",
        "target_name": "_ZN10uq9xgaUxlx10SgxMcbYBrmEv",
        "source_context": ["0x3858f0"],
        "spectron_context": ["0x398988"],
        "source_component": "TFileDownload script table",
        "target_component": "Spectron uq9xgaUxlx script table",
        "role": "adventure_clearfilestoignore script wrapper",
        "behavior": "clear the scripted-download ignore-list container when it has been initialized",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "The source row is script-table index 1 and the target row is the named adventure_clearfilestoignore entry at the corresponding shifted table position.",
            "The target retains an ABI name instead of an IDA sub_ name, but its class-local role is the clear-files-to-ignore helper.",
            "Both wrappers guard the ignore-list object and call its clear operation before returning the guarded object.",
        ],
    },
    {
        "original_ea": "0x1fbbe8",
        "original_name": "TFileDownload_script_Adventure_requestUpdateModTime",
        "spectron_ea": "0x2014e0",
        "target_name": "sub_2014E0",
        "source_context": ["0x385908", "0x3859c0", "0x385a98"],
        "spectron_context": ["0x3989a0", "0x398a80", "0x398b58"],
        "source_component": "TFileDownload script table",
        "target_component": "Spectron uq9xgaUxlx script table",
        "role": "adventure_requestupdatemodtime script wrapper",
        "behavior": "send a file modification-time update through the active client when present",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "The source row is the request-updatemodtime script entry and the target row is the same named entry in the target table.",
            "Both guard the client singleton and forward the script string argument to the client update method.",
            "The source and target table and client-call context references are paired in the artifact for later audit.",
        ],
    },
    {
        "original_ea": "0x1fbc04",
        "original_name": "TFileDownload_script_adventure_requestupdatecrc",
        "spectron_ea": "0x2014fc",
        "target_name": "sub_2014FC",
        "source_context": ["0x385900", "0x385990", "0x385a68"],
        "spectron_context": ["0x398998", "0x398a50", "0x398b28"],
        "source_component": "TFileDownload script table",
        "target_component": "Spectron uq9xgaUxlx script table",
        "role": "adventure_requestupdatecrc script wrapper",
        "behavior": "send a file CRC update through the active client when present",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "The source row is the requestupdatecrc script entry and the target row is the same named entry in the target table.",
            "Both guard the client singleton and forward the script string argument to the client CRC-update method.",
            "The source and target table and client-call context references are paired in the artifact for later audit.",
        ],
    },
    {
        "original_ea": "0x1fbc20",
        "original_name": "TFileDownload_script_adventure_requestdownload",
        "spectron_ea": "0x201518",
        "target_name": "sub_201518",
        "source_context": ["0x3858f8", "0x385960", "0x385a38"],
        "spectron_context": ["0x398990", "0x398a20", "0x398af8"],
        "source_component": "TFileDownload script table",
        "target_component": "Spectron uq9xgaUxlx script table",
        "role": "adventure_requestdownload script wrapper",
        "behavior": "request a file download through the active client when present",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "The source row is the requestdownload script entry and the target row is the same named entry in the target table.",
            "Both guard the client singleton and forward the script string argument to the client download-request method.",
            "The source and target table and client-call context references are paired in the artifact for later audit.",
        ],
    },
    {
        "original_ea": "0x217e50",
        "original_name": "TCallStackEntry_get_scriptcallobject",
        "spectron_ea": "0x21f460",
        "target_name": "sub_21F460",
        "source_context": ["0x387d70"],
        "spectron_context": ["0x39aec0"],
        "source_component": "TCallStackEntry property table",
        "target_component": "Spectron TCallStackEntry property table",
        "role": "script-call-object getter",
        "behavior": "return the call object's script-call object at offset +112, or zero when the call object is absent",
        "expected_metric_differences": set(),
        "layout_change": False,
        "evidence": [
            "The source and target entries are the first callbacks in corresponding TCallStackEntry property tables at 0x387d58 and 0x39aea8.",
            "Both bodies load the call object from receiver offset +224, test it, and return its field at +112 or zero.",
            "The identical two-level field access separates this target from the unrelated TGaniObject getter with the same compact feature shape.",
        ],
    },
    {
        "original_ea": "0x22bce0",
        "original_name": "TScriptUniverse_script_rungarbagecollector",
        "spectron_ea": "0x2356c4",
        "target_name": "sub_2356C4",
        "source_context": ["0x387dd8"],
        "spectron_context": ["0x39af28"],
        "source_component": "TScriptUniverse script table",
        "target_component": "Spectron QYZugaRKGu script table",
        "role": "rungarbagecollector script wrapper",
        "behavior": "run the script-universe garbage collector when the global universe object is present",
        "expected_metric_differences": {"register_detail_hash"},
        "layout_change": False,
        "evidence": [
            "The source and target entries occupy the corresponding script-property context at 0x387dd8 and 0x39af28.",
            "Both guard the global script-universe object and forward to its garbage-collect method.",
            "The target QYZugaRKGu and e4ZYfa8PV2 names identify the obfuscated universe and helper classes in the target pseudocode.",
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
        differing = {
            field
            for field in METRIC_FIELDS
            if source_metrics[field] != target_metrics[field]
        }
        if differing != spec["expected_metric_differences"]:
            raise ValueError(
                "unexpected metric differences at 0x%x: %s"
                % (source_ea, ", ".join(sorted(differing)))
            )
        if any(source_metrics[field] != target_metrics[field] for field in SHAPE_FIELDS):
            raise ValueError("normalized shape mismatch at 0x%x" % source_ea)

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
                "match_kind": "manual-compact-residual-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["role"],
                "behavior": spec["behavior"],
                "target_delta": "+0x%x" % (target_ea - source_ea),
                "target_delta_decimal": target_ea - source_ea,
                "metric_differences": sorted(differing),
                "evidence": spec["evidence"]
                + [
                    "All normalized shape fields match; the recorded register-detail difference reflects target relocation or allocation changes."
                    if differing
                    else "All recorded ARM64 features match exactly, including register detail."
                ],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
                "layout_change": spec["layout_change"],
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_compact_residual_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact property, wrapper, handler, cache, and script helpers below the broad semantic matcher cutoff",
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
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(
                not row["metric_differences"] for row in anchors
            ),
            "layout_change_anchor_count": sum(row["layout_change"] for row in anchors),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"]
                for row in anchors
            ),
            "source_default_name_count": sum(
                row["original_name"].startswith("sub_") for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "context": {
            "source_components": [
                "TGaniObject",
                "TPlayer",
                "GuiDrawingPanel",
                "TClient",
                "TCachedStream",
                "TFileDownload",
                "TCallStackEntry",
                "TScriptUniverse",
            ],
            "target_components": [
                "Spectron TGaniObject",
                "Spectron TPlayer",
                "Spectron V8fxgahcBw",
                "Spectron client handler state",
                "Spectron SDrvgadS3u",
                "Spectron uq9xgaUxlx",
                "Spectron TCallStackEntry",
                "Spectron QYZugaRKGu",
            ],
            "resolution": "property-table and inbound-handler alignment, target pseudocode, complete normalized ARM64 shape, and explicit target layout notes",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The broad matcher skips the compact functions in this artifact, so table context is part of the identity evidence rather than an after-the-fact label.",
            "The source TFileDownload canDownload body has the same small global-client predicate as the matched TPlayer online getter, but no separate target table entry was found. It remains an unresolved folded-body note and is intentionally not assigned a second target name.",
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
