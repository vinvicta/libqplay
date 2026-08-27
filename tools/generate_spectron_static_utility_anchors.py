#!/usr/bin/env python3
"""Create reviewed anchors for Spectron's static utility clusters."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


GROUP_EVIDENCE = {
    "log_stats": [
        "Both methods build the selectable engine statistics report for system, graphics, memory, profiler, and script sections. They preserve the same filters, UTC time, client version, platform and CPU lines, memory counters, drawing and texture counters, profiler handoff, and trailing separator.",
        "The target retains every source report literal and adds the target-only `GRAALRELOADED-version` line. Source metrics are 1844 bytes, 461 instructions, and 34 blocks. Target metrics are 1800 bytes, 450 instructions, and 34 blocks.",
        "The target and source occupy the corresponding logging utility position and use the same report list operations. The changed version line is an identified target addition, not a reason to reject the otherwise direct correspondence.",
    ],
    "profiler_dump": [
        "Both methods write the profiler tree and measured timing entries into a string list, including the ordered-by-non-sub-total heading, the function-tree heading, the seconds suffix, and the same formatted timing row.",
        "All six profiler-output literals are shared and the source and target each have 61 basic blocks. The target body is 1368 bytes and 341 instructions, compared with 1488 bytes and 371 instructions in 1.8.",
        "The target routine remains the profiler object helper called by the translated statistics method. The reduced target body reflects rebuilt list and floating-point wrappers while preserving the report structure.",
    ],
    "gui_style": [
        "Both methods read a named GUI style button entry, parse the same comma-separated normal, pressed, disabled, and focus image names, then copy the Bitmap, Image, FrameCount, tile, border, and progress fields into the result object.",
        "The target preserves all 16 style-property literals, including `Normal,Pressed,Disabled,Focus`, and keeps the exact 23-block structure. Target metrics are 1460 bytes and 362 instructions versus 1428 bytes and 354 instructions in 1.8.",
        "The target's obfuscated method is in the same GUI-style class-local cluster and retains the full property vocabulary, making this a direct semantic translation.",
    ],
    "zip_resource": [
        "Both functions scan a resource archive entry, reject non-resource names, detect `.uis`, and return the same resource-object result through the `~!` marker path.",
        "The source and target retain both distinctive literals, `.uis` and `~!`, and have the exact 47-block structure. The target is 1436 bytes and 358 instructions versus 1388 bytes and 346 instructions in 1.8.",
        "The target routine occupies the corresponding resource-file scan position. Its changed string and resource wrappers account for the small body growth without changing the archive filter behavior.",
    ],
    "translation": [
        "Both methods add a translation entry, parse the same `Plural-Forms:` header, recognize the same `nplurals=2;` and `plural=n>1;` expressions, and update the same translation data structures.",
        "The source and target preserve all three distinctive plural-form literals and have the exact 35-block structure. The target is 888 bytes and 222 instructions versus 856 bytes and 214 instructions in 1.8.",
        "The target method remains in the corresponding translation-file utility cluster. The small size increase is wrapper expansion around the same plural-rule parsing and insertion logic.",
    ],
}


ANCHOR_SPECS = [
    {
        "original_ea": "0xf8890",
        "original_name": "TLogActions_getStats_TString_const_TStringList",
        "spectron_ea": "0xfaee8",
        "target_name": "_ZN10SYX_HaZ3zD10EP5AFabwPBERK10C8THgaTQxFP10vuuHgangcF",
        "proposed_name": "v18_TLogActions_getStats_TString_const_TStringList",
        "source_metrics": (1844, 461, 34),
        "target_metrics": (1800, 450, 34),
        "group": "log_stats",
        "source_basis": "engine statistics report construction",
        "required_string_refs": (
            "Game engine profiler:",
            "Memory (in bytes):",
            "  Client-version: ",
            "graphics",
            "memory",
            "profiler",
            "scripts",
            "system",
        ),
    },
    {
        "original_ea": "0xfa2e0",
        "original_name": "TProfiler_dumpToList_TStringList",
        "spectron_ea": "0xfc8d8",
        "target_name": "_ZN10esKIvakHfi10_IfAFaEQ6AEP10vuuHgangcF",
        "proposed_name": "v18_TProfiler_dumpToList_TStringList",
        "source_metrics": (1488, 371, 61),
        "target_metrics": (1368, 341, 61),
        "group": "profiler_dump",
        "source_basis": "profiler tree and timing list serialization",
        "required_string_refs": (
            " seconds",
            "%7.3f %7.3f %8d %s",
            "%NSTime  % Time  Invoke #  Name",
            "Function tree:",
            "Measured time: ",
            "Ordered by non-sub total time:",
        ),
    },
    {
        "original_ea": "0x1cdb8c",
        "original_name": "TGUIStyle_getButton_TString_const",
        "spectron_ea": "0x1d277c",
        "target_name": "_ZN10iHmzga6Hmy10T__fIaGC4QERK10C8THgaTQxF",
        "proposed_name": "v18_TGUIStyle_getButton_TString_const",
        "source_metrics": (1428, 354, 23),
        "target_metrics": (1460, 362, 23),
        "group": "gui_style",
        "source_basis": "GUI style button property extraction",
        "required_string_refs": (
            "Bitmap",
            "BottomHeight",
            "Buttons",
            "FrameCount",
            "Image",
            "LeftWidth",
            "Normal,Pressed,Disabled,Focus",
            "Progress",
            "RightWidth",
            "Tile",
            "TileBottom",
            "TileLeft",
            "TileRight",
            "TileTop",
            "TopHeight",
            "Trans",
        ),
    },
    {
        "original_ea": "0xe8bac",
        "original_name": "TFileNameScan_scanZipResource_TResourceObject",
        "spectron_ea": "0xe96d0",
        "target_name": "_ZN10CDPvgaY2nv10c7PvgaJsovEP10bNZvga2Awv",
        "proposed_name": "v18_TFileNameScan_scanZipResource_TResourceObject",
        "source_metrics": (1388, 346, 47),
        "target_metrics": (1436, 358, 47),
        "group": "zip_resource",
        "source_basis": "resource archive filename scan",
        "required_string_refs": (".uis", "~!"),
    },
    {
        "original_ea": "0xe3c30",
        "original_name": "TTranslationFile_addTranslation_TString_const_TString_const_TString_const",
        "spectron_ea": "0xe47f8",
        "target_name": "_ZN10Ztjndb0_dS10Q96mdbXD3RERK10C8THgaTQxFS2_S2_",
        "proposed_name": "v18_TTranslationFile_addTranslation_TString_const_TString_const_TString_const",
        "source_metrics": (856, 214, 35),
        "target_metrics": (888, 222, 35),
        "group": "translation",
        "source_basis": "translation entry and plural-rule insertion",
        "required_string_refs": ("Plural-Forms:", "nplurals=2;", "plural=n>1;"),
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
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "mnemonic_hash",
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
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        for side, function in (("source", source), ("target", target)):
            expected = spec["%s_metrics" % side]
            actual = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual != expected:
                raise ValueError(
                    "unexpected %s metrics at %s: %s"
                    % (side, spec["%s_ea" % side], actual)
                )
        for literal in spec["required_string_refs"]:
            if literal not in source.get("string_refs", []):
                raise ValueError(
                    "source %s lacks required string reference %s"
                    % (spec["original_ea"], literal)
                )
            if literal not in target.get("string_refs", []):
                raise ValueError(
                    "target %s lacks required string reference %s"
                    % (spec["spectron_ea"], literal)
                )
        if spectron_ea in semantic_targets:
            raise ValueError(
                "target %s is already present in the semantic map" % spec["spectron_ea"]
            )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-static-utility-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": GROUP_EVIDENCE[spec["group"]],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in static utility anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in static utility anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_static_utility_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for logging, profiling, GUI styles, resource scanning, and translations",
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
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": sum(
                row["semantic_match_already_present"] for row in anchors
            ),
            "new_context_anchor_count": sum(
                not row["semantic_match_already_present"] for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated 2.2 name in the evidence row.",
            "The correspondences are supported by direct Hex-Rays pseudocode, complete or distinctive literal sets, shared branch order, class-local position, and close control-flow metrics.",
            "The Spectron statistics method adds a target-only GRAALRELOADED-version line. That explicit version difference is recorded rather than hidden.",
            "Changed byte sizes and instruction counts are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
