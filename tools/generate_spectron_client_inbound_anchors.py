#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for client inbound state paths."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1e7bf0",
        "original_name": "TClient_manageDataByScript_uchar_TString_const",
        "spectron_ea": "0x1ebf78",
        "target_name_fragment": "hRK10C8THgaTQxF",
        "expected_target_size": 252,
        "expected_target_instruction_count": 63,
        "expected_target_basic_block_count": 1,
        "source_basis": "script data event and array construction",
        "evidence": [
            "The source creates a script array, stores the boolean and string values, and invokes the onData event.",
            "The target preserves the same bool and const-string parameter shape, array slots, event construction, and cleanup sequence.",
            "Its position between the player lookup and incoming-package methods matches the client state helper cluster, while the target signature retains the const TString reference.",
        ],
    },
    {
        "original_ea": "0x1e9198",
        "original_name": "TClient_uploadFilesToServer_void",
        "spectron_ea": "0x1ed624",
        "target_name_fragment": "PUEv",
        "expected_target_size": 568,
        "expected_target_instruction_count": 141,
        "expected_target_basic_block_count": 14,
        "source_basis": "queued file upload loop and completion event",
        "evidence": [
            "The source walks the pending upload list, loads each file, sends upload-start and save-file packets, removes completed entries, and emits onFilesUploaded.",
            "The target retains the same queue guard, byte accounting, upload packet sequence, list cleanup, and final event path despite the rebuilt helper names.",
            "The target is the only no-argument upload-loop method between the one-file validator and the download-stall helper, and its mangled signature ends in a no-argument form.",
        ],
    },
    {
        "original_ea": "0x1ea9f4",
        "original_name": "TClient_processServerModifies2",
        "spectron_ea": "0x1eedfc",
        "target_name_fragment": "sub_1EEDFC",
        "expected_target_size": 420,
        "expected_target_instruction_count": 105,
        "expected_target_basic_block_count": 21,
        "source_basis": "server modification cleanup and level transition",
        "evidence": [
            "The source clears server-level object lists, resets the pending map state, and either enters the selected server level or applies server modifications in place.",
            "The target preserves both object-list cleanup loops, the active-player transition condition, and the same do-modifies or enter-level branches.",
            "The target remains an IDA default name and occupies the server-modification cluster immediately after the matched third modification helper.",
        ],
    },
    {
        "original_ea": "0x1eac34",
        "original_name": "TClient_enterServerMapTile",
        "spectron_ea": "0x1ef24c",
        "target_name_fragment": "sub_1EF24C",
        "expected_target_size": 936,
        "expected_target_instruction_count": 234,
        "expected_target_basic_block_count": 12,
        "required_target_strings": [".gmap"],
        "source_basis": "server map tile selection and level entry",
        "evidence": [
            "The source normalizes the .gmap filename, clamps tile coordinates to the map bounds, selects the tile level, and builds the resulting coordinate string.",
            "The target preserves the same active-player state fields, .gmap lookup, coordinate clamping, requested-warp comparison, and level-entry branches.",
            "The target has the same 12 basic blocks and the same .gmap discriminator, with a larger rebuilt body and a default sub_ name.",
        ],
    },
    {
        "original_ea": "0x1ec044",
        "original_name": "TClient_handleUpdatePackageDownloaded",
        "spectron_ea": "0x1f08ec",
        "target_name_fragment": "sub_1F08EC",
        "expected_target_size": 396,
        "expected_target_instruction_count": 97,
        "expected_target_basic_block_count": 11,
        "source_basis": "downloaded update-package state and completion events",
        "evidence": [
            "The source resolves the update package, marks it downloaded, saves its local version, emits onUpdatePackageDownloaded, and conditionally emits onPackagesDownloadComplete.",
            "The target preserves the package state writes, the object event argument, the package-complete branch, and the optional executable-replacer handoff.",
            "The target is the only object-backed default sub_ helper between encrypted-script loading and extra removal in the corresponding client path.",
        ],
    },
    {
        "original_ea": "0x1ed3e8",
        "original_name": "TClient_updateGlobalPlayer",
        "spectron_ea": "0x1f1d98",
        "target_name_fragment": "sub_1F1D98",
        "expected_target_size": 968,
        "expected_target_instruction_count": 237,
        "expected_target_basic_block_count": 28,
        "required_target_strings": ["\"Mass message:\""],
        "source_basis": "global-player creation, logout, login, and mass-message handling",
        "evidence": [
            "The source creates or updates a global player, moves logged-out players to the deleted list, handles mass-message merging, and emits onPlayerLogin or onPlayerLogout.",
            "The target preserves the same player allocation and property update flow, deleted-player recovery, list limits, message merge, and login or logout event arguments.",
            "The target retains the distinctive Mass message string and the same broad client-player update body, while its rebuilt function has the expected two-argument shape.",
        ],
    },
    {
        "original_ea": "0x1f1dd0",
        "original_name": "TClient_updateGaniFromString",
        "spectron_ea": "0x1f65d4",
        "target_name_fragment": "sub_1F65D4",
        "expected_target_size": 156,
        "expected_target_instruction_count": 39,
        "expected_target_basic_block_count": 5,
        "source_basis": "GANI object reload from a serialized string",
        "evidence": [
            "The source loads the selected GANI object, converts the supplied string into a line list, serializes it back, and replaces the animation data.",
            "The target preserves the same input list test, GANI load call, line-list conversion, and animation replacement sequence.",
            "The target has the same five-block shape and remains an IDA default sub_ name in the client script and animation cluster.",
        ],
    },
    {
        "original_ea": "0x1f2a20",
        "original_name": "TClient_handleGaniUpdate",
        "spectron_ea": "0x1f7268",
        "target_name_fragment": "sub_1F7268",
        "expected_target_size": 360,
        "expected_target_instruction_count": 90,
        "expected_target_basic_block_count": 15,
        "source_basis": "GANI update packet parsing and animation reload",
        "evidence": [
            "The source decodes the animation name and payload from the incoming string, loads the GANI, converts the payload to a line list, and applies the update.",
            "The target preserves the same index and length arithmetic, substring construction, GANI load, line-list conversion, and animation replacement calls.",
            "The target has the same 15 basic blocks and nearly identical instruction count, providing a stronger body match than a size-only alias.",
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
        if spec["target_name_fragment"] not in target.get("name", ""):
            raise ValueError(
                "target %s does not retain expected name fragment: %s"
                % (spec["spectron_ea"], spec["target_name_fragment"])
            )
        for field in ("size", "instruction_count", "basic_block_count"):
            expected = spec["expected_target_" + field]
            if target.get(field) != expected:
                raise ValueError(
                    "target %s %s mismatch: expected %s, got %s"
                    % (spec["spectron_ea"], field, expected, target.get(field))
                )
        target_strings = set(target.get("string_refs", []))
        missing_strings = sorted(
            set(spec.get("required_target_strings", [])) - target_strings
        )
        if missing_strings:
            raise ValueError(
                "target %s is missing expected strings: %s"
                % (spec["spectron_ea"], ", ".join(missing_strings))
            )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_size": source["size"],
                "original_instruction_count": source["instruction_count"],
                "original_basic_block_count": source["basic_block_count"],
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_size": target["size"],
                "spectron_instruction_count": target["instruction_count"],
                "spectron_basic_block_count": target["basic_block_count"],
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-client-inbound-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in client inbound anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_inbound_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for client inbound and state-transition helpers",
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
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated or default 2.2 name in the evidence row.",
            "These rows describe local client state and inbound packet handling; they do not establish compatibility with an external service.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
