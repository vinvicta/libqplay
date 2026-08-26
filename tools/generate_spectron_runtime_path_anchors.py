#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for the runtime path.

These rows cover map entry, file delivery, encrypted scripts, text controls,
and the server-list state machine.  The generator validates the exact target
string evidence and does not modify an IDA database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1ea56c",
        "original_name": "TClient_setServerLevelFile",
        "spectron_ea": "0x1eead4",
        "source_basis": "server level filename normalization and .gmap or level selection",
        "required_target_strings": [".gmap"],
        "evidence": [
            "The candidate normalizes the server level filename, checks the .gmap extension, and selects the active server-level object on the same branches.",
            "Its 2.2 pseudocode retains the same global level-name and server-level state updates as the readable 1.8 body.",
            "Both functions have seven basic blocks and the same unique .gmap discriminator; the target was an IDA default sub_ name.",
        ],
    },
    {
        "original_ea": "0x1ea878",
        "original_name": "TClient_enterServerMapFile",
        "spectron_ea": "0x1ef0a0",
        "source_basis": "map metadata transfer, first-level selection, and server-level entry",
        "required_target_strings": [".gmap"],
        "evidence": [
            "The candidate copies map metadata into the active player, resolves a .gmap, selects its first level, and enters that level.",
            "The target preserves the same map-resource lookup, level-list test, state reset, and level-entry call sequence.",
            "Both builds have seven basic blocks and the same .gmap branch; the rebuilt target remains an IDA default sub_ name.",
        ],
    },
    {
        "original_ea": "0x1f15b8",
        "original_name": "TClient_handleMapLevelPacket",
        "spectron_ea": "0x1f6108",
        "source_basis": "map-level packet decoding and selected-level entry",
        "required_target_strings": [".gmap"],
        "evidence": [
            "The candidate decodes the map coordinates and filename from the packet, recognizes .gmap data, and enters the selected server level.",
            "It preserves the same active-player fields, map lookup, first-level selection, and transition reset used by the 1.8 handler.",
            "The target retains 13 basic blocks and the .gmap discriminator, with a modest rebuilt-body expansion.",
        ],
    },
    {
        "original_ea": "0x1eb294",
        "original_name": "TClient_finishFileDownload",
        "spectron_ea": "0x1ef8fc",
        "source_basis": "cached-file completion, download event, package update, and resource validation",
        "required_target_strings": [".gupd"],
        "evidence": [
            "The candidate clears the completed cache entry, emits the file-download event, saves and updates the cached stream, and removes the requested file.",
            "It retains the .gupd package-update branch, resource file-key validation, and current-download reset sequence.",
            "Both builds have 12 basic blocks and the same completion-side state transitions; the target was an IDA default sub_ name.",
        ],
    },
    {
        "original_ea": "0x1ec764",
        "original_name": "TClient_processFileChunk",
        "spectron_ea": "0x1f1074",
        "source_basis": "file-chunk cache creation, progress events, and completion dispatch",
        "required_target_strings": [".gupd"],
        "evidence": [
            "The candidate creates or reuses the cached stream, resolves the download target, appends the chunk, and updates byte accounting.",
            "It preserves onFileChunkReceived and onFileDownloaded event behavior, .gupd handling, resource validation, and completion dispatch.",
            "Both builds retain 52 basic blocks and the same .gupd and file-progress context, while the target is a larger rebuilt default sub_ function.",
        ],
    },
    {
        "original_ea": "0x1f1e68",
        "original_name": "TClient_handleTextControlPacket",
        "spectron_ea": "0x1f6670",
        "source_basis": "GraalEngine and QEngine text-control dispatch",
        "required_target_strings": ["GraalEngine", "QEngine", "getstats", "receivetext", "stats"],
        "evidence": [
            "The candidate parses the same three control fields, handles QEngine getstats, and sends stats back through the same client text path.",
            "For ordinary controls it resolves the active player's weapon, builds the same receive-text argument array, and invokes receivetext.",
            "Both builds retain all five distinctive strings and 12 basic blocks; the target was an IDA default sub_ name.",
        ],
    },
    {
        "original_ea": "0x1f2b84",
        "original_name": "TClient_processTextControlAction",
        "spectron_ea": "0x1f73d0",
        "source_basis": "text-control action routing and QEngine statistics response",
        "required_target_strings": ["GraalEngine", "QEngine", "getstats", "receivetext", "stats"],
        "evidence": [
            "The candidate preserves the GraalEngine and QEngine tests, the getstats response, and the ordinary receivetext dispatch with parsed arguments.",
            "Its target pseudocode matches the 1.8 argument order and active-weapon routing even though the rebuilt signature is larger.",
            "The exact five-string set and 10 basic-block shape distinguish it from the neighboring text-control handler; the target was a default sub_ name.",
        ],
    },
    {
        "original_ea": "0x1f212c",
        "original_name": "TClient_setEncryptedScript",
        "spectron_ea": "0x1f696c",
        "source_basis": "encrypted script packet decoding and weapon or class routing",
        "required_target_strings": ["class", "gani", "weapon"],
        "evidence": [
            "The candidate decodes the same compact coordinates and length fields from the encrypted script packet.",
            "It routes weapon data to the encrypted-weapon setter and class data to the script-universe class path, preserving the npc and gani fallbacks.",
            "Both builds retain 32 basic blocks, nearly identical instruction counts, and the same class, gani, and weapon string set; the target was a default sub_ name.",
        ],
    },
    {
        "original_ea": "0x1f25a8",
        "original_name": "TClient_loadEncryptedScript",
        "spectron_ea": "0x1f6dec",
        "source_basis": "encrypted script packet decoding and weapon or class loading",
        "required_target_strings": ["class", "gani", "weapon"],
        "evidence": [
            "The candidate decodes the same encrypted script fields and optional timeout or revision value.",
            "It routes weapon data to the encrypted loader and class data to the class-request path, matching the 1.8 role and control flow.",
            "Both builds retain 30 basic blocks, nearly identical instruction counts, and the same class, gani, and weapon string set; the target was a default sub_ name.",
        ],
    },
    {
        "original_ea": "0x2031b0",
        "original_name": "TServerList_onClientDisconnected_void",
        "spectron_ea": "0x2087f4",
        "source_basis": "disconnect cleanup, SSL error reporting, and connector callback",
        "required_target_strings": ["StartScript_Connector"],
        "evidence": [
            "The candidate clears the active game connection, hides the connecting window, reads the SSL error, and invokes the connector onDisconnected event.",
            "It preserves the same StartScript_Connector lookup and disconnect-reason argument construction.",
            "The target has the same role and nearby server-list context with a rebuilt block boundary; the target was an IDA named C++ function.",
        ],
    },
    {
        "original_ea": "0x204488",
        "original_name": "TServerList_handleServerWarp_void",
        "spectron_ea": "0x20a010",
        "source_basis": "server-warp argument parsing and connector callback",
        "required_target_strings": ["StartScript_Connector"],
        "evidence": [
            "The candidate parses the same destination fields, resolves StartScript_Connector, and invokes onServerWarp with the same string and integer arguments.",
            "The target preserves the server-warp reset and connector-script lookup sequence from the readable 1.8 body.",
            "The target is in the same server-list state-machine neighborhood and retains the distinctive StartScript_Connector string.",
        ],
    },
    {
        "original_ea": "0x203360",
        "original_name": "TServerList_handleClient_void",
        "spectron_ea": "0x2089d0",
        "source_basis": "server-list client loop, timeout transition, and deleted-player cleanup",
        "required_target_strings": ["StartScript_Connector"],
        "evidence": [
            "The candidate handles reconnect notifications, processes incoming packages, checks the socket timeout state, and calls the reviewed disconnect routine.",
            "It preserves the all-player walking reset and deleted-player cleanup loop from the 1.8 client handler.",
            "The target pseudocode has the same state fields and control-flow phases, with 39 versus 40 basic blocks and the same connector-script context.",
        ],
    },
    {
        "original_ea": "0x1e7eb0",
        "original_name": "TClient_initStaticVars_void",
        "spectron_ea": "0x1ec294",
        "source_basis": "client static state and download-list initialization",
        "required_target_strings": ["0.0.0.0"],
        "evidence": [
            "The candidate initializes the same loopback default address, client lists, download state, and fixed-size packet or status tables.",
            "Its pseudocode shows the same static construction role, with the 2.2 build adding state that was not present in the shorter 1.8 initializer.",
            "The exact 0.0.0.0 string and initializer context make this a reviewed static-state anchor rather than a size-only match.",
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
        target_strings = set(target.get("string_refs", []))
        missing_strings = sorted(set(spec["required_target_strings"]) - target_strings)
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
                "match_kind": "manual-runtime-path-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in runtime-path anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_runtime_path_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for map entry, file delivery, scripts, text controls, and server-list state",
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
            "The map and file-path rows describe the client transition logic; they do not prove that an external server still emits the same packets.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
