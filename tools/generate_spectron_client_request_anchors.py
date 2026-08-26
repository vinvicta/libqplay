#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for client request helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1f8480",
        "original_name": "TClient_sendWeaponImgChange_TString_const",
        "spectron_ea": "0x1fe088",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "expected_target_size": 428,
        "expected_target_instruction_count": 105,
        "expected_target_basic_block_count": 15,
        "source_basis": "weapon-image request serialization",
        "evidence": [
            "The source emits the onSendWeaponImage diagnostic event or forwards one string through the normal client send slot.",
            "The target preserves the same one-string diagnostic and normal output paths in the first member of the client request tail.",
            "The target mangled signature retains the const TString reference and the surrounding request order is unchanged.",
        ],
    },
    {
        "original_ea": "0x1f8534",
        "original_name": "TClient_sendRCChat_TString_const",
        "spectron_ea": "0x1fe234",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "expected_target_size": 428,
        "expected_target_instruction_count": 105,
        "expected_target_basic_block_count": 15,
        "source_basis": "RC chat request serialization",
        "evidence": [
            "The source emits the onSendRCChat diagnostic event or forwards one string through the normal client send slot.",
            "The target preserves the same one-string method shape immediately after the weapon-image helper.",
            "The target method order and mangled const TString reference distinguish this request from the adjacent three-string helper.",
        ],
    },
    {
        "original_ea": "0x1f85e8",
        "original_name": "TClient_sendRequestText_TString_const_TString_const_TString_const",
        "spectron_ea": "0x1fe3e0",
        "target_name_fragment": "ERK10C8THgaTQxFS2_S2_",
        "expected_target_size": 656,
        "expected_target_instruction_count": 162,
        "expected_target_basic_block_count": 27,
        "source_basis": "three-string request-text serialization",
        "evidence": [
            "The source emits onSendRequestText with three strings in diagnostic mode and otherwise joins the same three values before normal dispatch.",
            "The target retains three string parameters, the diagnostic path, and the temporary list used by the normal comma-text encoding.",
            "Its position directly after the two one-string requests completes the corresponding source request order.",
        ],
    },
    {
        "original_ea": "0x1f88fc",
        "original_name": "TClient_sendRequestFileDeletion_TString_const",
        "spectron_ea": "0x1fe960",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "expected_target_size": 456,
        "expected_target_instruction_count": 112,
        "expected_target_basic_block_count": 15,
        "source_basis": "file-deletion request serialization",
        "evidence": [
            "The source emits onSendFileDeletion in diagnostic mode and otherwise strips the path to a filename before dispatch.",
            "The target preserves the same one-string event path and calls its file helper before normal packet output.",
            "The target follows the set-text serializer at the same point where the source begins the file-operation request tail.",
        ],
    },
    {
        "original_ea": "0x1f89d4",
        "original_name": "TClient_sendRequestFolderDeletion_TString_const",
        "spectron_ea": "0x1feb28",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "expected_target_size": 428,
        "expected_target_instruction_count": 105,
        "expected_target_basic_block_count": 15,
        "source_basis": "folder-deletion request serialization",
        "evidence": [
            "The source emits onSendFolderDeletion in diagnostic mode and forwards one string in normal mode.",
            "The target retains the same one-string diagnostic and normal client-send paths.",
            "Its position after file deletion and before file rename matches the source request sequence.",
        ],
    },
    {
        "original_ea": "0x1f8a88",
        "original_name": "TClient_sendRequestFileRename_TString_const_TString_const",
        "spectron_ea": "0x1fecd4",
        "target_name_fragment": "ERK10C8THgaTQxFS2_",
        "expected_target_size": 844,
        "expected_target_instruction_count": 211,
        "expected_target_basic_block_count": 41,
        "source_basis": "file-rename request serialization",
        "evidence": [
            "The source emits two strings in diagnostic mode and otherwise extracts, bounds, and joins both filenames before dispatch.",
            "The target retains the two-string mangled signature and the same compact or long-string handling for both path arguments.",
            "The target is the larger file-rename body immediately after folder deletion, matching the source method order.",
        ],
    },
    {
        "original_ea": "0x1f8cd0",
        "original_name": "TClient_sendRequestFilesMove_TString_const_TString_const",
        "spectron_ea": "0x1ff020",
        "target_name_fragment": "ERK10C8THgaTQxFS2_",
        "expected_target_size": 664,
        "expected_target_instruction_count": 164,
        "expected_target_basic_block_count": 30,
        "source_basis": "file-move request serialization",
        "evidence": [
            "The source encodes the source filename and destination string, using the long-string escape path when required.",
            "The target preserves the same two-string normal packet and diagnostic output paths with the corresponding target signature.",
            "The target follows file rename and precedes the update-package helper as in the source request cluster.",
        ],
    },
    {
        "original_ea": "0x1f8e60",
        "original_name": "TClient_sendRequestUpdatePackage_TUpdatePackage_bool",
        "spectron_ea": "0x1ff2b8",
        "target_name_fragment": "EP10RH6ygazf9xb",
        "expected_target_size": 1032,
        "expected_target_instruction_count": 258,
        "expected_target_basic_block_count": 35,
        "source_basis": "update-package request and checksum serialization",
        "evidence": [
            "The source emits the update-package object and boolean in diagnostic mode, then encodes package files, checksums, and the update marker for normal output.",
            "The target retains the update-package pointer and boolean signature and the same package-list, checksum, and downloads-blocked sequence.",
            "The target is the only large object-backed helper in the request tail and sits between file moves and window-state requests.",
        ],
    },
    {
        "original_ea": "0x1f9198",
        "original_name": "TClient_sendHaveWindow_bool_TString_const",
        "spectron_ea": "0x1ff6c0",
        "target_name_fragment": "EbRK10C8THgaTQxF",
        "expected_target_size": 520,
        "expected_target_instruction_count": 128,
        "expected_target_basic_block_count": 15,
        "source_basis": "window-presence request serialization",
        "evidence": [
            "The source emits the boolean and window name with the onSendHaveWindow diagnostic event or the compact bs normal packet.",
            "The target preserves the bool plus string signature and the same bs diagnostic and normal output shapes.",
            "Its location after update-package serialization and before ping matches the source request order.",
        ],
    },
    {
        "original_ea": "0x1f92b4",
        "original_name": "TClient_sendPingAnswer_int",
        "spectron_ea": "0x1ff8c8",
        "target_name_fragment": "Ei",
        "expected_target_size": 472,
        "expected_target_instruction_count": 118,
        "expected_target_basic_block_count": 12,
        "source_basis": "ping-answer integer serialization",
        "evidence": [
            "The source emits onSendPingAnswer with one integer or encodes the clamped integer in the compact two-character form.",
            "The target preserves the same integer clamp, compact encoding, and diagnostic event path.",
            "The target signature and position between window presence and window list provide an independent protocol anchor.",
        ],
    },
    {
        "original_ea": "0x1f93e8",
        "original_name": "TClient_sendWindowList_TString_const",
        "spectron_ea": "0x1ffaa0",
        "target_name_fragment": "ERK10C8THgaTQxF",
        "expected_target_size": 428,
        "expected_target_instruction_count": 105,
        "expected_target_basic_block_count": 15,
        "source_basis": "window-list request serialization",
        "evidence": [
            "The source emits onSendWindowList in diagnostic mode or forwards one string through the normal client send slot.",
            "The target preserves the same one-string diagnostic and normal output paths.",
            "It is the final member of the request tail before the target send-data and outgoing wrappers, matching the source order.",
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
                "target %s does not retain expected signature fragment: %s"
                % (spec["spectron_ea"], spec["target_name_fragment"])
            )
        for field in ("size", "instruction_count", "basic_block_count"):
            expected = spec["expected_target_" + field]
            if target.get(field) != expected:
                raise ValueError(
                    "target %s %s mismatch: expected %s, got %s"
                    % (spec["spectron_ea"], field, expected, target.get(field))
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
                "match_kind": "manual-client-request-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in client request anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_client_request_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for client request and window-state serializers",
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
            "These rows describe local client request and window-state logic; they do not establish compatibility with an external service.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
