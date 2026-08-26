#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for login and state helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1e96dc",
        "original_name": "TGameEnvironment_emit_onFolderLog",
        "spectron_ea": "0x1edb9c",
        "target_name": "sub_1EDB9C",
        "expected_target_size": 184,
        "expected_target_instruction_count": 45,
        "expected_target_basic_block_count": 6,
        "source_basis": "folder-log event helper",
        "evidence": [
            "The source is the first of two adjacent one-string game-environment event helpers.",
            "The target is the first corresponding helper after the preserved client state setter sequence.",
            "The target literal is transformed at compile time, but the same helper is independently referenced by the target upload-file size-error path, which is the source onFolderLog path.",
        ],
    },
    {
        "original_ea": "0x1e975c",
        "original_name": "TGameEnvironment_emit_onRCChat",
        "spectron_ea": "0x1edc54",
        "target_name": "sub_1EDC54",
        "expected_target_size": 184,
        "expected_target_instruction_count": 45,
        "expected_target_basic_block_count": 6,
        "source_basis": "RC chat event helper",
        "evidence": [
            "The source is the second adjacent one-string game-environment event helper after onFolderLog.",
            "The target is the second corresponding helper and has the same target-side decoder and invocation shape as the preceding helper.",
            "Its position and distinct transformed literal preserve the source event-helper order even though the original event text is not stored as a plain target string.",
        ],
    },
    {
        "original_ea": "0x1e97dc",
        "original_name": "TClient_handleServerLoginSignature",
        "spectron_ea": "0x1edd0c",
        "target_name": "sub_1EDD0C",
        "expected_target_size": 156,
        "expected_target_instruction_count": 38,
        "expected_target_basic_block_count": 3,
        "source_basis": "server-login signature storage and login event",
        "evidence": [
            "The source stores the incoming signature and invokes the onServerLogin event when the game environment exists.",
            "The target is the next helper after the two event wrappers and stores its argument in a client static before invoking a no-argument decoded event.",
            "The target retains the same three-block state-update and event-dispatch shape; the event literal is transformed rather than present as plain text.",
        ],
    },
    {
        "original_ea": "0x1e9840",
        "original_name": "TClient_setGhostMessage",
        "spectron_ea": "0x1edda8",
        "target_name": "sub_1EDDA8",
        "expected_target_size": 16,
        "expected_target_instruction_count": 4,
        "expected_target_basic_block_count": 2,
        "source_basis": "ghost-message string setter",
        "evidence": [
            "The source is the first of four consecutive global string setters following server-login handling.",
            "The target has the same four-instruction assignment body and is the first member of the corresponding four-function setter run.",
        ],
    },
    {
        "original_ea": "0x1e9850",
        "original_name": "TClient_setDisconnectReason",
        "spectron_ea": "0x1eddb8",
        "target_name": "sub_1EDDB8",
        "expected_target_size": 16,
        "expected_target_instruction_count": 4,
        "expected_target_basic_block_count": 2,
        "source_basis": "disconnect-reason string setter",
        "evidence": [
            "The source is the second consecutive global string setter in the server-login helper run.",
            "The target has the same four-instruction assignment body and preserves the same relative order.",
        ],
    },
    {
        "original_ea": "0x1e9860",
        "original_name": "TClient_setServerWarpDestination",
        "spectron_ea": "0x1eddc8",
        "target_name": "sub_1EDDC8",
        "expected_target_size": 16,
        "expected_target_instruction_count": 4,
        "expected_target_basic_block_count": 2,
        "source_basis": "server-warp destination string setter",
        "evidence": [
            "The source is the third consecutive global string setter following server-login handling.",
            "The target has the same four-instruction assignment body and preserves the setter sequence position.",
        ],
    },
    {
        "original_ea": "0x1e9870",
        "original_name": "TClient_setLoginAccountName",
        "spectron_ea": "0x1eddd8",
        "target_name": "sub_1EDDD8",
        "expected_target_size": 12,
        "expected_target_instruction_count": 3,
        "expected_target_basic_block_count": 2,
        "source_basis": "login-account string setter",
        "evidence": [
            "The source is the final, two-argument global string setter before update-package setup.",
            "The target has the same three-instruction assignment body and is immediately before the preserved update-package helper.",
        ],
    },
    {
        "original_ea": "0x1f17b4",
        "original_name": "TClient_handlePlayerLoginLogout",
        "spectron_ea": "0x1f3018",
        "target_name": "sub_1F3018",
        "expected_target_size": 152,
        "expected_target_instruction_count": 38,
        "expected_target_basic_block_count": 5,
        "source_basis": "player login and logout packet decoder",
        "evidence": [
            "The source decodes the two-character player id prefix, removes it from the packet, and handles the resulting player record.",
            "The target performs the same prefix decode and packet removal, then calls the already translated target updateGlobalPlayer implementation.",
            "The target splits the large 1.8 body into a compact packet decoder plus the shared update routine, so this is a role anchor rather than a byte-identical function match.",
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
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: expected %s, got %s"
                % (spec["spectron_ea"], spec["target_name"], target.get("name"))
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
                "match_kind": "manual-login-state-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in login helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_login_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for login, event, and small client state helpers",
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
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the default 2.2 name in the evidence row.",
            "Several event literals are transformed in the target, so event-helper identity uses call context and preserved order in addition to code shape.",
            "The player login and logout handler is a role anchor because the target splits packet decoding from the shared player update routine.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
