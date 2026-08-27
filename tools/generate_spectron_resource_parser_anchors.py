#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron resource and package parsers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


GROUP_EVIDENCE = {
    "gani_lexer": [
        "Both functions initialize and reuse the generated Gani lexer buffer, preserve the current input and output handles, expand the persistent buffer table when needed, restore the current cursor, and enter the same parser state machine.",
        "The source and target retain the same parser alphabet string and the `ATTR` and `PARAM` tokens. The target body is 12768 bytes, 3188 instructions, and 651 blocks, compared with 12748 bytes, 3184 instructions, and 651 blocks in 1.8.",
        "The target routine is the corresponding class-local obfuscated lexer entry. The near-exact metrics, preserved parser literals, and identical state transitions make this a direct translation rather than a name or proximity inference.",
    ],
    "download_filename": [
        "Both methods turn a cached resource name into its local download path. They handle the URL marker, escaped filenames, encrypted `.enc` names, update packages, sounds, maps, Gani files, fonts, paths, translations, GUI styles, music, videos, tiles, images, emoticons, smilies, help files, hats, body, head, sword, and shield resources.",
        "The target retains all 53 source path and extension literals, including `downloads`, `updatepackages`, `ganisc`, `gpaks`, `levels`, `levels3d`, `webfiles`, `heads`, `bodies`, `swords`, and `shields`. Source metrics are 3224 bytes, 803 instructions, and 89 blocks. Target metrics are 3392 bytes, 845 instructions, and 95 blocks.",
        "The target preserves the same branch order and output construction. The larger body comes from the target string and resource wrappers, while the path categories and encrypted-file handling remain aligned.",
    ],
    "update_package": [
        "Both methods load an update package from a cached stream or its package filename, require the `GRPKG001` header, clear the existing package lists and flags, and parse the same NAME, FLAG, VERSION, PLATFORM, DESCRIPTION, FILE, SUBPACKAGE, and checksum directives.",
        "The target retains the package header and all 19 directive literals from the source, including `DESCRIPTIONEND`, `ISMAINEXECUTABLE`, `PROTECTOVERWRITE`, `USECHECKSUM`, `QPlay.box`, and the version and platform fields.",
        "The source and target both have 63 basic blocks. The target is 2012 bytes and 501 instructions, close to the 2024-byte and 505-instruction source body. The target's changed helper names do not change the package-parser control flow.",
    ],
}


ANCHOR_SPECS = [
    {
        "original_ea": "0x192ec8",
        "original_name": "lex_load_TGraalAni",
        "spectron_ea": "0x1979cc",
        "target_name": "_Z10Qe7BkbfIGXP10Kc8uganwOu",
        "proposed_name": "v18_lex_load_TGraalAni",
        "source_metrics": (12748, 3184, 651),
        "target_metrics": (12768, 3188, 651),
        "group": "gani_lexer",
        "source_basis": "generated Gani lexer state initialization",
        "required_string_refs": (
            "ATTR",
            "PARAM",
            "edcb`_][ZWVUSQPNMKJFEDCBA@?>=<;:86/,)($\"!",
        ),
    },
    {
        "original_ea": "0x1fa920",
        "original_name": "TCachedStream_getDownloadFilename_TString_const",
        "spectron_ea": "0x2000f8",
        "target_name": "_ZN10SDrvgadS3u10t0Nyga0GTxERK10C8THgaTQxF",
        "proposed_name": "v18_TCachedStream_getDownloadFilename_TString_const",
        "source_metrics": (3224, 803, 89),
        "target_metrics": (3392, 845, 95),
        "group": "download_filename",
        "source_basis": "cached-resource local download path selection",
        "required_string_refs": (
            ".enc",
            ".gani",
            ".gmap",
            "downloads",
            "ganisc",
            "gpaks",
            "heads",
            "webfiles",
        ),
    },
    {
        "original_ea": "0x209fa4",
        "original_name": "TUpdatePackage_load_void",
        "spectron_ea": "0x210174",
        "target_name": "_ZN10RH6ygazf9x4loadEv",
        "proposed_name": "v18_TUpdatePackage_load_void",
        "source_metrics": (2024, 505, 63),
        "target_metrics": (2012, 501, 63),
        "group": "update_package",
        "source_basis": "update-package header and directive parser",
        "required_string_refs": (
            "GRPKG001",
            "NAME ",
            "FLAG ",
            "VERSION ",
            "PLATFORM ",
            "DESCRIPTION",
            "DESCRIPTIONEND",
            "PROTECTOVERWRITE",
            "USECHECKSUM",
            "QPlay.box",
        ),
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
                "match_kind": "manual-resource-parser-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": GROUP_EVIDENCE[spec["group"]],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in resource parser anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in resource parser anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_resource_parser_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for Gani lexing, cached resource paths, and update-package parsing",
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
            "The Gani lexer correspondence is supported by direct Hex-Rays pseudocode, shared parser literals, persistent-buffer state, and near-exact control-flow metrics.",
            "The cached-resource and update-package correspondences are supported by direct Hex-Rays pseudocode, complete or representative literal sets, shared branch order, and close control-flow metrics.",
            "Changed byte sizes and instruction counts are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
