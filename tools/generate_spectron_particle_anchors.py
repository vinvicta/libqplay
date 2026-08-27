#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron particle-data extension cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x232e64",
        "original_name": "TParticleDataEx_getAnimation_void",
        "spectron_ea": "0x23cc14",
        "target_name_fragment": "tJIwIaYe8310MKKOFa0WiNEv",
        "source_basis": "particle animation-name getter",
        "required_string_refs": [],
        "evidence": [
            "Both require a live gani object, obtain its full gani name, trim the optional animation parameter, and append that parameter after a comma when it is non-empty.",
            "Both return an empty string when no gani object is available and preserve the same eight-block getter flow. The target grows from 232 to 256 bytes for rebuilt string-wrapper operations.",
        ],
    },
    {
        "original_ea": "0x2331a8",
        "original_name": "TParticleDataEx_setPlayerLook_bool",
        "spectron_ea": "0x23cf70",
        "target_name_fragment": "tJIwIaYe8310kn6NFajZLMEb",
        "source_basis": "player-look gani customization",
        "required_string_refs": ["body.png", "head26.png", "shield1.png", "sword1.png"],
        "evidence": [
            "Both synchronize the gani object, update its player-look flag, and when the flag changes from enabled to disabled restore sword1.png, the default body, shield1.png, the default head, and five skin colors plus color index 18.",
            "The target retains all four image literals and the same six-block state transition, while its rebuilt string and color wrappers reduce the body from 396 to 316 bytes.",
        ],
    },
    {
        "original_ea": "0x2337ec",
        "original_name": "TParticleDataEx_copyFromTemplate_TParticleDataEx",
        "spectron_ea": "0x23d564",
        "target_name_fragment": "tJIwIaYe8310YQEnJalZvNEPS_",
        "source_basis": "particle-data template copy",
        "required_string_refs": [],
        "evidence": [
            "Both destroy the destination variables, copy the scalar and string fields, recreate the animation, copy direction and player-look state, and restore the source gani appearance when player-look is disabled.",
            "Both copy the four appearance strings and six color slots through the same nine-block flow. The target grows from 380 to 412 bytes as wrapper calls are rebuilt.",
        ],
    },
    {
        "original_ea": "0x233f08",
        "original_name": "TParticleDataEx_setCodedPolygon_TString_const",
        "spectron_ea": "0x23dca0",
        "target_name_fragment": "tJIwIaYe8310Cj1NFa8IHMERK10C8THgaTQxF",
        "source_basis": "coded polygon setter",
        "required_string_refs": [],
        "evidence": [
            "Both split the coded polygon text into fields, normalize the polygon type to 2 or 3, remove the type field, build a TGraalVar from the remaining values, mark it as a temporary value, and install it as the polygon.",
            "Both keep the same three-block setter flow and target only rebuilt TStringList and variable-construction wrappers. The body changes from 216 to 220 bytes.",
        ],
    },
    {
        "original_ea": "0x233fe0",
        "original_name": "TParticleDataEx_setTexturedCodedPolygon_TString_const",
        "spectron_ea": "0x23dd7c",
        "target_name_fragment": "tJIwIaYe8310keENFaKsnMERK10C8THgaTQxF",
        "source_basis": "textured coded polygon setter",
        "required_string_refs": [],
        "evidence": [
            "Both parse the type and texture fields, normalize the polygon type, update the gani texture name when present, remove the first two fields, and install the remaining values as a temporary polygon variable.",
            "Both preserve the same five-block setter role and texture-field offset. The target grows from 276 to 280 bytes for rebuilt list and string wrappers.",
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
        target_name = target.get("name", "")
        if spec["target_name_fragment"] not in target_name:
            raise ValueError(
                "target %s does not retain expected signature fragment: %s"
                % (spec["spectron_ea"], spec["target_name_fragment"])
            )
        if source.get("basic_block_count") != target.get("basic_block_count"):
            raise ValueError(
                "basic-block count mismatch at %s to %s"
                % (spec["original_ea"], spec["spectron_ea"])
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
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target_name,
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-particle-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in particle anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_particle_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for particle animation, appearance, and polygon helpers",
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
            "The changed-size rows rely on class-local order, preserved field offsets, distinctive image literals, matching block counts, and pseudocode behavior rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
