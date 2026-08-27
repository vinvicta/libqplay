#!/usr/bin/env python3
"""Create a reviewed anchor for Spectron's generated animation-lexer fatal path."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


FATAL_EVIDENCE = [
    "The source helper is a no-return four-instruction wrapper that calls `exit(2)`. The target helper is also a no-return four-instruction wrapper with one direct exit call, but the target calls `exit(0)`. The status change is recorded explicitly.",
    "The source helper is called by `lex_load_TGraalAni`. The target generated lexer at `0x1979cc` calls `_ZN10QYZugaRKGu10RzQ_IaWQttEv`, the target helper at `0x19af5c`, and keeps the corresponding previous-state callback in the same scanner state machine.",
    "Both fatal wrappers measure 16 bytes, 4 instructions, and 1 basic block with no string references. The target helper is relocated after `loadGaniFromString`, so the direct generated-lexer call relationship is stronger evidence than a simple address shift.",
]


FATAL_SPEC = {
    "original_ea": "0x1925e4",
    "original_name": "ani_lexer_fatalExit",
    "spectron_ea": "0x19af5c",
    "target_name": "_ZN10QYZugaRKGu10RzQ_IaWQttEv",
    "proposed_name": "v18_ani_lexer_fatalExit",
    "source_metrics": (16, 4, 1),
    "target_metrics": (16, 4, 1),
    "source_call_count": 1,
    "target_call_count": 1,
    "source_string_refs": (),
    "target_string_refs": (),
    "source_exit_status": 2,
    "target_exit_status": 0,
    "source_basis": "generated animation lexer fatal-exit callback",
}


LEXER_CONTEXT = {
    "original_ea": "0x192ec8",
    "original_name": "lex_load_TGraalAni",
    "target_ea": "0x1979cc",
    "target_name": "_Z10Qe7BkbfIGXP10Kc8uganwOu",
    "source_metrics": (12748, 3184, 651),
    "target_metrics": (12768, 3188, 651),
    "source_call_count": 209,
    "target_call_count": 210,
    "string_refs": (
        "ATTR",
        "PARAM",
        "edcb`_][ZWVUSQPNMKJFEDCBA@?>=<;:86/,)($\"!",
    ),
    "source_required_calls": ("ani_lexer_fatalExit", "ani_lexer_getPreviousState"),
    "target_required_calls": (
        "._ZN10QYZugaRKGu10RzQ_IaWQttEv",
        "v18_ani_lexer_getPreviousState",
    ),
}


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


def check_function(function: dict, spec: dict, side: str) -> None:
    expected_metrics = spec["%s_metrics" % side]
    actual_metrics = (
        function.get("size"),
        function.get("instruction_count"),
        function.get("basic_block_count"),
    )
    if actual_metrics != expected_metrics:
        raise ValueError("unexpected %s metrics: %s" % (side, actual_metrics))
    if function.get("call_count") != spec["%s_call_count" % side]:
        raise ValueError(
            "unexpected %s call count: %s" % (side, function.get("call_count"))
        )
    if function.get("string_refs", []) != list(spec["%s_string_refs" % side]):
        raise ValueError(
            "unexpected %s string references: %s"
            % (side, function.get("string_refs", []))
        )


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

    source = original.get(int(FATAL_SPEC["original_ea"], 16))
    target = spectron.get(int(FATAL_SPEC["spectron_ea"], 16))
    if source is None:
        raise ValueError("missing original feature at %s" % FATAL_SPEC["original_ea"])
    if target is None:
        raise ValueError("missing Spectron feature at %s" % FATAL_SPEC["spectron_ea"])
    if source.get("name") != FATAL_SPEC["original_name"]:
        raise ValueError("original name mismatch: %s" % source.get("name"))
    if target.get("name") != FATAL_SPEC["target_name"]:
        raise ValueError("target name mismatch: %s" % target.get("name"))
    check_function(source, FATAL_SPEC, "source")
    check_function(target, FATAL_SPEC, "target")
    if ".exit" not in source.get("direct_call_names", []):
        raise ValueError("source fatal helper lacks exit call")
    if ".exit" not in target.get("direct_call_names", []):
        raise ValueError("target fatal helper lacks exit call")
    if int(FATAL_SPEC["spectron_ea"], 16) in semantic_targets:
        raise ValueError("target is already present in the semantic map")

    source_lexer = original.get(int(LEXER_CONTEXT["original_ea"], 16))
    target_lexer = spectron.get(int(LEXER_CONTEXT["target_ea"], 16))
    if source_lexer is None or target_lexer is None:
        raise ValueError("missing generated lexer context")
    if source_lexer.get("name") != LEXER_CONTEXT["original_name"]:
        raise ValueError("unexpected source lexer name")
    if target_lexer.get("name") != LEXER_CONTEXT["target_name"]:
        raise ValueError("unexpected target lexer name")
    for side, function in (("source", source_lexer), ("target", target_lexer)):
        expected = LEXER_CONTEXT["%s_metrics" % side]
        actual = (
            function.get("size"),
            function.get("instruction_count"),
            function.get("basic_block_count"),
        )
        if actual != expected:
            raise ValueError("unexpected %s lexer metrics: %s" % (side, actual))
        if function.get("call_count") != LEXER_CONTEXT["%s_call_count" % side]:
            raise ValueError(
                "unexpected %s lexer call count: %s"
                % (side, function.get("call_count"))
            )
        if function.get("string_refs", []) != list(LEXER_CONTEXT["string_refs"]):
            raise ValueError("unexpected %s lexer string references" % side)
        for required_call in LEXER_CONTEXT["%s_required_calls" % side]:
            if required_call not in function.get("direct_call_names", []):
                raise ValueError(
                    "missing %s lexer call %s" % (side, required_call)
                )

    row = {
        "original_ea": FATAL_SPEC["original_ea"],
        "original_name": FATAL_SPEC["original_name"],
        "original_metrics": metrics(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "original_exit_status": FATAL_SPEC["source_exit_status"],
        "spectron_ea": FATAL_SPEC["spectron_ea"],
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metrics(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "spectron_exit_status": FATAL_SPEC["target_exit_status"],
        "proposed_name": FATAL_SPEC["proposed_name"],
        "confidence": "high",
        "match_kind": "manual-animation-lexer-context-anchor",
        "semantic_match_already_present": False,
        "source_basis": FATAL_SPEC["source_basis"],
        "evidence": FATAL_EVIDENCE,
        "name_action": "rename-with-v18-prefix",
    }
    result = {
        "schema_version": 1,
        "artifact": "spectron_ani_lexer_fatal_manual_translation_anchor_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchor for the generated animation lexer fatal-exit callback",
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
        "supporting_context": {
            "original_lexer": {
                "ea": LEXER_CONTEXT["original_ea"],
                "name": source_lexer["name"],
                "metrics": metrics(source_lexer),
                "string_refs": source_lexer.get("string_refs", []),
                "direct_call_names": source_lexer.get("direct_call_names", []),
            },
            "spectron_lexer": {
                "ea": LEXER_CONTEXT["target_ea"],
                "name": target_lexer["name"],
                "metrics": metrics(target_lexer),
                "string_refs": target_lexer.get("string_refs", []),
                "direct_call_names": target_lexer.get("direct_call_names", []),
            },
            "existing_translation_artifact": "spectron_resource_parser_manual_translation_anchors_20260826",
        },
        "summary": {
            "anchor_count": 1,
            "high_confidence_count": 1,
            "already_in_semantic_map": 0,
            "new_context_anchor_count": 1,
            "target_default_name_count": int(target.get("is_default_name", False)),
        },
        "anchors": [row],
        "interpretation": [
            "This is a reviewed semantic correspondence, not a restored original debug symbol.",
            "The address is valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ label preserves the readable 1.8 role while keeping the obfuscated 2.2 name and changed exit status in the evidence row.",
            "The generated lexer context is included to show that the target helper is called from the already translated target scanner. The existing lex_load anchor is not duplicated here.",
            "The target's exit(0) status is a behavioral difference from the source exit(2). This anchor identifies the callback role and does not claim identical process termination status.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
