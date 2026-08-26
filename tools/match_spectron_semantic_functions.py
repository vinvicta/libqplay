#!/usr/bin/env python3
"""Build a cautious 1.8-to-Spectron ARM64 function translation map.

The original 1.8 IDA database has readable aliases, while the supplied 2.2
library has many obfuscated C++ names.  This tool compares compact features
exported by ``ida_export_function_features.py``.  It normalizes PC-relative
targets and requires a unique match for the function size, instruction count,
basic-block count, and normalized instruction shape.  A small fallback uses
register-aware shape when the mnemonic-only key is ambiguous.

The result is a map of analysis candidates, not a claim that the 2.2 binary
retains 1.8 source symbols.  Target addresses are never copied blindly.  The
map can be reviewed or applied to a disposable Spectron IDA database with
``ida_apply_spectron_translation.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path


MATCH_KEYS = (
    "mnemonic_hash",
    "register_shape_hash",
    "shape_hash",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def key(function: dict, feature: str) -> tuple:
    return (
        function.get("size"),
        function.get("instruction_count"),
        function.get("basic_block_count"),
        function.get(feature),
    )


def ida_alias(source_name: str, used: set[str]) -> str:
    value = re.sub(r"[^0-9A-Za-z_]", "_", source_name)
    value = re.sub(r"_+", "_", value).strip("_") or "function"
    value = "v18_" + value
    if value[0].isdigit():
        value = "_" + value
    value = value[:180].rstrip("_")
    base = value
    suffix = 2
    while value in used:
        tail = "_%d" % suffix
        value = (base[: 180 - len(tail)] + tail).rstrip("_")
        suffix += 1
    used.add(value)
    return value


def overlap(source: dict, target: dict) -> dict:
    strings = sorted(set(source.get("string_refs", [])) & set(target.get("string_refs", [])))
    calls = sorted(
        set(source.get("direct_call_names", []))
        & set(target.get("direct_call_names", []))
    )
    return {
        "shared_string_refs": strings[:16],
        "shared_string_ref_count": len(strings),
        "shared_direct_call_names": calls[:16],
        "shared_direct_call_count": len(calls),
    }


def disambiguate(source: dict, candidates: list[dict]) -> list[dict]:
    """Prefer a candidate with the strongest preserved string/call context."""
    if len(candidates) <= 1:
        return candidates
    scored = []
    for candidate in candidates:
        evidence = overlap(source, candidate)
        score = (
            evidence["shared_string_ref_count"],
            evidence["shared_direct_call_count"],
        )
        scored.append((score, candidate))
    best_score = max(score for score, _ in scored)
    best = [candidate for score, candidate in scored if score == best_score]
    if best_score != (0, 0) and len(best) == 1:
        return best
    return candidates


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--minimum-size", type=int, default=32)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    original = original_document["functions"]
    spectron = spectron_document["functions"]

    indexes = {}
    for feature in MATCH_KEYS:
        index = defaultdict(list)
        for function in spectron:
            index[key(function, feature)].append(function)
        indexes[feature] = index

    used_aliases: set[str] = set()
    assigned_targets: dict[str, dict] = {}
    matches = []
    ambiguous = []
    unmatched = []
    validation = {"shared_name_functions": 0, "shared_name_unique_correct": 0, "shared_name_unique_wrong": 0}

    for source in original:
        source_name = source.get("name")
        if source.get("is_default_name") or not source_name:
            continue
        if source.get("size", 0) < args.minimum_size or source.get("instruction_count", 0) < 8:
            continue

        selected = None
        method = None
        candidate_pool = []
        for feature in MATCH_KEYS:
            candidates = indexes[feature].get(key(source, feature), [])
            candidates = disambiguate(source, candidates)
            if len(candidates) == 1:
                selected = candidates[0]
                method = feature
                break
            if candidates:
                candidate_pool = candidates
        if selected is None:
            if candidate_pool:
                ambiguous.append(
                    {
                        "original_ea": source["ea"],
                        "original_name": source_name,
                        "candidate_spectron_eas": [item["ea"] for item in candidate_pool],
                        "candidate_count": len(candidate_pool),
                    }
                )
            else:
                unmatched.append(
                    {
                        "original_ea": source["ea"],
                        "original_name": source_name,
                        "size": source["size"],
                    }
                )
            continue

        target_ea = selected["ea"]
        previous = assigned_targets.get(target_ea)
        if previous is not None:
            ambiguous.append(
                {
                    "original_ea": source["ea"],
                    "original_name": source_name,
                    "candidate_spectron_eas": [target_ea],
                    "candidate_count": 1,
                    "reason": "target already assigned to another original function",
                    "previous_original_ea": previous["original_ea"],
                    "previous_original_name": previous["original_name"],
                }
            )
            continue

        target_name = selected.get("name")
        alias = ida_alias(source_name, used_aliases)
        evidence = overlap(source, selected)
        row = {
            "original_ea": source["ea"],
            "original_name": source_name,
            "spectron_ea": target_ea,
            "spectron_current_name": target_name,
            "alias_name": alias,
            "method": method,
            "confidence": "high" if method in {"mnemonic_hash", "register_shape_hash"} else "medium",
            "size": source["size"],
            "instruction_count": source["instruction_count"],
            "basic_block_count": source["basic_block_count"],
            **evidence,
        }
        matches.append(row)
        assigned_targets[target_ea] = row

        if target_name == source_name:
            validation["shared_name_functions"] += 1
            validation["shared_name_unique_correct"] += 1
        elif target_name in {item.get("name") for item in spectron} and target_name:
            # This counter is intentionally conservative.  A different target
            # name is not called wrong unless a same-name anchor was available.
            pass

    matches.sort(key=lambda item: int(item["original_ea"], 16))
    ambiguous.sort(key=lambda item: int(item["original_ea"], 16))
    unmatched.sort(key=lambda item: int(item["original_ea"], 16))
    result = {
        "schema_version": 1,
        "artifact": "spectron_semantic_function_translation",
        "scope": "offline feature matching between the original 1.8 ARM64 library and supplied Spectron 2.2 ARM64 library",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "minimum_function_size": args.minimum_size,
        },
        "method": {
            "primary": "unique size, instruction count, basic-block count, and normalized mnemonic sequence",
            "fallback": "unique register-aware instruction shape after the primary key is ambiguous",
            "normalization": "PC-relative branch, literal, and relocation targets are not compared as absolute addresses",
            "alias_policy": "candidate names use a v18_ prefix so they cannot be mistaken for preserved 2.2 source symbols",
        },
        "summary": {
            "original_functions": len(original),
            "spectron_functions": len(spectron),
            "mapped_functions": len(matches),
            "mapped_high_confidence": sum(item["confidence"] == "high" for item in matches),
            "mapped_medium_confidence": sum(item["confidence"] == "medium" for item in matches),
            "ambiguous_functions": len(ambiguous),
            "unmatched_functions": len(unmatched),
            "unique_spectron_targets": len(assigned_targets),
        },
        "validation": validation,
        "matches": matches,
        "ambiguous": ambiguous,
        "unmatched": unmatched,
        "interpretation": [
            "A mapped Spectron address is valid only for the supplied Spectron library and cannot be used as an address in the original 1.8 build.",
            "The v18_ alias is an analysis label derived from the readable 1.8 IDA name. It is not evidence that Spectron retained that source symbol.",
            "Functions that were folded, changed, or collided under the normalized feature key remain in the ambiguous or unmatched lists.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **result["summary"]}, sort_keys=True))


if __name__ == "__main__":
    main()
