#!/usr/bin/env python3
"""Record exact function names shared by the 1.8 and Spectron builds.

This is a conservative companion to the semantic matcher.  It does not move
addresses, infer a name for an obfuscated function, or modify an IDA database.
It records only one-to-one cases where the function name is already present in
both feature exports.  A row can therefore be used as an address-independent
cross-build anchor without pretending that a stripped Spectron symbol was
restored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def classify_name(name: str) -> str:
    if name.startswith("."):
        return "shared_plt_or_import_name"
    if name.startswith("_Z") or name.startswith("_ZN"):
        return "shared_mangled_cpp_name"
    if name.startswith("Java_") or name.startswith("JNI_"):
        return "shared_jni_name"
    return "shared_readable_name"


def unique_by_name(functions: list[dict]) -> tuple[dict[str, list[dict]], list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for function in functions:
        name = function.get("name")
        if not name or function.get("is_default_name"):
            continue
        grouped[name].append(function)
    return grouped, [
        {"name": name, "count": len(rows)}
        for name, rows in sorted(grouped.items())
        if len(rows) != 1
    ]


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
    original_by_name, original_duplicates = unique_by_name(original_document["functions"])
    spectron_by_name, spectron_duplicates = unique_by_name(spectron_document["functions"])
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    rows = []
    ambiguous_names = []
    for name in sorted(set(original_by_name) & set(spectron_by_name)):
        original_rows = original_by_name[name]
        spectron_rows = spectron_by_name[name]
        if len(original_rows) != 1 or len(spectron_rows) != 1:
            ambiguous_names.append(
                {
                    "name": name,
                    "original_count": len(original_rows),
                    "spectron_count": len(spectron_rows),
                }
            )
            continue
        original = original_rows[0]
        spectron = spectron_rows[0]
        target_ea = int(spectron["ea"], 16)
        rows.append(
            {
                "original_ea": original["ea"],
                "original_name": name,
                "original_size": original["size"],
                "original_instruction_count": original["instruction_count"],
                "original_basic_block_count": original["basic_block_count"],
                "spectron_ea": spectron["ea"],
                "spectron_current_name": spectron["name"],
                "spectron_size": spectron["size"],
                "spectron_instruction_count": spectron["instruction_count"],
                "spectron_basic_block_count": spectron["basic_block_count"],
                "name_class": classify_name(name),
                "semantic_match_already_present": target_ea in semantic_targets,
                "evidence": [
                    "The exact non-default function name is present once in each feature export.",
                    "The row records both build-specific addresses; no address was transferred.",
                ],
            }
        )

    rows.sort(key=lambda row: int(row["original_ea"], 16))
    status_counts = Counter(
        "already_semantically_mapped"
        if row["semantic_match_already_present"]
        else "exact_name_anchor_only"
        for row in rows
    )
    name_class_counts = Counter(row["name_class"] for row in rows)
    result = {
        "schema_version": 1,
        "artifact": "spectron_exact_shared_name_anchors_20260826",
        "scope": "one-to-one exact non-default function names shared by the original 1.8 and supplied Spectron 2.2 ARM64 feature exports",
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
        "method": {
            "selection": "exact name present once in each build's function feature export",
            "address_policy": "both addresses are retained as separate fields; no address is copied between builds",
            "default_names": "IDA default sub_ names are excluded",
            "interpretation": "an exact shared name is a preserved name anchor, not proof that an unrelated obfuscated function has been translated",
        },
        "summary": {
            "original_functions": len(original_document["functions"]),
            "spectron_functions": len(spectron_document["functions"]),
            "shared_exact_names": len(rows),
            "already_in_semantic_map": status_counts["already_semantically_mapped"],
            "exact_name_anchor_only": status_counts["exact_name_anchor_only"],
            "ambiguous_shared_names": len(ambiguous_names),
            "original_duplicate_named_groups": len(original_duplicates),
            "spectron_duplicate_named_groups": len(spectron_duplicates),
            "name_class_counts": dict(sorted(name_class_counts.items())),
        },
        "anchors": rows,
        "ambiguous_shared_names": ambiguous_names,
        "interpretation": [
            "The 2.2 build retains these exact names, so they do not need a guessed v18_ alias.",
            "The exact-name inventory is useful for call-graph and string-context review, especially where rebuilt function sizes differ.",
            "Rows marked exact_name_anchor_only were not accepted by the stricter semantic matcher and must not be treated as inferred source-name translations for nearby obfuscated functions.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
