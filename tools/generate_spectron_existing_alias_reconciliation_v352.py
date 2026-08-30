#!/usr/bin/env python3
"""Reconcile reviewed v18_ aliases that predate the current semantic map.

Earlier translation passes applied many readable aliases to the target IDB and
stored their evidence in individual anchor artifacts. Later semantic-map
carry-forward files did not include every one of those older rows. This tool
joins an unmatched source row to the unique target function already named
``v18_<source name>`` and requires exactly one prior reviewed anchor artifact
for the same source and target pair.

The pass is intentionally semantic-map-only. It does not rename or mutate an
IDA database. The target feature export is used to verify that every existing
alias is still present in the persisted target build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path


ARTIFACT = "spectron_existing_v18_alias_reconciliation_20260829"
APPLICATION_ARTIFACT = "spectron_existing_v18_alias_reconciliation_application"
VERIFICATION_ARTIFACT = "spectron_existing_v18_alias_reconciliation_verification"
METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in document.get("functions", [])}


def metric_differences(source_metrics: dict, target_metrics: dict) -> list[str]:
    return [
        field
        for field in METRIC_FIELDS
        if field in source_metrics
        and field in target_metrics
        and source_metrics.get(field) != target_metrics.get(field)
    ]


def prior_shape_equal(anchor: dict) -> bool:
    for field in ("shape_equal", "normalized_shape_equal"):
        if field in anchor:
            return bool(anchor[field])
    for field in ("full_metric_equal", "exact_metric_match"):
        if field in anchor:
            return bool(anchor[field])
    source = anchor.get("original_metrics", {})
    target = anchor.get("spectron_metrics", {})
    fields = ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    values = [field for field in fields if field in source and field in target]
    return bool(values) and all(source[field] == target[field] for field in values)


def discover_prior_anchors(
    artifact_dir: Path, output_path: Path
) -> tuple[dict[tuple[str, str], list[tuple[dict, Path, str]]], list[dict]]:
    rows: defaultdict[tuple[str, str], list[tuple[dict, Path, str]]] = defaultdict(list)
    manifest = []
    output_resolved = output_path.resolve()
    for path in sorted(artifact_dir.glob("*.json")):
        if path.resolve() == output_resolved:
            continue
        try:
            document = load(path)
        except (OSError, json.JSONDecodeError):
            continue
        anchors = document.get("anchors")
        if not isinstance(anchors, list):
            continue
        digest = sha256_path(path)
        manifest.append(
            {
                "path": str(path),
                "sha256": digest,
                "artifact": document.get("artifact"),
                "anchor_count": len(anchors),
            }
        )
        for anchor in anchors:
            source_ea = anchor.get("original_ea")
            target_ea = anchor.get("spectron_ea")
            if not isinstance(source_ea, str) or not isinstance(target_ea, str):
                continue
            key = (source_ea, target_ea)
            rows[key].append((anchor, path, digest))

    return dict(rows), manifest


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--semantic-parent", required=True, type=Path)
    parser.add_argument("--target-features", required=True, type=Path)
    parser.add_argument("--artifact-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--application-report", required=True, type=Path)
    parser.add_argument("--verification-report", required=True, type=Path)
    args = parser.parse_args()

    parent = load(args.semantic_parent)
    target_document = load(args.target_features)
    target = by_ea(target_document)
    prior_anchors, provenance_manifest = discover_prior_anchors(
        args.artifact_dir, args.output
    )

    if parent.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected semantic-map parent artifact")
    if parent.get("network_contacted") is not False:
        raise ValueError("semantic-map parent is not offline")
    if target_document.get("network_contacted") is not False:
        raise ValueError("target feature export is not offline")
    if target_document.get("function_count") != 11707:
        raise ValueError("target feature count changed")

    parent_matches = {
        (row["original_ea"], row["spectron_ea"]): row
        for row in parent.get("matches", [])
    }
    parent_target_eas = {row["spectron_ea"] for row in parent.get("matches", [])}
    unmatched = sorted(
        parent.get("unmatched", []), key=lambda row: int(row["original_ea"], 16)
    )
    target_by_name: defaultdict[str, list[dict]] = defaultdict(list)
    for row in target.values():
        target_by_name[row.get("name")].append(row)

    anchors = []
    skipped_without_alias = []
    seen_targets: set[str] = set()
    for source_row in unmatched:
        source_ea = source_row["original_ea"]
        source_name = source_row["original_name"]
        expected_name = "v18_" + source_name
        candidates = target_by_name.get(expected_name, [])
        if not candidates:
            skipped_without_alias.append(source_ea)
            continue
        if len(candidates) != 1:
            raise ValueError("target alias is not unique for %s" % source_name)
        target_row = candidates[0]
        target_ea = target_row["ea"]
        key = (source_ea, target_ea)
        if target_ea in parent_target_eas:
            raise ValueError("target is already in the parent semantic map: %s" % target_ea)
        if target_ea in seen_targets:
            raise ValueError("target alias was selected twice: %s" % target_ea)
        seen_targets.add(target_ea)
        prior_entries = prior_anchors.get(key, [])
        matching_entries = [
            entry for entry in prior_entries if entry[0].get("proposed_name") == expected_name
        ]
        if not matching_entries:
            matching_entries = [
                entry for entry in prior_entries if entry[0].get("proposed_name") is None
            ]
        if not matching_entries:
            raise ValueError("no prior reviewed anchor for %s -> %s" % key)
        matching_entries.sort(
            key=lambda entry: (
                entry[0].get("confidence") in {"high", "medium"},
                bool(entry[0].get("evidence")),
                bool(entry[0].get("source_basis")),
            ),
            reverse=True,
        )
        prior, prior_path, prior_sha256 = matching_entries[0]
        if prior.get("original_name") != source_name:
            raise ValueError("prior anchor source name mismatch at %s" % source_ea)
        if prior.get("proposed_name") != expected_name:
            raise ValueError("prior anchor alias mismatch at %s" % source_ea)
        if target_row.get("is_default_name"):
            raise ValueError("existing alias is unexpectedly a default name: %s" % target_ea)
        confidence = prior.get("confidence")
        if confidence not in {"high", "medium"}:
            raise ValueError("prior anchor lacks reviewed confidence at %s" % source_ea)
        evidence = prior.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError("prior anchor lacks evidence at %s" % source_ea)

        source_metrics = dict(prior.get("original_metrics", {}))
        target_metrics = {
            field: target_row.get(field)
            for field in METRIC_FIELDS
            if field in target_row
        }
        shape_equal = prior_shape_equal(prior)
        changed_fields = metric_differences(source_metrics, target_metrics)
        source_calls = prior.get("original_direct_call_names", [])
        target_calls = prior.get("spectron_direct_call_names", [])
        source_strings = prior.get("original_string_refs", [])
        target_strings = prior.get("spectron_string_refs", [])
        anchors.append(
            {
                "original_ea": source_ea,
                "original_name": source_name,
                "original_metrics": source_metrics,
                "original_string_refs": source_strings,
                "original_direct_call_names": source_calls,
                "spectron_ea": target_ea,
                "spectron_current_name": target_row["name"],
                "spectron_default_name": target_row.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target_row.get("string_refs", []),
                "spectron_direct_call_names": target_row.get("direct_call_names", []),
                "proposed_name": expected_name,
                "confidence": confidence,
                "match_kind": "existing-reviewed-v18-alias-reconciliation",
                "source_category": "unmatched",
                "semantic_match_already_present": False,
                "source_basis": prior.get("source_basis"),
                "target_component": prior.get("target_component"),
                "shape_equal": shape_equal,
                "layout_change": not shape_equal,
                "metric_differences": changed_fields,
                "prior_metric_differences": prior.get("metric_differences", []),
                "shared_direct_call_names": sorted(set(source_calls).intersection(target_calls)),
                "shared_string_refs": sorted(set(source_strings).intersection(target_strings)),
                "evidence": evidence,
                "prior_match_kind": prior.get("match_kind"),
                "prior_confidence": confidence,
                "provenance_artifact": str(prior_path),
                "provenance_artifact_sha256": prior_sha256,
                "target_name_before_reconciliation": target_row["name"],
                "name_action": "retain-existing-v18-alias-and-reconcile-semantic-map",
            }
        )

    if len(anchors) != 509 or len(skipped_without_alias) != 89:
        raise ValueError(
            "unexpected alias reconciliation split: %d selected, %d skipped"
            % (len(anchors), len(skipped_without_alias))
        )

    high_count = sum(row["confidence"] == "high" for row in anchors)
    medium_count = sum(row["confidence"] == "medium" for row in anchors)
    exact_count = sum(row["shape_equal"] for row in anchors)
    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "offline reconciliation of existing reviewed v18_ target aliases into the Spectron semantic map",
        "network_contacted": False,
        "inputs": {
            "semantic_parent": str(args.semantic_parent),
            "semantic_parent_sha256": sha256_path(args.semantic_parent),
            "target_features": str(args.target_features),
            "target_features_sha256": sha256_path(args.target_features),
            "artifact_dir": str(args.artifact_dir),
            "provenance_artifact_count": len(provenance_manifest),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": high_count,
            "medium_confidence_count": medium_count,
            "exact_shape_prior_count": exact_count,
            "layout_change_prior_count": len(anchors) - exact_count,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "new_target_name_count": 0,
            "reconciled_unmatched_count": len(anchors),
            "remaining_unmatched_without_existing_alias": len(skipped_without_alias),
            "provenance_artifact_count": len(provenance_manifest),
        },
        "anchors": sorted(anchors, key=lambda row: int(row["original_ea"], 16)),
        "skipped_unmatched_source_eas": skipped_without_alias,
        "provenance_manifest": provenance_manifest,
        "interpretation": [
            "Every selected target already carried the exact v18_ alias and was backed by one earlier reviewed anchor artifact.",
            "This pass changes the semantic map only. It does not apply names, comments, function boundaries, or code changes to the target IDB.",
            "The existing anchor evidence remains the source of the semantic claim; the current target feature export proves that the alias is still present in the persisted build.",
            "The 89 skipped source rows have no unique existing v18_ target alias and remain unresolved for a later direct-evidence pass.",
        ],
    }
    write_json(args.output, result)

    application = {
        "schema_version": 1,
        "artifact": APPLICATION_ARTIFACT,
        "expected_artifact": ARTIFACT,
        "network_contacted": False,
        "operation": "semantic-map-only reconciliation of names already present in the target feature export",
        "apply": False,
        "anchor_count": len(anchors),
        "resolved_count": len(anchors),
        "renamed_count": 0,
        "comments_added": 0,
        "failure_count": 0,
        "saved": False,
        "database_changed": False,
        "verified": True,
        "target_feature_sha256": sha256_path(args.target_features),
    }
    write_json(args.application_report, application)

    verification_failures = []
    for row in anchors:
        target_row = target.get(int(row["spectron_ea"], 16))
        if target_row is None:
            verification_failures.append("missing target %s" % row["spectron_ea"])
        elif target_row.get("name") != row["proposed_name"]:
            verification_failures.append(
                "name mismatch at %s: %s" % (row["spectron_ea"], target_row.get("name"))
            )
    verification = {
        "schema_version": 1,
        "artifact": VERIFICATION_ARTIFACT,
        "expected_artifact": ARTIFACT,
        "network_contacted": False,
        "input_feature_sha256": sha256_path(args.target_features),
        "anchor_count": len(anchors),
        "verified_name_count": len(anchors) - len(verification_failures),
        "failure_count": len(verification_failures),
        "failures": verification_failures,
        "function_count": target_document.get("function_count"),
        "verified": not verification_failures,
        "database_changed": False,
    }
    write_json(args.verification_report, verification)
    if verification_failures:
        raise ValueError("alias verification failed")

    print(
        json.dumps(
            {
                "artifact": ARTIFACT,
                "anchor_count": len(anchors),
                "high_confidence_count": high_count,
                "medium_confidence_count": medium_count,
                "remaining_unmatched_without_existing_alias": len(skipped_without_alias),
                "provenance_artifact_count": len(provenance_manifest),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
