#!/usr/bin/env python3
"""Create reviewed aliases for the source-side dynamic-function gap.

The original 1.8 ELF named eleven GUI routines as dynamic FUNC symbols, but
the old IDA database had classified their ranges as data. Once those source
boundaries and the twelve Spectron boundaries are materialized, ten pairs have
exact normalized feature matches. The remaining button renderer has the same
class-local method slot, strings, control-flow counts, and decompiled
operation, but is eight bytes shorter in Spectron. This generator records both
groups without hiding the metric difference.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


METRICS = (
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

EXACT_PAIRS = {
    "0x1abf80": "0x1b0140",
    "0x1ae97c": "0x1b2b34",
    "0x1c21b8": "0x1c6c94",
    "0x1c2508": "0x1c6fe4",
    "0x1c63a8": "0x1caeb4",
    "0x1c8bb8": "0x1cd73c",
    "0x1c8f80": "0x1cdb04",
    "0x1d5fcc": "0x1dac5c",
    "0x1da320": "0x1df0bc",
    "0x1dc260": "0x1dfffc",
}
MANUAL_SOURCE_EA = "0x1ae65c"
MANUAL_SPECTRON_EA = "0x1b281c"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def row_at(document: dict, ea: str) -> dict:
    for row in document["functions"]:
        if row["ea"] == ea:
            return row
    raise ValueError(f"missing feature row at {ea}")


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def metric_differences(source: dict, target: dict) -> list[str]:
    return [
        field
        for field in METRICS
        if source.get(field) != target.get(field)
    ]


def exact_anchor(match: dict, source: dict, target: dict) -> dict:
    differences = metric_differences(source, target)
    if match["original_name"] != source["name"]:
        raise ValueError("matcher source name does not match feature export")
    if match["spectron_ea"] != target["ea"]:
        raise ValueError("matcher target address does not match feature export")
    if match["confidence"] != "high":
        raise ValueError("expected a high-confidence exact match")
    return {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_metrics": metric_record(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target["ea"],
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metric_record(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "high",
        "match_kind": "dynamic-boundary-exact-semantic-match",
        "source_basis": (
            "the original positive-size ELF FUNC boundary was restored, then "
            "the normalized ARM64 feature matcher selected one unique target"
        ),
        "matcher_method": match["method"],
        "normalized_shape_equal": all(
            source.get(field) == target.get(field)
            for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "evidence": [
            "The source and target ELF rows are positive-size dynamic FUNC symbols.",
            "The restored source boundary and target boundary have the same normalized function metrics required by the matcher.",
            "The readable source role is retained in a v18_ alias while the target's obfuscated name remains in the evidence row.",
        ],
        "name_action": "rename-with-v18-prefix",
    }


def manual_anchor(source: dict, target: dict) -> dict:
    differences = metric_differences(source, target)
    if source["name"] != "GuiButtonCtrl_drawWithStyle_TRectangle_const":
        raise ValueError("unexpected source drawWithStyle name")
    if target["name"] != "_ZN10EqV_Ka3Vx910KHqDgay4MBERK10i7FHgaP2lF":
        raise ValueError("unexpected target drawWithStyle name")
    if source["basic_block_count"] != target["basic_block_count"]:
        raise ValueError("button drawWithStyle block count changed")
    if source["branch_count"] != target["branch_count"]:
        raise ValueError("button drawWithStyle branch count changed")
    if source["call_count"] != target["call_count"]:
        raise ValueError("button drawWithStyle call count changed")
    if source["return_count"] != target["return_count"]:
        raise ValueError("button drawWithStyle return count changed")
    if source.get("string_refs") != target.get("string_refs"):
        raise ValueError("button drawWithStyle string references changed")
    return {
        "original_ea": source["ea"],
        "original_name": source["name"],
        "original_metrics": metric_record(source),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target["ea"],
        "spectron_current_name": target["name"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": metric_record(target),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source["name"],
        "confidence": "medium",
        "match_kind": "dynamic-boundary-manual-class-slot-match",
        "source_component": "GuiButtonCtrl",
        "target_component": "EqV_Ka3Vx9",
        "source_basis": (
            "the target method occupies the GuiButtonCtrl-equivalent class slot "
            "between the exact drawIconAndText and drawWithProfile methods"
        ),
        "normalized_shape_equal": all(
            source.get(field) == target.get(field)
            for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
        ),
        "full_metric_equal": not differences,
        "metric_differences": differences,
        "evidence": [
            "The source and target classes have the same property, constructor, icon-size, drawIconAndText, drawWithProfile, onRender, and destructor sequence.",
            "The source and target bodies have 32 basic blocks, 39 branches, 16 calls, and two returns.",
            "Both bodies reference the Buttons and Taskbar.Button style strings and decompile to the same style-button and icon-text rendering operation.",
            "Spectron is eight bytes and two instructions shorter because rebuilt wrapper code changes the body layout; the size and hash differences are recorded rather than hidden.",
        ],
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matcher", required=True, type=Path)
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--source-boundary-report", required=True, type=Path)
    parser.add_argument("--target-boundary-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    matcher = load(args.matcher)
    original = load(args.original_features)
    spectron = load(args.spectron_features)
    source_rows = {row["ea"]: row for row in original["functions"]}
    target_rows = {row["ea"]: row for row in spectron["functions"]}
    matcher_rows = {
        row["original_ea"]: row for row in matcher.get("matches", [])
    }

    anchors = []
    for source_ea, target_ea in EXACT_PAIRS.items():
        source = source_rows[source_ea]
        target = target_rows[target_ea]
        match = matcher_rows.get(source_ea)
        if match is None or match["spectron_ea"] != target_ea:
            raise ValueError(f"missing exact matcher pair {source_ea} -> {target_ea}")
        anchors.append(exact_anchor(match, source, target))

    manual_source = source_rows[MANUAL_SOURCE_EA]
    manual_target = target_rows[MANUAL_SPECTRON_EA]
    anchors.append(manual_anchor(manual_source, manual_target))
    anchors.sort(key=lambda row: int(row["spectron_ea"], 16))

    source_boundary = load(args.source_boundary_report)
    target_boundary = load(args.target_boundary_report)
    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_missing_function_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 aliases for eleven GUI functions whose ELF symbols survived but old IDA missed their boundaries",
        "network_contacted": False,
        "inputs": {
            "matcher": str(args.matcher),
            "matcher_sha256": sha256_path(args.matcher),
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "source_boundary_report": str(args.source_boundary_report),
            "source_boundary_report_sha256": sha256_path(args.source_boundary_report),
            "target_boundary_report": str(args.target_boundary_report),
            "target_boundary_report_sha256": sha256_path(args.target_boundary_report),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "source_dynamic_function_count": source_boundary["row_count"],
            "source_materialized_count": source_boundary["materialized_count"],
            "target_dynamic_function_count": target_boundary["defined_function_symbol_count"],
            "target_exact_start_count": target_boundary["ida_exact_start_count"],
            "target_missing_exact_start_count": target_boundary["ida_missing_exact_start_count"],
            "exact_pair_count": len(EXACT_PAIRS),
            "manual_pair_count": 1,
            "resolution": "ELF dynamic FUNC sizes and names, restored source boundaries, normalized ARM64 features, class-local method order, shared strings, and reviewed pseudocode",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "medium_confidence_count": sum(row["confidence"] == "medium" for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "normalized_shape_exact_count": sum(row["normalized_shape_equal"] for row in anchors),
            "metric_difference_count": sum(bool(row["metric_differences"]) for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not claims that Spectron retained readable 1.8 debug symbols.",
            "The v18_ labels preserve the readable source role while each target obfuscated name, address, and metric record remains available for audit.",
            "Ten pairs are exact normalized feature matches after restoring the source-side ELF boundaries.",
            "The GuiButtonCtrl drawWithStyle pair is a documented medium-confidence class-slot match because the rebuilt Spectron wrappers shorten the body by eight bytes and two instructions.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
