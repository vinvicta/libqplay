#!/usr/bin/env python3
"""Create reviewed anchors and one correction for the Spectron TClient table."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = (
    {
        "source_ea": "0x1edf04",
        "target_ea": "0x1f37e0",
        "source_name": "TClient_handleServerLoginPacket",
        "target_name": "sub_1F37E0",
        "source_table": "0x3699b0",
        "target_table": "0x37c780",
        "handler_index": 10,
        "source_component": "TClient inbound handler table",
        "target_component": "w6qzgacqqy inbound handler table",
        "operation": "decodes the server signature byte, stores it as the server signature, and invokes the onServerLogin event",
        "basis": "handler-table index 10, server-signature decode, and onServerLogin event dispatch",
        "evidence": [
            "The source and target registration records at 0x3699b0 and 0x37c780 occupy the same handler-table index 10.",
            "Both bodies require a non-empty packet, decode byte one minus 32, store the result as the server signature, and notify the game environment with onServerLogin.",
            "The target expands the TString and event wrappers, so its 192-byte body is larger than the 136-byte source body, but the handler role is fixed by the table slot and preserved event string.",
        ],
    },
    {
        "source_ea": "0x1eab78",
        "target_ea": "0x1eefa0",
        "source_name": "TClient_processServerModifies",
        "target_name": "sub_1EEFA0",
        "source_table": "0x369ae0",
        "target_table": "0x37c8b0",
        "handler_index": 48,
        "source_component": "TClient inbound handler table",
        "target_component": "w6qzgacqqy inbound handler table",
        "operation": "clears the leader state, decides between entering the pending server level and applying server modifications in place, then clears the pending transition",
        "basis": "handler-table index 48 and direct server-modification transition behavior",
        "evidence": [
            "The source and target registration records at 0x369ae0 and 0x37c8b0 occupy the same handler-table index 48.",
            "The source clears the leader state, checks the active player's pending transition, and chooses enterServerLevel or doServerModifies; the target preserves that same branch and final pending-state clear.",
            "The target body is 252 bytes versus 184 bytes in the source because target string and object wrappers are expanded, so normalized feature hashes are not used as the primary proof.",
        ],
    },
)

CORRECTIONS = (
    {
        "target_ea": "0xecba0",
        "current_name": "v18_TClient_processServerModifies",
        "restored_name": "_ZN10yL3_IaDMFt10XEm8Ta8FEQEP10vuuHgangcFRK10C8THgaTQxF",
        "reason": "A feature-shape collision assigned this hash-container method to TClient_processServerModifies. Its yL3_IaDMFt export and iterator body identify it as a THashStrings method, while the actual TClient handler-table slot 48 points to 0x1eefa0.",
        "source": "Spectron dynamic symbol table audit and target pseudocode",
    },
)

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


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"]: row for row in document["functions"]}


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, spec: dict) -> dict:
    if source["name"] != spec["source_name"]:
        raise ValueError(
            "unexpected source name at %s: %s"
            % (spec["source_ea"], source["name"])
        )
    if target["name"] != spec["target_name"]:
        raise ValueError(
            "unexpected target name at %s: %s"
            % (spec["target_ea"], target["name"])
        )
    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source[field] == target[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    full_equal = source_metrics == target_metrics
    return {
        "original_ea": spec["source_ea"],
        "original_name": spec["source_name"],
        "original_function_end": source["end_ea"],
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": spec["target_ea"],
        "spectron_current_name": spec["target_name"],
        "spectron_function_end": target["end_ea"],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + spec["source_name"],
        "confidence": "high",
        "match_kind": "manual-tclient-handler-table-anchor",
        "semantic_match_already_present": False,
        "source_component": spec["source_component"],
        "target_component": spec["target_component"],
        "handler_index": spec["handler_index"],
        "source_basis": spec["basis"],
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_equal,
        "metric_differences": [
            field
            for field in METRICS
            if source_metrics[field] != target_metrics[field]
        ],
        "source_handler_table_record": spec["source_table"],
        "target_handler_table_record": spec["target_table"],
        "evidence": [
            *spec["evidence"],
            (
                "The recorded normalized and complete metrics also match exactly."
                if normalized_equal and full_equal
                else "The direct table and pseudocode evidence is primary because the target expands the source operation and changes the recorded feature hashes."
            ),
        ],
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original = by_ea(load(args.original_features))
    spectron = by_ea(load(args.spectron_features))
    anchors = []
    for spec in SPECS:
        source = original.get(spec["source_ea"])
        target = spectron.get(spec["target_ea"])
        if source is None or target is None:
            raise ValueError(
                "missing feature row for %s or %s"
                % (spec["source_ea"], spec["target_ea"])
            )
        anchors.append(make_anchor(source, target, spec))

    result = {
        "schema_version": 1,
        "artifact": "spectron_tclient_handler_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron anchors for the TClient inbound handler table, including a correction to a prior feature-shape collision",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "source_table_base": "0x369960",
            "target_table_base": "0x37c730",
            "table_entry_stride": 8,
            "table_entry_count": 85,
            "primary_evidence": "same decoded handler index, table record, direct Hex-Rays behavior, and surrounding translated handler rows",
            "correction_policy": "restore the target's retained dynamic symbol before applying the corrected readable alias elsewhere",
        },
        "summary": {
            "anchor_count": len(anchors),
            "correction_count": len(CORRECTIONS),
            "high_confidence_count": sum(
                row["confidence"] == "high" for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "normalized_shape_exact_count": sum(
                row["normalized_shape_equal"] for row in anchors
            ),
            "full_metric_exact_count": sum(
                row["full_metric_equal"] for row in anchors
            ),
            "layout_change_count": sum(
                not row["normalized_shape_equal"] for row in anchors
            ),
        },
        "anchors": anchors,
        "corrections": list(CORRECTIONS),
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The handler-table index is stronger evidence than a broad shape key when compiler-generated bodies collide.",
            "The prior processServerModifies row at 0xecba0 is superseded by this correction; that address is restored to its retained yL3_IaDMFt dynamic symbol.",
            "The corrected readable alias belongs at target 0x1eefa0, the target pointer stored in handler-table slot 48.",
            "No APK, native library, external endpoint, or live service was modified or contacted.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
