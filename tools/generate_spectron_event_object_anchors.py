#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for event dispatch objects."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x226cac",
        "original_name": "TEventObject_TEventObject__2",
        "spectron_ea": "0x22f960",
        "target_name_fragment": "pWihMaQxaeD0Ev",
        "source_basis": "event-object deleting destructor",
        "evidence": [
            "Both are the ABI deleting-destructor wrapper for the event object, call the complete destructor, and then pass the object to operator delete.",
            "Both preserve the exact compact body shape: 32 bytes, 8 instructions, and 2 basic blocks, with no string references.",
        ],
    },
    {
        "original_ea": "0x226ce8",
        "original_name": "TEventObject_TEventObject_TString_const",
        "spectron_ea": "0x22f9a0",
        "target_name_fragment": "pWihMaQxaeC1ERK10C8THgaTQxF",
        "source_basis": "event-object constructor",
        "evidence": [
            "Both copy the supplied event name, initialize the inherited string/hash state, and allocate the event-catcher list owned by the object.",
            "The target keeps the constructor ABI signature and single-block layout while growing from 72 to 104 bytes around the rebuilt string wrapper and list allocation.",
        ],
    },
    {
        "original_ea": "0x226f74",
        "original_name": "TEventObject_addEventCatcher_TString_const_TGraalVar_TString_const",
        "spectron_ea": "0x22fc6c",
        "target_name_fragment": "pWihMaQxae10inC6fbhUaaERK10C8THgaTQxFP10G0gxgajWBwS2_",
        "source_basis": "event-catcher registration",
        "evidence": [
            "Both look up the event name in the event-object hash, lowercase the name and construct a catcher list when the entry is absent, then add the catcher to that list.",
            "The target retains the same seven-block control flow and registration order while growing from 200 to 228 bytes for changed string and hash wrappers.",
        ],
    },
    {
        "original_ea": "0x226df4",
        "original_name": "TEventCatcherList_TEventCatcherList_TString_const_TString_const",
        "spectron_ea": "0x22facc",
        "target_name_fragment": "SEPCMa33gwC1ERK10C8THgaTQxFS2_",
        "source_basis": "event-catcher list constructor",
        "evidence": [
            "Both copy the event and catching-function names into the list object, initialize the catcher storage, and preserve a single-block constructor layout.",
            "The target has the same class-local role and constructor signature, with 148 bytes versus 116 in the source because the 2.2 wrappers are larger.",
        ],
    },
    {
        "original_ea": "0x22a9dc",
        "original_name": "TEventCatcherList_TEventCatcherList__2",
        "spectron_ea": "0x234304",
        "target_name_fragment": "SEPCMa33gwD0Ev",
        "source_basis": "event-catcher list deleting destructor",
        "evidence": [
            "Both are the ABI deleting-destructor wrapper for the catcher list, call the complete destructor, and then pass the object to operator delete.",
            "Both preserve the exact compact body shape: 32 bytes, 8 instructions, and 2 basic blocks, with no string references.",
        ],
    },
    {
        "original_ea": "0x22af4c",
        "original_name": "TEventCatcherList_receiveEvent_TGraalVar",
        "spectron_ea": "0x2348bc",
        "target_name_fragment": "SEPCMa33gw10rVjVga1mQQEP10G0gxgajWBw",
        "source_basis": "event-catcher list receive path",
        "evidence": [
            "Both walk the catcher entries, retrieve each linked event object, and dispatch the received variable through the object's event callback.",
            "Both clean up entries whose linked object is gone while preserving the same eight-block loop and ownership decisions; the target grows from 216 to 288 bytes around changed object and string wrappers.",
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
                "match_kind": "manual-event-object-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in event-object anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_event_object_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for event objects, catcher lists, and receive dispatch",
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
            "The changed-size rows rely on class-local order, pseudocode behavior, target signatures, and caller context rather than byte identity.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
