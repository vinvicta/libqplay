#!/usr/bin/env python3
"""Extend a checked-in Spectron checkpoint with a later verified IDA copy.

The main checkpoint generator has accumulated many historical anchor options.
This small companion keeps a later checkpoint reproducible without requiring
every earlier optional input to be supplied again. It copies the parent
record, updates only the database identity, and adds the newly verified
anchor group.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_ARTIFACT = (
    "spectron_gui_text_list_entry_property_manual_translation_anchors_20260828"
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent", required=True, type=Path)
    parser.add_argument("--anchors", required=True, type=Path)
    parser.add_argument("--verification", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--anchor-artifact", default=ANCHOR_ARTIFACT)
    parser.add_argument(
        "--checkpoint-artifact",
        default="spectron_translation_checkpoint_20260828",
    )
    parser.add_argument(
        "--checkpoint-key",
        default="gui_text_list_entry_property_anchors",
    )
    parser.add_argument("--function-count", type=int)
    parser.add_argument("--default-sub-function-count", required=True, type=int)
    args = parser.parse_args()

    parent = load(args.parent)
    anchors = load(args.anchors)
    verification = load(args.verification)
    if anchors.get("artifact") != args.anchor_artifact:
        raise ValueError("unexpected anchor artifact")
    if not verification.get("verified"):
        raise ValueError("the anchor reopen verification did not pass")
    expected_count = anchors["summary"].get("anchor_count")
    if expected_count is None:
        expected_count = anchors["summary"].get("label_count")
    if expected_count is None:
        raise ValueError("anchor artifact has neither anchor_count nor label_count")
    if verification.get("verified_name_count") != expected_count:
        raise ValueError("anchor verification count differs from anchor artifact")
    if verification.get("failure_count") != 0:
        raise ValueError("anchor verification contains failures")
    if not args.database.is_file():
        raise ValueError("database path is not a regular file")

    result = json.loads(json.dumps(parent))
    result["artifact"] = args.checkpoint_artifact
    result["parent_checkpoint"] = {
        "path": str(args.parent),
        "sha256": sha256_path(args.parent),
        "artifact": parent.get("artifact"),
    }
    result["database"] = {
        **parent["database"],
        "path": str(args.database),
        "sha256": sha256_path(args.database),
        "default_sub_function_count": args.default_sub_function_count,
    }
    if args.function_count is not None:
        result["database"]["function_count"] = args.function_count
    result[args.checkpoint_key] = {
        "anchor_path": str(args.anchors),
        "anchor_sha256": sha256_path(args.anchors),
        "reopen_verification": str(args.verification),
        "anchor_count": expected_count,
        "verified_name_count": verification["verified_name_count"],
        "reopen_failure_count": verification["failure_count"],
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "This database revision also contains the separately reviewed anchor group recorded under "
        + args.checkpoint_key
        + "."
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "artifact": result["artifact"],
                "database_sha256": result["database"]["sha256"],
                "anchor_count": expected_count,
                "default_sub_function_count": result["database"][
                    "default_sub_function_count"
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
