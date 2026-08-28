#!/usr/bin/env python3
"""Extend a Spectron checkpoint with a verified IDA database repair."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


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
    parser.add_argument("--repair-artifact", required=True, type=Path)
    parser.add_argument("--application-report", required=True, type=Path)
    parser.add_argument("--reopen-report", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repair-artifact-name", required=True)
    parser.add_argument("--checkpoint-artifact", required=True)
    parser.add_argument("--repair-key", required=True)
    parser.add_argument("--function-count", required=True, type=int)
    parser.add_argument("--default-sub-function-count", required=True, type=int)
    args = parser.parse_args()

    parent = load(args.parent)
    repair = load(args.repair_artifact)
    application = load(args.application_report)
    reopen = load(args.reopen_report)
    if repair.get("artifact") != args.repair_artifact_name:
        raise ValueError("unexpected repair artifact")
    if repair.get("network_contacted") is not False:
        raise ValueError("repair artifact is not marked offline")
    if repair.get("summary", {}).get("bytes_changed") is not False:
        raise ValueError("repair artifact does not prove byte preservation")
    if repair.get("summary", {}).get("reopen_failure_count") != 0:
        raise ValueError("repair artifact contains reopen failures")
    if not application.get("verified") or application.get("failure_count") != 0:
        raise ValueError("repair application report contains failures")
    if not reopen.get("verified") or reopen.get("failure_count") != 0:
        raise ValueError("repair reopen report contains failures")
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
        "function_count": args.function_count,
        "default_sub_function_count": args.default_sub_function_count,
    }
    result[args.repair_key] = {
        "artifact_path": str(args.repair_artifact),
        "artifact_sha256": sha256_path(args.repair_artifact),
        "application_report": str(args.application_report),
        "reopen_verification": str(args.reopen_report),
        "pool_count": repair["summary"]["pool_count"],
        "phantom_function_count_removed": repair["summary"][
            "phantom_function_count_removed"
        ],
        "data_item_count_created": repair["summary"]["data_item_count_created"],
        "reopen_failure_count": repair["summary"]["reopen_failure_count"],
    }
    result["interpretation"] = list(result.get("interpretation", []))
    result["interpretation"].append(
        "This database revision also contains the verified forward-DCT literal-pool boundary repair recorded under "
        + args.repair_key
        + "."
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "artifact": result["artifact"],
                "database_sha256": result["database"]["sha256"],
                "function_count": result["database"]["function_count"],
                "default_sub_function_count": result["database"][
                    "default_sub_function_count"
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
