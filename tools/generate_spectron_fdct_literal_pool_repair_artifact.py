#!/usr/bin/env python3
"""Package the verified forward-DCT literal-pool repair as archive evidence."""

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
    parser.add_argument("--application", required=True, type=Path)
    parser.add_argument("--reopen-verification", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--parent-database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    application = load(args.application)
    reopen = load(args.reopen_verification)
    if not application.get("apply") or not application.get("saved"):
        raise ValueError("literal-pool application report is not a saved apply run")
    if application.get("failure_count") != 0 or not application.get("verified"):
        raise ValueError("literal-pool application report contains failures")
    if not reopen.get("verified") or reopen.get("failure_count") != 0:
        raise ValueError("literal-pool reopen report contains failures")
    before = application["before"][0]
    after = application["after"][0]
    if before["raw_hex"] != after["raw_hex"]:
        raise ValueError("literal-pool bytes changed during database repair")
    if before["function_before"] is None:
        raise ValueError("application report did not contain the phantom function")
    if after["function_before"] is not None:
        raise ValueError("application report still contains the phantom function")
    if not all(item["is_data"] for item in after["data_items"]):
        raise ValueError("repaired pool is not represented as data")

    result = {
        "schema_version": 1,
        "artifact": "spectron_fdct_literal_pool_boundary_repair_20260828",
        "scope": "verified IDA boundary repair for the Spectron forward-DCT NEON literal pool",
        "network_contacted": False,
        "inputs": {
            "parent_database": str(args.parent_database),
            "parent_database_sha256": sha256_path(args.parent_database),
            "repaired_database": str(args.database),
            "repaired_database_sha256": sha256_path(args.database),
            "application_report": str(args.application),
            "reopen_verification": str(args.reopen_verification),
        },
        "pool": {
            "target_start": "0x2b9870",
            "target_end": "0x2b98b0",
            "size": 64,
            "phantom_function_before": before["function_before"],
            "real_function_after_pool": after["next_function"],
            "raw_bytes": before["raw_hex"],
            "references": before["references"],
            "data_items_after": after["data_items"],
            "bytes_preserved": before["raw_hex"] == after["raw_hex"],
        },
        "summary": {
            "pool_count": 1,
            "phantom_function_count_removed": 1,
            "data_item_count_created": len(after["data_items"]),
            "bytes_changed": False,
            "reopen_failure_count": reopen["failure_count"],
        },
        "application": application,
        "reopen": reopen,
        "interpretation": [
            "The pool is embedded in executable .text because the compiler uses ADR followed by vector loads; executable permissions alone do not make it code.",
            "Every incoming reference is an ADR used to obtain a vector address. No BL or BLR reference enters the pool.",
            "The repair changes only IDA's database interpretation. The native bytes are preserved exactly, and the real v18_jpeg_fdct_ifast_int function remains at 0x2b98b0.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
