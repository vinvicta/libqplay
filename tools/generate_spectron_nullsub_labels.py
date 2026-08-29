"""Create reviewed labels for the remaining one-instruction null stubs.

These functions have no surviving source symbol and no demonstrated 1.8
counterpart.  They are still given stable target-only labels so the translated
IDA database has no unexplained auto-generated function names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_nullsub_target_only_labels_20260828"
EXPECTED_INPUT_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
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
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binary-sha256", default=EXPECTED_INPUT_SHA256)
    args = parser.parse_args()

    audit = load(args.audit)
    if audit.get("input_sha256") != args.binary_sha256:
        raise ValueError("name audit input hash does not match the target library")
    if audit.get("function_count") != 11695:
        raise ValueError("unexpected translated function count")

    source_rows = [
        row for row in audit.get("rows", []) if row.get("default_kind") == "nullsub"
    ]
    if len(source_rows) != 9:
        raise ValueError("unexpected nullsub count: %d" % len(source_rows))

    labels = []
    for row in sorted(source_rows, key=lambda item: int(item["ea"], 16)):
        if row.get("size") != 4 or row.get("bytes_hex") != "c0035fd6":
            raise ValueError("nullsub body is not the expected AArch64 RET")
        if row.get("first_instruction") != "RET":
            raise ValueError("nullsub disassembly is not RET")
        ea = row["ea"].lower()
        labels.append(
            {
                "target_ea": ea,
                "current_name": row["name"],
                "function_end": hex(int(ea, 16) + row["size"]),
                "proposed_name": "spectron_nullsub_stub_" + ea,
                "target_default_name": True,
                "target_metrics": {
                    "size": row["size"],
                    "bytes_hex": row["bytes_hex"],
                    "first_instruction": row["first_instruction"],
                    "xrefs_to": row["xrefs_to"],
                },
                "script_name": "one-instruction null return stub",
                "role": "nullsub_return_stub",
                "operation": "returns immediately without executing a body",
                "source_counterpart": None,
                "source_counterpart_status": "not-demonstrated",
                "confidence": "high",
                "match_kind": "reviewed-target-only-nullsub",
                "evidence": [
                    "The reopened translated IDA database contains a four-byte function at this address.",
                    "The complete body is the AArch64 RET instruction with bytes c0035fd6.",
                    "The function has no surviving source symbol and no demonstrated 1.8 counterpart.",
                ],
                "name_action": "rename-with-spectron-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed target-only labels for the nine remaining one-instruction null return stubs",
        "network_contacted": False,
        "inputs": {
            "name_coverage_audit": str(args.audit),
            "name_coverage_audit_sha256": sha256_path(args.audit),
            "spectron_binary_sha256": args.binary_sha256,
        },
        "summary": {
            "label_count": len(labels),
            "high_confidence_count": len(labels),
            "target_default_name_count": len(labels),
            "target_only_count": len(labels),
            "nullsub_count": len(labels),
        },
        "labels": labels,
        "interpretation": [
            "The spectron_ prefix marks a target-specific descriptive label rather than a restored source symbol.",
            "Each row is a complete one-instruction AArch64 RET function. The label records that behavior and the exact target address.",
            "The labels remove the last nine IDA nullsub defaults from this database revision, but they do not claim that an original source name was recovered.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
