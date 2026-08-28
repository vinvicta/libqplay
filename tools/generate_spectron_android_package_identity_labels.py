#!/usr/bin/env python3
"""Create a reviewed target-only label for Spectron's package-signature helper."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_android_package_identity_labels_20260828"
TARGET_EA = "0x24a9ec"


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    document = load(args.spectron_features)
    target = next(row for row in document["functions"] if row["ea"].lower() == TARGET_EA)
    expected_name = "sub_24A9EC"
    if target["name"] != expected_name:
        raise ValueError(f"unexpected target name at {TARGET_EA}: {target['name']}")

    label = {
        "target_ea": TARGET_EA,
        "current_name": target["name"],
        "function_end": target["end_ea"],
        "proposed_name": "spectron_quattro_android_getsignature",
        "target_default_name": target.get("is_default_name", False),
        "target_metrics": {field: target.get(field) for field in METRICS},
        "target_string_refs": target.get("string_refs", []),
        "target_direct_call_names": target.get("direct_call_names", []),
        "script_name": "quattro::android::getsignature",
        "target_function_table_record": "0x39f0f0",
        "target_callback_xref": "0x39f108",
        "operation": "gets the application package name, calls PackageManager.getPackageInfo(packageName, 0x40), reads signatures[0], and converts it with toCharsString(), returning null when no signature object is available",
        "decoded_method_names": [
            "getPackageManager",
            "getPackageName",
            "getPackageInfo",
            "signatures",
            "toCharsString",
        ],
        "source_counterpart": None,
        "source_counterpart_status": "not-demonstrated",
        "confidence": "high",
        "match_kind": "reviewed-target-only-android-package-identity-label",
        "evidence": [
            "The decoded target script-function table row for quattro::android::getsignature is at 0x39f0f0.",
            "The row points to this callback through the target callback cell at 0x39f108.",
            "Reversing the target's stored method-name fragments yields getPackageManager, getPackageName, getPackageInfo, signatures, and toCharsString.",
            "Target pseudocode walks from ActivityThread to Application, obtains the PackageManager, requests PackageInfo with flag 0x40, reads signatures[0], and returns its toCharsString value or null.",
            "No original 1.8 source address is claimed for this target-only label.",
        ],
        "name_action": "rename-with-spectron-prefix",
    }

    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "scope": "reviewed target-only label for Spectron's Android package-signature helper",
        "network_contacted": False,
        "inputs": {
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "target_components": [
                "Spectron Android script-function table near 0x39f000",
                "Spectron package identity helper at 0x24a9ec",
            ],
            "resolution": "decoded target table name, exact callback cell, reversed method-name fragments, function boundary, and reviewed pseudocode",
            "mapping_boundary": "This label describes target behavior only. It is not a 1.8-to-Spectron correspondence.",
        },
        "summary": {
            "label_count": 1,
            "high_confidence_count": 1,
            "target_default_name_count": int(label["target_default_name"]),
            "source_counterpart_count": 0,
            "target_only_count": 1,
        },
        "labels": [label],
        "interpretation": [
            "The spectron_ prefix marks a target-specific descriptive label rather than a restored 1.8 symbol.",
            "This pass corrects the earlier body description that associated 0x24a9ec with ANDROID_ID. The Android ID correspondence is the separately reviewed 0x2502f4 helper.",
            "The nearby 0x24b958 helper is a separate getInstallerPackageName path and is not relabeled by this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
