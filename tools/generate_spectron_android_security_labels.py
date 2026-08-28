#!/usr/bin/env python3
"""Create reviewed target-only labels for Android helpers and anti-instrumentation code."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_android_security_target_only_labels_corrected_20260828"


SPECS = (
    (
        "0x24a1d8",
        "0x39e428",
        "0x39e448",
        "spectron_getandroidabi",
        "getandroidabi",
        "the target callback is registered as getandroidabi and returns a rebuilt string produced by the target Android helper path",
    ),
    (
        "0x2500ec",
        "0x39e488",
        "0x39e4a8",
        "spectron_android_getstaticjavafuncexists",
        "getstaticjavafuncexists",
        "the target resolves a Java static method through the JNI bridge and returns whether the lookup succeeded",
    ),
    (
        "0x2501f0",
        "0x39e458",
        "0x39e478",
        "spectron_android_getjavafuncexists",
        "getjavafuncexists",
        "the target resolves a Java method using the requested class and method strings and returns whether the lookup succeeded",
    ),
    (
        "0x250090",
        "0x39e4b8",
        "0x39e4d8",
        "spectron_android_getjavaclassexists",
        "getjavaclassexists",
        "the target resolves a Java class through the JNI bridge and returns whether the lookup succeeded",
    ),
    (
        "0x24a188",
        "0x39e5d8",
        "0x39e5f8",
        "spectron_setactiononfridadetected",
        "setactiononfridadetected",
        "the target callback stores the supplied action value in the global used by the Frida detection loops",
    ),
    (
        "0x24a2ac",
        None,
        "0x24a6d0,0x24a6dc",
        "spectron_frida_detection_sleep_loop",
        "DetectFridaLoop1 helper",
        "the target increments its detection-loop counter and sleeps in an intentional non-returning nanosleep loop",
    ),
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
    return {row["ea"].lower(): row for row in document["functions"]}


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def make_label(target: dict, spec: tuple[str, ...]) -> dict:
    target_ea, table_record, callback_xref, proposed_name, script_name, operation = spec
    expected_name = "sub_" + target_ea[2:].upper()
    if target["name"] != expected_name:
        raise ValueError(f"unexpected target name at {target_ea}: {target['name']}")
    if target["end_ea"] is None:
        raise ValueError(f"missing target function boundary at {target_ea}")
    evidence = [
        f"The target helper is associated with {script_name} at {callback_xref}.",
        f"Target pseudocode shows that it {operation}.",
        "No original 1.8 symbol is claimed for this target-only label.",
    ]
    if table_record is None:
        evidence[0] = (
            f"The helper is called from the retained DetectFridaLoop1 body at {callback_xref}; it has no script-table record."
        )
    result = {
        "target_ea": target_ea,
        "current_name": target["name"],
        "function_end": target["end_ea"],
        "proposed_name": proposed_name,
        "target_default_name": target.get("is_default_name", False),
        "target_metrics": metric_record(target),
        "target_string_refs": target.get("string_refs", []),
        "target_direct_call_names": target.get("direct_call_names", []),
        "script_name": script_name,
        "target_function_table_record": table_record,
        "target_callback_xref": callback_xref,
        "operation": operation,
        "source_counterpart": None,
        "source_counterpart_status": "not-demonstrated",
        "confidence": "high",
        "match_kind": "reviewed-target-only-android-security-label",
        "evidence": evidence,
        "name_action": "rename-with-spectron-prefix",
    }
    if target_ea == "0x2500ec":
        result["accepted_current_names"] = ["spectron_android_getjavaclassexists"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256", required=True)
    parser.add_argument("--artifact", default=ARTIFACT)
    args = parser.parse_args()

    spectron = by_ea(load(args.spectron_features))
    labels = []
    for spec in SPECS:
        target = spectron.get(spec[0])
        if target is None:
            raise ValueError(f"missing target feature row for {spec[0]}")
        labels.append(make_label(target, spec))
    proposed = [row["proposed_name"] for row in labels]
    if len(proposed) != len(set(proposed)):
        raise ValueError("target-only label names are not unique")

    result = {
        "schema_version": 1,
        "artifact": args.artifact,
        "scope": "reviewed target-only labels for Spectron Android helpers and anti-instrumentation callbacks",
        "network_contacted": False,
        "inputs": {
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "target_components": [
                "Spectron Android helper function table near 0x39e400",
                "Spectron Frida detection loop near 0x24a1ac",
            ],
            "resolution": "decoded target script-function names, callback cells, retained helper callers, function boundaries, and reviewed pseudocode",
            "mapping_boundary": "These labels describe target behavior only. They are not 1.8-to-Spectron correspondences.",
        },
        "summary": {
            "label_count": len(labels),
            "high_confidence_count": sum(row["confidence"] == "high" for row in labels),
            "target_default_name_count": sum(row["target_default_name"] for row in labels),
            "source_counterpart_count": 0,
            "target_only_count": len(labels),
        },
        "labels": labels,
        "interpretation": [
            "The spectron_ prefix marks a target-specific descriptive label.",
            "The Frida-related names describe observed control flow and retained callers. They do not claim that the anti-instrumentation code is the only reason the client may fail to start.",
            "The Android helper names come from the target script table and are kept separate from the larger 22-row bridge artifact.",
            "This corrected artifact separates getstaticjavafuncexists at 0x2500ec from getjavaclassexists at 0x250090; the earlier v266 artifact had those two table roles reversed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
