#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron script-table anchors.

This pass covers the small identification, time, file-scripting, control
binding, and hardware-keyboard registrations.  The target has stripped its
static symbol table, so the script-table row, decompiled behavior, and ARM64
feature record are kept together as the audit trail for each proposed alias.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_BINARY_SHA256 = (
    "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
)
SPECTRON_BINARY_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
)


def spec(
    original_ea: str,
    spectron_ea: str,
    original_name: str,
    spectron_name: str,
    script_name: str,
    source_record: str,
    target_record: str,
    source_component: str,
    target_component: str,
    operation: str,
    *,
    match_kind: str = "manual-script-table-context-anchor",
    additional_registrations: tuple[dict[str, str], ...] = (),
) -> dict:
    return {
        "original_ea": original_ea,
        "spectron_ea": spectron_ea,
        "original_name": original_name,
        "spectron_name": spectron_name,
        "script_name": script_name,
        "source_record": source_record,
        "target_record": target_record,
        "source_component": source_component,
        "target_component": target_component,
        "operation": operation,
        "match_kind": match_kind,
        "additional_registrations": list(additional_registrations),
    }


SPECS = (
    spec(
        "0xec6d8",
        "0xed694",
        "TIdentification_script_getOSID",
        "sub_ED694",
        "adventure_getosid",
        "0x3768d0",
        "0x3898d8",
        "TIdentification static script table",
        "Spectron obfuscated identification table",
        "calls the native OS identifier getter and returns the script result slot",
    ),
    spec(
        "0xec270",
        "0xed0b8",
        "TIdentification_script_getNetworkID",
        "sub_ED0B8",
        "adventure_getnetworkid",
        "0x376900",
        "0x389908",
        "TIdentification static script table",
        "Spectron obfuscated identification table",
        "calls the native network identifier getter and returns the script result slot",
    ),
    spec(
        "0xec7ac",
        "0xed77c",
        "TIdentification_script_getSystemID",
        "sub_ED77C",
        "adventure_getsystemid",
        "0x376930",
        "0x389938",
        "TIdentification static script table",
        "Spectron obfuscated identification table",
        "passes the integer selector to the native system identifier getter and returns the result slot",
    ),
    spec(
        "0xf6e58",
        "0xf87d0",
        "TTime_script_adventure_getframetick",
        "sub_F87D0",
        "adventure_getframetick",
        "0x3769f0",
        "0x3899f8",
        "TTime static script table",
        "Spectron obfuscated time table",
        "reads the global frame-tick value",
        additional_registrations=(
            {
                "script_name": "getFrameTick",
                "source_record": "0x376a50",
                "target_script_name": "getframetick",
                "target_record": "0x389a58",
            },
        ),
    ),
    spec(
        "0xf6e68",
        "0xf87e0",
        "TTime_script_adventure_setframetick",
        "sub_F87E0",
        "adventure_setframetick",
        "0x376a20",
        "0x389a28",
        "TTime static script table",
        "Spectron obfuscated time table",
        "stores the incoming script value as the global frame tick",
    ),
    spec(
        "0xfc880",
        "0xfee28",
        "TFileScripting_script_getScriptAccessFile",
        "sub_FEE28",
        "getscriptaccessfile",
        "0x376bd0",
        "0x389be0",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "forwards to the script-access filename helper and returns its output slot",
    ),
    spec(
        "0xfbba4",
        "0xfe124",
        "TFileScripting_script_escapeFilename",
        "sub_FE124",
        "escapefilename",
        "0x376c30",
        "0x389c40",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "forwards to the filename escaping helper",
    ),
    spec(
        "0xfbeec",
        "0xfe46c",
        "TFileScripting_script_removeEscapesFromFilename",
        "sub_FE46C",
        "removeescapesfromfilename",
        "0x376c60",
        "0x389c70",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "forwards to the helper that removes filename escapes",
    ),
    spec(
        "0xfbe68",
        "0xfe3e8",
        "TFileScripting_script_freeAllResources",
        "sub_FE3E8",
        "freeallresources",
        "0x376cf0",
        "0x389d00",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "forwards the script request to the client environment resource cleanup",
    ),
    spec(
        "0xfbe20",
        "0xfe3a0",
        "TFileScripting_script_findFiles",
        "sub_FE3A0",
        "findfiles",
        "0x376d20",
        "0x389d30",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "finds files for a pattern, converts the list to a script value, and releases the temporary list",
    ),
    spec(
        "0xfbb84",
        "0xfe104",
        "TFileScripting_script_extractFileExt",
        "sub_FE104",
        "extractfileext",
        "0x376d50",
        "0x389d60",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "forwards to the file-extension extraction helper",
    ),
    spec(
        "0xfbb64",
        "0xfe0e4",
        "TFileScripting_script_getExtension",
        "sub_FE0E4",
        "getextension",
        "0x376d80",
        "0x389d90",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "uses the same native extension extraction helper under the getextension script name",
    ),
    spec(
        "0xfc540",
        "0xfeac0",
        "TFileScripting_script_setFileModTime",
        "sub_FEAC0",
        "adventure_setfilemodtime",
        "0x376e10",
        "0x389e20",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "updates the UTC modification time for a script-visible file or level resource",
        match_kind="manual-script-table-context-expanded-body",
    ),
    spec(
        "0xfbc5c",
        "0xfe1dc",
        "TFileScripting_script_extractFileBase",
        "sub_FE1DC",
        "extractfilebase",
        "0x376ff0",
        "0x38a000",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "forwards to the file-base extraction helper",
    ),
    spec(
        "0xfbb44",
        "0xfe0c4",
        "TFileScripting_script_extractFilename",
        "sub_FE0C4",
        "extractfilename",
        "0x377020",
        "0x38a030",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "forwards to the filename extraction helper and returns its output slot",
    ),
    spec(
        "0xfbb24",
        "0xfe0a4",
        "TFileScripting_script_extractFilepath",
        "sub_FE0A4",
        "extractfilepath",
        "0x377050",
        "0x38a060",
        "TFileScripting static script table",
        "Spectron obfuscated file-scripting table",
        "forwards to the filepath extraction helper and returns its output slot",
    ),
    spec(
        "0x168b10",
        "0x16c4e8",
        "TControlBinding_getAction",
        "sub_16C4E8",
        "action",
        "0x37ae98",
        "0x38deb8",
        "TControlBinding property table",
        "Spectron obfuscated input property table",
        "reads the control binding action field at object offset +112",
    ),
    spec(
        "0x168b18",
        "0x16c4f0",
        "TControlBinding_getKeycode",
        "sub_16C4F0",
        "keycode",
        "0x37aec8",
        "0x38dee8",
        "TControlBinding property table",
        "Spectron obfuscated input property table",
        "reads the control binding keycode field at object offset +120",
    ),
    spec(
        "0x168e40",
        "0x16c840",
        "TControlBinding_getKeytext",
        "sub_16C840",
        "keytext",
        "0x37aef8",
        "0x38df18",
        "TControlBinding property table",
        "Spectron obfuscated input property table",
        "resolves the binding keycode through the native key-text helper",
    ),
    spec(
        "0x168b20",
        "0x16c4f8",
        "TControlBinding_getSlot",
        "sub_16C4F8",
        "slot",
        "0x37af28",
        "0x38df48",
        "TControlBinding property table",
        "Spectron obfuscated input property table",
        "reads the control binding slot field at object offset +116",
    ),
    spec(
        "0x168af0",
        "0x16c4c8",
        "TInput_getHardwareKeyboardEnabled",
        "sub_16C4C8",
        "enablehardwarekeyboard",
        "0x37af58",
        "0x38df78",
        "TInput property table",
        "Spectron obfuscated input property table",
        "reads the global hardware-keyboard enable flag",
    ),
    spec(
        "0x168b00",
        "0x16c4d8",
        "TInput_setHardwareKeyboardEnabled",
        "sub_16C4D8",
        "enablehardwarekeyboard",
        "0x37af58",
        "0x38df78",
        "TInput property table",
        "Spectron obfuscated input property table",
        "stores the incoming value in the global hardware-keyboard enable flag",
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
NORMALIZED_METRICS = ("opcode_shape_hash", "register_shape_hash", "shape_hash")


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


def make_anchor(source: dict, target: dict, item: dict) -> dict:
    if source["name"] != item["original_name"]:
        raise ValueError(
            f"unexpected source name at {item['original_ea']}: {source['name']}"
        )
    if target["name"] != item["spectron_name"]:
        raise ValueError(
            f"unexpected target name at {item['spectron_ea']}: {target['name']}"
        )
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    normalized_equal = all(
        source[field] == target[field] for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    target_default = bool(target.get("is_default_name"))
    if not target_default:
        raise ValueError(f"target is no longer a default name: {item['spectron_ea']}")

    evidence = [
        f"The source registration row for {item['script_name']} is at {item['source_record']}.",
        f"The target registration row for {item['script_name']} is at {item['target_record']}.",
        f"The source and target pseudocode preserve the same role: {item['operation']}.",
        "The target row is in the matching class or subsystem table, and the callback was a default sub before this pass.",
    ]
    if item["additional_registrations"]:
        evidence.append(
            "The same frame-tick getter is also registered under the legacy alias "
            "getFrameTick/getframetick; both builds point that row at this callback."
        )
    if full_metric_equal:
        evidence.append("All recorded function metrics match exactly.")
    elif normalized_equal:
        evidence.append(
            "Normalized ARM64 instruction shape matches; remaining differences are recorded as register-detail changes."
        )
    else:
        evidence.append(
            "The target body is expanded, so the metric differences are retained instead of being hidden behind an exact-shape claim."
        )

    return {
        "original_ea": item["original_ea"],
        "original_name": item["original_name"],
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": item["spectron_ea"],
        "spectron_current_name": item["spectron_name"],
        "spectron_default_name": target_default,
        "spectron_metrics": target_metrics,
        "spectron_function_end": target.get("end_ea"),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + item["original_name"],
        "confidence": "high",
        "match_kind": item["match_kind"],
        "source_component": item["source_component"],
        "target_component": item["target_component"],
        "source_basis": (
            f"matching {item['script_name']} registration and decompiled operation: "
            + item["operation"]
        ),
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "additional_registrations": item["additional_registrations"],
        "script_name": item["script_name"],
        "operation": item["operation"],
        "evidence": evidence,
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", default=SOURCE_BINARY_SHA256)
    parser.add_argument("--spectron-binary-sha256", default=SPECTRON_BINARY_SHA256)
    args = parser.parse_args()

    original = by_ea(load(args.original_features))
    spectron = by_ea(load(args.spectron_features))
    anchors = []
    for item in SPECS:
        source = original.get(item["original_ea"])
        target = spectron.get(item["spectron_ea"])
        if source is None or target is None:
            raise ValueError(
                f"missing feature row for {item['original_ea']} or {item['spectron_ea']}"
            )
        anchors.append(make_anchor(source, target, item))

    result = {
        "schema_version": 1,
        "artifact": "spectron_time_files_input_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for identification, time, file-scripting, control-binding, and hardware-keyboard callbacks",
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
            "source_components": [
                "TIdentification",
                "TTime",
                "TFileScripting",
                "TControlBinding",
                "TInput",
            ],
            "target_components": [
                "Spectron obfuscated identification table",
                "Spectron obfuscated time table",
                "Spectron obfuscated file-scripting table",
                "Spectron obfuscated input property table",
            ],
            "resolution": "decoded registration names, matching table roles, reviewed pseudocode, and persisted ARM64 feature metrics",
            "target_table_copy": "The target addresses use the .data copy of the registration records, not the duplicate .data.rel.ro copy.",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "normalized_shape_exact_count": sum(
                row["normalized_shape_equal"] for row in anchors
            ),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_count": sum(
                not row["normalized_shape_equal"] for row in anchors
            ),
            "register_detail_difference_count": sum(
                "register_detail_hash" in row["metric_differences"] for row in anchors
            ),
            "expanded_body_count": sum(
                row["match_kind"] == "manual-script-table-context-expanded-body"
                for row in anchors
            ),
            "additional_registration_count": sum(
                len(row["additional_registrations"]) for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not a claim that stripped Spectron debug symbols can be recovered byte for byte.",
            "The v18_ aliases preserve the readable 1.8 names while comments retain the target registration and behavior evidence.",
            "The target setFileModTime body is longer than the 1.8 body, but the script row and decompiled file-resource update logic retain the same role, so that difference is called out explicitly.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
