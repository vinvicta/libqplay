#!/usr/bin/env python3
"""Create reviewed TOptions property anchors for the Spectron target."""

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
NORMALIZED_METRICS = ("opcode_shape_hash", "register_shape_hash", "shape_hash")


def add_pair(
    rows: list[dict],
    property_name: str,
    source_record: str,
    target_record: str,
    getter_source_ea: str,
    getter_target_ea: str,
    getter_source_name: str,
    getter_target_name: str,
    value_kind: str,
    getter_operation: str,
    *,
    setter_source_ea: str | None = None,
    setter_target_ea: str | None = None,
    setter_source_name: str | None = None,
    setter_target_name: str | None = None,
    setter_operation: str | None = None,
) -> None:
    rows.append(
        {
            "role": "getter",
            "property_name": property_name,
            "source_record": source_record,
            "target_record": target_record,
            "original_ea": getter_source_ea,
            "spectron_ea": getter_target_ea,
            "original_name": getter_source_name,
            "spectron_name": getter_target_name,
            "value_kind": value_kind,
            "operation": getter_operation,
        }
    )
    if setter_source_ea is not None:
        if not all(
            value is not None
            for value in (
                setter_target_ea,
                setter_source_name,
                setter_target_name,
                setter_operation,
            )
        ):
            raise ValueError(f"incomplete setter specification for {property_name}")
        rows.append(
            {
                "role": "setter",
                "property_name": property_name,
                "source_record": source_record,
                "target_record": target_record,
                "original_ea": setter_source_ea,
                "spectron_ea": setter_target_ea,
                "original_name": setter_source_name,
                "spectron_name": setter_target_name,
                "value_kind": value_kind,
                "operation": setter_operation,
            }
        )


SPECS: list[dict] = []
add_pair(
    SPECS,
    "graalplugincookie",
    "0x37b148",
    "0x38e168",
    "0x16a4b8",
    "0x16df10",
    "TOptions_get_graalplugincookie",
    "sub_16DF10",
    "string",
    "copies the global plugin-cookie string into the script result",
)
add_pair(
    SPECS,
    "isgraalplugin",
    "0x37b178",
    "0x38e198",
    "0x16a26c",
    "0x16dcc4",
    "TOptions_get_isgraalplugin",
    "sub_16DCC4",
    "boolean",
    "reads the global Graal-plugin flag",
)
add_pair(
    SPECS,
    "$pref::graal::dontsavepasswords",
    "0x37b1a8",
    "0x38e1c8",
    "0x16a27c",
    "0x16dcd4",
    "TOptions_get_pref__graal__dontsavepasswords",
    "sub_16DCD4",
    "boolean",
    "reads the global dontsavepasswords preference",
    setter_source_ea="0x16a28c",
    setter_target_ea="0x16dce4",
    setter_source_name="TOptions_set_pref__graal__dontsavepasswords",
    setter_target_name="sub_16DCE4",
    setter_operation="stores the incoming value in the global dontsavepasswords preference",
)
add_pair(
    SPECS,
    "$pref::graal::limitnicknames",
    "0x37b1d8",
    "0x38e1f8",
    "0x16a29c",
    "0x16dcf4",
    "TOptions_get_pref__graal__limitnicknames",
    "sub_16DCF4",
    "boolean",
    "reads the global limitnicknames preference",
    setter_source_ea="0x16a2ac",
    setter_target_ea="0x16dd04",
    setter_source_name="TOptions_set_pref__graal__limitnicknames",
    setter_target_name="sub_16DD04",
    setter_operation="stores the incoming value in the global limitnicknames preference",
)
add_pair(
    SPECS,
    "$pref::graal::nicknamelimit",
    "0x37b208",
    "0x38e228",
    "0x16a2bc",
    "0x16dd14",
    "TOptions_get_pref__graal__nicknamelimit",
    "sub_16DD14",
    "integer",
    "reads the global nickname-limit value",
    setter_source_ea="0x16a2cc",
    setter_target_ea="0x16dd24",
    setter_source_name="TOptions_set_pref__graal__nicknamelimit",
    setter_target_name="sub_16DD24",
    setter_operation="stores the incoming value in the global nickname-limit value",
)
add_pair(
    SPECS,
    "drawallinsidenpcs",
    "0x37b238",
    "0x38e258",
    "0x16a2dc",
    "0x16dd34",
    "TOptions_get_drawallinsidenpcs",
    "sub_16DD34",
    "boolean",
    "reads the global drawallinsidenpcs preference",
    setter_source_ea="0x16a2ec",
    setter_target_ea="0x16dd44",
    setter_source_name="TOptions_set_drawallinsidenpcs",
    setter_target_name="sub_16DD44",
    setter_operation="stores the incoming value in the global drawallinsidenpcs preference",
)
add_pair(
    SPECS,
    "lighteffectsenabled",
    "0x37b268",
    "0x38e288",
    "0x16a2fc",
    "0x16dd54",
    "TOptions_get_lighteffectsenabled",
    "sub_16DD54",
    "boolean",
    "reads the global lighteffectsenabled preference",
    setter_source_ea="0x16a30c",
    setter_target_ea="0x16dd64",
    setter_source_name="TOptions_set_lighteffectsenabled",
    setter_target_name="sub_16DD64",
    setter_operation="stores the incoming value in the global lighteffectsenabled preference",
)
add_pair(
    SPECS,
    "weathereffectsenabled",
    "0x37b298",
    "0x38e2b8",
    "0x16a31c",
    "0x16dd74",
    "TOptions_get_weathereffectsenabled",
    "sub_16DD74",
    "boolean",
    "reads the global weathereffectsenabled preference",
    setter_source_ea="0x16a32c",
    setter_target_ea="0x16dd84",
    setter_source_name="TOptions_set_weathereffectsenabled",
    setter_target_name="sub_16DD84",
    setter_operation="stores the incoming value in the global weathereffectsenabled preference",
)
add_pair(
    SPECS,
    "particleeffectsenabled",
    "0x37b2c8",
    "0x38e2e8",
    "0x16a33c",
    "0x16dd94",
    "TOptions_get_particleeffectsenabled",
    "sub_16DD94",
    "boolean",
    "reads the global particleeffectsenabled preference",
    setter_source_ea="0x16a34c",
    setter_target_ea="0x16dda4",
    setter_source_name="TOptions_set_particleeffectsenabled",
    setter_target_name="sub_16DDA4",
    setter_operation="stores the incoming value in the global particleeffectsenabled preference",
)
add_pair(
    SPECS,
    "$pref::audio::reversestereo",
    "0x37b2f8",
    "0x38e318",
    "0x16a35c",
    "0x16ddb4",
    "TOptions_get_pref__audio__reversestereo",
    "sub_16DDB4",
    "boolean",
    "reads the global reverse-stereo preference",
    setter_source_ea="0x16a36c",
    setter_target_ea="0x16ddc4",
    setter_source_name="TOptions_set_pref__audio__reversestereo",
    setter_target_name="sub_16DDC4",
    setter_operation="stores the incoming value in the global reverse-stereo preference",
)
add_pair(
    SPECS,
    "$pref::audio::midivolume",
    "0x37b328",
    "0x38e348",
    "0x16a37c",
    "0x16ddd4",
    "TOptions_get_pref__audio__midivolume",
    "sub_16DDD4",
    "integer",
    "reads the global MIDI volume preference",
    setter_source_ea="0x16a38c",
    setter_target_ea="0x16dde4",
    setter_source_name="TOptions_set_pref__audio__midivolume",
    setter_target_name="sub_16DDE4",
    setter_operation="stores the incoming value in the global MIDI volume preference",
)
add_pair(
    SPECS,
    "$pref::audio::mp3volume",
    "0x37b358",
    "0x38e378",
    "0x16a39c",
    "0x16ddf4",
    "TOptions_get_pref__audio__mp3volume",
    "sub_16DDF4",
    "integer",
    "reads the global MP3 volume preference",
    setter_source_ea="0x16a3ac",
    setter_target_ea="0x16de04",
    setter_source_name="TOptions_set_pref__audio__mp3volume",
    setter_target_name="sub_16DE04",
    setter_operation="stores the incoming value in the global MP3 volume preference",
)
add_pair(
    SPECS,
    "$pref::audio::radiovolume",
    "0x37b388",
    "0x38e3a8",
    "0x16a3bc",
    "0x16de14",
    "TOptions_get_pref__audio__radiovolume",
    "sub_16DE14",
    "integer",
    "reads the global radio volume preference",
    setter_source_ea="0x16a3cc",
    setter_target_ea="0x16de24",
    setter_source_name="TOptions_set_pref__audio__radiovolume",
    setter_target_name="sub_16DE24",
    setter_operation="stores the incoming value in the global radio volume preference",
)
add_pair(
    SPECS,
    "$pref::audio::sfxvolume",
    "0x37b3b8",
    "0x38e3d8",
    "0x16a3dc",
    "0x16de34",
    "TOptions_get_pref__audio__sfxvolume",
    "sub_16DE34",
    "integer",
    "reads the global sound-effect volume preference",
    setter_source_ea="0x16a3ec",
    setter_target_ea="0x16de44",
    setter_source_name="TOptions_set_pref__audio__sfxvolume",
    setter_target_name="sub_16DE44",
    setter_operation="stores the incoming value in the global sound-effect volume preference",
)
add_pair(
    SPECS,
    "$pref::video::defaultguistyle",
    "0x37b3e8",
    "0x38e408",
    "0x16a480",
    "0x16ded8",
    "TOptions_get_pref__video__defaultguistyle",
    "sub_16DED8",
    "string",
    "copies the global default GUI style string into the script result",
)
add_pair(
    SPECS,
    "$pref::video::externalguistyle",
    "0x37b418",
    "0x38e438",
    "0x16a448",
    "0x16dea0",
    "TOptions_get_pref__video__externalguistyle",
    "sub_16DEA0",
    "string",
    "copies the global external GUI style string into the script result",
)
add_pair(
    SPECS,
    "$pref::video::screenshotformat",
    "0x37b448",
    "0x38e468",
    "0x16a410",
    "0x16de68",
    "TOptions_get_pref__video__screenshotformat",
    "sub_16DE68",
    "string",
    "copies the global screenshot format string into the script result",
    setter_source_ea="0x16a3fc",
    setter_target_ea="0x16de54",
    setter_source_name="TOptions_set_pref__video__screenshotformat",
    setter_target_name="sub_16DE54",
    setter_operation="assigns the incoming script string to the global screenshot format",
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


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRICS}


def make_anchor(source: dict, target: dict, item: dict) -> dict:
    if source["name"] != item["original_name"]:
        raise ValueError(f"unexpected source name at {item['original_ea']}: {source['name']}")
    if target["name"] != item["spectron_name"]:
        raise ValueError(f"unexpected target name at {item['spectron_ea']}: {target['name']}")
    if not target.get("is_default_name"):
        raise ValueError(f"target is no longer a default name at {item['spectron_ea']}")
    source_metrics = metrics(source)
    target_metrics = metrics(target)
    normalized_equal = all(
        source[field] == target[field] for field in NORMALIZED_METRICS
    )
    full_metric_equal = source_metrics == target_metrics
    differences = [
        field for field in METRICS if source_metrics[field] != target_metrics[field]
    ]
    return {
        "original_ea": item["original_ea"],
        "original_name": item["original_name"],
        "original_metrics": source_metrics,
        "original_function_end": source.get("end_ea"),
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": item["spectron_ea"],
        "spectron_current_name": item["spectron_name"],
        "spectron_default_name": True,
        "spectron_metrics": target_metrics,
        "spectron_function_end": target.get("end_ea"),
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + item["original_name"],
        "confidence": "high",
        "match_kind": "manual-options-property-table-anchor",
        "source_component": "TOptions static property table",
        "target_component": "Spectron obfuscated TOptions property table",
        "source_basis": f"matching TOptions {item['role']} registration for {item['property_name']} and decompiled global-access behavior: {item['operation']}",
        "normalized_shape_equal": normalized_equal,
        "full_metric_equal": full_metric_equal,
        "metric_differences": differences,
        "source_script_table_record": item["source_record"],
        "target_script_table_record": item["target_record"],
        "script_name": item["property_name"],
        "property_role": item["role"],
        "value_kind": item["value_kind"],
        "operation": item["operation"],
        "evidence": [
            f"The source registration row for {item['property_name']} is at {item['source_record']}.",
            f"The target registration row for {item['property_name']} is at {item['target_record']}.",
            f"The source and target pseudocode preserve the same {item['value_kind']} {item['role']} operation: {item['operation']}.",
            "The target callback remains in the corresponding TOptions preference block and began as a default sub name.",
            (
                "All recorded normalized and complete function metrics match exactly."
                if normalized_equal and full_metric_equal
                else "Normalized instruction shape matches; the target register-detail differences are retained explicitly."
            ),
        ],
        "name_action": "rename-with-v18-prefix",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256", required=True)
    parser.add_argument("--spectron-binary-sha256", required=True)
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
        "artifact": "spectron_options_property_residual_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the residual TOptions preference getters and setters",
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
            "source_component": "TOptions_initStaticScriptVars property table at 0x37b148",
            "target_component": "Spectron obfuscated TOptions property table at 0x38e168",
            "resolution": "decoded preference keys, getter/setter role, direct callback pointers, decompiled global access, and ARM64 feature metrics",
            "target_table_copy": "The target addresses use the .data copy of the registration table.",
            "already_translated_target_setters": [
                "0x16e03c for $pref::video::defaultguistyle",
                "0x16df48 for $pref::video::externalguistyle",
            ],
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
            "getter_count": sum(row["property_role"] == "getter" for row in anchors),
            "setter_count": sum(row["property_role"] == "setter" for row in anchors),
            "preexisting_target_alias_count": 2,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source and target table rows retain the same preference keys and getter/setter roles even though the target class and global names are obfuscated.",
            "Two video preference setters in the same table were already translated and are intentionally excluded from this residual batch.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
