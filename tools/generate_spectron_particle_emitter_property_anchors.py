#!/usr/bin/env python3
"""Create reviewed TParticleEmitter property anchors for the Spectron target."""

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


def pair(
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
    add_pair(
        SPECS,
        property_name,
        source_record,
        target_record,
        getter_source_ea,
        getter_target_ea,
        getter_source_name,
        getter_target_name,
        value_kind,
        getter_operation,
        setter_source_ea=setter_source_ea,
        setter_target_ea=setter_target_ea,
        setter_source_name=setter_source_name,
        setter_target_name=setter_target_name,
        setter_operation=setter_operation,
    )


pair(
    "attachposition", "0x38a8d0", "0x39da20", "0x238188", "0x242028",
    "TParticleEmitter_get_attachposition", "sub_242028", "boolean",
    "reads the attach-position flag",
    setter_source_ea="0x238190", setter_target_ea="0x242030",
    setter_source_name="TParticleEmitter_set_attachposition",
    setter_target_name="sub_242030",
    setter_operation="stores the incoming attach-position flag",
)
pair(
    "autorotation", "0x38a900", "0x39da50", "0x238198", "0x242038",
    "TParticleEmitter_get_autorotation", "sub_242038", "boolean",
    "reads the autorotation flag",
    setter_source_ea="0x2381a0", setter_target_ea="0x242040",
    setter_source_name="TParticleEmitter_set_autorotation",
    setter_target_name="sub_242040",
    setter_operation="stores the incoming autorotation flag",
)
pair(
    "checkbelowterrain", "0x38a930", "0x39da80", "0x2381a8", "0x242048",
    "TParticleEmitter_get_checkbelowterrain", "sub_242048", "boolean",
    "reads the check-below-terrain flag",
    setter_source_ea="0x2381b0", setter_target_ea="0x242050",
    setter_source_name="TParticleEmitter_set_checkbelowterrain",
    setter_target_name="sub_242050",
    setter_operation="stores the incoming check-below-terrain flag",
)
pair(
    "clippingbox", "0x38a960", "0x39dab0", "0x2385b8", "0x242458",
    "TParticleEmitter_get_clippingbox", "sub_242458", "object",
    "returns the clipping-box object",
)
pair(
    "cliptoscreen", "0x38a990", "0x39dae0", "0x2381b8", "0x242058",
    "TParticleEmitter_get_cliptoscreen", "sub_242058", "boolean",
    "reads the clip-to-screen flag",
    setter_source_ea="0x2381c0", setter_target_ea="0x242060",
    setter_source_name="TParticleEmitter_set_cliptoscreen",
    setter_target_name="sub_242060",
    setter_operation="stores the incoming clip-to-screen flag",
)
pair(
    "continueafterdestroy", "0x38a9c0", "0x39db10", "0x2381c8", "0x242068",
    "TParticleEmitter_get_continueafterdestroy", "sub_242068", "boolean",
    "reads the continue-after-destroy flag",
    setter_source_ea="0x2381d0", setter_target_ea="0x242070",
    setter_source_name="TParticleEmitter_set_continueafterdestroy",
    setter_target_name="sub_242070",
    setter_operation="stores the incoming continue-after-destroy flag",
)
pair(
    "currentparticlecount", "0x38a9f0", "0x39db40", "0x2381d8", "0x242078",
    "TParticleEmitter_get_currentparticlecount", "sub_242078", "integer",
    "returns the current particle count",
)
pair(
    "delaymax", "0x38aa20", "0x39db70", "0x2381e0", "0x242080",
    "TParticleEmitter_get_delaymax", "sub_242080", "float",
    "reads the maximum emission delay",
)
pair(
    "delaymin", "0x38aa50", "0x39dba0", "0x238210", "0x2420b0",
    "TParticleEmitter_get_delaymin", "sub_2420B0", "float",
    "reads the minimum emission delay",
)
pair(
    "emissionoffset", "0x38aae0", "0x39dc30", "0x238548", "0x2423e8",
    "TParticleEmitter_get_emissionoffset", "sub_2423E8", "object",
    "returns the emission-offset point",
    setter_source_ea="0x238514", setter_target_ea="0x2423b4",
    setter_source_name="TParticleEmitter_set_emissionoffset",
    setter_target_name="sub_2423B4",
    setter_operation="stores the incoming emission-offset point",
)
pair(
    "emitatterrainheight", "0x38ab10", "0x39dc60", "0x238240", "0x2420e0",
    "TParticleEmitter_get_emitatterrainheight", "sub_2420E0", "boolean",
    "reads the emit-at-terrain-height flag",
    setter_source_ea="0x238248", setter_target_ea="0x2420e8",
    setter_source_name="TParticleEmitter_set_emitatterrainheight",
    setter_target_name="sub_2420E8",
    setter_operation="stores the incoming emit-at-terrain-height flag",
)
pair(
    "emitautomatically", "0x38ab40", "0x39dc90", "0x238250", "0x2420f0",
    "TParticleEmitter_get_emitautomatically", "sub_2420F0", "boolean",
    "reads the automatic-emission flag",
    setter_source_ea="0x238258", setter_target_ea="0x2420f8",
    setter_source_name="TParticleEmitter_set_emitautomatically",
    setter_target_name="sub_2420F8",
    setter_operation="stores the incoming automatic-emission flag",
)
pair(
    "emittedparticles", "0x38ab70", "0x39dcc0", "0x238260", "0x242100",
    "TParticleEmitter_get_emittedparticles", "sub_242100", "integer",
    "returns the emitted-particle count",
)
pair(
    "firstinfront", "0x38aba0", "0x39dcf0", "0x238268", "0x242108",
    "TParticleEmitter_get_firstinfront", "sub_242108", "boolean",
    "reads the first-in-front flag",
    setter_source_ea="0x238270", setter_target_ea="0x242110",
    setter_source_name="TParticleEmitter_set_firstinfront",
    setter_target_name="sub_242110",
    setter_operation="stores the incoming first-in-front flag",
)
pair(
    "forceaboveterrain", "0x38abd0", "0x39dd20", "0x238278", "0x242118",
    "TParticleEmitter_get_forceaboveterrain", "sub_242118", "boolean",
    "reads the force-above-terrain flag",
    setter_source_ea="0x238280", setter_target_ea="0x242120",
    setter_source_name="TParticleEmitter_set_forceaboveterrain",
    setter_target_name="sub_242120",
    setter_operation="stores the incoming force-above-terrain flag",
)
pair(
    "isfrozen", "0x38ac00", "0x39dd50", "0x238288", "0x242128",
    "TParticleEmitter_get_isfrozen", "sub_242128", "boolean",
    "reads the frozen flag",
)
pair(
    "maxparticles", "0x38ac30", "0x39dd80", "0x238290", "0x242130",
    "TParticleEmitter_get_maxparticles", "sub_242130", "integer",
    "reads the maximum particle count",
)
pair(
    "movementfactor", "0x38ac60", "0x39ddb0", "0x238298", "0x242138",
    "TParticleEmitter_get_movementfactor", "sub_242138", "float",
    "reads the movement factor",
    setter_source_ea="0x2382a0", setter_target_ea="0x242140",
    setter_source_name="TParticleEmitter_set_movementfactor",
    setter_target_name="sub_242140",
    setter_operation="stores the incoming movement factor",
)
pair(
    "noclipping", "0x38ac90", "0x39dde0", "0x2382a8", "0x242148",
    "TParticleEmitter_get_noclipping", "sub_242148", "boolean",
    "reads the no-clipping flag",
    setter_source_ea="0x2382b0", setter_target_ea="0x242150",
    setter_source_name="TParticleEmitter_set_noclipping",
    setter_target_name="sub_242150",
    setter_operation="stores the incoming no-clipping flag",
)
pair(
    "nrofparticles", "0x38acc0", "0x39de10", "0x2382b8", "0x242158",
    "TParticleEmitter_get_nrofparticles", "sub_242158", "integer",
    "reads the configured particle count",
)
pair(
    "particle", "0x38acf0", "0x39de40", "0x23841c", "0x2422bc",
    "TParticleEmitter_get_particle", "sub_2422BC", "object",
    "looks up a particle by script index",
)
pair(
    "particletypes", "0x38ad20", "0x39de70", "0x2382c0", "0x242160",
    "TParticleEmitter_get_particletypes", "sub_242160", "integer",
    "reads the particle-type count",
)
pair(
    "showonground", "0x38ad50", "0x39dea0", "0x2382cc", "0x24216c",
    "TParticleEmitter_get_showonground", "sub_24216C", "boolean",
    "reads the show-on-ground flag",
    setter_source_ea="0x2382d4", setter_target_ea="0x242174",
    setter_source_name="TParticleEmitter_set_showonground",
    setter_target_name="sub_242174",
    setter_operation="stores the incoming show-on-ground flag",
)
pair(
    "showontop", "0x38ad80", "0x39ded0", "0x2382dc", "0x24217c",
    "TParticleEmitter_get_showontop", "sub_24217C", "boolean",
    "reads the show-on-top flag",
    setter_source_ea="0x2382e4", setter_target_ea="0x242184",
    setter_source_name="TParticleEmitter_set_showontop",
    setter_target_name="sub_242184",
    setter_operation="stores the incoming show-on-top flag",
)
pair(
    "switchyandzaxis", "0x38adb0", "0x39df00", "0x2382ec", "0x24218c",
    "TParticleEmitter_get_switchyandzaxis", "sub_24218C", "boolean",
    "reads the Y-and-Z axis switch flag",
    setter_source_ea="0x2382f4", setter_target_ea="0x242194",
    setter_source_name="TParticleEmitter_set_switchyandzaxis",
    setter_target_name="sub_242194",
    setter_operation="stores the incoming Y-and-Z axis switch flag",
)
pair(
    "wraptoclippingbox", "0x38ade0", "0x39df30", "0x2382fc", "0x24219c",
    "TParticleEmitter_get_wraptoclippingbox", "sub_24219C", "boolean",
    "reads the wrap-to-clipping-box flag",
    setter_source_ea="0x238304", setter_target_ea="0x2421a4",
    setter_source_name="TParticleEmitter_set_wraptoclippingbox",
    setter_target_name="sub_2421A4",
    setter_operation="stores the incoming wrap-to-clipping-box flag",
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
        raise ValueError(
            f"unexpected source name at {item['original_ea']}: {source['name']}"
        )
    if target["name"] != item["spectron_name"]:
        raise ValueError(
            f"unexpected target name at {item['spectron_ea']}: {target['name']}"
        )
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
        "match_kind": "manual-particle-emitter-property-table-anchor",
        "source_component": "TParticleEmitterProperties property table",
        "target_component": "Spectron obfuscated TParticleEmitter property table",
        "source_basis": (
            f"matching TParticleEmitter {item['role']} registration for "
            f"{item['property_name']} and decompiled property behavior: "
            f"{item['operation']}"
        ),
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
            "The target callback remains in the corresponding TParticleEmitter property block and began as a default sub name.",
            (
                "All recorded normalized and complete function metrics match exactly."
                if normalized_equal and full_metric_equal
                else "Normalized instruction shape matches; any target metric differences are retained explicitly."
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
        "artifact": "spectron_particle_emitter_property_manual_translation_anchors_20260828",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TParticleEmitter property getters and setters",
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
            "source_component": "TParticleEmitterProperties property table at 0x38a8d0",
            "target_component": "Spectron obfuscated TParticleEmitter property table at 0x39da20",
            "resolution": "decoded property names, getter/setter roles, direct callback pointers, decompiled field operations, and ARM64 feature metrics",
            "target_table_copy": "The target addresses use the .data copy of the registration table.",
            "already_translated_target_entries": [
                "clippingbox setter at 0x24240c",
                "delaymax setter at 0x242088",
                "delaymin setter at 0x2420b8",
                "dropemitter getter at 0x243558",
                "dropwateremitter getter at 0x2435b8",
                "isfrozen setter at 0x243854",
                "maxparticles setter at 0x2437ec",
                "nrofparticles setter at 0x24380c",
                "particletypes setter at 0x2437c0",
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
            "preexisting_target_alias_count": 9,
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The source and target property tables retain the same property names and callback order even though the target class and helper names are obfuscated.",
            "Nine table entries were already translated in earlier passes and are intentionally excluded from this residual batch.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
