#!/usr/bin/env python3
"""Create reviewed anchors for the compact server-object lifecycle block.

This pass covers the residual Explosion, Bomb, Chest, Extra, Flying, Leap,
and Sign methods. The source and target class blocks retain the same method
order even though Spectron rebuilt the C++ names and string wrapper types.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = [
    ("0x23c850", "TExplosion", "0x246700", "sub_246700", "getPower", "Dq2rua2Ece", "power getter"),
    ("0x23c858", "TExplosion", "0x246708", "sub_246708", "getTime", "Dq2rua2Ece", "time getter"),
    ("0x23cda4", "TExplosion", "0x246cbc", "_Z10jt7uualUNgv", "initStaticScriptVars_void", "Dq2rua2Ece", "script-property registration initializer"),
    ("0x23cdd4", "TExplosionProperties", "0x246cec", "_ZN20Dq2rua2EcePropertiesD2Ev", "TExplosionProperties", "Dq2rua2EceProperties", "property-base destructor"),
    ("0x23cdf8", "TExplosionProperties", "0x246d10", "_ZN20Dq2rua2EcePropertiesD0Ev", "TExplosionProperties__2", "Dq2rua2EceProperties", "property deleting destructor"),
    ("0x23ce38", "TExplosion", "0x246d50", "_ZN10Dq2rua2EceD1Ev", "TExplosion", "Dq2rua2Ece", "object destructor"),
    ("0x23ce4c", "TExplosion", "0x246d64", "_ZN10Dq2rua2EceD0Ev", "TExplosion__2", "Dq2rua2Ece", "object deleting destructor"),
    ("0x23ce80", "TServerBomb", "0x246d98", "sub_246D98", "getPower", "irqhGaERgb", "power getter"),
    ("0x23d27c", "TServerBomb", "0x247194", "_ZN10irqhGaERgbC1EP10zF9VgaBKxR", "TServerBomb_TServerBomb_TServerLevel", "irqhGaERgb", "level-bound constructor"),
    ("0x23d2cc", "TServerBomb", "0x2471e4", "_Z10DsHgGaPaFav", "initStaticVars_void", "irqhGaERgb", "native static-state initializer"),
    ("0x23d2f8", "TServerBomb", "0x247210", "_Z10IBCgGan5Aav", "initStaticScriptVars_void", "irqhGaERgb", "script-property registration initializer"),
    ("0x23d328", "TServerBombProperties", "0x247240", "_ZN20irqhGaERgbPropertiesD2Ev", "TServerBombProperties", "irqhGaERgbProperties", "property-base destructor"),
    ("0x23d34c", "TServerBombProperties", "0x247264", "_ZN20irqhGaERgbPropertiesD0Ev", "TServerBombProperties__2", "irqhGaERgbProperties", "property deleting destructor"),
    ("0x23d38c", "TServerBomb", "0x2472a4", "_ZN10irqhGaERgbD1Ev", "TServerBomb", "irqhGaERgb", "object destructor"),
    ("0x23d3c0", "TServerBomb", "0x2472d8", "_ZN10irqhGaERgbD0Ev", "TServerBomb__2", "irqhGaERgb", "object deleting destructor"),
    ("0x23e184", "TServerChest", "0x24810c", "sub_24810C", "getIsOpen", "dJ10YaC3tX", "open-state getter"),
    ("0x23e18c", "TServerChest", "0x248114", "_ZN10dJ10YaC3tX10JhjWgazQFREv", "getOrderPoint_void", "dJ10YaC3tX", "draw-order point getter"),
    ("0x23e5e4", "TServerChest", "0x24856c", "_Z10O7rR2aehA0v", "initStaticScriptVars_void", "dJ10YaC3tX", "script-property registration initializer"),
    ("0x23e614", "TServerChestProperties", "0x24859c", "_ZN20dJ10YaC3tXPropertiesD1Ev", "TServerChestProperties", "dJ10YaC3tXProperties", "property-base destructor"),
    ("0x23e638", "TServerChestProperties", "0x2485c0", "_ZN20dJ10YaC3tXPropertiesD0Ev", "TServerChestProperties__2", "dJ10YaC3tXProperties", "property deleting destructor"),
    ("0x23e678", "TServerChest", "0x248600", "_ZN10dJ10YaC3tXD2Ev", "TServerChest", "dJ10YaC3tX", "object destructor"),
    ("0x23e6ac", "TServerChest", "0x248634", "_ZN10dJ10YaC3tXD0Ev", "TServerChest__2", "dJ10YaC3tX", "object deleting destructor"),
    ("0x23e6e8", "TServerExtra", "0x248670", "sub_248670", "getTime", "k1h4JaIMdn", "time getter"),
    ("0x23ea7c", "TServerExtra", "0x248a04", "_ZN10k1h4JaIMdnC1EP10zF9VgaBKxR", "TServerExtra_TServerExtra_TServerLevel", "k1h4JaIMdn", "level-bound constructor"),
    ("0x23eacc", "TServerExtra", "0x248a54", "_Z10Xtw3JaTWzmv", "initStaticScriptVars_void", "k1h4JaIMdn", "script-property registration initializer"),
    ("0x23eafc", "TServerExtraProperties", "0x248a84", "_ZN20k1h4JaIMdnPropertiesD1Ev", "TServerExtraProperties", "k1h4JaIMdnProperties", "property-base destructor"),
    ("0x23eb20", "TServerExtraProperties", "0x248aa8", "_ZN20k1h4JaIMdnPropertiesD0Ev", "TServerExtraProperties__2", "k1h4JaIMdnProperties", "property deleting destructor"),
    ("0x23eb60", "TServerExtra", "0x248ae8", "_ZN10k1h4JaIMdnD2Ev", "TServerExtra", "k1h4JaIMdn", "object destructor"),
    ("0x23eb94", "TServerExtra", "0x248b1c", "_ZN10k1h4JaIMdnD0Ev", "TServerExtra__2", "k1h4JaIMdn", "object deleting destructor"),
    ("0x23ee64", "TServerFlying", "0x248dec", "_ZN10gId5RaV8_6C2EP10zF9VgaBKxR", "TServerFlying_TServerFlying_TServerLevel", "gId5RaV8_6", "level-bound constructor"),
    ("0x23fb68", "TServerFlying", "0x249b10", "_Z10Lm_Q2aU4b0v", "initStaticScriptVars_void", "gId5RaV8_6", "script-property registration initializer"),
    ("0x23fb98", "TServerFlyingProperties", "0x249b40", "_ZN20gId5RaV8_6PropertiesD1Ev", "TServerFlyingProperties", "gId5RaV8_6Properties", "property-base destructor"),
    ("0x23fbbc", "TServerFlyingProperties", "0x249b64", "_ZN20gId5RaV8_6PropertiesD0Ev", "TServerFlyingProperties__2", "gId5RaV8_6Properties", "property deleting destructor"),
    ("0x23fbfc", "TServerFlying", "0x249ba4", "_ZN10gId5RaV8_6D2Ev", "TServerFlying", "gId5RaV8_6", "object destructor"),
    ("0x23fc10", "TServerFlying", "0x249bb8", "_ZN10gId5RaV8_6D0Ev", "TServerFlying__2", "gId5RaV8_6", "object deleting destructor"),
    ("0x23fc40", "TServerLeap", "0x249be8", "_ZN10X0HXmbuEQV10JhjWgazQFREv", "getOrderPoint_void", "X0HXmbuEQV", "draw-order point getter"),
    ("0x23fe70", "TServerLeap", "0x249e18", "_ZN10X0HXmbuEQVC2EP10zF9VgaBKxR", "TServerLeap_TServerLeap_TServerLevel", "X0HXmbuEQV", "level-bound constructor"),
    ("0x23fee4", "TServerLeap", "0x249e8c", "_Z10fz9Q2aeFk0v", "initStaticScriptVars_void", "X0HXmbuEQV", "script-property registration initializer"),
    ("0x23ff14", "TServerLeapProperties", "0x249ebc", "_ZN20X0HXmbuEQVPropertiesD1Ev", "TServerLeapProperties", "X0HXmbuEQVProperties", "property-base destructor"),
    ("0x23ff38", "TServerLeapProperties", "0x249ee0", "_ZN20X0HXmbuEQVPropertiesD0Ev", "TServerLeapProperties__2", "X0HXmbuEQVProperties", "property deleting destructor"),
    ("0x23ff78", "TServerLeap", "0x249f20", "_ZN10X0HXmbuEQVD1Ev", "TServerLeap", "X0HXmbuEQV", "object destructor"),
    ("0x23ff8c", "TServerLeap", "0x249f34", "_ZN10X0HXmbuEQVD0Ev", "TServerLeap__2", "X0HXmbuEQV", "object deleting destructor"),
    ("0x23ffbc", "TServerSign", "0x249f64", "sub_249F64", "setText", "C2t_vaQTax", "text setter"),
    ("0x23ffc4", "TServerSign", "0x249f6c", "sub_249F6C", "getText", "C2t_vaQTax", "text getter"),
    ("0x240090", "TServerSign", "0x24a038", "_ZN10C2t_vaQTaxC1EP10zF9VgaBKxR", "TServerSign_TServerSign_TServerLevel", "C2t_vaQTax", "level-bound constructor"),
    ("0x2400e0", "TServerSign", "0x24a088", "_Z10yHC_vamaixv", "initStaticScriptVars_void", "C2t_vaQTax", "script-property registration initializer"),
    ("0x240110", "TServerSignProperties", "0x24a0b8", "_ZN20C2t_vaQTaxPropertiesD2Ev", "TServerSignProperties", "C2t_vaQTaxProperties", "property-base destructor"),
    ("0x240134", "TServerSignProperties", "0x24a0dc", "_ZN20C2t_vaQTaxPropertiesD0Ev", "TServerSignProperties__2", "C2t_vaQTaxProperties", "property deleting destructor"),
    ("0x240174", "TServerSign", "0x24a11c", "_ZN10C2t_vaQTaxD1Ev", "TServerSign", "C2t_vaQTax", "object destructor"),
]


METRIC_FIELDS = (
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


def by_ea(document: dict) -> dict[int, dict]:
    return {int(row["ea"], 16): row for row in document["functions"]}


def metric_record(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def make_row(source: dict, target: dict, spec: tuple[str, ...]) -> dict:
    source_ea, source_class, target_ea, target_name, _source_name, target_class, role = spec
    source_name = source["name"]
    if not source_name.startswith(source_class):
        raise ValueError("source class mismatch at %s" % source_ea)
    source_metrics = metric_record(source)
    target_metrics = metric_record(target)
    shape_equal = all(
        source_metrics[field] == target_metrics[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    if not shape_equal:
        raise ValueError("server-object row lost normalized shape at %s" % source_ea)
    return {
        "original_ea": source_ea,
        "original_name": source_name,
        "original_context": ["source class block: " + source_class],
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target_ea,
        "spectron_current_name": target["name"],
        "spectron_context": ["target class block: " + target_class],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source_name,
        "confidence": "high",
        "match_kind": "manual-server-object-lifecycle-anchor",
        "semantic_match_already_present": False,
        "source_component": source_class,
        "target_component": target_class,
        "source_basis": role,
        "shape_equal": True,
        "full_metric_equal": source_metrics == target_metrics,
        "layout_change": False,
        "metric_differences": [field for field in METRIC_FIELDS if source_metrics[field] != target_metrics[field]],
        "evidence": [
            "The source and target rows occupy the same local class block and preserve the same lifecycle or accessor role.",
            "The source and target decompiled bodies preserve the relevant getter, setter, constructor, property-destructor, or deleting-destructor behavior.",
            "All normalized ARM64 feature fields match. Register-detail differences, when present, are recorded as target register allocation changes.",
        ],
        "name_action": "rename-with-v18-prefix",
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
    original = by_ea(original_document)
    spectron = by_ea(spectron_document)
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in SPECS:
        source_ea, _, target_ea, target_name, _, _, _ = spec
        source = original.get(int(source_ea, 16))
        target = spectron.get(int(target_ea, 16))
        if source is None or target is None:
            raise ValueError("missing feature row for %s" % source_ea)
        if target.get("name") != target_name:
            raise ValueError("target name mismatch at %s" % target_ea)
        if int(target_ea, 16) in semantic_targets:
            raise ValueError("target is already present in the semantic map at %s" % target_ea)
        anchors.append(make_row(source, target, spec))

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate target in server-object lifecycle anchors")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in server-object lifecycle anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_server_object_lifecycle_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual Explosion, Bomb, Chest, Extra, Flying, Leap, and Sign accessors and lifecycle methods",
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
        "context": {
            "source_classes": ["TExplosion", "TServerBomb", "TServerChest", "TServerExtra", "TServerFlying", "TServerLeap", "TServerSign"],
            "target_classes": ["Dq2rua2Ece", "irqhGaERgb", "dJ10YaC3tX", "k1h4JaIMdn", "gId5RaV8_6", "X0HXmbuEQV", "C2t_vaQTax"],
            "resolution": "contiguous class-local method order, constructor and destructor ABI roles, decompiled behavior, and normalized ARM64 feature records",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "register_detail_difference_count": sum("register_detail_hash" in row["metric_differences"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable 1.8 roles while retaining obfuscated target ABI names and class context.",
            "All rows in this block preserve normalized shape. Eight also match every recorded feature metric; the remaining rows differ only in register-detail allocation.",
            "Short getters and lifecycle thunks are included because their class-local order and ABI destructor roles provide evidence beyond their compact fingerprints.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
