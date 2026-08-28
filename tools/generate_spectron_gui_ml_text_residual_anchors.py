#!/usr/bin/env python3
"""Create reviewed anchors for the residual GuiMLTextCtrl methods.

The compact property accessors retain exact code fingerprints in Spectron.
The larger input, reflow, and script wrappers retain their class-local order
and behavior, but some gained wrapper conversion or target-base calls. Those
rows are recorded as reviewed layout changes instead of being presented as
automatic fingerprint matches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SPECS = [
    ("0x1bc6fc", "0x1c0028", "sub_1C0028", "GuiMLTextCtrl", "GbMhIaz9yS", "HTML-link flag getter", False),
    ("0x1bc704", "0x1c0030", "sub_1C0030", "GuiMLTextCtrl", "GbMhIaz9yS", "HTML-link flag setter", False),
    ("0x1bc70c", "0x1c0038", "sub_1C0038", "GuiMLTextCtrl", "GbMhIaz9yS", "HTML alpha getter", False),
    ("0x1bc718", "0x1c0044", "sub_1C0044", "GuiMLTextCtrl", "GbMhIaz9yS", "cursor-position field getter", False),
    ("0x1bc720", "0x1c004c", "sub_1C004C", "GuiMLTextCtrl", "GbMhIaz9yS", "cursor-position virtual setter", False),
    ("0x1bc740", "0x1c006c", "sub_1C006C", "GuiMLTextCtrl", "GbMhIaz9yS", "maximum-character-count getter", False),
    ("0x1bc748", "0x1c0074", "sub_1C0074", "GuiMLTextCtrl", "GbMhIaz9yS", "maximum-character-count setter", False),
    ("0x1bc750", "0x1c007c", "sub_1C007C", "GuiMLTextCtrl", "GbMhIaz9yS", "word-wrap getter", False),
    ("0x1bc794", "0x1c00c0", "sub_1C00C0", "GuiMLTextCtrl", "GbMhIaz9yS", "parse-tags flag getter", False),
    ("0x1bc79c", "0x1c00c8", "sub_1C00C8", "GuiMLTextCtrl", "GbMhIaz9yS", "script reflow virtual dispatch", False),
    ("0x1bc818", "0x1c0144", "sub_1C0144", "GuiMLTextCtrl", "GbMhIaz9yS", "word-wrap setter through the HTML page", False),
    ("0x1bc820", "0x1c014c", "sub_1C014C", "GuiMLTextCtrl", "GbMhIaz9yS", "URL-base setter through the HTML page", False),
    ("0x1bc828", "0x1c0154", "sub_1C0154", "GuiMLTextCtrl", "GbMhIaz9yS", "URL-base getter through the HTML page", False),
    ("0x1bc8d8", "0x1c0204", "sub_1C0204", "GuiMLTextCtrl", "GbMhIaz9yS", "HTML-compatibility setter", False),
    ("0x1bc8e0", "0x1c020c", "sub_1C020C", "GuiMLTextCtrl", "GbMhIaz9yS", "HTML-compatibility getter", False),
    ("0x1bc8e8", "0x1c0214", "sub_1C0214", "GuiMLTextCtrl", "GbMhIaz9yS", "allowed-tags serializer", False),
    ("0x1bc90c", "0x1c0238", "sub_1C0238", "GuiMLTextCtrl", "GbMhIaz9yS", "denied-sound string setter", False),
    ("0x1bc914", "0x1c0240", "sub_1C0240", "GuiMLTextCtrl", "GbMhIaz9yS", "denied-sound string getter", False),
    ("0x1bc944", "0x1c0270", "sub_1C0270", "GuiMLTextCtrl", "GbMhIaz9yS", "HTML alpha setter", False),
    ("0x1bc9e0", "0x1c030c", "_ZN10GbMhIaz9ySD0Ev", "GuiMLTextCtrl", "GbMhIaz9yS", "deleting destructor", False),
    ("0x1bcc04", "0x1c0530", "_ZN10GbMhIaz9yS10jAiwga8eNvERK10cXoLgatBuI", "GuiMLTextCtrl", "GbMhIaz9yS", "right-button link and tag handling", True),
    ("0x1bcec0", "0x1c0824", "_Z20GbMhIaz9ySE7Bm2aaHDBRK10C8THgaTQxF", "GuiMLTextCtrl", "GbMhIaz9yS", "factory wrapper", False),
    ("0x1bcf60", "0x1c08c4", "_ZNK10GbMhIaz9yS10mK1ILaB4uLEv", "GuiMLTextCtrl", "GbMhIaz9yS", "character-count getter", False),
    ("0x1bd48c", "0x1c0df0", "_ZN10GbMhIaz9yS10c9LILap7gLEv", "GuiMLTextCtrl", "GbMhIaz9yS", "cursor-line cache update and event", True),
    ("0x1bd6e8", "0x1c1084", "sub_1C1084", "GuiMLTextCtrl", "GbMhIaz9yS", "script line getter wrapper", False),
    ("0x1bd7c8", "0x1c1164", "sub_1C1164", "GuiMLTextCtrl", "GbMhIaz9yS", "script line-list getter wrapper", False),
    ("0x1bd8cc", "0x1c1268", "_ZNK10GbMhIaz9yS10IJUMLaclLOEv", "GuiMLTextCtrl", "GbMhIaz9yS", "selection-active getter", False),
    ("0x1bdf1c", "0x1c18b8", "sub_1C18B8", "GuiMLTextCtrl", "GbMhIaz9yS", "script find-text wrapper", False),
    ("0x1be504", "0x1c1ea0", "sub_1C1EA0", "GuiMLTextCtrl", "GbMhIaz9yS", "plain-text setter wrapper", False),
    ("0x1be52c", "0x1c1ec8", "sub_1C1EC8", "GuiMLTextCtrl", "GbMhIaz9yS", "script line-list setter wrapper", True),
    ("0x1be758", "0x1c210c", "_ZN10GbMhIaz9yS10MeKxLabw_BEb", "GuiMLTextCtrl", "GbMhIaz9yS", "reflow-and-resize path", True),
    ("0x1bed78", "0x1c2764", "sub_1C2764", "GuiMLTextCtrl", "GbMhIaz9yS", "allowed-tags string wrapper", True),
    ("0x1bef2c", "0x1c291c", "sub_1C291C", "GuiMLTextCtrl", "GbMhIaz9yS", "disallowed-tags string wrapper", True),
    ("0x1bf0e4", "0x1c2ad8", "_ZN10GbMhIaz9yS10q2hwgaKNMvERK10cXoLgatBuI", "GuiMLTextCtrl", "GbMhIaz9yS", "mouse-down selection and link handling", True),
    ("0x1bf4b0", "0x1c2ee0", "_ZN10GbMhIaz9yS10umViIaxSwTERK10cXoLgatBuI", "GuiMLTextCtrl", "GbMhIaz9yS", "mouse-drag selection and autoscroll", True),
    ("0x1bf6f4", "0x1c3124", "_ZN10GbMhIaz9yS10LcTxgao36wERK10cXoLgatBuI", "GuiMLTextCtrl", "GbMhIaz9yS", "mouse-up selection and tag activation", True),
    ("0x1bfb0c", "0x1c3578", "_ZN10GbMhIaz9yS10OIFwLasI5AEv", "GuiMLTextCtrl", "GbMhIaz9yS", "style update hook", False),
    ("0x1bfc94", "0x1c4700", "_ZN20GbMhIaz9ySPropertiesD1Ev", "GuiMLTextCtrlProperties", "GbMhIaz9ySProperties", "property-base destructor", False),
    ("0x1bfcb8", "0x1c4724", "_ZN20GbMhIaz9ySPropertiesD0Ev", "GuiMLTextCtrlProperties", "GbMhIaz9ySProperties", "property deleting destructor", False),
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


def metrics(row: dict) -> dict:
    return {field: row.get(field) for field in METRIC_FIELDS}


def make_row(source: dict, target: dict, spec: tuple[str, ...]) -> dict:
    source_ea, target_ea, target_name, source_class, target_class, role, expected_layout_change = spec
    source_name = source["name"]
    if not source_name.startswith(source_class):
        raise ValueError("source class mismatch at %s" % source_ea)
    if target["name"] != target_name:
        raise ValueError("target name mismatch at %s" % target_ea)

    source_metrics = metrics(source)
    target_metrics = metrics(target)
    shape_equal = all(
        source_metrics[field] == target_metrics[field]
        for field in ("opcode_shape_hash", "register_shape_hash", "shape_hash")
    )
    if expected_layout_change == shape_equal:
        if expected_layout_change:
            raise ValueError("layout-change row unexpectedly preserves shape at %s" % source_ea)
        raise ValueError("exact row unexpectedly changes normalized shape at %s" % source_ea)

    full_metric_equal = source_metrics == target_metrics
    differences = [field for field in METRIC_FIELDS if source_metrics[field] != target_metrics[field]]
    if expected_layout_change:
        evidence = [
            "The source and target rows occupy the corresponding position in the GuiMLTextCtrl class method block.",
            "The decompiled target body preserves the source operation, including text selection, reflow, wrapper conversion, or event dispatch behavior.",
            "Spectron changes the wrapper types or base dispatch enough to alter the normalized fingerprint; those metric differences are kept visible in this row.",
        ]
    elif full_metric_equal:
        evidence = [
            "The source and target decompiled bodies implement the same field access, virtual dispatch, wrapper operation, factory path, or destructor ABI role.",
            "The class-local order places the target beside the translated neighboring GuiMLTextCtrl methods.",
            "All recorded ARM64 feature metrics match, including normalized shape and register allocation detail.",
        ]
    else:
        evidence = [
            "The source and target decompiled bodies implement the same operation and occupy the corresponding class-local slot.",
            "Normalized ARM64 shape is preserved; the remaining difference is register allocation detail introduced by the target build.",
        ]

    return {
        "original_ea": source_ea,
        "original_name": source_name,
        "original_context": ["source GuiMLTextCtrl class block: 0x1bc6fc-0x1bfcf0"],
        "original_metrics": source_metrics,
        "original_string_refs": source.get("string_refs", []),
        "original_direct_call_names": source.get("direct_call_names", []),
        "spectron_ea": target_ea,
        "spectron_current_name": target["name"],
        "spectron_context": ["target %s class block" % target_class],
        "spectron_default_name": target.get("is_default_name", False),
        "spectron_metrics": target_metrics,
        "spectron_string_refs": target.get("string_refs", []),
        "spectron_direct_call_names": target.get("direct_call_names", []),
        "proposed_name": "v18_" + source_name,
        "confidence": "high",
        "match_kind": "manual-gui-ml-text-residual-anchor",
        "semantic_match_already_present": False,
        "source_component": source_class,
        "target_component": target_class,
        "source_basis": role,
        "shape_equal": shape_equal,
        "full_metric_equal": full_metric_equal,
        "layout_change": expected_layout_change,
        "metric_differences": differences,
        "evidence": evidence,
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
    semantic_targets = {int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])}

    anchors = []
    for spec in SPECS:
        source_ea, target_ea, _, _, _, _, _ = spec
        source = original.get(int(source_ea, 16))
        target = spectron.get(int(target_ea, 16))
        if source is None or target is None:
            raise ValueError("missing feature row for %s" % source_ea)
        if int(target_ea, 16) in semantic_targets:
            raise ValueError("target is already present in the semantic map at %s" % target_ea)
        anchors.append(make_row(source, target, spec))

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate target in GuiMLTextCtrl anchors")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in GuiMLTextCtrl anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_gui_ml_text_residual_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining GuiMLTextCtrl accessors, script wrappers, input handlers, reflow path, and property destructors",
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
            "source_class": "GuiMLTextCtrl",
            "target_class": "GbMhIaz9yS",
            "target_property_class": "GbMhIaz9ySProperties",
            "source_method_block": ["0x1bc6fc", "0x1bfcf0"],
            "target_method_block": ["0x1c0028", "0x1c35fc"],
            "target_property_destructors": ["0x1c4700", "0x1c475c"],
            "resolution": "class-local method order, decompiled behavior, ABI destructor roles, and normalized ARM64 feature records",
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": sum(row["shape_equal"] for row in anchors),
            "full_metric_exact_count": sum(row["full_metric_equal"] for row in anchors),
            "layout_change_anchor_count": sum(row["layout_change"] for row in anchors),
            "register_detail_difference_count": sum("register_detail_hash" in row["metric_differences"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable 1.8 roles while retaining the obfuscated target ABI names and class context.",
            "The compact accessors and several wrappers are exact feature matches. The larger handlers and line-list wrappers are explicit layout-change rows because Spectron introduced different wrapper or base-class code.",
            "The GUI input rows should be useful when following focus, selection, hyperlink, and reflow behavior, but their translation does not by itself establish a connection or service-side fix.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
