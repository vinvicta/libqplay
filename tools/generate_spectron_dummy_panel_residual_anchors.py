#!/usr/bin/env python3
"""Create reviewed anchors for the residual panel-interface and dummy-panel methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The three source TPanelInterface methods are a contiguous no-op block immediately before the source TDummyPanel methods. The target oMhmIajzmW class has the same three methods at the matching end of its panel-interface cluster.",
    "The target HtZ2_aJk7E class preserves the complete TDummyPanel method order, including the empty drawing hooks, the zero-return drawing-panel factory, the zeroed transformed-clipping rectangle, and the D1 or D0 destructor pair.",
    "Every reviewed source and target pair has matching size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode shape, register shape, and overall shape hash. The target method signatures also retain the corresponding argument families.",
    "The rows are not already present in the semantic translation map. They are recorded as manual context anchors for the exact hashed Spectron library.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x103b40",
        "original_name": "TPanelInterface_addModificationClipped_float_float_float_float",
        "spectron_ea": "0x1061a8",
        "target_name": "_ZN10oMhmIajzmW10okvPKaRYW_Effff",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_addModificationClipped_float_float_float_float",
        "metrics": (4, 1, 1),
        "source_basis": "panel-interface clipped-modification hook",
        "context_group": "TPanelInterface residual tail",
        "context_order": 1,
    },
    {
        "original_ea": "0x103b44",
        "original_name": "TPanelInterface_addModification_float_float_float_float",
        "spectron_ea": "0x1061ac",
        "target_name": "_ZN10oMhmIajzmW10vSc2MazrtSEffff",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_addModification_float_float_float_float",
        "metrics": (4, 1, 1),
        "source_basis": "panel-interface modification hook",
        "context_group": "TPanelInterface residual tail",
        "context_order": 2,
    },
    {
        "original_ea": "0x103b48",
        "original_name": "TPanelInterface_drawArrays_int_int_int",
        "spectron_ea": "0x1061b0",
        "target_name": "_ZN10oMhmIajzmW10alSIfatkmQEiii",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_drawArrays_int_int_int",
        "metrics": (4, 1, 1),
        "source_basis": "panel-interface array-draw hook",
        "context_group": "TPanelInterface residual tail",
        "context_order": 3,
    },
    {
        "original_ea": "0x103b4c",
        "original_name": "TDummyPanel_drawImage_TString_const_float_float_float_float_int_int_int_int",
        "spectron_ea": "0x1061b4",
        "target_name": "_ZN10HtZ2_aJk7E10cXs_ganY9UERK10C8THgaTQxFffffiiii",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_drawImage_TString_const_float_float_float_float_int_int_int_int",
        "metrics": (4, 1, 1),
        "source_basis": "dummy-panel image hook",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 1,
    },
    {
        "original_ea": "0x103b50",
        "original_name": "TDummyPanel_drawLine_float_float_float_float_float",
        "spectron_ea": "0x1061b8",
        "target_name": "_ZN10HtZ2_aJk7E10O70xgakzexEfffff",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_drawLine_float_float_float_float_float",
        "metrics": (4, 1, 1),
        "source_basis": "dummy-panel line hook",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 2,
    },
    {
        "original_ea": "0x103b54",
        "original_name": "TDummyPanel_fillRectangle_float_float_float_float_bool",
        "spectron_ea": "0x1061bc",
        "target_name": "_ZN10HtZ2_aJk7E10i_TLfa_IUSEffffb",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_fillRectangle_float_float_float_float_bool",
        "metrics": (4, 1, 1),
        "source_basis": "dummy-panel rectangle-fill hook",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 3,
    },
    {
        "original_ea": "0x103b58",
        "original_name": "TDummyPanel_drawDrawingPanel_TDrawingPanelPort_float_float_float_float_int_int_int_int",
        "spectron_ea": "0x1061c0",
        "target_name": "_ZN10HtZ2_aJk7E10nOWKfa445REP10OYYKfaPU7Rffffiiii",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_drawDrawingPanel_TDrawingPanelPort_float_float_float_float_int_int_int_int",
        "metrics": (4, 1, 1),
        "source_basis": "dummy-panel nested drawing-panel hook",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 4,
    },
    {
        "original_ea": "0x103b5c",
        "original_name": "TDummyPanel_drawTriangleStripPanel_TDrawingPanelPort_float_int_float_float_bool",
        "spectron_ea": "0x1061c4",
        "target_name": "_ZN10HtZ2_aJk7E10OZ5KfaLEeSEP10OYYKfaPU7RPfiS2_S2_b",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_drawTriangleStripPanel_TDrawingPanelPort_float_int_float_float_bool",
        "metrics": (4, 1, 1),
        "source_basis": "dummy-panel triangle-strip hook",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 5,
    },
    {
        "original_ea": "0x103b60",
        "original_name": "TDummyPanel_drawText_TFontOptions_const_TPoint_const_char_const_int",
        "spectron_ea": "0x1061c8",
        "target_name": "_ZN10HtZ2_aJk7E10u9WRgaBn_NERK10KcKRganuPNRK10eY2wgaf6pwPKci",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_drawText_TFontOptions_const_TPoint_const_char_const_int",
        "metrics": (4, 1, 1),
        "source_basis": "dummy-panel text hook",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 6,
    },
    {
        "original_ea": "0x103b64",
        "original_name": "TDummyPanel_createDrawingPanel_int_int_int_int",
        "spectron_ea": "0x1061cc",
        "target_name": "_ZN10HtZ2_aJk7E10BbvgHauRu0Eiiii",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_createDrawingPanel_int_int_int_int",
        "metrics": (8, 2, 1),
        "source_basis": "dummy-panel null drawing-panel factory",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 7,
    },
    {
        "original_ea": "0x103b6c",
        "original_name": "TDummyPanel_setTransformedClippingRectangle_float_float_float_float",
        "spectron_ea": "0x1061d4",
        "target_name": "_ZN10HtZ2_aJk7E10eR3LfamR2SEffff",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_setTransformedClippingRectangle_float_float_float_float",
        "metrics": (4, 1, 1),
        "source_basis": "dummy-panel transformed-clipping setter",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 8,
    },
    {
        "original_ea": "0x103b70",
        "original_name": "TDummyPanel_getTransformedClippingRectangle_void",
        "spectron_ea": "0x1061d8",
        "target_name": "_ZN10HtZ2_aJk7E10NkzLfaflDSEv",
        "target_prefix": "_ZN10HtZ2_aJk7E10",
        "proposed_name": "v18_TDummyPanel_getTransformedClippingRectangle_void",
        "metrics": (28, 7, 1),
        "source_basis": "dummy-panel zero transformed-clipping rectangle",
        "context_group": "TDummyPanel residual virtual block",
        "context_order": 9,
    },
    {
        "original_ea": "0x103b8c",
        "original_name": "TDummyPanel_TDummyPanel",
        "spectron_ea": "0x1061f4",
        "target_name": "_ZN10HtZ2_aJk7ED1Ev",
        "target_prefix": "_ZN10HtZ2_aJk7E",
        "proposed_name": "v18_TDummyPanel_TDummyPanel",
        "metrics": (20, 5, 2),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "dummy-panel complete destructor",
        "context_group": "TDummyPanel lifecycle pair",
        "context_order": 1,
    },
    {
        "original_ea": "0x103ba0",
        "original_name": "TDummyPanel_TDummyPanel__2",
        "spectron_ea": "0x106208",
        "target_name": "_ZN10HtZ2_aJk7ED0Ev",
        "target_prefix": "_ZN10HtZ2_aJk7E",
        "proposed_name": "v18_TDummyPanel_TDummyPanel__2",
        "metrics": (48, 12, 2),
        "source_call_count": 1,
        "target_call_count": 1,
        "required_source_calls": ("plt_TPanelInterface_TPanelInterface__2",),
        "required_target_calls": ("._ZN10oMhmIajzmWD2Ev",),
        "source_basis": "dummy-panel deleting destructor",
        "context_group": "TDummyPanel lifecycle pair",
        "context_order": 2,
    },
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(functions: list[dict]) -> dict[int, dict]:
    return {int(function["ea"], 16): function for function in functions}


def metrics(function: dict) -> dict:
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "branch_count",
            "call_count",
            "mnemonic_hash",
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
        )
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
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        source = original.get(int(spec["original_ea"], 16))
        target = spectron.get(int(spec["spectron_ea"], 16))
        if source is None or target is None:
            raise ValueError("missing source or target feature for %s" % spec["original_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("original name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
        if not target["name"].startswith(spec["target_prefix"]):
            raise ValueError("target class context mismatch at %s" % spec["spectron_ea"])
        for side, function in (("source", source), ("target", target)):
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual_metrics != spec["metrics"]:
                raise ValueError("unexpected %s metrics at %s: %s" % (side, spec["original_ea" if side == "source" else "spectron_ea"], actual_metrics))
            if function.get("call_count") != spec.get("%s_call_count" % side, 0):
                raise ValueError("unexpected %s call count at %s" % (side, spec["original_ea" if side == "source" else "spectron_ea"]))
            if function.get("string_refs", []):
                raise ValueError("unexpected string references at %s" % spec["original_ea"])
            for required_call in spec.get("required_%s_calls" % side, ()):
                if required_call not in function.get("direct_call_names", []):
                    raise ValueError("missing %s call %s at %s" % (side, required_call, spec["original_ea" if side == "source" else "spectron_ea"]))
        if any(source.get(field) != target.get(field) for field in ("branch_count", "mnemonic_hash", "opcode_shape_hash", "register_shape_hash", "shape_hash")):
            raise ValueError("source and target shape mismatch at %s" % spec["original_ea"])
        if int(spec["spectron_ea"], 16) in semantic_targets:
            raise ValueError("target is already present in the semantic map")
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-dummy-panel-residual-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "context_group": spec["context_group"],
                "context_order": spec["context_order"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_dummy_panel_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual panel-interface hooks and the TDummyPanel virtual and lifecycle block",
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
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "context": {
            "target_classes": {
                "oMhmIajzmW": "three residual panel-interface hooks at 0x1061a8 through 0x1061b0",
                "HtZ2_aJk7E": "dummy-panel virtual and lifecycle block at 0x1061b4 through 0x106208",
            },
            "source_sequence": "The source TPanelInterface residual tail is followed immediately by the TDummyPanel virtual block and its two destructor forms.",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable source roles while retaining the obfuscated target names and changed target class names in the evidence rows.",
            "The HtZ2_aJk7E methods are portable dummy-panel hooks. They should not be confused with the active OpenGL drawing implementation in the OYYKfaPU7R and related classes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
