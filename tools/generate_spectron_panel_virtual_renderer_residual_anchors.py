#!/usr/bin/env python3
"""Create reviewed anchors for panel virtual hooks and renderer flush methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target oMhmIajzmW class contains the same contiguous panel-interface virtual block as the source. The source block has one target-only four-byte hook inserted after setArrays, so the later rows are aligned by signature, class context, and order rather than by raw position alone.",
    "The panel-interface base methods preserve the source behavior. The boolean hooks return zero, the rendering and state hooks are empty, and both matrix getters write the identity matrix. The matching target pseudocode confirms those roles.",
    "The target OYYKfaPU7R class continues immediately after the base block with the no-op flushTexture hook, then the already translated panel-port methods. Its later setPixels and getPixels methods sit beside the target captureScreen method and preserve the source method signatures and bodies.",
    "The target s40xgamwex renderer method matches TGraphicOperation_flushTextures exactly in size, instruction count, block count, branch and call count, mnemonic shape, and register shape. Both walk a global drawing-panel list and dispatch the texture flush through the panel vtable. The target vtable slot is shifted from 320 to 328 bytes by its layout.",
    "The rows are not already present in the semantic translation map. They are recorded as manual context anchors for the exact hashed Spectron library.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0xfe308",
        "original_name": "TPanelInterface_isNative_void",
        "spectron_ea": "0x100970",
        "target_name": "_ZN10oMhmIajzmW10aZ9nIa7_WXEv",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_isNative_void",
        "source_metrics": (8, 2, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface native-mode predicate",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 1,
    },
    {
        "original_ea": "0xfe310",
        "original_name": "TPanelInterface_drawTextureStretched_TPixelBuffer_float_float_float_float_int_int_int_int",
        "spectron_ea": "0x100978",
        "target_name": "_ZN10oMhmIajzmW10I3_JfaSFjREP10uSjUgask_Pffffiiii",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_drawTextureStretched_TPixelBuffer_float_float_float_float_int_int_int_int",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface texture stretch hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 2,
    },
    {
        "original_ea": "0xfe314",
        "original_name": "TPanelInterface_setArrays_int_int_float_const_float_const_float_const_float_const_void_const",
        "spectron_ea": "0x10097c",
        "target_name": "_ZN10oMhmIajzmW10pNXRfaaV_XEiiPKfS1_S1_S1_PKv",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_setArrays_int_int_float_const_float_const_float_const_float_const_void_const",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface array setup hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 3,
    },
    {
        "original_ea": "0xfe318",
        "original_name": "TPanelInterface_drawElements_int_int_int_void_const",
        "spectron_ea": "0x100984",
        "target_name": "_ZN10oMhmIajzmW10TVnAfatKdJEiiiPKv",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_drawElements_int_int_int_void_const",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface indexed draw hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 4,
    },
    {
        "original_ea": "0xfe31c",
        "original_name": "TPanelInterface_requestState_int_int",
        "spectron_ea": "0x100988",
        "target_name": "_ZN10oMhmIajzmW10gRTfHauBZ_Eii",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_requestState_int_int",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface state request hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 5,
    },
    {
        "original_ea": "0xfe320",
        "original_name": "TPanelInterface_clearStates_void",
        "spectron_ea": "0x10098c",
        "target_name": "_ZN10oMhmIajzmW10arzfHawqI_Ev",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_clearStates_void",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface state clear hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 6,
    },
    {
        "original_ea": "0xfe324",
        "original_name": "TPanelInterface_setBlendMode_int",
        "spectron_ea": "0x100990",
        "target_name": "_ZN10oMhmIajzmW10gSNIfakziQEi",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_setBlendMode_int",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface blend-mode hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 7,
    },
    {
        "original_ea": "0xfe328",
        "original_name": "TPanelInterface_setBlendColor_ColorF_const",
        "spectron_ea": "0x100994",
        "target_name": "_ZN10oMhmIajzmW10DgqIfaJIZPERK10bagMga8cdJ",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_setBlendColor_ColorF_const",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface blend-color hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 8,
    },
    {
        "original_ea": "0xfe32c",
        "original_name": "TPanelInterface_setAlphaReference_float",
        "spectron_ea": "0x100998",
        "target_name": "_ZN10oMhmIajzmW10uwBIfa2a8PEf",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_setAlphaReference_float",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface alpha-reference hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 9,
    },
    {
        "original_ea": "0xfe330",
        "original_name": "TPanelInterface_canUseShader_void",
        "spectron_ea": "0x10099c",
        "target_name": "_ZN10oMhmIajzmW10EMsIfazP0PEv",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_canUseShader_void",
        "source_metrics": (8, 2, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface shader capability predicate",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 10,
    },
    {
        "original_ea": "0xfe338",
        "original_name": "TPanelInterface_setShader_TOpenGLShaderProgram",
        "spectron_ea": "0x1009a4",
        "target_name": "_ZN10oMhmIajzmW10AixzfagDvIEP10MiAzfay9xI",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_setShader_TOpenGLShaderProgram",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface shader selection hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 11,
    },
    {
        "original_ea": "0xfe33c",
        "original_name": "TPanelInterface_clearShader_void",
        "spectron_ea": "0x1009a8",
        "target_name": "_ZN10oMhmIajzmW10pxczfaO9dIEv",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_clearShader_void",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface shader clear hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 12,
    },
    {
        "original_ea": "0xfe340",
        "original_name": "TPanelInterface_reloadDefaultShaders_void",
        "spectron_ea": "0x1009ac",
        "target_name": "_ZN10oMhmIajzmW10ARHfHaOvP_Ev",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_reloadDefaultShaders_void",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface shader reload hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 13,
    },
    {
        "original_ea": "0xfe344",
        "original_name": "TPanelInterface_freeResources_void",
        "spectron_ea": "0x1009b0",
        "target_name": "_ZN10oMhmIajzmW10wgSQgaCg5MEv",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_freeResources_void",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface resource release hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 14,
    },
    {
        "original_ea": "0xfe348",
        "original_name": "TPanelInterface_getProjMatrix_void",
        "spectron_ea": "0x1009b4",
        "target_name": "_ZN10oMhmIajzmW10CJDIfa019PEv",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_getProjMatrix_void",
        "source_metrics": (80, 20, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface identity projection matrix hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 15,
    },
    {
        "original_ea": "0xfe398",
        "original_name": "TPanelInterface_getModelMatrix_void",
        "spectron_ea": "0x100a04",
        "target_name": "_ZN10oMhmIajzmW10sToJfagyOQEv",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_getModelMatrix_void",
        "source_metrics": (80, 20, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface identity model matrix hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 16,
    },
    {
        "original_ea": "0xfe3e8",
        "original_name": "TPanelInterface_setProjMatrix_MatrixF_const",
        "spectron_ea": "0x100a54",
        "target_name": "_ZN10oMhmIajzmW10FA8HfaAQKPERK10lKR7faAPdb",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_setProjMatrix_MatrixF_const",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface projection matrix setter hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 17,
    },
    {
        "original_ea": "0xfe3ec",
        "original_name": "TPanelInterface_setModelMatrix_MatrixF_const",
        "spectron_ea": "0x100a58",
        "target_name": "_ZN10oMhmIajzmW10JcBJfasVYQERK10lKR7faAPdb",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_setModelMatrix_MatrixF_const",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface model matrix setter hook",
        "context_group": "TPanelInterface base virtual block",
        "context_order": 18,
    },
    {
        "original_ea": "0xfe3f0",
        "original_name": "TDrawingPanelPort_flushTexture_void",
        "spectron_ea": "0x100a5c",
        "target_name": "_ZN10OYYKfaPU7R10jfS1_azfbEEv",
        "target_prefix": "_ZN10OYYKfaPU7R10",
        "proposed_name": "v18_TDrawingPanelPort_flushTexture_void",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "drawing-panel texture flush hook",
        "context_group": "TDrawingPanelPort inherited hook",
        "context_order": 1,
    },
    {
        "original_ea": "0x102760",
        "original_name": "TPanelInterface_captureScreen_int_int_int_int_uchar_int_int",
        "spectron_ea": "0x104dc8",
        "target_name": "_ZN10oMhmIajzmW10t_8wfaabvGEiiiiPhii",
        "target_prefix": "_ZN10oMhmIajzmW10",
        "proposed_name": "v18_TPanelInterface_captureScreen_int_int_int_int_uchar_int_int",
        "source_metrics": (8, 2, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "panel-interface screen capture hook",
        "context_group": "panel-port tail hooks",
        "context_order": 1,
    },
    {
        "original_ea": "0x102768",
        "original_name": "TDrawingPanelPort_setPixels_uchar_int_int",
        "spectron_ea": "0x104dd0",
        "target_name": "_ZN10OYYKfaPU7R10OY5TgaPDOPEPhii",
        "target_prefix": "_ZN10OYYKfaPU7R10",
        "proposed_name": "v18_TDrawingPanelPort_setPixels_uchar_int_int",
        "source_metrics": (4, 1, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "drawing-panel pixel setter hook",
        "context_group": "panel-port tail hooks",
        "context_order": 2,
    },
    {
        "original_ea": "0x10276c",
        "original_name": "TDrawingPanelPort_getPixels_void",
        "spectron_ea": "0x104dd4",
        "target_name": "_ZN10OYYKfaPU7R10KQm_ga7P4UEv",
        "target_prefix": "_ZN10OYYKfaPU7R10",
        "proposed_name": "v18_TDrawingPanelPort_getPixels_void",
        "source_metrics": (8, 2, 1),
        "source_call_count": 0,
        "target_call_count": 0,
        "source_basis": "drawing-panel pixel pointer hook",
        "context_group": "panel-port tail hooks",
        "context_order": 3,
    },
    {
        "original_ea": "0x1030a4",
        "original_name": "TGraphicOperation_flushTextures_void",
        "spectron_ea": "0x10570c",
        "target_name": "_ZN10s40xgamwex10C2xOKaWf8ZEv",
        "target_prefix": "_ZN10s40xgamwex10",
        "proposed_name": "v18_TGraphicOperation_flushTextures_void",
        "source_metrics": (108, 27, 3),
        "source_call_count": 2,
        "target_call_count": 2,
        "required_source_calls": ("plt_TList_operator_index_int",),
        "required_target_calls": ("._ZNK10vy1JgaKVkHixEi",),
        "source_basis": "graphic-operation drawing-panel texture flush loop",
        "context_group": "TGraphicOperation renderer cluster",
        "context_order": 9,
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
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("original name mismatch at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("target name mismatch at %s" % spec["spectron_ea"])
        if not target["name"].startswith(spec["target_prefix"]):
            raise ValueError("target class context mismatch at %s" % spec["spectron_ea"])
        actual_metrics = (
            source.get("size"),
            source.get("instruction_count"),
            source.get("basic_block_count"),
        )
        if actual_metrics != spec["source_metrics"]:
            raise ValueError("unexpected source metrics at %s: %s" % (spec["original_ea"], actual_metrics))
        target_metrics = (
            target.get("size"),
            target.get("instruction_count"),
            target.get("basic_block_count"),
        )
        if target_metrics != spec["source_metrics"]:
            raise ValueError("unexpected target metrics at %s: %s" % (spec["spectron_ea"], target_metrics))
        if source.get("call_count") != spec.get("source_call_count", 0):
            raise ValueError("unexpected source call count at %s" % spec["original_ea"])
        if target.get("call_count") != spec.get("target_call_count", 0):
            raise ValueError("unexpected target call count at %s" % spec["spectron_ea"])
        for side, function in (("source", source), ("target", target)):
            for required_call in spec.get("required_%s_calls" % side, ()):
                if required_call not in function.get("direct_call_names", []):
                    raise ValueError(
                        "missing %s call %s at %s"
                        % (side, required_call, spec["original_ea" if side == "source" else "spectron_ea"])
                    )
        if source.get("string_refs", []) or target.get("string_refs", []):
            raise ValueError("unexpected string reference in residual hook anchor")
        if int(spec["spectron_ea"], 16) in semantic_targets:
            raise ValueError("target is already present in the semantic map")
        row = {
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
            "match_kind": "manual-panel-virtual-renderer-residual-context-anchor",
            "semantic_match_already_present": False,
            "source_basis": spec["source_basis"],
            "context_group": spec["context_group"],
            "context_order": spec["context_order"],
            "evidence": EVIDENCE,
            "name_action": "rename-with-v18-prefix",
        }
        anchors.append(row)

    result = {
        "schema_version": 1,
        "artifact": "spectron_panel_virtual_renderer_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for panel-interface virtual hooks, panel-port tail hooks, and the graphic-operation texture flush loop",
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
            "target_only_inserted_method": {
                "spectron_ea": "0x100980",
                "spectron_current_name": "_ZN10oMhmIajzmW10D8eJfa_lGQEiiPKfS1_S1_S1_PKvii",
                "description": "The 2.2 target adds a four-byte panel hook after setArrays. It has no direct 1.8 source counterpart and is intentionally left unlabeled by this batch.",
            },
            "target_class_sequence": [
                "oMhmIajzmW base panel hooks at 0x100970 through 0x100a58",
                "OYYKfaPU7R inherited flush hook at 0x100a5c",
                "oMhmIajzmW and OYYKfaPU7R panel tail hooks at 0x104dc8 through 0x104dd4",
                "s40xgamwex graphic-operation flush loop at 0x10570c",
            ],
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable source roles while retaining the obfuscated target names and changed class layouts in the evidence rows.",
            "The target-only panel hook is preserved as an explicit gap so later analysis does not accidentally force it into a 1.8 role.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
