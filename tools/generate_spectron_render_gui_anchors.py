#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for render and GUI helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x105110",
        "original_name": "TTexture_getBitmap_void",
        "spectron_ea": "0x107798",
        "target_name": "_ZN10_WevgakbUu10awYAEaJwILEv",
        "source_basis": "texture bitmap accessor",
        "evidence": [
            "Both bodies return the bitmap pointer and update the same texture timestamp field.",
            "The source and target preserve the same two-load sequence and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x1091e8",
        "original_name": "TDrawTexture_draw_float_float",
        "spectron_ea": "0x10bb38",
        "target_name": "_ZN10NVxhJah9mI10tIIEga1dSCEff",
        "source_basis": "draw-texture coordinate wrapper",
        "evidence": [
            "Both wrappers forward the two supplied coordinates and the same two stored integer dimensions to the four-argument draw helper.",
            "The source and target preserve the same float conversions, argument order, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x109d30",
        "original_name": "TScreenPanelOpenGL_clearStates_void",
        "spectron_ea": "0x10c680",
        "target_name": "_ZN10SU3JfaCUmR10arzfHawqI_Ev",
        "source_basis": "OpenGL state reset",
        "evidence": [
            "Both bodies clear the same three state words at object offsets 24, 28, and 32.",
            "The target remains in the matching obfuscated OpenGL screen-panel class context.",
        ],
    },
    {
        "original_ea": "0x109d50",
        "original_name": "TScreenPanelOpenGL_setBlendColor_ColorF_const",
        "spectron_ea": "0x10c6a0",
        "target_name": "_ZN10SU3JfaCUmR10DgqIfaJIZPERK10bagMga8cdJ",
        "source_basis": "OpenGL blend-color setter",
        "evidence": [
            "Both bodies pass the four float components of the color record directly to glColor4f.",
            "The source and target preserve the same four-component load sequence and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x11274c",
        "original_name": "GuiControlProfile_getTextWidth_char_const_int",
        "spectron_ea": "0x115000",
        "target_name": "_ZNK10XoqxgaMPJw10IGa6gaABO_EPKci",
        "source_basis": "GUI control-profile text measurement",
        "evidence": [
            "Both wrappers pass the same font object, profile text settings, string, character buffer, and integer argument to the font manager.",
            "The target preserves the same profile offsets, argument order, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x117e94",
        "original_name": "TDrawingPanel_set_enablecache",
        "spectron_ea": "0x11a944",
        "target_name": "sub_11A944",
        "source_basis": "drawing-panel cache flag setter",
        "evidence": [
            "Both bodies store the cache flag at offset 140 and clear the cache when the flag is false.",
            "The target belongs to the matching V8fxgahcBw drawing-panel class context.",
        ],
    },
    {
        "original_ea": "0x118164",
        "original_name": "TDrawingPanel_clearAll_void",
        "spectron_ea": "0x11ac14",
        "target_name": "_ZN10V8fxgahcBw10n3TvDaxMrREv",
        "source_basis": "drawing-panel clear-all operation",
        "evidence": [
            "Both bodies skip clearing for the same nonzero mode and otherwise forward the mode and stored dimensions to clearRectangle.",
            "The target preserves the same field offsets, conditional call, and drawing-panel class context.",
        ],
    },
    {
        "original_ea": "0x1195d8",
        "original_name": "TPanelOperation_DrawText_execute_void",
        "spectron_ea": "0x11c0dc",
        "target_name": "_ZN10PO392awP4g10kCI62aW8feEv",
        "source_basis": "draw-text panel operation",
        "evidence": [
            "Both bodies forward the stored panel, font options, point, and text fields to the drawing-panel text implementation.",
            "The target preserves the same object offsets and argument-forwarding shape.",
        ],
    },
    {
        "original_ea": "0x11ab6c",
        "original_name": "TPanelOperation_DrawImage_TPanelOperation_DrawImage",
        "spectron_ea": "0x11d674",
        "target_name": "_ZN10EbOa3arQHhD1Ev",
        "source_basis": "draw-image panel operation destructor",
        "evidence": [
            "Both destructors install the operation vtable and destroy the embedded resource-file user object at offset 32.",
            "The target preserves the same destructor body and neighboring panel-operation context.",
        ],
    },
    {
        "original_ea": "0x1ac7e0",
        "original_name": "GuiControl_updateClientBounds_void",
        "spectron_ea": "0x1b09a0",
        "target_name": "_ZN10w9XxgaJdbx10JCFhCaeDtPEv",
        "source_basis": "GUI client-bound update",
        "evidence": [
            "Both bodies reset the client origin and copy the stored width and height into the client bounds.",
            "The target preserves the same four destination fields and GUI-control class context.",
        ],
    },
    {
        "original_ea": "0x1afe18",
        "original_name": "GuiCanvas_script_cursoroff",
        "spectron_ea": "0x1b4008",
        "target_name": "sub_1B4008",
        "source_basis": "GUI canvas cursor-off script wrapper",
        "evidence": [
            "Both wrappers read the global canvas and call the cursor setter with false when the canvas exists.",
            "The target preserves the same global guard, boolean argument, and normalized function shape.",
        ],
    },
    {
        "original_ea": "0x1afe34",
        "original_name": "GuiCanvas_script_cursoron",
        "spectron_ea": "0x1b4024",
        "target_name": "sub_1B4024",
        "source_basis": "GUI canvas cursor-on script wrapper",
        "evidence": [
            "Both wrappers read the global canvas and call the cursor setter with true when the canvas exists.",
            "The target preserves the same global guard, boolean argument, and normalized function shape beside cursor-off.",
        ],
    },
    {
        "original_ea": "0x1b2770",
        "original_name": "GuiControl_setAreaClickPriority",
        "spectron_ea": "0x1b6c70",
        "target_name": "sub_1B6C70",
        "source_basis": "GUI area-click priority setter",
        "evidence": [
            "Both bodies clamp the priority to zero through two and store it at the same control field.",
            "The source property-table comment and target setter body identify the same GUI-control property.",
        ],
    },
    {
        "original_ea": "0x1b2f48",
        "original_name": "GuiControl_getScrollLineSizes_uint_uint",
        "spectron_ea": "0x1b7448",
        "target_name": "_ZN10w9XxgaJdbx10_crxLaDvKBEPjS0_",
        "source_basis": "GUI scroll-line size accessor",
        "evidence": [
            "Both bodies return the two stored scroll-line dimensions through the same output pointers.",
            "The target preserves the same source fields and w9XxgaJdbx GUI-control class context.",
        ],
    },
    {
        "original_ea": "0x1b6478",
        "original_name": "GuiControl_buildUpdateRegion_void",
        "spectron_ea": "0x1bab44",
        "target_name": "_ZN10w9XxgaJdbx10tK0KBaIeanEv",
        "source_basis": "GUI update-region extraction",
        "evidence": [
            "Both bodies return the pending update-region pointer and clear the stored pointer.",
            "The target preserves the same field access and normalized function shape in the GUI-control class.",
        ],
    },
    {
        "original_ea": "0x1bc75c",
        "original_name": "GuiMLTextCtrl_script_getselectedposition",
        "spectron_ea": "0x1c0088",
        "target_name": "sub_1C0088",
        "source_basis": "GUI markup selection-position getter",
        "evidence": [
            "Both bodies return the selected position when the selection flag is set and -1 otherwise.",
            "The source script-table comment and target fields preserve the same selection state layout.",
        ],
    },
    {
        "original_ea": "0x1bdc50",
        "original_name": "GuiMLTextCtrl_clearSelection_void",
        "spectron_ea": "0x1c15ec",
        "target_name": "_ZN10GbMhIaz9yS10eiXxMa0uasEv",
        "source_basis": "GUI markup selection reset",
        "evidence": [
            "Both bodies clear the selection flag and endpoints, then invalidate the control rectangle.",
            "The target preserves the same selection fields, invalidation argument, and GUI markup class context.",
        ],
    },
    {
        "original_ea": "0x1bea5c",
        "original_name": "GuiMLTextCtrl_getFlowExtent_void",
        "spectron_ea": "0x1c2448",
        "target_name": "_ZN10GbMhIaz9yS10ckNxLaz61BEv",
        "source_basis": "GUI markup flow extent accessor",
        "evidence": [
            "Both bodies copy the flow extent from the same nested text-flow object at offset 308.",
            "The target preserves the same nested pointer and result-store shape in the GUI markup class.",
        ],
    },
    {
        "original_ea": "0x1bffec",
        "original_name": "GuiScrollCtrl_set_wheelscrolllines",
        "spectron_ea": "0x1c4a58",
        "target_name": "sub_1C4A58",
        "source_basis": "GUI wheel-scroll line setter",
        "evidence": [
            "Both bodies accept positive values and store them at the same scroll-control field.",
            "The source property-table comment and target setter shape identify the matching wheel-scroll property.",
        ],
    },
    {
        "original_ea": "0x1c199c",
        "original_name": "GuiScrollCtrl_scrollDelta_int_int",
        "spectron_ea": "0x1c6478",
        "target_name": "_ZN10_k_Bgam3zA10qKVxbbLb9jEii",
        "source_basis": "GUI scroll delta wrapper",
        "evidence": [
            "Both wrappers add the delta coordinates to the stored scroll position and forward the result to scrollTo.",
            "The target preserves the same two stored offsets, argument order, and normalized function shape.",
        ],
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
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("unexpected original name at %s" % spec["original_ea"])
        if target.get("name") != spec["target_name"]:
            raise ValueError("unexpected Spectron name at %s" % spec["spectron_ea"])
        for field in ("size", "instruction_count", "basic_block_count"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
                )
        for field in ("mnemonic_hash", "register_shape_hash", "shape_hash"):
            if source.get(field) != target.get(field):
                raise ValueError(
                    "%s mismatch at %s to %s"
                    % (field, spec["original_ea"], spec["spectron_ea"])
                )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_size": source["size"],
                "original_instruction_count": source["instruction_count"],
                "original_basic_block_count": source["basic_block_count"],
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_size": target["size"],
                "spectron_instruction_count": target["instruction_count"],
                "spectron_basic_block_count": target["basic_block_count"],
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": "manual-render-gui-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in render/GUI anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_render_gui_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for compact texture, OpenGL, drawing-panel, GUI-control, markup, and scroll helpers",
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
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": sum(row["semantic_match_already_present"] for row in anchors),
            "new_context_anchor_count": sum(not row["semantic_match_already_present"] for row in anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The target render and GUI helpers preserve local texture, OpenGL, drawing-panel, control, markup, and scrolling behavior with exact normalized function hashes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
