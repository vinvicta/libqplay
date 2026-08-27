#!/usr/bin/env python3
"""Create reviewed anchors for the remaining Spectron window input methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EVIDENCE = [
    "The target LJyzga9Pwy methods remain in the same local order as the source TWindow methods, between the translated focus, pointer, wheel, and window-state helpers.",
    "The mouse dispatcher preserves canvas lookup, event-type conversion, button mapping, cursor-position adjustment, canvas dispatch, and fallback to the input object.",
    "The key dispatcher preserves key normalization for special keys, modifier and press-state handling, canvas dispatch, main-window control binding checks, and the onControlKeyDown or onControlKeyUp event path.",
    "The target adds explicit diagnostic logging and rebuilt string, event, and input wrappers. These changed call counts and global names are recorded as target-version differences rather than treated as a protocol change.",
]


ANCHOR_SPECS = [
    {
        "original_ea": "0x107334",
        "original_name": "TWindow_invokeMouseEvent_int_int_int_int_double_double_int",
        "spectron_ea": "0x109bac",
        "target_name": "_ZN10LJyzga9Pwy10pUAyJa9EIWEiiiiddi",
        "proposed_name": "v18_TWindow_invokeMouseEvent_int_int_int_int_double_double_int",
        "source_metrics": (548, 137, 24),
        "target_metrics": (488, 122, 23),
        "source_call_count": 9,
        "target_call_count": 8,
        "source_string_refs": (),
        "target_string_refs": (),
        "required_source_calls": (
            "plt_TWindow_getCanvasControl_void",
            "plt_GuiCanvas_getCursorPos_int",
            "plt_GuiCanvas_processInputEvent_InputEvent_const",
            "plt_TInput_processInputEvent_InputEvent_const",
        ),
        "required_target_calls": (
            "._ZN10LJyzga9Pwy10ggIZgagRwUEv",
            "._ZN10SsrLga3IwI10i2GxgaCPXwEi",
            "._ZN10SsrLga3IwI10MQ0sfa9j1CEPK10ik3sfaFp3C",
            "._ZN10GaA2gaD2MX10MQ0sfa9j1CEPK10ik3sfaFp3C",
        ),
        "source_basis": "window mouse-event normalization and dispatch",
    },
    {
        "original_ea": "0x107728",
        "original_name": "TWindow_onKeyEvent_int_int_TString_const_int_bool_bool",
        "spectron_ea": "0x109f64",
        "target_name": "_ZN10LJyzga9Pwy10onKeyEventEiiRK10C8THgaTQxFibb",
        "proposed_name": "v18_TWindow_onKeyEvent_int_int_TString_const_int_bool_bool",
        "source_metrics": (516, 129, 22),
        "target_metrics": (792, 195, 23),
        "source_call_count": 9,
        "target_call_count": 30,
        "source_string_refs": ("isis", "onControlKeyDown", "onControlKeyUp"),
        "target_string_refs": (", mod: ", ", press: ", ", scan: ", "isis", "key: ", "onKeyEvent"),
        "required_source_calls": (
            "plt_TWindow_getCanvasControl_void",
            "plt_GuiCanvas_processInputEvent_InputEvent_const",
            "plt_TInput_checkControlBinding_int_int_bool",
            "plt_TGraalVar_invokeEvent_TString_const_char_const",
        ),
        "required_target_calls": (
            "._ZN10LJyzga9Pwy10ggIZgagRwUEv",
            "._ZN10SsrLga3IwI10MQ0sfa9j1CEPK10ik3sfaFp3C",
            "._ZN10GaA2gaD2MX10byZsfako_CEiib",
            "._ZN10G0gxgajWBw10BRcLgaJqkIERK10C8THgaTQxFPKcz",
        ),
        "source_basis": "window key-event normalization and game event dispatch",
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
            "mnemonic_hash",
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
        for side, function in (("source", source), ("target", target)):
            actual_metrics = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            expected_metrics = spec["%s_metrics" % side]
            ea = spec["original_ea" if side == "source" else "spectron_ea"]
            if actual_metrics != expected_metrics:
                raise ValueError(
                    "unexpected %s metrics at %s: %s" % (side, ea, actual_metrics)
                )
            if function.get("call_count") != spec["%s_call_count" % side]:
                raise ValueError("unexpected %s call count at %s" % (side, ea))
            if function.get("string_refs", []) != list(spec["%s_string_refs" % side]):
                raise ValueError(
                    "unexpected %s string references at %s: %s"
                    % (side, ea, function.get("string_refs", []))
                )
            for required_call in spec["required_%s_calls" % side]:
                if required_call not in function.get("direct_call_names", []):
                    raise ValueError("missing %s call %s at %s" % (side, required_call, ea))
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
                "match_kind": "manual-window-input-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": EVIDENCE,
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in window-input anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in window-input anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_window_input_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TWindow mouse and key event dispatch",
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
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve readable 1.8 window input roles while keeping the obfuscated target names and wrapper differences in the evidence rows.",
            "The target retains the same mouse and key event state transitions, with explicit logging and rebuilt input, string, and event wrappers recorded as version differences.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
