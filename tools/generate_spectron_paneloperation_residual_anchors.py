#!/usr/bin/env python3
"""Create reviewed anchors for the residual TPanelOperation block."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


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


def spec(original_ea, original_name, spectron_ea, spectron_name, operation, evidence):
    return {
        "original_ea": original_ea,
        "original_name": original_name,
        "spectron_ea": spectron_ea,
        "spectron_name": spectron_name,
        "operation": operation,
        "basis": "Hex-Rays pseudocode, normalized ARM64 feature metrics, and class-local TPanelOperation order",
        "evidence": evidence,
    }


ANCHOR_SPECS = (
    spec(
        "0x11a810", "TPanelOperation_Clear_getBounds_void", "0x11d318",
        "_ZN10eHD62a2_be10rMBEgasoMCEv", "returns the clear operation bounds",
        [
            "Both bodies copy the clear operation's x, y, width, and height fields into the caller's rectangle result.",
            "The source and target are exact 44-byte normalized matches in the getBounds sequence.",
        ],
    ),
    spec(
        "0x11a83c", "TPanelOperation_DrawCurve_getBounds_void", "0x11d344",
        "_ZN10xKbb3aMu1h10rMBEgasoMCEv", "computes the curve operation bounds",
        [
            "Both bodies choose the minimum endpoints and compute absolute width and height values with the same four-field result layout.",
            "The source and target are exact 100-byte normalized matches, and the target follows the same clear getBounds boundary.",
        ],
    ),
    spec(
        "0x11a8cc", "TPanelOperation_DrawStretched_getBounds_void", "0x11d3d4",
        "_ZN10AK892aVY8g10rMBEgasoMCEv", "returns the stretched-image operation bounds",
        [
            "Both bodies copy the operation's x, y, width, and height fields into the output rectangle.",
            "The source and target are exact 44-byte normalized matches and sit immediately before the draw-line bounds method.",
        ],
    ),
    spec(
        "0x11a8f8", "TPanelOperation_DrawLine_getBounds_void", "0x11d400",
        "_ZN10m0ka3aUhjh10rMBEgasoMCEv", "computes the line operation bounds",
        [
            "Both bodies compute the endpoint minima and absolute extents for a line and write the same four integer result fields.",
            "The source and target are exact 100-byte normalized matches in the target's obfuscated getBounds sequence.",
        ],
    ),
    spec(
        "0x11a95c", "TPanelOperation_DrawText_getBounds_void", "0x11d464",
        "_ZN10PO392awP4g10rMBEgasoMCEv", "returns an empty rectangle for a text operation",
        [
            "Both bodies zero all four rectangle result fields and return the caller-provided result address.",
            "The source and target are exact 24-byte normalized matches at the end of the getBounds sequence.",
        ],
    ),
    spec(
        "0x11a974", "TPanelOperation_DrawLine_TPanelOperation_DrawLine", "0x11d47c",
        "_ZN10m0ka3aUhjhD1Ev", "provides the empty complete DrawLine destructor boundary",
        [
            "The source function has the C++ D1 destructor as its alternative name and is an empty four-byte body.",
            "The target m0ka3aUhjh D1 entry preserves the same four-byte normalized boundary in the line destructor sequence.",
        ],
    ),
    spec(
        "0x11a978", "TPanelOperation_DrawCurve_TPanelOperation_DrawCurve", "0x11d480",
        "_ZN10xKbb3aMu1hD1Ev", "provides the empty complete DrawCurve destructor boundary",
        [
            "The source function has the C++ D2 destructor as its alternative name and is an empty four-byte body.",
            "The target xKbb3aMu1h D1 entry preserves the same four-byte normalized boundary beside the line D1 entry.",
        ],
    ),
    spec(
        "0x11a97c", "TPanelOperation_Clear_TPanelOperation_Clear", "0x11d484",
        "_ZN10eHD62a2_beD1Ev", "provides the empty complete Clear destructor boundary",
        [
            "The source function has the C++ D1 destructor as its alternative name and is an empty four-byte body.",
            "The target eHD62a2_be D1 entry preserves the same four-byte normalized boundary in the line, curve, and clear sequence.",
        ],
    ),
    spec(
        "0x11aa28", "TPanelOperation_DrawLine_TPanelOperation_DrawLine__2", "0x11d530",
        "_ZN10m0ka3aUhjhD0Ev", "runs the deleting DrawLine destructor",
        [
            "Both bodies are four-byte deleting-destructor thunks that release the empty DrawLine object with operator delete.",
            "The source and target are exact normalized matches, with the target D0 entry following the property destructor quartet.",
        ],
    ),
    spec(
        "0x11aa2c", "TPanelOperation_DrawCurve_TPanelOperation_DrawCurve__2", "0x11d534",
        "_ZN10xKbb3aMu1hD0Ev", "runs the deleting DrawCurve destructor",
        [
            "Both bodies are four-byte deleting-destructor thunks that release the empty DrawCurve object with operator delete.",
            "The source and target are exact normalized matches in the same derived-operation destructor sequence.",
        ],
    ),
    spec(
        "0x11aa30", "TPanelOperation_Clear_TPanelOperation_Clear__2", "0x11d538",
        "_ZN10eHD62a2_beD0Ev", "runs the deleting Clear destructor",
        [
            "Both bodies are four-byte deleting-destructor thunks that release the empty Clear object with operator delete.",
            "The source and target are exact normalized matches immediately before the already translated DrawText deleting destructor.",
        ],
    ),
    spec(
        "0x11a9c4", "TDrawingPanelProperties_TDrawingPanelProperties", "0x11d4cc",
        "_ZN20V8fxgahcBwPropertiesD2Ev", "runs the complete drawing-panel property destructor",
        [
            "Both bodies install the primary and secondary property vtables and call the base TProperties destructor.",
            "The target V8fxgahcBwProperties D2 body is the 28-byte class-local counterpart; only register-detail allocation differs.",
        ],
    ),
    spec(
        "0x11a9e0", "non_virtual_thunk_to_TDrawingPanelProperties_TDrawingPanelProperties", "0x11d4e8",
        "_ZThn16_N20V8fxgahcBwPropertiesD1Ev", "adjusts the secondary drawing-panel property destructor receiver",
        [
            "Both thunks subtract 16 bytes from the secondary-base receiver and call the complete property destructor.",
            "The source and target are exact eight-byte normalized thunk matches.",
        ],
    ),
    spec(
        "0x11a9e8", "TDrawingPanelProperties_TDrawingPanelProperties__2", "0x11d4f0",
        "_ZN20V8fxgahcBwPropertiesD0Ev", "runs the deleting drawing-panel property destructor",
        [
            "Both bodies install the property vtables, call the base TProperties destructor, and then release the object.",
            "The target V8fxgahcBwProperties D0 body differs only in register-detail allocation from the 56-byte source body.",
        ],
    ),
    spec(
        "0x11aa20", "non_virtual_thunk_to_TDrawingPanelProperties_TDrawingPanelProperties__2", "0x11d528",
        "_ZThn16_N20V8fxgahcBwPropertiesD0Ev", "adjusts the secondary deleting property destructor receiver",
        [
            "Both thunks subtract 16 bytes from the secondary-base receiver and call the deleting property destructor.",
            "The source and target are exact eight-byte normalized thunk matches.",
        ],
    ),
    spec(
        "0x11ab28", "TPanelOperation_DrawRectangle_TPanelOperation_DrawRectangle", "0x11d5ec",
        "_ZN10AK892aVY8gD1Ev", "runs the complete DrawRectangle destructor",
        [
            "Both bodies install the derived-operation vtable and destroy the embedded resource-file user at the same receiver offset.",
            "The target AK892aVY8g D1 body preserves the source destructor sequence, with only register-detail allocation differing.",
        ],
    ),
    spec(
        "0x11ab3c", "TPanelOperation_DrawRectangle_TPanelOperation_DrawRectangle__2", "0x11d600",
        "_ZN10AK892aVY8gD0Ev", "runs the deleting DrawRectangle destructor",
        [
            "Both bodies perform the complete DrawRectangle cleanup and then call operator delete.",
            "The target AK892aVY8g D0 body is the same 48-byte destructor shape with only register-detail allocation changed.",
        ],
    ),
    spec(
        "0x11aae4", "TPanelOperation_DrawStretched_TPanelOperation_DrawStretched", "0x11d630",
        "_ZN10zfJa3aJGDhD2Ev", "runs the complete DrawStretched destructor",
        [
            "Both bodies install the derived-operation vtable and destroy the embedded resource-file user at offset 48.",
            "The target zfJa3aJGDh D2 body is the 20-byte source counterpart with only register-detail allocation changed.",
        ],
    ),
    spec(
        "0x11aaf8", "TPanelOperation_DrawStretched_TPanelOperation_DrawStretched__2", "0x11d644",
        "_ZN10zfJa3aJGDhD0Ev", "runs the deleting DrawStretched destructor",
        [
            "Both bodies perform the complete DrawStretched cleanup and then call operator delete.",
            "The target zfJa3aJGDh D0 body is the same 48-byte destructor shape with only register-detail allocation changed.",
        ],
    ),
    spec(
        "0x11ab80", "TPanelOperation_DrawImage_TPanelOperation_DrawImage__2", "0x11d688",
        "_ZN10EbOa3arQHhD0Ev", "runs the deleting DrawImage destructor",
        [
            "Both bodies install the DrawImage vtable, destroy the embedded resource-file user at offset 32, and call operator delete.",
            "The target EbOa3arQHh D0 body is a 48-byte layout-change counterpart; the complete D2 body at the preceding translated boundary supplies the class context.",
        ],
    ),
)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(rows):
    return {int(row["ea"], 16): row for row in rows}


def metrics(row):
    return {field: row.get(field) for field in METRIC_FIELDS}


def evidence_by_ea(paths):
    rows = {}
    inputs = []
    for path in paths:
        document = load(path)
        inputs.append({"path": str(path), "sha256": sha256_path(path)})
        for row in document.get("targets", []):
            ea = int(row["ea"], 16)
            previous = rows.get(ea)
            if previous is not None:
                if previous.get("name") != row.get("name") or previous.get("pseudocode") != row.get("pseudocode"):
                    raise ValueError("conflicting evidence row at %s" % row["ea"])
                continue
            rows[ea] = row
    return rows, inputs


def pseudocode_sha256(row):
    pseudocode = row.get("pseudocode")
    if pseudocode is None:
        return None
    return hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()


def semantic_rows(document):
    return {
        (int(row["original_ea"], 16), int(row["spectron_ea"], 16)): row
        for row in document.get("matches", [])
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path, action="append")
    parser.add_argument("--target-evidence", required=True, type=Path, action="append")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    source_evidence, source_inputs = evidence_by_ea(args.source_evidence)
    target_evidence, target_inputs = evidence_by_ea(args.target_evidence)
    semantic = semantic_rows(semantic_document)

    anchors = []
    for reviewed in ANCHOR_SPECS:
        original_ea = int(reviewed["original_ea"], 16)
        spectron_ea = int(reviewed["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        source_trace = source_evidence.get(original_ea)
        target_trace = target_evidence.get(spectron_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % reviewed["original_ea"])
        if source.get("name") != reviewed["original_name"]:
            raise ValueError("source name mismatch at %s" % reviewed["original_ea"])
        if target.get("name") != reviewed["spectron_name"]:
            raise ValueError("target name mismatch at %s" % reviewed["spectron_ea"])
        if target.get("is_default_name"):
            raise ValueError("target unexpectedly has a default IDA name at %s" % reviewed["spectron_ea"])
        if source_trace is None or target_trace is None:
            raise ValueError("missing pseudocode evidence at %s" % reviewed["original_ea"])
        if source_trace.get("pseudocode") is None or target_trace.get("pseudocode") is None:
            raise ValueError("pseudocode was unavailable at %s" % reviewed["original_ea"])

        semantic_row = semantic.get((original_ea, spectron_ea))
        source_metrics = metrics(source)
        target_metrics = metrics(target)
        differences = [
            field
            for field in METRIC_FIELDS
            if source_metrics.get(field) != target_metrics.get(field)
        ]
        anchors.append(
            {
                "original_ea": reviewed["original_ea"],
                "original_name": source["name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_direct_call_names": source.get("direct_call_names", []),
                "original_string_refs": source.get("string_refs", []),
                "source_pseudocode_sha256": pseudocode_sha256(source_trace),
                "source_evidence_name": source_trace.get("name"),
                "spectron_ea": reviewed["spectron_ea"],
                "spectron_name": target["name"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_metrics": target_metrics,
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "spectron_string_refs": target.get("string_refs", []),
                "target_pseudocode_sha256": pseudocode_sha256(target_trace),
                "target_evidence_name": target_trace.get("name"),
                "source_component": "TPanelOperation and TDrawingPanelProperties residual runtime",
                "target_component": "obfuscated V8fxgahcBw drawing-panel runtime",
                "operation": reviewed["operation"],
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-paneloperation-residual-exact-anchor"
                if not differences
                else "manual-paneloperation-residual-layout-anchor",
                "exact_metric_match": not differences,
                "metric_differences": differences,
                "semantic_match_already_present": semantic_row is not None,
                "semantic_match_confidence": None if semantic_row is None else semantic_row.get("confidence"),
                "semantic_match_method": None if semantic_row is None else semantic_row.get("method"),
                "source_basis": reviewed["basis"],
                "evidence": reviewed["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors) or len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source or target in TPanelOperation residual anchors")

    result = {
        "schema_version": 1,
        "artifact": "spectron_paneloperation_residual_manual_translation_anchors_20260829",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TPanelOperation bounds, derived-operation destructors, and TDrawingPanelProperties cleanup",
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
            "source_evidence": source_inputs,
            "target_evidence": target_inputs,
        },
        "summary": {
            "anchor_count": len(anchors),
            "exact_metric_anchor_count": sum(row["exact_metric_match"] for row in anchors),
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "layout_change_anchor_count": sum(not row["exact_metric_match"] for row in anchors),
            "source_pseudocode_count": sum(row["source_pseudocode_sha256"] is not None for row in anchors),
            "target_pseudocode_count": sum(row["target_pseudocode_sha256"] is not None for row in anchors),
            "semantic_promotion_count": sum(row["semantic_match_already_present"] for row in anchors),
            "new_context_anchor_count": sum(not row["semantic_match_already_present"] for row in anchors),
        },
        "anchors": anchors,
        "interpretation": [
            "The five getBounds rows preserve the source rectangle contracts exactly, including endpoint-minimum and absolute-extent behavior for curve and line operations.",
            "The empty line, curve, and clear D1 entries are matched to the source constructor boundaries because the source rows carry the corresponding C++ destructor names as alternative names; their deleting D0 entries are separate exact four-byte rows.",
            "The V8fxgahcBwProperties family preserves the base TProperties destructor and both secondary-base thunks. AK892aVY8g, zfJa3aJGDh, and EbOa3arQHh preserve the resource-file-user cleanup offsets and deleting-destructor forms.",
            "All reviewed aliases are high-confidence manual anchors. The target class-local sequence is used to resolve the small ABI boundaries, while normalized metrics and pseudocode provide the primary body evidence.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
