#!/usr/bin/env python3
"""Create reviewed anchors for the remaining TShowImg class methods.

The property table translated the registered getter and setter callbacks. This
follow-up records the nearby class methods whose target symbols remain
obfuscated. The short wrappers are checked by complete normalized metrics and
their target pseudocode role. The two property-destructor rows are recorded as
layout-aware lifecycle anchors because vtable literals differ between builds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


DEFAULT_ORIGINAL_BINARY = Path(
    "/home/v/Desktop/graal-decomp/GraalOnline+Classic_1.8_APKPure/"
    "lib/arm64-v8a/libqplay.so"
)
DEFAULT_SPECTRON_BINARY = Path(
    "/tmp/spectron-libqplay-inspect/lib/arm64-v8a/libqplay.so"
)

METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)

COMMON_LIFECYCLE_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "mnemonic_hash",
    "register_shape_hash",
    "string_refs_hash",
)

GENERAL_EVIDENCE = [
    "The source and target methods occupy the same TShowImg class-local implementation cluster after the translated property callbacks, list methods, and render helpers.",
    "The target name retains the obfuscated eODlJaQ5OL class or its adjacent properties-class destructor role. The anchor preserves that original name in the evidence row and adds only a readable v18_ analysis alias.",
    "Addresses are valid only for the exact hashed ARM64 libraries recorded in the artifact. This is a static analysis overlay and does not modify the APK.",
]

ANCHOR_SPECS = [
    {
        "original_ea": "0x2343cc",
        "original_name": "TShowImg_getz_void",
        "spectron_ea": "0x23e124",
        "target_name_fragment": "eODlJaQ5OL10gkQVgaDDgREv",
        "source_basis": "double z helper immediately after the registered zoom accessors",
        "evidence": [
            "Both return the double at the same logical z-helper field position, and the target pseudocode is a direct field read.",
        ],
    },
    {
        "original_ea": "0x23476c",
        "original_name": "TShowImg_TShowImg__2",
        "spectron_ea": "0x23e55c",
        "target_name_fragment": "eODlJaQ5OLD0Ev",
        "source_basis": "TShowImg D0 deleting destructor",
        "evidence": [
            "The source body calls the complete destructor and operator delete. The target _ZN10eODlJaQ5OLD0Ev body has the same 32-byte deleting-destructor shape and occupies the corresponding position after the complete destructor.",
        ],
    },
    {
        "original_ea": "0x234dc4",
        "original_name": "TShowImg_onResourceFileUpdated_TString_const",
        "spectron_ea": "0x23ec4c",
        "target_name_fragment": "eODlJaQ5OL10py0qgaE4krERK10C8THgaTQxF",
        "source_basis": "resource-link update thunk after TShowImg::readString",
        "evidence": [
            "Both are one-instruction thunks forwarding two string arguments into the resource-object update implementation.",
        ],
    },
    {
        "original_ea": "0x235554",
        "original_name": "TShowImg_tilewidthplain_void",
        "spectron_ea": "0x23f3dc",
        "target_name_fragment": "eODlJaQ5OL10NE5cXa4mDqEv",
        "source_basis": "plain tile-width virtual helper",
        "evidence": [
            "Both return the floating-point zero constant used for the plain tile-width case.",
        ],
    },
    {
        "original_ea": "0x235854",
        "original_name": "TShowImg_tilesize_void",
        "spectron_ea": "0x23f6dc",
        "target_name_fragment": "eODlJaQ5OL10pIS3IaYDSwEv",
        "source_basis": "tile-size conversion helper",
        "evidence": [
            "Both call the TShowImg pixel-size helper, convert the two integer components by 1/16, and return the pair through the caller buffer.",
        ],
    },
    {
        "original_ea": "0x236a0c",
        "original_name": "TShowImg_showText_TString_const",
        "spectron_ea": "0x240894",
        "target_name_fragment": "eODlJaQ5OL10WoSUWaLnsaERK10C8THgaTQxF",
        "source_basis": "show-text wrapper",
        "evidence": [
            "Both set image type 2 and forward the string to the coded-text particle-data helper.",
        ],
    },
    {
        "original_ea": "0x236a9c",
        "original_name": "TShowImg_showPoly_TString_const",
        "spectron_ea": "0x240924",
        "target_name_fragment": "eODlJaQ5OL10__VUWaHpvaERK10C8THgaTQxF",
        "source_basis": "show-polygon wrapper",
        "evidence": [
            "Both set image type 3 and forward the string to the coded-polygon particle-data helper.",
        ],
    },
    {
        "original_ea": "0x236ad0",
        "original_name": "TShowImg_showTexturedPoly_TString_const",
        "spectron_ea": "0x240958",
        "target_name_fragment": "eODlJaQ5OL10nvvZWa56leERK10C8THgaTQxF",
        "source_basis": "show-textured-polygon wrapper",
        "evidence": [
            "Both set image type 3 and forward the string to the textured coded-polygon particle-data helper, including the target's second polygon helper rather than the plain polygon helper.",
        ],
    },
    {
        "original_ea": "0x236b58",
        "original_name": "TShowImg_showAni_TString_const",
        "spectron_ea": "0x2409e0",
        "target_name_fragment": "eODlJaQ5OL10MtfZWaID8dERK10C8THgaTQxF",
        "source_basis": "show-animation wrapper",
        "evidence": [
            "Both set image type 4 and forward the string to the coded-animation particle-data helper.",
        ],
    },
    {
        "original_ea": "0x237984",
        "original_name": "TShowImg_getAni_void",
        "spectron_ea": "0x241824",
        "target_name_fragment": "eODlJaQ5OL10jlavgawjQuEv",
        "source_basis": "animation getter wrapper",
        "evidence": [
            "Both call the particle-data animation getter on the TShowImg subobject and preserve the caller-provided return buffer.",
        ],
    },
    {
        "original_ea": "0x237a58",
        "original_name": "TShowImg_setDir_int",
        "spectron_ea": "0x2418f8",
        "target_name_fragment": "eODlJaQ5OL10Bn9cHauvGYEi",
        "source_basis": "direction setter wrapper",
        "evidence": [
            "Both set image type 4 and call the particle-data direction setter with the integer argument.",
        ],
    },
    {
        "original_ea": "0x237a90",
        "original_name": "TShowImg_setFont_TString_const",
        "spectron_ea": "0x241930",
        "target_name_fragment": "eODlJaQ5OL10UgsKFaUoHJERK10C8THgaTQxF",
        "source_basis": "font setter wrapper",
        "evidence": [
            "Both set image type 2 and assign the supplied string into the font member at the same logical class field.",
        ],
    },
    {
        "original_ea": "0x237b34",
        "original_name": "TShowImg_setImage_TString_const",
        "spectron_ea": "0x2419d4",
        "target_name_fragment": "eODlJaQ5OL10kcRIFa3mlIERK10C8THgaTQxF",
        "source_basis": "image setter thunk to showImage",
        "evidence": [
            "Both are one-instruction thunks that forward the image string to the class show-image implementation. The adjacent property jump thunk is a separate callback and is not confused with this method.",
        ],
    },
    {
        "original_ea": "0x237b3c",
        "original_name": "TShowImg_getImageIndex_void",
        "spectron_ea": "0x2419dc",
        "target_name_fragment": "eODlJaQ5OL10FSUSXaJsOZEv",
        "source_basis": "image-index field getter",
        "evidence": [
            "Both return the image-index field directly from the expanded TShowImg object.",
        ],
    },
    {
        "original_ea": "0x237b48",
        "original_name": "TShowImg_getLayer_void",
        "spectron_ea": "0x2419e8",
        "target_name_fragment": "eODlJaQ5OL10MJuWXagtP1Ev",
        "source_basis": "layer getter normalization",
        "evidence": [
            "Both normalize the stored layer mode through the same 8, below-10, and above-10 cases. The complete normalized metrics match despite changed object constants.",
        ],
    },
    {
        "original_ea": "0x237c78",
        "original_name": "TShowImg_setPolygon_TGraalVar",
        "spectron_ea": "0x241b18",
        "target_name_fragment": "eODlJaQ5OL10hoANFa0dkMEP10G0gxgajWBw",
        "source_basis": "polygon variable setter wrapper",
        "evidence": [
            "Both set image type 3 and forward the TGraalVar object to the polygon particle-data setter.",
        ],
    },
    {
        "original_ea": "0x237cb0",
        "original_name": "TShowImg_setStyle_TString_const",
        "spectron_ea": "0x241b50",
        "target_name_fragment": "eODlJaQ5OL10l7cPgaSEHLERK10C8THgaTQxF",
        "source_basis": "style setter wrapper",
        "evidence": [
            "Both set image type 2 and assign the string into the style member at the same logical class field.",
        ],
    },
    {
        "original_ea": "0x237ce8",
        "original_name": "TShowImg_setText_TString_const",
        "spectron_ea": "0x241b88",
        "target_name_fragment": "eODlJaQ5OL10AceLgadzlIERK10C8THgaTQxF",
        "source_basis": "text setter wrapper",
        "evidence": [
            "Both set image type 2 and assign the string into the text member at the same logical class field.",
        ],
    },
    {
        "original_ea": "0x237d7c",
        "original_name": "TShowImg_getAttachToOwner_void",
        "spectron_ea": "0x241c1c",
        "target_name_fragment": "eODlJaQ5OL10myF7XaBz3bEv",
        "source_basis": "attach-to-owner flag getter",
        "evidence": [
            "Both return the attach-to-owner byte directly. The target pseudocode reads the expanded object's corresponding byte field.",
        ],
    },
    {
        "original_ea": "0x2380f4",
        "original_name": "TShowImg_initStaticScriptVars_void",
        "spectron_ea": "0x241f94",
        "target_name_fragment": "_Z10soSA2abnDNv",
        "source_basis": "TShowImg property singleton initializer",
        "evidence": [
            "Both allocate the properties object, call its constructor, store the singleton pointer, and return the singleton address. The complete normalized metrics match.",
        ],
    },
    {
        "original_ea": "0x238124",
        "original_name": "TShowImgProperties_TShowImgProperties",
        "spectron_ea": "0x241fc4",
        "target_name_fragment": "eODlJaQ5OLPropertiesD2Ev",
        "source_basis": "TShowImgProperties complete destructor role",
        "expected_exact": False,
        "evidence": [
            "The source alternative symbol identifies this as the D1 complete destructor, while the target retains the equivalent D2 spelling. Both reset the two vtables and destroy the TProperties base object.",
        ],
    },
    {
        "original_ea": "0x238148",
        "original_name": "TShowImgProperties_TShowImgProperties__2",
        "spectron_ea": "0x241fe8",
        "target_name_fragment": "eODlJaQ5OLPropertiesD0Ev",
        "source_basis": "TShowImgProperties D0 deleting destructor role",
        "expected_exact": False,
        "evidence": [
            "Both reset the properties vtables, destroy the TProperties base object, and release the allocation. The target keeps the D0 role in its retained C++ symbol, while vtable literal normalization prevents an exact opcode-shape claim.",
        ],
    },
    {
        "original_ea": "0x238140",
        "original_name": "non_virtual_thunk_to_TShowImgProperties_TShowImgProperties",
        "spectron_ea": "0x241fe0",
        "target_name_fragment": "_ZThn16_N20eODlJaQ5OLPropertiesD1Ev",
        "source_basis": "TShowImgProperties D1 non-virtual thunk",
        "evidence": [
            "Both subtract 16 from the adjusted this pointer and branch to the complete properties destructor. The two-instruction thunk fingerprint is exact.",
        ],
    },
    {
        "original_ea": "0x238180",
        "original_name": "non_virtual_thunk_to_TShowImgProperties_TShowImgProperties__2",
        "spectron_ea": "0x242020",
        "target_name_fragment": "_ZThn16_N20eODlJaQ5OLPropertiesD0Ev",
        "source_basis": "TShowImgProperties D0 non-virtual thunk",
        "evidence": [
            "Both subtract 16 from the adjusted this pointer and branch to the deleting properties destructor. The two-instruction thunk fingerprint is exact.",
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


def metrics(function: dict) -> dict:
    return {field: function.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary", type=Path, default=DEFAULT_ORIGINAL_BINARY)
    parser.add_argument("--spectron-binary", type=Path, default=DEFAULT_SPECTRON_BINARY)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])

    anchors = []
    seen_targets: set[int] = set()
    exact_count = 0
    layout_count = 0
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None or target is None:
            raise ValueError(
                "missing feature row for %s -> %s"
                % (spec["original_ea"], spec["spectron_ea"])
            )
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "source name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        if spec["target_name_fragment"] not in target.get("name", ""):
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        if target.get("end_ea") is None or source.get("end_ea") is None:
            raise ValueError("missing function boundary for %s" % spec["original_ea"])
        if spectron_ea in seen_targets:
            raise ValueError("duplicate target address %s" % spec["spectron_ea"])
        seen_targets.add(spectron_ea)

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        shape_equal = source_metrics == target_metrics
        expected_exact = spec.get("expected_exact", True)
        if expected_exact and not shape_equal:
            raise ValueError(
                "expected exact metrics for %s -> %s"
                % (spec["original_ea"], spec["spectron_ea"])
            )
        if not expected_exact:
            for field in COMMON_LIFECYCLE_FIELDS:
                if source_metrics[field] != target_metrics[field]:
                    raise ValueError(
                        "lifecycle field mismatch for %s -> %s: %s"
                        % (spec["original_ea"], spec["spectron_ea"], field)
                    )

        if shape_equal:
            exact_count += 1
            match_kind = "manual-showimg-residual-exact-anchor"
        else:
            layout_count += 1
            match_kind = "manual-showimg-residual-layout-anchor"
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_function_end": source.get("end_ea"),
                "original_metrics": source_metrics,
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_function_end": target.get("end_ea"),
                "spectron_current_name": target.get("name"),
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": target_metrics,
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + spec["original_name"],
                "confidence": "high",
                "match_kind": match_kind,
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_delta": "+0x%x" % (spectron_ea - original_ea),
                "evidence": GENERAL_EVIDENCE + spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": shape_equal,
            }
        )

    if len(anchors) != 24 or exact_count != 22 or layout_count != 2:
        raise ValueError(
            "unexpected residual counts: anchors=%d exact=%d layout=%d"
            % (len(anchors), exact_count, layout_count)
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_showimg_residual_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual TShowImg methods and properties-class lifecycle callbacks",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary": str(args.original_binary),
            "original_binary_sha256": args.original_binary_sha256
            or sha256_path(args.original_binary),
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary": str(args.spectron_binary),
            "spectron_binary_sha256": args.spectron_binary_sha256
            or sha256_path(args.spectron_binary),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": exact_count,
            "layout_change_anchor_count": layout_count,
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "address_delta_groups": dict(
                sorted(Counter(row["target_delta"] for row in anchors).items())
            ),
        },
        "context": {
            "source_class": "TShowImg and TShowImgProperties",
            "target_class": "eODlJaQ5OL and eODlJaQ5OLProperties",
            "target_class_method_cluster": "0x23e124..0x242020",
            "layout_change_roles": [
                "TShowImgProperties complete destructor",
                "TShowImgProperties deleting destructor",
            ],
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The exact rows match the complete normalized function feature set. The two properties-class destructor rows preserve lifecycle role and all common metrics, but changed vtable literals alter opcode and overall-shape hashes.",
            "The short show-text, polygon, animation, direction, font, style, and text wrappers were assigned by their target pseudocode calls and exact normalized fingerprints, not by address order alone.",
            "The v18_ aliases are scoped to the exact hashed Spectron library in the inputs and are an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
