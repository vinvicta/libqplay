#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron compression helper family.

The global matcher can find the two builds' compression methods by their
normalized ARM64 bodies, but it does not assign names to every overload when
the stripped target keeps only obfuscated C++ names. This generator records
the class-local overload order, the wrapper behavior seen in IDA, and the
complete feature comparison in one reproducible artifact.
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

GENERAL_EVIDENCE = [
    "The source and target rows are the corresponding overloads in the TCompression and MHEiIauRiT class-local clusters. The target retains an obfuscated C++ class name, so the readable alias is an analysis translation rather than recovered target debug information.",
    "The complete normalized ARM64 feature record matches for every row. The comparison includes size, instruction count, control-flow counts, mnemonic, opcode, register, overall-shape, and string-reference fields.",
    "Addresses are valid only for the exact hashed ARM64 libraries recorded in the artifact. This is a static IDA analysis overlay and does not modify the APK or native library.",
]

ANCHOR_SPECS = [
    {
        "original_ea": "0xe4f30",
        "original_name": "TCompression_CompressBuf_TString_const_uchar_uint",
        "spectron_ea": "0xe5b18",
        "target_name_fragment": "MHEiIauRiT10E8yGKaVaqT",
        "source_basis": "TCompression TString compression wrapper",
        "evidence": [
            "Both unpack the TString storage when present, select the dummy string storage when it is empty, and forward the same buffer and length arguments to the raw CompressBuf implementation.",
            "This is the first readable-string overload in the ordered compression wrapper pair, matching the target E8yGKaVaq method before its raw-buffer overload.",
        ],
    },
    {
        "original_ea": "0xe4f68",
        "original_name": "TCompression_CompressBuf_void_const_int_uchar_uint",
        "spectron_ea": "0xe5b50",
        "target_name_fragment": "MHEiIauRiT10E8yGKaVaqTEPKviPhj",
        "source_basis": "TCompression raw-buffer compression wrapper",
        "evidence": [
            "Both clear the output TString, call the raw compression implementation, and append either the caller buffer or the object's compression buffer when the caller did not provide one.",
            "The raw-buffer overload follows the TString wrapper in both class-local clusters and has the same three-call, five-block body.",
        ],
    },
    {
        "original_ea": "0xe50d8",
        "original_name": "TCompression_DecompressBuf_TString_const_uchar_uint",
        "spectron_ea": "0xe5cc0",
        "target_name_fragment": "MHEiIauRiT10FReiIaT6XSERK10C8THgaTQxFPhj",
        "source_basis": "TCompression TString decompression wrapper",
        "evidence": [
            "Both select the embedded TString bytes and length when the object has a value, otherwise pass the dummy string and a null source buffer to the raw decompression implementation.",
            "The wrapper is the first decompression method after the two CompressBuf overloads in the source and target class-local order.",
        ],
    },
    {
        "original_ea": "0xe51d8",
        "original_name": "TCompression_CompressBuf2_TString_const_uchar_uint",
        "spectron_ea": "0xe5dc0",
        "target_name_fragment": "MHEiIauRiT10H3FyYaR_MyERK10C8THgaTQxFPhj",
        "source_basis": "TCompression second-mode TString compression wrapper",
        "evidence": [
            "Both have the same TString extraction and empty-value fallback as the first compression wrapper, but forward to the distinct CompressBuf2 implementation entry point.",
            "The target H3FyYaR_My method is the ordered second-mode TString wrapper after the decompression row, which separates it from the otherwise identical first-mode wrapper.",
        ],
    },
    {
        "original_ea": "0xe5210",
        "original_name": "TCompression_CompressBuf2_void_const_int_uchar_uint",
        "spectron_ea": "0xe5df8",
        "target_name_fragment": "MHEiIauRiT10H3FyYaR_MyEPKviPhj",
        "source_basis": "TCompression second-mode raw-buffer compression wrapper",
        "evidence": [
            "Both clear the output TString, call the second-mode raw compressor, and append the caller or internal compression buffer according to the same null-buffer rule.",
            "The raw-buffer overload immediately follows the second-mode TString wrapper in both builds and retains the same three-call, five-block body.",
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
        if spectron_ea in seen_targets:
            raise ValueError("duplicate target address %s" % spec["spectron_ea"])
        seen_targets.add(spectron_ea)

        source_metrics = metrics(source)
        target_metrics = metrics(target)
        if source_metrics != target_metrics:
            differing = [
                field
                for field in METRIC_FIELDS
                if source_metrics[field] != target_metrics[field]
            ]
            raise ValueError(
                "expected exact metrics for %s -> %s, differing fields: %s"
                % (spec["original_ea"], spec["spectron_ea"], ", ".join(differing))
            )

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
                "match_kind": "manual-compression-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "target_delta": "+0x%x" % (spectron_ea - original_ea),
                "evidence": GENERAL_EVIDENCE + spec["evidence"],
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_compression_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TCompression compression, decompression, and second-mode wrapper overloads",
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
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
            "address_delta_groups": dict(
                sorted(Counter(row["target_delta"] for row in anchors).items())
            ),
        },
        "context": {
            "source_classes": ["TCompression"],
            "target_class_clusters": ["MHEiIauRiT"],
            "resolution": "class-local overload order, wrapper behavior, target pseudocode, and exact normalized function features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "Every row matches the complete normalized function feature set. The overload identities are resolved by the source and target wrapper behavior and their stable class-local order.",
            "The v18_ aliases are scoped to the exact hashed Spectron library in the inputs and are an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
