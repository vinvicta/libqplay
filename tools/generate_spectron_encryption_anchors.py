#!/usr/bin/env python3
"""Create reviewed anchors for the Spectron encryption helper family.

The target keeps these helpers under an obfuscated C++ class. This artifact
records the DES, MD5, RSA, RC4, and AES correspondences using target
pseudocode, class-local ordering, and complete normalized ARM64 features.
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
    "The source and target rows are corresponding overloads or algorithm wrappers in the TEncryption and cHovga0n1u class-local clusters. The target retains an obfuscated C++ class name, so the readable alias is an analysis translation rather than recovered target debug information.",
    "The complete normalized ARM64 feature record matches for every row. The comparison includes size, instruction count, control-flow counts, mnemonic, opcode, register, overall-shape, and string-reference fields.",
    "Addresses are valid only for the exact hashed ARM64 libraries recorded in the artifact. This is a static IDA analysis overlay and does not modify the APK or native library.",
]

ANCHOR_SPECS = [
    {
        "original_ea": "0xe5abc",
        "original_name": "TEncryption_des_encrypt_TString_const_TString_const",
        "spectron_ea": "0xe66a4",
        "target_name_fragment": "cHovga0n1u10UHr4FaIVl0",
        "source_basis": "TEncryption DES string encryption wrapper",
        "evidence": [
            "Both require a nonempty input string and a key longer than seven bytes, copy the input into a unique temporary TString, invoke the DES memory-encryption helper, return the transformed string, and clear the temporary.",
            "The target UHr4FaIVl0 method is the first member of the ordered DES encrypt/decrypt wrapper pair.",
        ],
    },
    {
        "original_ea": "0xe5c24",
        "original_name": "TEncryption_des_decrypt_TString_const_TString_const",
        "spectron_ea": "0xe680c",
        "target_name_fragment": "cHovga0n1u10ga33Fadh1_",
        "source_basis": "TEncryption DES string decryption wrapper",
        "evidence": [
            "Both use the same input and key guards, unique temporary-string handling, output assignment, and cleanup as the encrypt wrapper, but call the DES memory-decryption helper.",
            "The target ga33Fadh1_ method immediately follows the target DES encrypt wrapper in the same class-local block.",
        ],
    },
    {
        "original_ea": "0xe5d6c",
        "original_name": "TEncryption_script_md5",
        "spectron_ea": "0xe6954",
        "target_name_fragment": "sub_E6954",
        "source_basis": "TEncryption script-facing MD5 wrapper",
        "evidence": [
            "Both are eight-instruction script wrappers that forward the supplied TString to the class MD5 digest helper and return the caller-provided result slot.",
            "The target body is the short default-named method immediately after the DES wrapper pair, matching the source's script-facing helper role.",
        ],
    },
    {
        "original_ea": "0xf7464",
        "original_name": "TEncryption_rsa_sign_TString_const_TString_const",
        "spectron_ea": "0xf96f8",
        "target_name_fragment": "cHovga0n1u10GjD5FacHl1",
        "source_basis": "TEncryption RSA private-key signing wrapper",
        "evidence": [
            "Both initialize and decode an RSA private key, initialize an RNG, calculate the RSA output size, sign the input buffer, append a positive result to the output TString, and free the key state.",
            "The target GjD5FacHl1 method is in the later asymmetric-encryption block, where the source has the corresponding RSA helper and a separate address delta from the DES block.",
        ],
    },
    {
        "original_ea": "0xf77d4",
        "original_name": "TEncryption_rc4_deletekey_void",
        "spectron_ea": "0xf9a68",
        "target_name_fragment": "cHovga0n1u10OQfeYa5WBhEPv",
        "source_basis": "TEncryption RC4 key cleanup wrapper",
        "evidence": [
            "Both conditionally release the RC4 state with the native delete operator and otherwise return without side effects.",
            "The target OQfeYa5WBh method is the first short lifecycle helper in the ordered RC4 pair.",
        ],
    },
    {
        "original_ea": "0xf77e0",
        "original_name": "TEncryption_rc4_process_void_uchar_uchar_int",
        "spectron_ea": "0xf9a74",
        "target_name_fragment": "cHovga0n1u10r5NzYabLJzEPvPhS1_i",
        "source_basis": "TEncryption RC4 process wrapper",
        "evidence": [
            "Both validate the state, input, output, and positive length before calling the native Arc4Process routine, otherwise returning the state pointer unchanged.",
            "The target r5NzYabLJz method immediately follows RC4 key cleanup and preserves the ordered process-helper role.",
        ],
    },
    {
        "original_ea": "0xf79ec",
        "original_name": "TEncryption_aes_deletekey_void",
        "spectron_ea": "0xf9c80",
        "target_name_fragment": "cHovga0n1u10ZirdYaFAVgEPv",
        "source_basis": "TEncryption AES key cleanup wrapper",
        "evidence": [
            "Both conditionally release the AES state with the native delete operator and otherwise return without side effects.",
            "The target ZirdYaFAVg method is the first short lifecycle helper in the ordered AES encrypt/decrypt block.",
        ],
    },
    {
        "original_ea": "0xf79f8",
        "original_name": "TEncryption_aes_encrypt_void_uchar_uchar_int",
        "spectron_ea": "0xf9c8c",
        "target_name_fragment": "cHovga0n1u10wdyzYa5owzEPvPhS1_i",
        "source_basis": "TEncryption AES-CBC encryption wrapper",
        "evidence": [
            "Both require valid state, input, output, and positive length before forwarding to the native AesCbcEncrypt routine, otherwise returning the state pointer.",
            "The target wdyzYa5owz method follows AES key cleanup and precedes the matching decrypt wrapper, preserving the source order.",
        ],
    },
    {
        "original_ea": "0xf7a14",
        "original_name": "TEncryption_aes_decrypt_void_uchar_uchar_int",
        "spectron_ea": "0xf9ca8",
        "target_name_fragment": "cHovga0n1u10eDbEYaGoqDEPvPhS1_i",
        "source_basis": "TEncryption AES-CBC decryption wrapper",
        "evidence": [
            "Both use the same argument guards as AES encryption and forward valid buffers to the native AesCbcDecrypt routine, otherwise returning the state pointer.",
            "The target eDbEYaGoqD method immediately follows AES encryption in the matching class-local sequence.",
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
                "match_kind": "manual-encryption-exact-anchor",
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
        "artifact": "spectron_encryption_manual_translation_anchors_20260827",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for TEncryption DES, MD5, RSA, RC4, and AES wrappers",
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
            "source_classes": ["TEncryption"],
            "target_class_clusters": ["cHovga0n1u"],
            "resolution": "algorithm-specific pseudocode, class-local helper order, and exact normalized function features",
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "Every row matches the complete normalized function feature set. The algorithm identities are resolved by the DES, MD5, RSA, RC4, and AES wrapper behavior rather than by shape alone.",
            "The v18_ aliases are scoped to the exact hashed Spectron library in the inputs and are an IDA analysis overlay only.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
