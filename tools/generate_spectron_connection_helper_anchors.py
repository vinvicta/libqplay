#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for connection and SSL helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x1fc200",
        "original_name": "TGraalConnection_clearEncryptionKeyIn_void",
        "spectron_ea": "0x201b34",
        "target_name": "_ZN10psSDxavq9U10u6jtYa4whuEv",
        "source_basis": "incoming encryption key cleanup",
        "evidence": [
            "Both bodies inspect the incoming key and algorithm byte, delete RC4 or AES state, then clear the key pointer and algorithm byte.",
            "The source and target have the same 76-byte, 24-instruction, four-branch body shape.",
        ],
    },
    {
        "original_ea": "0x1fc24c",
        "original_name": "TGraalConnection_clearEncryptionKeyOut_void",
        "spectron_ea": "0x201b80",
        "target_name": "_ZN10psSDxavq9U10NDntYaevkuEv",
        "source_basis": "outgoing encryption key cleanup",
        "evidence": [
            "Both bodies inspect the outgoing key and algorithm byte, delete RC4 or AES state, then clear the key pointer and algorithm byte.",
            "The target preserves the same 76-byte body immediately after the incoming-key cleanup helper.",
        ],
    },
    {
        "original_ea": "0x1fc298",
        "original_name": "TGraalConnection_clearOutList_void",
        "spectron_ea": "0x201bcc",
        "target_name": "_ZN10psSDxavq9U10rBztYaczuuEv",
        "source_basis": "outgoing string-list cleanup",
        "evidence": [
            "Both bodies walk the outgoing list, clear and delete each stored TString, then clear the list container.",
            "The source and target retain the same 124-byte, 30-instruction, six-block loop shape.",
        ],
    },
    {
        "original_ea": "0x1fc3cc",
        "original_name": "TGraalConnection_TGraalConnection__2",
        "spectron_ea": "0x201d00",
        "target_name": "_ZN10psSDxavq9UD0Ev",
        "source_basis": "deleting destructor wrapper",
        "evidence": [
            "Both wrappers call the connection destructor and then operator delete on the object.",
            "The source and target retain the same five-instruction, 32-byte wrapper shape and position after the connection cleanup helpers.",
        ],
    },
    {
        "original_ea": "0x1fcd50",
        "original_name": "TGraalConnection_setEncryptionParseKey_TString_const",
        "spectron_ea": "0x202684",
        "target_name": "_ZN10psSDxavq9U10YfGuSa79psERK10C8THgaTQxF",
        "source_basis": "incoming encryption parse-key setter",
        "evidence": [
            "Both bodies assign the supplied TString into connection field offset 168.",
            "The source and target retain the same eight-byte, four-instruction setter shape immediately before packet-id checking.",
        ],
    },
    {
        "original_ea": "0x1fce4c",
        "original_name": "TGraalConnection_printSocketError_void",
        "spectron_ea": "0x202780",
        "target_name": "_ZN10psSDxavq9U10gUchYaVs5jEv",
        "source_basis": "socket-error state flag setter",
        "evidence": [
            "Both bodies set the connection byte at offset 272 and return the connection pointer.",
            "The source and target retain the same 12-byte, five-instruction setter shape after packet-id checking.",
        ],
    },
    {
        "original_ea": "0x1fea58",
        "original_name": "TGraalConnection_isblocked_void",
        "spectron_ea": "0x2043ac",
        "target_name": "_ZN10psSDxavq9U10VrWDYaaNcDEv",
        "source_basis": "outgoing queue saturation check",
        "evidence": [
            "Both bodies read the outgoing list count, shift it by ten, and compare it with 65000.",
            "The source and target retain the same 24-byte, four-instruction predicate immediately before SSL setters.",
        ],
    },
    {
        "original_ea": "0x1fea70",
        "original_name": "TGraalConnection_setEnableSSL_bool",
        "spectron_ea": "0x2043c4",
        "target_name": "_ZN10psSDxavq9U10Sf9Aga1oSzEb",
        "source_basis": "SSL enable flag propagation",
        "evidence": [
            "Both bodies update the connection SSL byte only when it changes, then propagate the bool to the live socket object when present.",
            "The source and target retain the same 40-byte, 13-instruction, three-branch body shape.",
        ],
    },
    {
        "original_ea": "0x1fea98",
        "original_name": "TGraalConnection_setSSLCipherList_TString_const",
        "spectron_ea": "0x2043ec",
        "target_name": "_ZN10psSDxavq9U10ze1AgaTELzERK10C8THgaTQxF",
        "source_basis": "SSL cipher-list propagation",
        "evidence": [
            "Both bodies assign the cipher-list TString at connection offset 128 and copy it to the live socket object's matching field.",
            "The source and target retain the same 80-byte, 12-instruction, two-branch body shape.",
        ],
    },
    {
        "original_ea": "0x1feae8",
        "original_name": "TGraalConnection_setSSLProtocol_TString_const",
        "spectron_ea": "0x20443c",
        "target_name": "_ZN10psSDxavq9U10S12AgafaNzERK10C8THgaTQxF",
        "source_basis": "SSL protocol propagation",
        "evidence": [
            "Both bodies assign the protocol TString at connection offset 136 and copy it to the live socket object's matching field.",
            "The target is the adjacent 80-byte setter after the cipher-list helper, preserving the source order and shape.",
        ],
    },
    {
        "original_ea": "0x1feb80",
        "original_name": "TGraalConnection_getSSLError_void",
        "spectron_ea": "0x2044d4",
        "target_name": "_ZNK10psSDxavq9U10S86dLaeDulEv",
        "source_basis": "socket SSL error getter",
        "evidence": [
            "Both bodies return the live socket SSL error field when a socket exists and -1 otherwise.",
            "The source and target retain the same 24-byte, ten-instruction, two-branch getter shape before connectToServer.",
        ],
    },
    {
        "original_ea": "0x1fec48",
        "original_name": "TGraalConnection_getByte228",
        "spectron_ea": "0x204598",
        "target_name": "sub_204598",
        "source_basis": "connection byte field getter at offset 228",
        "evidence": [
            "Both bodies read the unsigned byte at connection offset 228.",
            "The target is the first compact field accessor after connectToServer, matching the source order.",
        ],
    },
    {
        "original_ea": "0x1fec50",
        "original_name": "TGraalConnection_setByte228",
        "spectron_ea": "0x2045a0",
        "target_name": "sub_2045A0",
        "source_basis": "connection byte field setter at offset 228",
        "evidence": [
            "Both bodies write the supplied byte to connection offset 228 and return the connection pointer.",
            "The target follows the matching byte getter with the same compact accessor order.",
        ],
    },
    {
        "original_ea": "0x1fec58",
        "original_name": "TGraalConnection_getDword304",
        "spectron_ea": "0x2045a8",
        "target_name": "sub_2045A8",
        "source_basis": "connection dword field getter at offset 304",
        "evidence": [
            "Both bodies read the unsigned dword at connection offset 304.",
            "The target follows the byte setter in the same compact accessor run.",
        ],
    },
    {
        "original_ea": "0x1fec60",
        "original_name": "TGraalConnection_getByte240",
        "spectron_ea": "0x2045b0",
        "target_name": "sub_2045B0",
        "source_basis": "connection byte field getter at offset 240",
        "evidence": [
            "Both bodies read the unsigned byte at connection offset 240.",
            "The target preserves the source compact accessor order.",
        ],
    },
    {
        "original_ea": "0x1fec68",
        "original_name": "TGraalConnection_getDouble312",
        "spectron_ea": "0x2045b8",
        "target_name": "sub_2045B8",
        "source_basis": "connection double field getter at offset 312",
        "evidence": [
            "Both bodies read the double at connection offset 312.",
            "The target preserves the field-accessor run and its floating-point return type.",
        ],
    },
    {
        "original_ea": "0x1fec70",
        "original_name": "TGraalConnection_getDword176",
        "spectron_ea": "0x2045c0",
        "target_name": "sub_2045C0",
        "source_basis": "connection dword field getter at offset 176",
        "evidence": [
            "Both bodies read the unsigned dword at connection offset 176.",
            "The target preserves the compact accessor order after the double getter.",
        ],
    },
    {
        "original_ea": "0x1fec78",
        "original_name": "TGraalConnection_getDword244",
        "spectron_ea": "0x2045c8",
        "target_name": "sub_2045C8",
        "source_basis": "connection dword field getter at offset 244",
        "evidence": [
            "Both bodies read the unsigned dword at connection offset 244.",
            "The target is the final compact accessor in the corresponding source run.",
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
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: expected %s, got %s"
                % (spec["spectron_ea"], spec["target_name"], target.get("name"))
            )
        if source["size"] != target["size"]:
            raise ValueError(
                "size mismatch at %s to %s: %s versus %s"
                % (spec["original_ea"], spec["spectron_ea"], source["size"], target["size"])
            )
        if source["instruction_count"] != target["instruction_count"]:
            raise ValueError(
                "instruction count mismatch at %s to %s: %s versus %s"
                % (
                    spec["original_ea"],
                    spec["spectron_ea"],
                    source["instruction_count"],
                    target["instruction_count"],
                )
            )
        if source["basic_block_count"] != target["basic_block_count"]:
            raise ValueError(
                "basic block mismatch at %s to %s: %s versus %s"
                % (
                    spec["original_ea"],
                    spec["spectron_ea"],
                    source["basic_block_count"],
                    target["basic_block_count"],
                )
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
                "match_kind": "manual-connection-ssl-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in connection helper anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_connection_helper_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for connection cleanup, packet state, SSL configuration, and low-level fields",
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
            "already_in_semantic_map": sum(
                row["semantic_match_already_present"] for row in anchors
            ),
            "new_context_anchor_count": sum(
                not row["semantic_match_already_present"] for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The connection and SSL helpers preserve byte size, instruction count, basic block count, and direct field behavior across the two builds.",
            "These local helpers do not prove that a current remote certificate or service endpoint is compatible.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
