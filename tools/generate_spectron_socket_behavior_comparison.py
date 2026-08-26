#!/usr/bin/env python3
"""Record the reviewed behavior comparison for changed socket functions."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PAIR_SPECS = [
    {
        "original_ea": "0x206450",
        "original_name": "TSocketConnection_enableSSLOnSocket_void",
        "spectron_ea": "0x20c59c",
        "spectron_name": "_ZN10u3cBgayBVz10WzkZ1a0VchEv",
        "role": "CyaSSL context creation, verify-buffer loading, and TLS handshake start",
        "shared_behavior": [
            "Both bodies require a valid descriptor and status five before starting the TLS path.",
            "Both bodies select a cached CyaSSL context by the same per-socket mode byte and initialize the library when that context is absent.",
            "Both bodies support SSLv3, SSLv23, TLSv1, TLSv1_1, and TLSv1_2 method selection with the same SSLv23 fallback.",
            "Both bodies load the per-socket verify buffer, choose the same verification-mode arguments, apply the configured cipher list, optionally check the configured domain, enable nonblocking TLS, and call CyaSSL_connect.",
        ],
        "differences": [
            "The 2.2 body is shorter and has one fewer basic block, with renamed CyaSSL, string, logging, and socket symbols.",
            "The 2.2 error paths use the obfuscated logging helper and preserve the same context or socket cleanup decisions.",
        ],
        "conclusion": "The changed body does not show a new certificate-pinning policy. Its static verification and handshake sequence remains the same as 1.8.",
    },
    {
        "original_ea": "0x206bd8",
        "original_name": "TSocketConnection_connectSocket_TString_const_int",
        "spectron_ea": "0x20ccd8",
        "spectron_name": "_ZN10u3cBgayBVz10n9sqgau8SqERK10C8THgaTQxFi",
        "role": "nonblocking TCP socket creation, hostname resolution, and status transition",
        "shared_behavior": [
            "Both bodies close an earlier socket, reset status, copy the hostname, and store the requested port.",
            "Both bodies create an IPv4 TCP socket, set it nonblocking, accept a numeric address or resolve a hostname, and store the numeric IP field.",
            "Both bodies use status four for in-progress connection, status five for completion, retry EINTR, and report connection failure with status two.",
            "Both bodies run the subprocess-close and Nagle-delay hooks, then enter the SSL-on-socket helper when SSL is enabled and the TCP status is five.",
        ],
        "differences": [
            "The 2.2 body is larger and has one fewer basic block than 1.8.",
            "The 2.2 failure paths add explicit diagnostic messages naming the connectSocket operation.",
        ],
        "conclusion": "The changed connect body preserves the nonblocking and delayed-TLS state machine. No static branch shows a new pinning decision before SSL setup.",
    },
    {
        "original_ea": "0x2074d4",
        "original_name": "TSocketConnection_read_void",
        "spectron_ea": "0x20d614",
        "spectron_name": "_ZN10u3cBgayBVz4readEv",
        "role": "plain, UDP, and CyaSSL receive handling",
        "shared_behavior": [
            "Both bodies first process a pending nonblocking connection and skip reads for the same closed or connecting states.",
            "Both bodies use recv for stream data, recvfrom for UDP data, and CyaSSL_read when the TLS object is present.",
            "Both bodies treat the same transient receive errors as nonfatal, close on a zero-length receive, record a CyaSSL error, and close on non-ignored TLS errors.",
            "Both bodies return the accumulated data through the script TString result and update the received-byte counter.",
        ],
        "differences": [
            "The 2.2 body is slightly larger with the same basic-block count.",
            "The 2.2 body adds a bytesread==0 diagnostic before closing a zero-length stream receive and uses obfuscated helper names.",
        ],
        "conclusion": "The changed read body preserves the receive and TLS error policy visible in 1.8. Its added diagnostic does not itself explain a connection failure.",
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


def shape(function: dict) -> dict:
    return {
        "size": function["size"],
        "instruction_count": function["instruction_count"],
        "basic_block_count": function["basic_block_count"],
        "mnemonic_hash": function["mnemonic_hash"],
        "register_shape_hash": function["register_shape_hash"],
        "shape_hash": function["shape_hash"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    pairs = []
    for spec in PAIR_SPECS:
        source = original.get(int(spec["original_ea"], 16))
        target = spectron.get(int(spec["spectron_ea"], 16))
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError("unexpected original name at %s" % spec["original_ea"])
        if target.get("name") != spec["spectron_name"]:
            raise ValueError("unexpected Spectron name at %s" % spec["spectron_ea"])
        source_shape = shape(source)
        target_shape = shape(target)
        pairs.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "spectron_ea": spec["spectron_ea"],
                "spectron_name": spec["spectron_name"],
                "role": spec["role"],
                "original_shape": source_shape,
                "spectron_shape": target_shape,
                "exact_shape_match": source_shape == target_shape,
                "shared_behavior": spec["shared_behavior"],
                "differences": spec["differences"],
                "conclusion": spec["conclusion"],
            }
        )

    if any(pair["exact_shape_match"] for pair in pairs):
        raise ValueError("changed socket comparison unexpectedly contains an exact shape match")

    result = {
        "schema_version": 1,
        "artifact": "spectron_socket_behavior_comparison_20260826",
        "scope": "static 1.8-to-Spectron ARM64 behavior comparison for changed socket and TLS paths",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "summary": {
            "pair_count": len(pairs),
            "size_changed_count": sum(
                pair["original_shape"]["size"] != pair["spectron_shape"]["size"]
                for pair in pairs
            ),
            "instruction_count_changed": sum(
                pair["original_shape"]["instruction_count"]
                != pair["spectron_shape"]["instruction_count"]
                for pair in pairs
            ),
            "exact_shape_match_count": sum(pair["exact_shape_match"] for pair in pairs),
        },
        "pairs": pairs,
        "interpretation": [
            "The changed socket functions were compared as behaviors, not renamed as exact body matches.",
            "The 2.2 CyaSSL setup still shows the same verify-buffer, verification-mode, domain-check, nonblocking, and handshake sequence as 1.8.",
            "This is static evidence only. It does not prove that a current live service accepts the old certificate, protocol, or client query.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
