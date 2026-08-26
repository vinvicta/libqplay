#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for the connector and socket path.

The target addresses in this file are not guessed from an address delta.  Each
one was reviewed against the clean Spectron IDA pseudocode and the corresponding
1.8 function.  This generator verifies the feature-export metadata, records
both build-specific ranges, and emits an analysis artifact without touching an
IDA database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0x203df4",
        "original_name": "TServerList_enterNextConnectorMode_int",
        "spectron_ea": "0x2094c0",
        "source_basis": "connector-mode parameter construction and caller context",
        "evidence": [
            "The candidate builds the same three connector mode strings through the same decode helpers.",
            "It preserves the retry counter, mode counter, premium option, platform, version, build, and ?p= parameter construction.",
            "The candidate's 2.2 date and version literals are the expected release changes, while the surrounding control flow remains the same role.",
        ],
    },
    {
        "original_ea": "0x200010",
        "original_name": "THTTPRequest_saveDownloadedData_void",
        "spectron_ea": "0x205958",
        "source_basis": "HTTP response status branches and download completion behavior",
        "evidence": [
            "The candidate handles the same 404, 304, and 4xx response families and the same requested-file bookkeeping.",
            "It owns the shared File download, webfiles, and not found strings and retains the same 104 basic-block boundary.",
            "The expanded 2.2 body contains the same cache, event, update-package, and resource-validation sequence with a changed build size.",
        ],
    },
    {
        "original_ea": "0x206450",
        "original_name": "TSocketConnection_enableSSLOnSocket_void",
        "spectron_ea": "0x20c59c",
        "source_basis": "CyaSSL context creation and socket verification policy",
        "evidence": [
            "The candidate selects SSLv3, SSLv23, TLSv1, TLSv1_1, or TLSv1_2 from the same protocol string.",
            "It creates and configures the CyaSSL context, installs the plain I/O callbacks, loads the verification buffer, applies the cipher list and verify policy, checks the domain, and starts the nonblocking handshake.",
            "The candidate owns the same SSL setup and error strings; the small block-count and size changes are consistent with the 2.2 rebuild.",
        ],
    },
    {
        "original_ea": "0x206bd8",
        "original_name": "TSocketConnection_connectSocket_TString_const_int",
        "spectron_ea": "0x20ccd8",
        "source_basis": "socket creation, hostname resolution, nonblocking connect, and status transitions",
        "evidence": [
            "The candidate closes and resets the old socket, creates an IPv4 stream socket, resolves the configured host, fills the sockaddr, and issues the nonblocking connect call.",
            "It preserves the same connect, gethostbyname, and socket failure strings and the same status values for in-progress, connected, and failed states.",
            "The candidate is the only reviewed socket routine that owns the complete TSocketConnection::connectSocket diagnostic string set.",
        ],
    },
    {
        "original_ea": "0x1fe940",
        "original_name": "TGraalConnection_read_void",
        "spectron_ea": "0x204274",
        "source_basis": "socket read, byte accounting, decrypt branch, and protocol parser dispatch",
        "evidence": [
            "The candidate reads through the obfuscated 2.2 socket-connection member, appends the bytes to the same stream buffer, and updates the byte counter.",
            "It preserves the decrypt-when-enabled branch and dispatches to the old or NewGraal protocol parser based on the same mode field.",
            "The candidate's neighboring parser and socket classes match the reviewed 2.2 translations, making this a context anchor rather than a size-only match.",
        ],
    },
    {
        "original_ea": "0x2074d4",
        "original_name": "TSocketConnection_read_void",
        "spectron_ea": "0x20d614",
        "source_basis": "plain recv, UDP recvfrom, CyaSSL_read, and socket error handling",
        "evidence": [
            "The candidate contains the same plain and UDP receive branches followed by the same CyaSSL_read loop.",
            "It owns the same SSL read, recv, and socket-closed diagnostic strings and preserves the same nonblocking error filtering.",
            "Both builds retain the same 34 basic-block structure; the 2.2 function is only modestly larger.",
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
    result = {}
    for function in functions:
        result[int(function["ea"], 16)] = function
    return result


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
        if target.get("is_default_name"):
            raise ValueError("Spectron target unexpectedly has a default name")
        proposed_name = "v18_" + spec["original_name"]
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_size": source["size"],
                "original_instruction_count": source["instruction_count"],
                "original_basic_block_count": source["basic_block_count"],
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_size": target["size"],
                "spectron_instruction_count": target["instruction_count"],
                "spectron_basic_block_count": target["basic_block_count"],
                "proposed_name": proposed_name,
                "confidence": "high",
                "match_kind": "manual-network-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in manual anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_network_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for connector, HTTP, TLS, and socket routines",
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
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated 2.2 name in the evidence row.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
