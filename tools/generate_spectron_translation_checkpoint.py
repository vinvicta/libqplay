#!/usr/bin/env python3
"""Record hashes and counts for a persisted Spectron translation checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--verification", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manual-anchors", type=Path)
    parser.add_argument("--manual-verification", type=Path)
    parser.add_argument("--network-anchors", type=Path)
    parser.add_argument("--network-verification", type=Path)
    parser.add_argument("--core-anchors", type=Path)
    parser.add_argument("--core-verification", type=Path)
    parser.add_argument("--runtime-path-anchors", type=Path)
    parser.add_argument("--runtime-path-verification", type=Path)
    parser.add_argument("--update-protocol-anchors", type=Path)
    parser.add_argument("--update-protocol-verification", type=Path)
    parser.add_argument("--client-action-anchors", type=Path)
    parser.add_argument("--client-action-verification", type=Path)
    parser.add_argument("--client-outbound-anchors", type=Path)
    parser.add_argument("--client-outbound-verification", type=Path)
    parser.add_argument("--resource-anchors", type=Path)
    parser.add_argument("--resource-verification", type=Path)
    parser.add_argument("--script-bridge-anchors", type=Path)
    parser.add_argument("--script-bridge-verification", type=Path)
    parser.add_argument("--client-request-anchors", type=Path)
    parser.add_argument("--client-request-verification", type=Path)
    args = parser.parse_args()

    translation = load(args.map)
    verification = load(args.verification)
    if translation.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected translation map artifact")
    if not verification.get("verified"):
        raise ValueError("IDA reopen verification did not pass")
    expected = translation["summary"]["mapped_high_confidence"]
    if verification["high_confidence_match_count"] != expected:
        raise ValueError("verification match count differs from translation map")
    manual = None
    if args.manual_anchors or args.manual_verification:
        if not args.manual_anchors or not args.manual_verification:
            raise ValueError("manual anchors and manual verification must be supplied together")
        manual_document = load(args.manual_anchors)
        manual_verification = load(args.manual_verification)
        if manual_document.get("artifact") != "spectron_manual_translation_anchors_20260826":
            raise ValueError("unexpected manual-anchor artifact")
        if not manual_verification.get("verified"):
            raise ValueError("manual-anchor reopen verification did not pass")
        expected_manual = len(manual_document["anchors"])
        if manual_verification["verified_name_count"] != expected_manual:
            raise ValueError("manual-anchor verification count differs from artifact")
        manual = {
            "anchor_path": str(args.manual_anchors),
            "anchor_sha256": sha256_path(args.manual_anchors),
            "reopen_verification": str(args.manual_verification),
            "anchor_count": expected_manual,
            "verified_name_count": manual_verification["verified_name_count"],
            "reopen_failure_count": manual_verification["failure_count"],
        }
    network = None
    if args.network_anchors or args.network_verification:
        if not args.network_anchors or not args.network_verification:
            raise ValueError("network anchors and network verification must be supplied together")
        network_document = load(args.network_anchors)
        network_verification = load(args.network_verification)
        if network_document.get("artifact") != "spectron_network_manual_translation_anchors_20260826":
            raise ValueError("unexpected network-anchor artifact")
        if not network_verification.get("verified"):
            raise ValueError("network-anchor reopen verification did not pass")
        expected_network = len(network_document["anchors"])
        if network_verification["verified_name_count"] != expected_network:
            raise ValueError("network-anchor verification count differs from artifact")
        network = {
            "anchor_path": str(args.network_anchors),
            "anchor_sha256": sha256_path(args.network_anchors),
            "reopen_verification": str(args.network_verification),
            "anchor_count": expected_network,
            "verified_name_count": network_verification["verified_name_count"],
            "reopen_failure_count": network_verification["failure_count"],
        }
    core = None
    if args.core_anchors or args.core_verification:
        if not args.core_anchors or not args.core_verification:
            raise ValueError("core anchors and core verification must be supplied together")
        core_document = load(args.core_anchors)
        core_verification = load(args.core_verification)
        if core_document.get("artifact") != "spectron_core_manual_translation_anchors_20260826":
            raise ValueError("unexpected core-anchor artifact")
        if not core_verification.get("verified"):
            raise ValueError("core-anchor reopen verification did not pass")
        expected_core = len(core_document["anchors"])
        if core_verification["verified_name_count"] != expected_core:
            raise ValueError("core-anchor verification count differs from artifact")
        core = {
            "anchor_path": str(args.core_anchors),
            "anchor_sha256": sha256_path(args.core_anchors),
            "reopen_verification": str(args.core_verification),
            "anchor_count": expected_core,
            "verified_name_count": core_verification["verified_name_count"],
            "reopen_failure_count": core_verification["failure_count"],
        }
    result = {
        "schema_version": 1,
        "artifact": "spectron_translation_checkpoint_20260826",
        "scope": "persisted high-confidence 1.8-to-Spectron ARM64 semantic labels",
        "network_contacted": False,
        "inputs": {
            "original_binary_sha256": translation["inputs"].get("original_binary_sha256"),
            "spectron_binary_sha256": translation["inputs"].get("spectron_binary_sha256"),
            "translation_map": str(args.map),
            "translation_map_sha256": sha256_path(args.map),
            "reopen_verification": str(args.verification),
        },
        "database": {
            "path": str(args.database),
            "sha256": sha256_path(args.database),
            "format": "packed IDA 9.3 database",
            "close_reopen_verified": True,
            "function_count": verification["function_count"],
            "default_sub_function_count": verification["default_sub_function_count"],
        },
        "translation": {
            "mapped_functions": translation["summary"]["mapped_functions"],
            "high_confidence_applied": translation["summary"]["mapped_high_confidence"],
            "medium_confidence_review_only": translation["summary"]["mapped_medium_confidence"],
            "ambiguous_functions": translation["summary"]["ambiguous_functions"],
            "unmatched_functions": translation["summary"]["unmatched_functions"],
            "unique_spectron_targets": translation["summary"]["unique_spectron_targets"],
            "reopen_failure_count": verification["failure_count"],
        },
        "interpretation": [
            "The saved database contains v18_ analysis labels on the verified high-confidence target functions.",
            "The labels preserve the original 1.8 semantic names while keeping the Spectron address and obfuscated name in the map.",
            "The medium-confidence, ambiguous, and unmatched functions remain review-only and were not silently renamed.",
        ],
    }
    if manual is not None:
        result["manual_anchors"] = manual
        result["interpretation"].append(
            "The second database revision also contains the separately reviewed manual context anchors."
        )
    if network is not None:
        result["network_anchors"] = network
        result["interpretation"].append(
            "The third database revision also contains the separately reviewed connector and socket context anchors."
        )
    if core is not None:
        result["core_anchors"] = core
        result["interpretation"].append(
            "The fourth database revision also contains the separately reviewed resource, rendering, GUI, scripting, and client context anchors."
        )
    runtime_path = None
    if args.runtime_path_anchors or args.runtime_path_verification:
        if not args.runtime_path_anchors or not args.runtime_path_verification:
            raise ValueError(
                "runtime-path anchors and runtime-path verification must be supplied together"
            )
        runtime_path_document = load(args.runtime_path_anchors)
        runtime_path_verification = load(args.runtime_path_verification)
        if runtime_path_document.get("artifact") != "spectron_runtime_path_manual_translation_anchors_20260826":
            raise ValueError("unexpected runtime-path anchor artifact")
        if not runtime_path_verification.get("verified"):
            raise ValueError("runtime-path anchor reopen verification did not pass")
        expected_runtime_path = len(runtime_path_document["anchors"])
        if runtime_path_verification["verified_name_count"] != expected_runtime_path:
            raise ValueError("runtime-path verification count differs from artifact")
        runtime_path = {
            "anchor_path": str(args.runtime_path_anchors),
            "anchor_sha256": sha256_path(args.runtime_path_anchors),
            "reopen_verification": str(args.runtime_path_verification),
            "anchor_count": expected_runtime_path,
            "verified_name_count": runtime_path_verification["verified_name_count"],
            "reopen_failure_count": runtime_path_verification["failure_count"],
        }
    if runtime_path is not None:
        result["runtime_path_anchors"] = runtime_path
        result["interpretation"].append(
            "The fifth database revision also contains the separately reviewed map-entry, file-delivery, script, text-control, and server-list context anchors."
        )
    update_protocol = None
    if args.update_protocol_anchors or args.update_protocol_verification:
        if not args.update_protocol_anchors or not args.update_protocol_verification:
            raise ValueError(
                "update-protocol anchors and update-protocol verification must be supplied together"
            )
        update_protocol_document = load(args.update_protocol_anchors)
        update_protocol_verification = load(args.update_protocol_verification)
        if update_protocol_document.get("artifact") != "spectron_update_protocol_manual_translation_anchors_20260826":
            raise ValueError("unexpected update-protocol anchor artifact")
        if not update_protocol_verification.get("verified"):
            raise ValueError("update-protocol anchor reopen verification did not pass")
        expected_update_protocol = len(update_protocol_document["anchors"])
        if update_protocol_verification["verified_name_count"] != expected_update_protocol:
            raise ValueError("update-protocol verification count differs from artifact")
        update_protocol = {
            "anchor_path": str(args.update_protocol_anchors),
            "anchor_sha256": sha256_path(args.update_protocol_anchors),
            "reopen_verification": str(args.update_protocol_verification),
            "anchor_count": expected_update_protocol,
            "verified_name_count": update_protocol_verification["verified_name_count"],
            "reopen_failure_count": update_protocol_verification["failure_count"],
        }
    if update_protocol is not None:
        result["update_protocol_anchors"] = update_protocol
        result["interpretation"].append(
            "The sixth database revision also contains the separately reviewed download-queue, update-request, server-modify, and image-checksum context anchors."
        )
    client_action = None
    if args.client_action_anchors or args.client_action_verification:
        if not args.client_action_anchors or not args.client_action_verification:
            raise ValueError(
                "client-action anchors and client-action verification must be supplied together"
            )
        client_action_document = load(args.client_action_anchors)
        client_action_verification = load(args.client_action_verification)
        if client_action_document.get("artifact") != "spectron_client_action_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-action anchor artifact")
        if not client_action_verification.get("verified"):
            raise ValueError("client-action anchor reopen verification did not pass")
        expected_client_action = len(client_action_document["anchors"])
        if client_action_verification["verified_name_count"] != expected_client_action:
            raise ValueError("client-action verification count differs from artifact")
        client_action = {
            "anchor_path": str(args.client_action_anchors),
            "anchor_sha256": sha256_path(args.client_action_anchors),
            "reopen_verification": str(args.client_action_verification),
            "anchor_count": expected_client_action,
            "verified_name_count": client_action_verification["verified_name_count"],
            "reopen_failure_count": client_action_verification["failure_count"],
        }
    if client_action is not None:
        result["client_action_anchors"] = client_action
        result["interpretation"].append(
            "The seventh database revision also contains the separately reviewed client action packet serializer anchors."
        )
    client_outbound = None
    if args.client_outbound_anchors or args.client_outbound_verification:
        if not args.client_outbound_anchors or not args.client_outbound_verification:
            raise ValueError(
                "client-outbound anchors and client-outbound verification must be supplied together"
            )
        client_outbound_document = load(args.client_outbound_anchors)
        client_outbound_verification = load(args.client_outbound_verification)
        if client_outbound_document.get("artifact") != "spectron_client_outbound_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-outbound anchor artifact")
        if not client_outbound_verification.get("verified"):
            raise ValueError("client-outbound anchor reopen verification did not pass")
        expected_client_outbound = len(client_outbound_document["anchors"])
        if client_outbound_verification["verified_name_count"] != expected_client_outbound:
            raise ValueError("client-outbound verification count differs from artifact")
        client_outbound = {
            "anchor_path": str(args.client_outbound_anchors),
            "anchor_sha256": sha256_path(args.client_outbound_anchors),
            "reopen_verification": str(args.client_outbound_verification),
            "anchor_count": expected_client_outbound,
            "verified_name_count": client_outbound_verification["verified_name_count"],
            "reopen_failure_count": client_outbound_verification["failure_count"],
        }
    if client_outbound is not None:
        result["client_outbound_anchors"] = client_outbound
        result["interpretation"].append(
            "The eighth database revision also contains the separately reviewed remaining client outbound packet serializer anchors."
        )
    resource = None
    if args.resource_anchors or args.resource_verification:
        if not args.resource_anchors or not args.resource_verification:
            raise ValueError(
                "resource anchors and resource verification must be supplied together"
            )
        resource_document = load(args.resource_anchors)
        resource_verification = load(args.resource_verification)
        if resource_document.get("artifact") != "spectron_resource_manual_translation_anchors_20260826":
            raise ValueError("unexpected resource anchor artifact")
        if not resource_verification.get("verified"):
            raise ValueError("resource anchor reopen verification did not pass")
        expected_resource = len(resource_document["anchors"])
        if resource_verification["verified_name_count"] != expected_resource:
            raise ValueError("resource verification count differs from artifact")
        resource = {
            "anchor_path": str(args.resource_anchors),
            "anchor_sha256": sha256_path(args.resource_anchors),
            "reopen_verification": str(args.resource_verification),
            "anchor_count": expected_resource,
            "verified_name_count": resource_verification["verified_name_count"],
            "reopen_failure_count": resource_verification["failure_count"],
        }
    if resource is not None:
        result["resource_anchors"] = resource
        result["interpretation"].append(
            "The ninth database revision also contains the separately reviewed resource matching, stream, and game-file resolution anchors."
        )
    script_bridge = None
    if args.script_bridge_anchors or args.script_bridge_verification:
        if not args.script_bridge_anchors or not args.script_bridge_verification:
            raise ValueError(
                "script-bridge anchors and script-bridge verification must be supplied together"
            )
        script_bridge_document = load(args.script_bridge_anchors)
        script_bridge_verification = load(args.script_bridge_verification)
        if script_bridge_document.get("artifact") != "spectron_script_bridge_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-bridge anchor artifact")
        if not script_bridge_verification.get("verified"):
            raise ValueError("script-bridge anchor reopen verification did not pass")
        expected_script_bridge = len(script_bridge_document["anchors"])
        if script_bridge_verification["verified_name_count"] != expected_script_bridge:
            raise ValueError("script-bridge verification count differs from artifact")
        script_bridge = {
            "anchor_path": str(args.script_bridge_anchors),
            "anchor_sha256": sha256_path(args.script_bridge_anchors),
            "reopen_verification": str(args.script_bridge_verification),
            "anchor_count": expected_script_bridge,
            "verified_name_count": script_bridge_verification["verified_name_count"],
            "reopen_failure_count": script_bridge_verification["failure_count"],
        }
    if script_bridge is not None:
        result["script_bridge_anchors"] = script_bridge
        result["interpretation"].append(
            "The tenth database revision also contains the separately reviewed client script bridge anchors."
        )
    client_request = None
    if args.client_request_anchors or args.client_request_verification:
        if not args.client_request_anchors or not args.client_request_verification:
            raise ValueError(
                "client-request anchors and client-request verification must be supplied together"
            )
        client_request_document = load(args.client_request_anchors)
        client_request_verification = load(args.client_request_verification)
        if client_request_document.get("artifact") != "spectron_client_request_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-request anchor artifact")
        if not client_request_verification.get("verified"):
            raise ValueError("client-request anchor reopen verification did not pass")
        expected_client_request = len(client_request_document["anchors"])
        if client_request_verification["verified_name_count"] != expected_client_request:
            raise ValueError("client-request verification count differs from artifact")
        client_request = {
            "anchor_path": str(args.client_request_anchors),
            "anchor_sha256": sha256_path(args.client_request_anchors),
            "reopen_verification": str(args.client_request_verification),
            "anchor_count": expected_client_request,
            "verified_name_count": client_request_verification["verified_name_count"],
            "reopen_failure_count": client_request_verification["failure_count"],
        }
    if client_request is not None:
        result["client_request_anchors"] = client_request
        result["interpretation"].append(
            "The eleventh database revision also contains the separately reviewed client request and window-state serializer anchors."
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **result["translation"], "database_sha256": result["database"]["sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
