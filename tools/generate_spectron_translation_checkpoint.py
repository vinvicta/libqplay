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
    parser.add_argument("--client-inbound-anchors", type=Path)
    parser.add_argument("--client-inbound-verification", type=Path)
    parser.add_argument("--login-helper-anchors", type=Path)
    parser.add_argument("--login-helper-verification", type=Path)
    parser.add_argument("--parse-wrapper-anchors", type=Path)
    parser.add_argument("--parse-wrapper-verification", type=Path)
    parser.add_argument("--lookup-helper-anchors", type=Path)
    parser.add_argument("--lookup-helper-verification", type=Path)
    parser.add_argument("--connection-helper-anchors", type=Path)
    parser.add_argument("--connection-helper-verification", type=Path)
    parser.add_argument("--client-state-helper-anchors", type=Path)
    parser.add_argument("--client-state-helper-verification", type=Path)
    parser.add_argument("--connection-state-anchors", type=Path)
    parser.add_argument("--connection-state-verification", type=Path)
    parser.add_argument("--http-request-anchors", type=Path)
    parser.add_argument("--http-request-verification", type=Path)
    parser.add_argument("--socket-state-anchors", type=Path)
    parser.add_argument("--socket-state-verification", type=Path)
    parser.add_argument("--http-request-state-anchors", type=Path)
    parser.add_argument("--http-request-state-verification", type=Path)
    parser.add_argument("--npc-helper-anchors", type=Path)
    parser.add_argument("--npc-helper-verification", type=Path)
    parser.add_argument("--html-atom-anchors", type=Path)
    parser.add_argument("--html-atom-verification", type=Path)
    parser.add_argument("--player-helper-anchors", type=Path)
    parser.add_argument("--player-helper-verification", type=Path)
    parser.add_argument("--input-window-anchors", type=Path)
    parser.add_argument("--input-window-verification", type=Path)
    parser.add_argument("--visual-helper-anchors", type=Path)
    parser.add_argument("--visual-helper-verification", type=Path)
    parser.add_argument("--script-runtime-anchors", type=Path)
    parser.add_argument("--script-runtime-verification", type=Path)
    parser.add_argument("--core-helper-anchors", type=Path)
    parser.add_argument("--core-helper-verification", type=Path)
    parser.add_argument("--render-gui-anchors", type=Path)
    parser.add_argument("--render-gui-verification", type=Path)
    parser.add_argument("--json-folder-anchors", type=Path)
    parser.add_argument("--json-folder-verification", type=Path)
    parser.add_argument("--resource-object-anchors", type=Path)
    parser.add_argument("--resource-object-verification", type=Path)
    parser.add_argument("--script-machine-anchors", type=Path)
    parser.add_argument("--script-machine-verification", type=Path)
    parser.add_argument("--script-space-anchors", type=Path)
    parser.add_argument("--script-space-verification", type=Path)
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
    client_inbound = None
    if args.client_inbound_anchors or args.client_inbound_verification:
        if not args.client_inbound_anchors or not args.client_inbound_verification:
            raise ValueError(
                "client-inbound anchors and client-inbound verification must be supplied together"
            )
        client_inbound_document = load(args.client_inbound_anchors)
        client_inbound_verification = load(args.client_inbound_verification)
        if client_inbound_document.get("artifact") != "spectron_client_inbound_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-inbound anchor artifact")
        if not client_inbound_verification.get("verified"):
            raise ValueError("client-inbound anchor reopen verification did not pass")
        expected_client_inbound = len(client_inbound_document["anchors"])
        if client_inbound_verification["verified_name_count"] != expected_client_inbound:
            raise ValueError("client-inbound verification count differs from artifact")
        client_inbound = {
            "anchor_path": str(args.client_inbound_anchors),
            "anchor_sha256": sha256_path(args.client_inbound_anchors),
            "reopen_verification": str(args.client_inbound_verification),
            "anchor_count": expected_client_inbound,
            "verified_name_count": client_inbound_verification["verified_name_count"],
            "reopen_failure_count": client_inbound_verification["failure_count"],
        }
    if client_inbound is not None:
        result["client_inbound_anchors"] = client_inbound
        result["interpretation"].append(
            "The twelfth database revision also contains the separately reviewed client inbound and state-transition anchors."
        )
    login_helper = None
    if args.login_helper_anchors or args.login_helper_verification:
        if not args.login_helper_anchors or not args.login_helper_verification:
            raise ValueError(
                "login-helper anchors and login-helper verification must be supplied together"
            )
        login_helper_document = load(args.login_helper_anchors)
        login_helper_verification = load(args.login_helper_verification)
        if login_helper_document.get("artifact") != "spectron_login_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected login-helper anchor artifact")
        if not login_helper_verification.get("verified"):
            raise ValueError("login-helper anchor reopen verification did not pass")
        expected_login_helper = len(login_helper_document["anchors"])
        if login_helper_verification["verified_name_count"] != expected_login_helper:
            raise ValueError("login-helper verification count differs from artifact")
        login_helper = {
            "anchor_path": str(args.login_helper_anchors),
            "anchor_sha256": sha256_path(args.login_helper_anchors),
            "reopen_verification": str(args.login_helper_verification),
            "anchor_count": expected_login_helper,
            "verified_name_count": login_helper_verification["verified_name_count"],
            "reopen_failure_count": login_helper_verification["failure_count"],
        }
    if login_helper is not None:
        result["login_helper_anchors"] = login_helper
        result["interpretation"].append(
            "The thirteenth database revision also contains the separately reviewed login, event, and small client state helper anchors."
        )
    parse_wrapper = None
    if args.parse_wrapper_anchors or args.parse_wrapper_verification:
        if not args.parse_wrapper_anchors or not args.parse_wrapper_verification:
            raise ValueError(
                "parse-wrapper anchors and parse-wrapper verification must be supplied together"
            )
        parse_wrapper_document = load(args.parse_wrapper_anchors)
        parse_wrapper_verification = load(args.parse_wrapper_verification)
        if parse_wrapper_document.get("artifact") != "spectron_parse_wrapper_manual_translation_anchor_20260826":
            raise ValueError("unexpected parse-wrapper anchor artifact")
        if not parse_wrapper_verification.get("verified"):
            raise ValueError("parse-wrapper anchor reopen verification did not pass")
        expected_parse_wrapper = len(parse_wrapper_document["anchors"])
        if parse_wrapper_verification["verified_name_count"] != expected_parse_wrapper:
            raise ValueError("parse-wrapper verification count differs from artifact")
        parse_wrapper = {
            "anchor_path": str(args.parse_wrapper_anchors),
            "anchor_sha256": sha256_path(args.parse_wrapper_anchors),
            "reopen_verification": str(args.parse_wrapper_verification),
            "anchor_count": expected_parse_wrapper,
            "verified_name_count": parse_wrapper_verification["verified_name_count"],
            "reopen_failure_count": parse_wrapper_verification["failure_count"],
        }
    if parse_wrapper is not None:
        result["parse_wrapper_anchors"] = parse_wrapper
        result["interpretation"].append(
            "The fourteenth database revision also contains the separately reviewed client encryption-in tail-thunk anchor."
        )
    lookup_helper = None
    if args.lookup_helper_anchors or args.lookup_helper_verification:
        if not args.lookup_helper_anchors or not args.lookup_helper_verification:
            raise ValueError(
                "lookup-helper anchors and lookup-helper verification must be supplied together"
            )
        lookup_helper_document = load(args.lookup_helper_anchors)
        lookup_helper_verification = load(args.lookup_helper_verification)
        if lookup_helper_document.get("artifact") != "spectron_lookup_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected lookup-helper anchor artifact")
        if not lookup_helper_verification.get("verified"):
            raise ValueError("lookup-helper anchor reopen verification did not pass")
        expected_lookup_helper = len(lookup_helper_document["anchors"])
        if lookup_helper_verification["verified_name_count"] != expected_lookup_helper:
            raise ValueError("lookup-helper verification count differs from artifact")
        lookup_helper = {
            "anchor_path": str(args.lookup_helper_anchors),
            "anchor_sha256": sha256_path(args.lookup_helper_anchors),
            "reopen_verification": str(args.lookup_helper_verification),
            "anchor_count": expected_lookup_helper,
            "verified_name_count": lookup_helper_verification["verified_name_count"],
            "reopen_failure_count": lookup_helper_verification["failure_count"],
        }
    if lookup_helper is not None:
        result["lookup_helper_anchors"] = lookup_helper
        result["interpretation"].append(
            "The fifteenth database revision also contains the separately reviewed player and download lookup helper anchors."
        )
    connection_helper = None
    if args.connection_helper_anchors or args.connection_helper_verification:
        if not args.connection_helper_anchors or not args.connection_helper_verification:
            raise ValueError(
                "connection-helper anchors and connection-helper verification must be supplied together"
            )
        connection_helper_document = load(args.connection_helper_anchors)
        connection_helper_verification = load(args.connection_helper_verification)
        if connection_helper_document.get("artifact") != "spectron_connection_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected connection-helper anchor artifact")
        if not connection_helper_verification.get("verified"):
            raise ValueError("connection-helper anchor reopen verification did not pass")
        expected_connection_helper = len(connection_helper_document["anchors"])
        if connection_helper_verification["verified_name_count"] != expected_connection_helper:
            raise ValueError("connection-helper verification count differs from artifact")
        connection_helper = {
            "anchor_path": str(args.connection_helper_anchors),
            "anchor_sha256": sha256_path(args.connection_helper_anchors),
            "reopen_verification": str(args.connection_helper_verification),
            "anchor_count": expected_connection_helper,
            "verified_name_count": connection_helper_verification["verified_name_count"],
            "reopen_failure_count": connection_helper_verification["failure_count"],
        }
    if connection_helper is not None:
        result["connection_helper_anchors"] = connection_helper
        result["interpretation"].append(
            "The sixteenth database revision also contains the separately reviewed connection, packet-state, SSL, and low-level field anchors."
        )
    client_state_helper = None
    if args.client_state_helper_anchors or args.client_state_helper_verification:
        if not args.client_state_helper_anchors or not args.client_state_helper_verification:
            raise ValueError(
                "client-state-helper anchors and client-state-helper verification must be supplied together"
            )
        client_state_helper_document = load(args.client_state_helper_anchors)
        client_state_helper_verification = load(args.client_state_helper_verification)
        if client_state_helper_document.get("artifact") != "spectron_client_state_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-state-helper anchor artifact")
        if not client_state_helper_verification.get("verified"):
            raise ValueError("client-state-helper anchor reopen verification did not pass")
        expected_client_state_helper = len(client_state_helper_document["anchors"])
        if client_state_helper_verification["verified_name_count"] != expected_client_state_helper:
            raise ValueError("client-state-helper verification count differs from artifact")
        client_state_helper = {
            "anchor_path": str(args.client_state_helper_anchors),
            "anchor_sha256": sha256_path(args.client_state_helper_anchors),
            "reopen_verification": str(args.client_state_helper_verification),
            "anchor_count": expected_client_state_helper,
            "verified_name_count": client_state_helper_verification["verified_name_count"],
            "reopen_failure_count": client_state_helper_verification["failure_count"],
        }
    if client_state_helper is not None:
        result["client_state_helper_anchors"] = client_state_helper
        result["interpretation"].append(
            "The seventeenth database revision also contains the separately reviewed compact client state and forwarding anchors."
        )
    connection_state = None
    if args.connection_state_anchors or args.connection_state_verification:
        if not args.connection_state_anchors or not args.connection_state_verification:
            raise ValueError(
                "connection-state anchors and connection-state verification must be supplied together"
            )
        connection_state_document = load(args.connection_state_anchors)
        connection_state_verification = load(args.connection_state_verification)
        if connection_state_document.get("artifact") != "spectron_connection_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected connection-state anchor artifact")
        if not connection_state_verification.get("verified"):
            raise ValueError("connection-state anchor reopen verification did not pass")
        expected_connection_state = len(connection_state_document["anchors"])
        if connection_state_verification["verified_name_count"] != expected_connection_state:
            raise ValueError("connection-state verification count differs from artifact")
        connection_state = {
            "anchor_path": str(args.connection_state_anchors),
            "anchor_sha256": sha256_path(args.connection_state_anchors),
            "reopen_verification": str(args.connection_state_verification),
            "anchor_count": expected_connection_state,
            "verified_name_count": connection_state_verification["verified_name_count"],
            "reopen_failure_count": connection_state_verification["failure_count"],
        }
    if connection_state is not None:
        result["connection_state_anchors"] = connection_state
        result["interpretation"].append(
            "The eighteenth database revision also contains the separately reviewed client connection-state and encrypted-file helper anchors."
        )
    http_request = None
    if args.http_request_anchors or args.http_request_verification:
        if not args.http_request_anchors or not args.http_request_verification:
            raise ValueError(
                "HTTP request anchors and HTTP request verification must be supplied together"
            )
        http_request_document = load(args.http_request_anchors)
        http_request_verification = load(args.http_request_verification)
        if http_request_document.get("artifact") != "spectron_http_request_manual_translation_anchors_20260826":
            raise ValueError("unexpected HTTP request anchor artifact")
        if not http_request_verification.get("verified"):
            raise ValueError("HTTP request anchor reopen verification did not pass")
        expected_http_request = len(http_request_document["anchors"])
        if http_request_verification["verified_name_count"] != expected_http_request:
            raise ValueError("HTTP request verification count differs from artifact")
        http_request = {
            "anchor_path": str(args.http_request_anchors),
            "anchor_sha256": sha256_path(args.http_request_anchors),
            "reopen_verification": str(args.http_request_verification),
            "anchor_count": expected_http_request,
            "verified_name_count": http_request_verification["verified_name_count"],
            "reopen_failure_count": http_request_verification["failure_count"],
        }
    if http_request is not None:
        result["http_request_anchors"] = http_request
        result["interpretation"].append(
            "The nineteenth database revision also contains the separately reviewed HTTP request field, lifecycle, and outbound-buffer anchors."
        )
    socket_state = None
    if args.socket_state_anchors or args.socket_state_verification:
        if not args.socket_state_anchors or not args.socket_state_verification:
            raise ValueError(
                "socket-state anchors and socket-state verification must be supplied together"
            )
        socket_state_document = load(args.socket_state_anchors)
        socket_state_verification = load(args.socket_state_verification)
        if socket_state_document.get("artifact") != "spectron_socket_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected socket-state anchor artifact")
        if not socket_state_verification.get("verified"):
            raise ValueError("socket-state anchor reopen verification did not pass")
        expected_socket_state = len(socket_state_document["anchors"])
        if socket_state_verification["verified_name_count"] != expected_socket_state:
            raise ValueError("socket-state verification count differs from artifact")
        socket_state = {
            "anchor_path": str(args.socket_state_anchors),
            "anchor_sha256": sha256_path(args.socket_state_anchors),
            "reopen_verification": str(args.socket_state_verification),
            "anchor_count": expected_socket_state,
            "verified_name_count": socket_state_verification["verified_name_count"],
            "reopen_failure_count": socket_state_verification["failure_count"],
        }
    if socket_state is not None:
        result["socket_state_anchors"] = socket_state
        result["interpretation"].append(
            "The twentieth database revision also contains the separately reviewed socket status and address helper anchors."
        )
    http_request_state = None
    if args.http_request_state_anchors or args.http_request_state_verification:
        if not args.http_request_state_anchors or not args.http_request_state_verification:
            raise ValueError(
                "HTTP request-state anchors and HTTP request-state verification must be supplied together"
            )
        http_request_state_document = load(args.http_request_state_anchors)
        http_request_state_verification = load(args.http_request_state_verification)
        if http_request_state_document.get("artifact") != "spectron_http_request_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected HTTP request-state anchor artifact")
        if not http_request_state_verification.get("verified"):
            raise ValueError("HTTP request-state anchor reopen verification did not pass")
        expected_http_request_state = len(http_request_state_document["anchors"])
        if http_request_state_verification["verified_name_count"] != expected_http_request_state:
            raise ValueError("HTTP request-state verification count differs from artifact")
        http_request_state = {
            "anchor_path": str(args.http_request_state_anchors),
            "anchor_sha256": sha256_path(args.http_request_state_anchors),
            "reopen_verification": str(args.http_request_state_verification),
            "anchor_count": expected_http_request_state,
            "verified_name_count": http_request_state_verification["verified_name_count"],
            "reopen_failure_count": http_request_state_verification["failure_count"],
        }
    if http_request_state is not None:
        result["http_request_state_anchors"] = http_request_state
        result["interpretation"].append(
            "The twenty-first database revision also contains the separately reviewed HTTP request counters and download-state anchors."
        )
    npc_helper = None
    if args.npc_helper_anchors or args.npc_helper_verification:
        if not args.npc_helper_anchors or not args.npc_helper_verification:
            raise ValueError(
                "NPC helper anchors and NPC helper verification must be supplied together"
            )
        npc_helper_document = load(args.npc_helper_anchors)
        npc_helper_verification = load(args.npc_helper_verification)
        if npc_helper_document.get("artifact") != "spectron_npc_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected NPC helper anchor artifact")
        if not npc_helper_verification.get("verified"):
            raise ValueError("NPC helper anchor reopen verification did not pass")
        expected_npc_helper = len(npc_helper_document["anchors"])
        if npc_helper_verification["verified_name_count"] != expected_npc_helper:
            raise ValueError("NPC helper verification count differs from artifact")
        npc_helper = {
            "anchor_path": str(args.npc_helper_anchors),
            "anchor_sha256": sha256_path(args.npc_helper_anchors),
            "reopen_verification": str(args.npc_helper_verification),
            "anchor_count": expected_npc_helper,
            "verified_name_count": npc_helper_verification["verified_name_count"],
            "reopen_failure_count": npc_helper_verification["failure_count"],
        }
    if npc_helper is not None:
        result["npc_helper_anchors"] = npc_helper
        result["interpretation"].append(
            "The twenty-second database revision also contains the separately reviewed TServerNPC blocking, draw-mode, visibility, bow, and pelt helper anchors."
        )
    html_atom = None
    if args.html_atom_anchors or args.html_atom_verification:
        if not args.html_atom_anchors or not args.html_atom_verification:
            raise ValueError(
                "HTML atom anchors and HTML atom verification must be supplied together"
            )
        html_atom_document = load(args.html_atom_anchors)
        html_atom_verification = load(args.html_atom_verification)
        if html_atom_document.get("artifact") != "spectron_html_atom_manual_translation_anchors_20260826":
            raise ValueError("unexpected HTML atom anchor artifact")
        if not html_atom_verification.get("verified"):
            raise ValueError("HTML atom anchor reopen verification did not pass")
        expected_html_atom = len(html_atom_document["anchors"])
        if html_atom_verification["verified_name_count"] != expected_html_atom:
            raise ValueError("HTML atom verification count differs from artifact")
        html_atom = {
            "anchor_path": str(args.html_atom_anchors),
            "anchor_sha256": sha256_path(args.html_atom_anchors),
            "reopen_verification": str(args.html_atom_verification),
            "anchor_count": expected_html_atom,
            "verified_name_count": html_atom_verification["verified_name_count"],
            "reopen_failure_count": html_atom_verification["failure_count"],
        }
    if html_atom is not None:
        result["html_atom_anchors"] = html_atom
        result["interpretation"].append(
            "The twenty-third database revision also contains the separately reviewed THTMLAtom constructor and buffer accessor anchors."
        )
    player_helper = None
    if args.player_helper_anchors or args.player_helper_verification:
        if not args.player_helper_anchors or not args.player_helper_verification:
            raise ValueError(
                "player helper anchors and player helper verification must be supplied together"
            )
        player_helper_document = load(args.player_helper_anchors)
        player_helper_verification = load(args.player_helper_verification)
        if player_helper_document.get("artifact") != "spectron_player_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected player helper anchor artifact")
        if not player_helper_verification.get("verified"):
            raise ValueError("player helper anchor reopen verification did not pass")
        expected_player_helper = len(player_helper_document["anchors"])
        if player_helper_verification["verified_name_count"] != expected_player_helper:
            raise ValueError("player helper verification count differs from artifact")
        player_helper = {
            "anchor_path": str(args.player_helper_anchors),
            "anchor_sha256": sha256_path(args.player_helper_anchors),
            "reopen_verification": str(args.player_helper_verification),
            "anchor_count": expected_player_helper,
            "verified_name_count": player_helper_verification["verified_name_count"],
            "reopen_failure_count": player_helper_verification["failure_count"],
        }
    if player_helper is not None:
        result["player_helper_anchors"] = player_helper
        result["interpretation"].append(
            "The twenty-fourth database revision also contains the separately reviewed compact TPlayer attachment, update, freeze, and sprite helper anchors."
        )
    input_window = None
    if args.input_window_anchors or args.input_window_verification:
        if not args.input_window_anchors or not args.input_window_verification:
            raise ValueError(
                "input/window anchors and input/window verification must be supplied together"
            )
        input_window_document = load(args.input_window_anchors)
        input_window_verification = load(args.input_window_verification)
        if input_window_document.get("artifact") != "spectron_input_window_manual_translation_anchors_20260826":
            raise ValueError("unexpected input/window anchor artifact")
        if not input_window_verification.get("verified"):
            raise ValueError("input/window anchor reopen verification did not pass")
        expected_input_window = len(input_window_document["anchors"])
        if input_window_verification["verified_name_count"] != expected_input_window:
            raise ValueError("input/window verification count differs from artifact")
        input_window = {
            "anchor_path": str(args.input_window_anchors),
            "anchor_sha256": sha256_path(args.input_window_anchors),
            "reopen_verification": str(args.input_window_verification),
            "anchor_count": expected_input_window,
            "verified_name_count": input_window_verification["verified_name_count"],
            "reopen_failure_count": input_window_verification["failure_count"],
        }
    if input_window is not None:
        result["input_window_anchors"] = input_window
        result["interpretation"].append(
            "The twenty-fifth database revision also contains the separately reviewed input and window bridge helper anchors."
        )
    visual_helper = None
    if args.visual_helper_anchors or args.visual_helper_verification:
        if not args.visual_helper_anchors or not args.visual_helper_verification:
            raise ValueError(
                "visual helper anchors and visual helper verification must be supplied together"
            )
        visual_helper_document = load(args.visual_helper_anchors)
        visual_helper_verification = load(args.visual_helper_verification)
        if visual_helper_document.get("artifact") != "spectron_visual_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected visual helper anchor artifact")
        if not visual_helper_verification.get("verified"):
            raise ValueError("visual helper anchor reopen verification did not pass")
        expected_visual_helper = len(visual_helper_document["anchors"])
        if visual_helper_verification["verified_name_count"] != expected_visual_helper:
            raise ValueError("visual helper verification count differs from artifact")
        visual_helper = {
            "anchor_path": str(args.visual_helper_anchors),
            "anchor_sha256": sha256_path(args.visual_helper_anchors),
            "reopen_verification": str(args.visual_helper_verification),
            "anchor_count": expected_visual_helper,
            "verified_name_count": visual_helper_verification["verified_name_count"],
            "reopen_failure_count": visual_helper_verification["failure_count"],
        }
    if visual_helper is not None:
        result["visual_helper_anchors"] = visual_helper
        result["interpretation"].append(
            "The twenty-sixth database revision also contains the separately reviewed animation, particle, and show-image helper anchors."
        )
    script_runtime = None
    if args.script_runtime_anchors or args.script_runtime_verification:
        if not args.script_runtime_anchors or not args.script_runtime_verification:
            raise ValueError(
                "script-runtime anchors and script-runtime verification must be supplied together"
            )
        script_runtime_document = load(args.script_runtime_anchors)
        script_runtime_verification = load(args.script_runtime_verification)
        if script_runtime_document.get("artifact") != "spectron_script_runtime_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-runtime anchor artifact")
        if not script_runtime_verification.get("verified"):
            raise ValueError("script-runtime anchor reopen verification did not pass")
        expected_script_runtime = len(script_runtime_document["anchors"])
        if script_runtime_verification["verified_name_count"] != expected_script_runtime:
            raise ValueError("script-runtime verification count differs from artifact")
        script_runtime = {
            "anchor_path": str(args.script_runtime_anchors),
            "anchor_sha256": sha256_path(args.script_runtime_anchors),
            "reopen_verification": str(args.script_runtime_verification),
            "anchor_count": expected_script_runtime,
            "verified_name_count": script_runtime_verification["verified_name_count"],
            "reopen_failure_count": script_runtime_verification["failure_count"],
        }
    if script_runtime is not None:
        result["script_runtime_anchors"] = script_runtime
        result["interpretation"].append(
            "The twenty-seventh database revision also contains the separately reviewed GS2-facing TGraalVar, TScript, TScriptSpace, and TScriptUniverse helper anchors."
        )
    core_helper = None
    if args.core_helper_anchors or args.core_helper_verification:
        if not args.core_helper_anchors or not args.core_helper_verification:
            raise ValueError(
                "core-helper anchors and core-helper verification must be supplied together"
            )
        core_helper_document = load(args.core_helper_anchors)
        core_helper_verification = load(args.core_helper_verification)
        if core_helper_document.get("artifact") != "spectron_core_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected core-helper anchor artifact")
        if not core_helper_verification.get("verified"):
            raise ValueError("core-helper anchor reopen verification did not pass")
        expected_core_helper = len(core_helper_document["anchors"])
        if core_helper_verification["verified_name_count"] != expected_core_helper:
            raise ValueError("core-helper verification count differs from artifact")
        core_helper = {
            "anchor_path": str(args.core_helper_anchors),
            "anchor_sha256": sha256_path(args.core_helper_anchors),
            "reopen_verification": str(args.core_helper_verification),
            "anchor_count": expected_core_helper,
            "verified_name_count": core_helper_verification["verified_name_count"],
            "reopen_failure_count": core_helper_verification["failure_count"],
        }
    if core_helper is not None:
        result["core_helper_anchors"] = core_helper
        result["interpretation"].append(
            "The twenty-eighth database revision also contains the separately reviewed level, script, network-policy, tile, particle, and native callback helper anchors."
        )
    render_gui = None
    if args.render_gui_anchors or args.render_gui_verification:
        if not args.render_gui_anchors or not args.render_gui_verification:
            raise ValueError(
                "render/GUI anchors and render/GUI verification must be supplied together"
            )
        render_gui_document = load(args.render_gui_anchors)
        render_gui_verification = load(args.render_gui_verification)
        if render_gui_document.get("artifact") != "spectron_render_gui_manual_translation_anchors_20260826":
            raise ValueError("unexpected render/GUI anchor artifact")
        if not render_gui_verification.get("verified"):
            raise ValueError("render/GUI anchor reopen verification did not pass")
        expected_render_gui = len(render_gui_document["anchors"])
        if render_gui_verification["verified_name_count"] != expected_render_gui:
            raise ValueError("render/GUI verification count differs from artifact")
        render_gui = {
            "anchor_path": str(args.render_gui_anchors),
            "anchor_sha256": sha256_path(args.render_gui_anchors),
            "reopen_verification": str(args.render_gui_verification),
            "anchor_count": expected_render_gui,
            "verified_name_count": render_gui_verification["verified_name_count"],
            "reopen_failure_count": render_gui_verification["failure_count"],
        }
    if render_gui is not None:
        result["render_gui_anchors"] = render_gui
        result["interpretation"].append(
            "The twenty-ninth database revision also contains the separately reviewed texture, OpenGL, drawing-panel, GUI-control, markup, and scrolling helper anchors."
        )
    json_folder = None
    if args.json_folder_anchors or args.json_folder_verification:
        if not args.json_folder_anchors or not args.json_folder_verification:
            raise ValueError(
                "JSON/folder anchors and JSON/folder verification must be supplied together"
            )
        json_folder_document = load(args.json_folder_anchors)
        json_folder_verification = load(args.json_folder_verification)
        if json_folder_document.get("artifact") != "spectron_json_folder_manual_translation_anchors_20260826":
            raise ValueError("unexpected JSON/folder anchor artifact")
        if not json_folder_verification.get("verified"):
            raise ValueError("JSON/folder anchor reopen verification did not pass")
        expected_json_folder = len(json_folder_document["anchors"])
        if json_folder_verification["verified_name_count"] != expected_json_folder:
            raise ValueError("JSON/folder verification count differs from artifact")
        json_folder = {
            "anchor_path": str(args.json_folder_anchors),
            "anchor_sha256": sha256_path(args.json_folder_anchors),
            "reopen_verification": str(args.json_folder_verification),
            "anchor_count": expected_json_folder,
            "verified_name_count": json_folder_verification["verified_name_count"],
            "reopen_failure_count": json_folder_verification["failure_count"],
        }
    if json_folder is not None:
        result["json_folder_anchors"] = json_folder
        result["interpretation"].append(
            "The thirtieth database revision also contains the separately reviewed image callbacks, recursive folder-loader helper, and YAJL JSON callback anchors."
        )
    resource_object = None
    if args.resource_object_anchors or args.resource_object_verification:
        if not args.resource_object_anchors or not args.resource_object_verification:
            raise ValueError(
                "resource-object anchors and resource-object verification must be supplied together"
            )
        resource_object_document = load(args.resource_object_anchors)
        resource_object_verification = load(args.resource_object_verification)
        if resource_object_document.get("artifact") != "spectron_resource_object_manual_translation_anchors_20260826":
            raise ValueError("unexpected resource-object anchor artifact")
        if not resource_object_verification.get("verified"):
            raise ValueError("resource-object anchor reopen verification did not pass")
        expected_resource_object = len(resource_object_document["anchors"])
        if resource_object_verification["verified_name_count"] != expected_resource_object:
            raise ValueError("resource-object verification count differs from artifact")
        resource_object = {
            "anchor_path": str(args.resource_object_anchors),
            "anchor_sha256": sha256_path(args.resource_object_anchors),
            "reopen_verification": str(args.resource_object_verification),
            "anchor_count": expected_resource_object,
            "verified_name_count": resource_object_verification["verified_name_count"],
            "reopen_failure_count": resource_object_verification["failure_count"],
        }
    if resource_object is not None:
        result["resource_object_anchors"] = resource_object
        result["interpretation"].append(
            "The thirty-first database revision also contains the separately reviewed resource comparator, link, alternative, and stream-materialization anchors."
        )
    script_machine = None
    if args.script_machine_anchors or args.script_machine_verification:
        if not args.script_machine_anchors or not args.script_machine_verification:
            raise ValueError(
                "script-machine anchors and script-machine verification must be supplied together"
            )
        script_machine_document = load(args.script_machine_anchors)
        script_machine_verification = load(args.script_machine_verification)
        if script_machine_document.get("artifact") != "spectron_script_machine_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-machine anchor artifact")
        if not script_machine_verification.get("verified"):
            raise ValueError("script-machine anchor reopen verification did not pass")
        expected_script_machine = len(script_machine_document["anchors"])
        if script_machine_verification["verified_name_count"] != expected_script_machine:
            raise ValueError("script-machine verification count differs from artifact")
        script_machine = {
            "anchor_path": str(args.script_machine_anchors),
            "anchor_sha256": sha256_path(args.script_machine_anchors),
            "reopen_verification": str(args.script_machine_verification),
            "anchor_count": expected_script_machine,
            "verified_name_count": script_machine_verification["verified_name_count"],
            "reopen_failure_count": script_machine_verification["failure_count"],
        }
    if script_machine is not None:
        result["script_machine_anchors"] = script_machine
        result["interpretation"].append(
            "The thirty-second database revision also contains the separately reviewed GS2 script-machine construction, resolution, assignment, and comparison anchors."
        )
    script_space = None
    if args.script_space_anchors or args.script_space_verification:
        if not args.script_space_anchors or not args.script_space_verification:
            raise ValueError(
                "script-space anchors and script-space verification must be supplied together"
            )
        script_space_document = load(args.script_space_anchors)
        script_space_verification = load(args.script_space_verification)
        if script_space_document.get("artifact") != "spectron_script_space_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-space anchor artifact")
        if not script_space_verification.get("verified"):
            raise ValueError("script-space anchor reopen verification did not pass")
        expected_script_space = len(script_space_document["anchors"])
        if script_space_verification["verified_name_count"] != expected_script_space:
            raise ValueError("script-space verification count differs from artifact")
        script_space = {
            "anchor_path": str(args.script_space_anchors),
            "anchor_sha256": sha256_path(args.script_space_anchors),
            "reopen_verification": str(args.script_space_verification),
            "anchor_count": expected_script_space,
            "verified_name_count": script_space_verification["verified_name_count"],
            "reopen_failure_count": script_space_verification["failure_count"],
        }
    if script_space is not None:
        result["script_space_anchors"] = script_space
        result["interpretation"].append(
            "The thirty-third database revision also contains the separately reviewed TScriptSpace event, class-transition, event-state, and timeout anchors."
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **result["translation"], "database_sha256": result["database"]["sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
