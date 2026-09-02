#!/usr/bin/env python3
"""Generate the static connector retry and TLS-fallback review.

The report is based on fixed ARM64 IDA observations from the original 1.8
library. It does not open a socket or contact a service. An optional binary
argument lets a local analyst verify that the expected input hash is present
before using the report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "connector_fallback_review_20260902.json"
EXPECTED_BINARY_SHA256 = (
    "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normal_failure_transition(mode: int, attempt: int) -> tuple[int, int]:
    """Model enterNextConnectorMode(-1) for a failed attempt."""

    if mode <= 0 or attempt > 1:
        return mode + 1, 1
    return mode, attempt + 1


def normal_attempts() -> list[dict]:
    endpoints = {
        (1, 1): ("https", "con.quattroplay.com", "/con.png"),
        (1, 2): ("https", "con2.quattroplay.com", "/con.png"),
        (2, 1): ("https", "con.quattroplay.com", "/con.gs"),
        (2, 2): ("https", "con2.quattroplay.com", "/con.gs"),
        (3, 1): ("http", "con.quattroplay.com", "/conf.gs"),
        (3, 2): ("http", "con2.quattroplay.com", "/conf.gs"),
    }
    result = []
    mode, attempt = 1, 1
    while mode <= 3:
        scheme, host, path = endpoints[(mode, attempt)]
        result.append(
            {
                "mode": mode,
                "attempt": attempt,
                "scheme": scheme,
                "host": host,
                "path": path,
                "endpoint": "%s://%s%s" % (scheme, host, path),
                "failure_transition": (
                    {
                        "mode": normal_failure_transition(mode, attempt)[0],
                        "attempt": normal_failure_transition(mode, attempt)[1],
                    }
                    if not (mode == 3 and attempt == 2)
                    else {"mode": 4, "attempt": 0, "result": "showConnectFailure"}
                ),
            }
        )
        mode, attempt = normal_failure_transition(mode, attempt)
    return result


def build_report(binary_path: Path | None = None) -> dict:
    binary_observation = {
        "sha256": EXPECTED_BINARY_SHA256,
        "path": "private original ARM64 libqplay.so",
    }
    if binary_path is not None:
        observed_hash = sha256_file(binary_path)
        if observed_hash != EXPECTED_BINARY_SHA256:
            raise ValueError(
                "unexpected binary hash: %s (expected %s)"
                % (observed_hash, EXPECTED_BINARY_SHA256)
            )
        binary_observation["verified_input_path"] = str(binary_path)
        binary_observation["verified_input_sha256"] = observed_hash

    return {
        "schema": "libqplay.connector-fallback-review.v1",
        "artifact": "connector_fallback_review_20260902",
        "analysis_date": "2026-09-02",
        "scope": "static ARM64 IDA review of connector retry and TLS-error fallback",
        "network_contacted": False,
        "binary": binary_observation,
        "functions": {
            "login": {
                "address": "0x204420",
                "name": "TServerList_login_void",
                "evidence": [
                    "The login path calls enterNextConnectorMode_int with mode 1 after showing the connecting window.",
                ],
            },
            "enter_next_connector_mode": {
                "address": "0x203df4",
                "name": "TServerList_enterNextConnectorMode_int",
                "evidence": [
                    "An explicit positive mode stores connectormode and resets connectortries to 1.",
                    "A negative argument increments connectortries when the current attempt is the first try.",
                    "A negative argument advances the mode and resets connectortries to 1 after the second try or an invalid current mode.",
                    "Modes 1 through 3 construct the connector request; mode 4 calls showConnectFailure.",
                ],
            },
            "request_state_machine": {
                "address": "0x2025a0",
                "name": "THTTPRequest_runScript_void",
                "evidence": [
                    "A request with a socket error reaches the completion path that calls saveDownloadedData after the normal read and parse checks.",
                    "The redirect branch is separate and has its own ten-attempt counter.",
                ],
            },
            "download_completion": {
                "address": "0x200010",
                "name": "THTTPRequest_saveDownloadedData_void",
                "evidence": [
                    "The connector marker at request offset 229 distinguishes connector failure from ordinary file failure.",
                    "The failure path reads the socket error field at byte offset 8312 and calls enterNextConnectorMode_int.",
                    "When that field is nonzero and connectormode is at most 2, the call argument is the explicit mode 3 value.",
                    "Otherwise the failure path uses the negative argument and follows the normal two-attempt progression.",
                ],
            },
            "socket_error_field": {
                "read_address": "0x2074d4",
                "read_name": "TSocketConnection_read_void",
                "write_address": "0x207118",
                "write_name": "TSocketConnection_sendData_void_const_int",
                "evidence": [
                    "The CyaSSL read and write error paths store the CyaSSL error result at byte offset 8312 and close the socket.",
                    "The plain recv and send paths report ordinary transport errors through the socket message field instead of this CyaSSL error field.",
                ],
            },
        },
        "normal_attempt_order": normal_attempts(),
        "tls_error_shortcuts": [
            {
                "from": "mode 1, attempt 1 or 2",
                "condition": "connector request fails with a nonzero CyaSSL error field",
                "next": "mode 3, attempt 1",
                "endpoint": "http://con.quattroplay.com/conf.gs",
            },
            {
                "from": "mode 2, attempt 1 or 2",
                "condition": "connector request fails with a nonzero CyaSSL error field",
                "next": "mode 3, attempt 1",
                "endpoint": "http://con.quattroplay.com/conf.gs",
            },
            {
                "from": "mode 3, attempt 1",
                "condition": "connector request fails with a nonzero CyaSSL error field",
                "next": "mode 3, attempt 2",
                "endpoint": "http://con2.quattroplay.com/conf.gs",
            },
        ],
        "findings": [
            {
                "id": "CONNECTOR-FALLBACK-001",
                "title": "TLS errors trigger a cleartext connector fallback",
                "severity": "compatibility and transport-policy concern",
                "confidence": "confirmed-static",
                "assessment": "The first HTTPS certificate failure can occur before any HTTP request, then the native error path deliberately enters mode 3 and tries the cleartext conf.gs endpoint. If that legacy endpoint is unavailable, the user sees the generic connector failure even though the HTTPS failure was the first cause.",
                "limits": [
                    "The static path does not prove that a current service still publishes conf.gs.",
                    "The existing local expired-certificate control listened on the TLS diagnostic port and therefore did not observe a mode-3 request.",
                    "No live endpoint was contacted.",
                ],
            }
        ],
        "diagnostic_sequence": [
            "Record the first HTTPS TCP connection and whether a ClientHello completes.",
            "If the handshake fails before GET, observe the next destination separately rather than treating the absence of HTTP as the final state.",
            "Record whether mode 3 opens a plain TCP connection and sends GET /conf.gs.",
            "Keep certificate verification enabled while testing a current authorized endpoint; the fallback trace is not a reason to disable it.",
        ],
        "limitations": [
            "This report is a static control-flow model, not a runtime trace.",
            "The redirect retry counter and connector-mode counter are independent state variables.",
            "A physical ARM64 run and a current service-side response are still required for end-to-end confirmation.",
        ],
        "repair_targets": [
            "Use a current authorized trust chain and preserve peer and hostname verification.",
            "Make fallback policy explicit and reject an HTTPS-to-HTTP downgrade unless the operator deliberately supports it.",
            "Log connector mode, attempt, transport, and native socket error separately so the first failure is not hidden by the fallback result.",
        ],
        "tool": "tools/generate_connector_fallback_review.py",
        "tool_version": 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="optional private ARM64 binary to hash")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report(args.binary)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"finding_count": len(report["findings"]), "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
