#!/usr/bin/env python3
"""Add a Classic success-path loading-screen clear to recovered GS2 source.

The recovered connector script logs ``Connected.`` in ``onServerLogin`` but
does not clear the global ``loadingscreenenabled`` flag. This helper inserts
that assignment immediately before the existing reconnection reset. It is a
source-level diagnostic candidate, not a native verification bypass.

The input is never overwritten and no network connection is opened.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


FUNCTION_RE = re.compile(
    r"\bfunction\s+onServerLogin\s*\([^)]*\)\s*\{(?P<body>.*?)(?=\n\s*function\s+|\Z)",
    re.DOTALL,
)
ASSIGNMENT = "  loadingscreenenabled = false;\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_gs2", type=Path)
    parser.add_argument("output_gs2", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    if args.source_gs2.resolve() == args.output_gs2.resolve():
        raise SystemExit("refusing to overwrite the input GS2 source")

    source_bytes = args.source_gs2.read_bytes()
    source = source_bytes.decode("utf-8")
    match = FUNCTION_RE.search(source)
    if not match:
        raise SystemExit("onServerLogin function not found")
    body = match.group("body")
    if "echo(\"Connected.\")" not in body:
        raise SystemExit("onServerLogin does not contain the expected success log")
    if ASSIGNMENT.strip() in body:
        raise SystemExit("onServerLogin already clears loadingscreenenabled")

    marker = "  this.reconnections = 0;"
    marker_offset = body.find(marker)
    if marker_offset < 0:
        raise SystemExit("onServerLogin reconnection reset not found")

    replacement_body = body[:marker_offset] + ASSIGNMENT + body[marker_offset:]
    output = source[: match.start("body")] + replacement_body + source[match.end("body") :]
    output_bytes = output.encode("utf-8")
    args.output_gs2.parent.mkdir(parents=True, exist_ok=True)
    args.output_gs2.write_bytes(output_bytes)

    report = {
        "source_gs2": str(args.source_gs2),
        "output_gs2": str(args.output_gs2),
        "source_sha256": sha256(source_bytes),
        "output_sha256": sha256(output_bytes),
        "inserted_occurrences": 1,
        "insertion": "onServerLogin before this.reconnections = 0",
        "assignment": ASSIGNMENT.strip(),
        "verification_bypassed": False,
        "network_contacted": False,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
