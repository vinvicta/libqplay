#!/usr/bin/env python3
"""Check whether a recovered GS2 source enables game-server TLS for Classic.

This is a source-text audit for a decompiled ``StartScript_Connector``. It
does not compile or execute the script and does not open a socket. The checks
are intentionally narrow: they verify the Classic branch assignment, the
conditional around ``setSSLParameters`` in the NewGraal login function, and
the final unconditional SSL assignment found in this client revision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def function_region(source: str, function_name: str) -> tuple[str, int]:
    match = re.search(
        rf"\bfunction\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{",
        source,
    )
    if not match:
        raise ValueError(f"function not found: {function_name}")
    next_function = re.search(r"\bfunction\s+[A-Za-z0-9_]+\s*\(", source[match.end() :])
    end = match.end() + next_function.start() if next_function else len(source)
    return source[match.start() : end], line_number(source, match.start())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_gs2", type=Path)
    args = parser.parse_args()

    raw = args.source_gs2.read_bytes()
    source = raw.decode("utf-8")
    decide_region, decide_line = function_region(source, "decideHostAndPort")
    login_region, login_line = function_region(source, "sendLoginNewProtocol")

    classic = re.search(
        r'else\s+if\s*\([^)]*==\s*"classic"\s*\)\s*\{(?P<body>.*?)(?=\n\s*else\s+if\s*\(|\n\s*else\s*\{)',
        decide_region,
        re.DOTALL,
    )
    if not classic:
        raise ValueError("Classic branch not found")
    classic_body = classic.group("body")
    classic_false = bool(re.search(r"\bthis\.usessl\s*=\s*false\s*;", classic_body))

    guarded_ssl = bool(
        re.search(
            r"if\s*\(\s*this\.usessl\s*\)\s*\{.*?setSSLParameters",
            login_region,
            re.DOTALL,
        )
    )
    final_ssl = bool(re.search(r"\bthis\.usessl\s*=\s*false\s*;\s*\}\s*$", decide_region, re.DOTALL))
    set_ssl_count = source.count("setSSLParameters")

    report = {
        "source": str(args.source_gs2),
        "source_bytes": len(raw),
        "source_sha256": sha256(raw),
        "decide_host_function_line": decide_line,
        "send_login_new_protocol_function_line": login_line,
        "classic_branch_sets_usessl_false": classic_false,
        "new_protocol_ssl_call_is_guarded": guarded_ssl,
        "decide_host_final_usessl_false": final_ssl,
        "set_ssl_parameters_occurrences": set_ssl_count,
        "classic_game_server_tls_active": not (classic_false and guarded_ssl and final_ssl),
        "network_contacted": False,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
