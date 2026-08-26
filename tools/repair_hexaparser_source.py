#!/usr/bin/env python3
"""Repair the known missing brace in HexaParser connector output.

The pinned HexaParser decompiler emits one malformed ``printDisconnectError``
block for the archived connector script. This helper inserts the missing
closing brace without changing any statement or literal. It refuses to
overwrite the input and performs no compiler, APK, or network operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


FUNCTION_START = "function printDisconnectError("
NEXT_FUNCTION = "\nfunction onAppleMessageBoxButton("
BROKEN_SEQUENCE = "      return 0;\n  }\n  if (doclosebutton) {"
REPAIRED_SEQUENCE = "      return 0;\n    }\n  }\n  if (doclosebutton) {"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def repair(source: str) -> tuple[str, int]:
    start = source.find(FUNCTION_START)
    if start < 0:
        raise ValueError("printDisconnectError function was not found")
    end = source.find(NEXT_FUNCTION, start)
    if end < 0:
        raise ValueError("onAppleMessageBoxButton boundary was not found")
    body = source[start:end]
    if body.count(BROKEN_SEQUENCE) != 1:
        if body.count(REPAIRED_SEQUENCE) == 1:
            raise ValueError("source already contains the repaired brace")
        raise ValueError("expected one known malformed brace sequence")
    return source[:start] + body.replace(BROKEN_SEQUENCE, REPAIRED_SEQUENCE, 1) + source[end:], 1


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
    try:
        output, count = repair(source)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    output_bytes = output.encode("utf-8")
    args.output_gs2.parent.mkdir(parents=True, exist_ok=True)
    args.output_gs2.write_bytes(output_bytes)

    report = {
        "source_gs2": str(args.source_gs2),
        "output_gs2": str(args.output_gs2),
        "source_sha256": sha256(source_bytes),
        "output_sha256": sha256(output_bytes),
        "inserted_occurrences": count,
        "repair": "close printDisconnectError doreconnectbutton block",
        "verification_bypassed": False,
        "network_contacted": False,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
