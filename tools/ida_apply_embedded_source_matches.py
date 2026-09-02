#!/usr/bin/env python3
"""Apply checked-in source-match aliases to the active IDA database.

The default mode is a read-only dry run.  Set
``LIBQPLAY_EMBEDDED_SOURCE_APPLY=1`` only when the active database is the
intended working copy.  The script validates function boundaries and refuses
to replace an unrelated existing name.  It applies aliases from the libjpeg,
zlib, and giflib source-match artifacts and leaves the input binary untouched.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name


REPO = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACTS = (
    REPO / "artifacts/ida_libjpeg_source_matches_20260902.json",
    REPO / "artifacts/ida_zlib_source_matches_20260902.json",
    REPO / "artifacts/ida_giflib_source_matches_20260902.json",
)
APPLY = os.environ.get("LIBQPLAY_EMBEDDED_SOURCE_APPLY") == "1"
ALLOW_NONDEFAULT = os.environ.get("LIBQPLAY_EMBEDDED_SOURCE_ALLOW_NONDEFAULT") == "1"


def artifact_paths() -> list[Path]:
    value = os.environ.get("LIBQPLAY_SOURCE_MATCH_ARTIFACTS")
    if not value:
        return list(DEFAULT_ARTIFACTS)
    return [Path(item).expanduser().resolve() for item in value.split(os.pathsep) if item]


def load_matches() -> list[dict]:
    matches = []
    seen_addresses = set()
    seen_names = set()
    for path in artifact_paths():
        document = json.loads(path.read_text(encoding="utf-8"))
        for item in document.get("matches", []):
            ea = int(item["address"], 0)
            name = item["ida_name"]
            if ea in seen_addresses:
                raise RuntimeError(f"duplicate source-match address: 0x{ea:x}")
            if name in seen_names:
                raise RuntimeError(f"duplicate source-match alias: {name}")
            seen_addresses.add(ea)
            seen_names.add(name)
            matches.append({**item, "artifact": path.as_posix()})
    return sorted(matches, key=lambda item: int(item["address"], 0))


def is_generated_name(name: str | None) -> bool:
    return bool(name) and name.startswith(
        ("sub_", "nullsub_", "libjpeg_", "zlib_", "giflib_")
    )


def source_comment(item: dict) -> str:
    source = item.get("source_file", "<unknown>")
    line = item.get("source_line", "?")
    upstream = item.get("upstream_name", "<unknown>")
    return (
        f"Source match: {item.get('role', upstream)}; "
        f"{source}:{line}; {item.get('source_url', 'pinned source artifact')}"
    )


def main() -> None:
    ida_auto.auto_wait()
    matches = load_matches()
    failures = []
    pending = []
    applied = []
    for item in matches:
        ea = int(item["address"], 0)
        expected_name = item["ida_name"]
        expected_size = int(item["size"])
        function = ida_funcs.get_func(ea)
        if function is None:
            failures.append({"address": hex(ea), "error": "no function boundary"})
            continue
        actual_size = int(function.end_ea - function.start_ea)
        if actual_size != expected_size:
            failures.append(
                {
                    "address": hex(ea),
                    "error": "function size mismatch",
                    "expected_size": expected_size,
                    "actual_size": actual_size,
                }
            )
            continue
        current_name = ida_name.get_name(ea) or ""
        if current_name == expected_name:
            applied.append({"address": hex(ea), "name": expected_name, "state": "already_named"})
            continue
        if not ALLOW_NONDEFAULT and not is_generated_name(current_name):
            failures.append(
                {
                    "address": hex(ea),
                    "error": "refusing to replace unrelated name",
                    "current_name": current_name,
                    "expected_name": expected_name,
                }
            )
            continue
        existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, expected_name)
        if existing_ea not in (ida_idaapi.BADADDR, ea):
            failures.append(
                {
                    "address": hex(ea),
                    "error": "target name already belongs to another address",
                    "expected_name": expected_name,
                    "existing_ea": hex(existing_ea),
                }
            )
            continue
        pending.append(
            {
                "address": hex(ea),
                "current_name": current_name,
                "new_name": expected_name,
                "comment": source_comment(item),
            }
        )

    if APPLY and not failures:
        for item in pending:
            ea = int(item["address"], 0)
            if not ida_name.set_name(ea, item["new_name"], ida_name.SN_CHECK):
                failures.append(
                    {
                        "address": item["address"],
                        "error": "IDA rejected rename",
                        "new_name": item["new_name"],
                    }
                )
                continue
            function = ida_funcs.get_func(ea)
            if function is not None:
                ida_funcs.set_func_cmt(function, item["comment"], False)
            ida_bytes.set_cmt(ea, item["comment"], False)
            applied.append(
                {
                    "address": item["address"],
                    "name": item["new_name"],
                    "state": "renamed",
                }
            )

    result = {
        "apply": APPLY,
        "artifact_count": len(artifact_paths()),
        "match_count": len(matches),
        "pending_count": len(pending),
        "applied_count": len(applied),
        "failure_count": len(failures),
        "failures": failures,
        "applied": applied,
        "status": "ok" if not failures else "failed",
    }
    print(json.dumps(result, sort_keys=True))
    if failures:
        raise RuntimeError("embedded source-match application failed")


if __name__ == "__main__":
    main()
