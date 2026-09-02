#!/usr/bin/env python3
"""Generate the focused static review of cache filenames and writes.

The report ties the ARM64 filename mapper, cache writer, URL cache, and
resource-update callers to the checked-in IDA inventory. It distinguishes the
lexical escaping used for URL-derived names from the weaker string-prefix
checks used by ordinary cache paths. It records interrupted-write behavior as
a startup and cache-integrity concern, not as proof of a remote exploit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "symbols" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "cache_filename_policy_review_20260902.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def function_row(rows: dict[int, dict], address: int, name: str) -> dict:
    row = rows.get(address)
    if row is None:
        raise ValueError(f"{name} is absent from the inventory at {address:#x}")
    if row.get("name") != name:
        raise ValueError(
            f"unexpected name at {address:#x}: {row.get('name')} != {name}"
        )
    size = row.get("size", 0)
    if isinstance(size, str):
        size = int(size, 0)
    return {"address": f"{address:#x}", "ida_name": name, "size": size}


def build_report(inventory_path: Path) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")
    rows = {int(item["ea"]): item for item in document}

    functions = {
        "url_filename_escape": function_row(
            rows, 0xE7A50, "TFiles_escapedFilename_TString_const"
        ),
        "absolute_path_test": function_row(
            rows, 0xE8208, "TFiles_hasAbsolutePath_TString_const"
        ),
        "force_directories": function_row(
            rows, 0xE74D4, "TFiles_forceDirectories_TString_const"
        ),
        "download_filename_mapper": function_row(
            rows, 0x1FA920, "TCachedStream_getDownloadFilename_TString_const"
        ),
        "resolve_cached_filename": function_row(
            rows, 0x1FB5B8, "TCachedStream_resolveFilename_void"
        ),
        "cache_save": function_row(rows, 0x1FA6E8, "TCachedStream_save_bool"),
        "cache_save_and_update": function_row(
            rows, 0x1FB744, "TCachedStream_saveAndUpdate_TCachedStream_TString_const"
        ),
        "stream_save_file": function_row(
            rows, 0xF0AA8, "TStream_SaveToFile_TString_const_uint"
        ),
        "url_cache_load": function_row(rows, 0x207EEC, "TURLCache_load_void"),
        "url_cache_check_save": function_row(
            rows, 0x20800C, "TURLCache_checkSave_bool_bool"
        ),
        "download_completion": function_row(
            rows, 0x200010, "THTTPRequest_saveDownloadedData_void"
        ),
        "resource_update": function_row(
            rows,
            0xEE078,
            "TResourceFunctions_updateResourceObject_TString_const_bool",
        ),
    }

    return {
        "artifact": "cache_filename_policy_review_20260902",
        "schema": "libqplay.cache-filename-policy-review.v1",
        "tool": "tools/generate_cache_filename_policy_review.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": (
            "static review of URL-derived cache filenames, ordinary resource "
            "paths, cache writes, URLCACHE persistence, and post-download "
            "resource updates"
        ),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "functions": functions,
        "policy": {
            "allowed_url_filename_characters": (
                "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            ),
            "url_cache_prefix": "baseuserfolder/webfiles/",
            "url_filename_encoding": (
                "Characters outside the allowed set are emitted as '%' plus a "
                "zero-padded decimal byte value of at least three digits."
            ),
            "ordinary_cache_mapping": (
                "Recognized extensions are routed below application-owned "
                "directories such as levels, maps, sounds, music, tiles, and "
                "updatepackages. Relative names are not emitted as raw URL "
                "path separators by the URL-derived route."
            ),
            "absolute_path_detection": (
                "The helper checks for the configured URL marker, a leading '/', "
                "a colon, and configured '/' or '\\\\' separators."
            ),
            "directory_mode": "0775",
            "save_mode": {"replace": "wb", "append": "ab"},
            "write_count_checked": False,
            "atomic_tempfile_rename_seen": False,
            "fsync_seen": False,
            "urlcache_filename": "baseuserfolder/URLCACHE.txt",
            "urlcache_line_limit": None,
            "urlcache_integrity_tag": False,
        },
        "flows": {
            "ordinary_download": [
                "THTTPRequest_saveDownloadedData_void",
                "TCachedStream_saveAndUpdate_TCachedStream_TString_const",
                "TCachedStream_resolveFilename_void",
                "TCachedStream_save_bool",
                "TFiles_forceDirectories_TString_const",
                "TStream_SaveToFile_TString_const_uint",
                "TResourceFunctions_updateResourceObject_TString_const_bool",
            ],
            "url_cache": [
                "TURLCache_load_void",
                "TURLCache_addURL_TString_const_TString_const",
                "TURLCache_checkSave_bool_bool",
                "TStream_SaveToFile_TString_const_uint",
            ],
            "replacement_guard": (
                "TCachedStream_save_bool recognizes the configured base executable "
                "and full executable path, deletes an existing target, then "
                "writes the replacement and sets the replacedgraalexe flag."
            ),
        },
        "findings": [
            {
                "id": "CACHE-001",
                "severity": "cache-integrity and startup-availability gap, conditional",
                "addresses": [
                    "0x200010",
                    "0x1fb744",
                    "0x1fa6e8",
                    "0xf0aa8",
                    "0xf0b5c",
                    "0xee078",
                ],
                "instruction": (
                    "THTTPRequest_saveDownloadedData_void reaches the cache save "
                    "path after a response is accepted. TStream_SaveToFile opens "
                    "the destination, calls fwrite with the complete TString length, "
                    "ignores the returned count and stream error state, and closes "
                    "the file. TCachedStream_saveAndUpdate then continues into the "
                    "resource-object update path without a write-success result."
                ),
                "evidence": {
                    "download_completion_address": "0x200010",
                    "cache_save_and_update_address": "0x1fb744",
                    "cache_save_address": "0x1fa6e8",
                    "fwrite_address": "0xf0b5c",
                    "fclose_address": "0xf0b64",
                    "resource_update_call_address": "0x2003c0",
                    "ordinary_save_mode": "wb",
                },
                "assessment": (
                    "A process stop, storage-full condition, or other short write can "
                    "leave a partial file at the expected cache name while the "
                    "resource layer is still refreshed. A later load can then parse "
                    "truncated or stale bytes and appear to be a network or protocol "
                    "failure. This is a conditional local cache-integrity and startup "
                    "availability finding, not proof of a remotely controlled write "
                    "failure."
                ),
            },
            {
                "id": "CACHE-002",
                "severity": "filesystem hardening gap, conditional",
                "addresses": [
                    "0xe8208",
                    "0xe74e8",
                    "0x1fa920",
                    "0x1fb5b8",
                    "0x1fa6e8",
                    "0xf0aa8",
                ],
                "instruction": (
                    "URL-derived names are placed below webfiles and passed through "
                    "TFiles_escapedFilename_TString_const, which preserves only an "
                    "alphanumeric or underscore byte and encodes the rest. Ordinary "
                    "paths are instead classified with string prefixes and the "
                    "TFiles_hasAbsolutePath_TString_const heuristic. Directory "
                    "creation and fopen then operate on the resulting path without "
                    "a visible canonical-root check or no-follow flag."
                ),
                "evidence": {
                    "url_escape_address": "0xe7a50",
                    "allowed_character_initialization_address": "0xe8408",
                    "absolute_path_test_address": "0xe8208",
                    "directory_creation_address": "0xe75e4",
                    "save_open_address": "0xf0b3c",
                    "save_directory_prefix_checks": ["0x1fa738", "0x1fa7c4"],
                },
                "assessment": (
                    "The URL-derived route reduces ordinary slash and dot traversal "
                    "because those bytes are encoded. The broader ordinary-file path "
                    "still relies on lexical policy and platform filesystem behavior, "
                    "so a future repair should resolve beneath an owned directory, "
                    "reject symlinks where appropriate, and use an exclusive or "
                    "atomic write strategy. No direct traversal through a reviewed "
                    "server response was demonstrated."
                ),
            },
            {
                "id": "CACHE-003",
                "severity": "local cache availability and provenance gap, conditional",
                "addresses": ["0x207eec", "0x20800c", "0x208114", "0x1fb704"],
                "instruction": (
                    "TURLCache_load_void reads baseuserfolder/URLCACHE.txt into a "
                    "TStringList and processes every loaded line that contains at "
                    "least two comma-separated fields. TURLCache_checkSave_bool_bool "
                    "serializes all current entries back to the same file. The cache "
                    "is keyed by a case-normalized filename and has no visible line "
                    "count, byte budget, or integrity tag."
                ),
                "evidence": {
                    "load_path_construction_address": "0x207f14",
                    "line_load_address": "0x207f3c",
                    "line_iteration_address": "0x207f4c",
                    "entry_save_address": "0x208098",
                    "urlcache_save_address": "0x208114",
                    "filename_normalization_address": "0x1fb708",
                    "code_extension_exclusion_address": "0x207d7c",
                },
                "assessment": (
                    "A malformed or very large local URL cache can consume parser and "
                    "allocation time before the network path begins, and its entries "
                    "are not authenticated. The reviewed path excludes '.code' from "
                    "URL-cache insertion, which limits its effect on level-code "
                    "provenance. This is a local-state hardening observation, not a "
                    "claim that a remote peer can edit URLCACHE.txt."
                ),
            },
        ],
        "repair_targets": [
            "Return and check the exact fwrite count before updating a resource object.",
            "Write downloaded data to a temporary file in the same directory and use a validated atomic rename.",
            "Use checked canonical-root and no-follow policy for ordinary cache paths.",
            "Bound URLCACHE.txt by bytes and entries, and treat malformed records as a cache reset rather than a partial load.",
            "Keep the executable replacement path separate from ordinary resource caching and validate its final target explicitly.",
        ],
        "limitations": [
            "No storage-full or interrupted-write runtime test was performed.",
            "No symlink or hostile external-storage test was performed.",
            "The report does not claim that a network peer can directly edit URLCACHE.txt.",
            "This pass does not assign a live remote reachability result to any finding.",
        ],
        "overall_assessment": (
            "The original client has a useful lexical escape for URL-derived cache "
            "names, but its persistence layer treats file writes and local URL-cache "
            "records as trusted. The unchecked write result is the most useful "
            "compatibility lead because a corrupted external cache can reproduce a "
            "silent loading failure after a nominally successful download."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    report = build_report(args.inventory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
