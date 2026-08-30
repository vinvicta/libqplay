#!/usr/bin/env python3
"""Index large local-only research artifacts without loading JSON documents.

The public repository keeps compact evidence and regeneration scripts. Large
derived exports live under ``research-data/generated`` and are intentionally
ignored by Git. This tool records their original repository path, local archive
path, size, line count, and SHA-256 in a small checked-in manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE_ROOT = ROOT / "research-data" / "generated"
DEFAULT_OUTPUT = ROOT / "artifacts" / "research_archive_manifest.json"


def classify(relative_path: Path) -> str:
    name = relative_path.name
    if name.startswith("spectron_features_"):
        return "spectron_feature_export"
    if name.startswith("spectron_name_coverage_audit"):
        return "spectron_name_coverage_audit"
    if name.startswith("spectron_dynamic_symbol_coverage_audit"):
        return "spectron_dynamic_symbol_coverage_audit"
    if name.startswith("spectron_dynamic_symbol_boundaries"):
        return "spectron_dynamic_symbol_boundaries"
    if name.startswith("spectron_semantic_translation_"):
        return "spectron_semantic_translation"
    if name.startswith("spectron_semantic_function_translation"):
        return "spectron_semantic_function_translation"
    return "other_generated_export"


def file_record(path: Path, archive_root: Path) -> tuple[dict, int, int]:
    digest = hashlib.sha256()
    byte_count = 0
    newline_count = 0
    last_byte = b""
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            byte_count += len(chunk)
            newline_count += chunk.count(b"\n")
            last_byte = chunk[-1:]

    lines = newline_count + (1 if byte_count and last_byte != b"\n" else 0)
    relative = path.relative_to(archive_root)
    record = {
        "source_path": relative.as_posix(),
        "archive_path": path.relative_to(ROOT).as_posix(),
        "kind": classify(relative),
        "bytes": byte_count,
        "lines": lines,
        "sha256": digest.hexdigest(),
    }
    return record, byte_count, lines


def build_manifest(archive_root: Path) -> dict:
    files = []
    total_bytes = 0
    total_lines = 0
    for path in sorted(archive_root.rglob("*")):
        if not path.is_file():
            continue
        record, byte_count, lines = file_record(path, archive_root)
        files.append(record)
        total_bytes += byte_count
        total_lines += lines

    return {
        "schema": "libqplay.research-archive-manifest.v1",
        "purpose": "Index large reproducible analysis exports kept outside Git.",
        "archive_root": archive_root.relative_to(ROOT).as_posix(),
        "tracked_source_paths": [record["source_path"] for record in files],
        "totals": {
            "file_count": len(files),
            "bytes": total_bytes,
            "lines": total_lines,
        },
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive-root",
        type=Path,
        default=DEFAULT_ARCHIVE_ROOT,
        help="Local archive directory, relative to the repository by default.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Manifest path, relative to the repository by default.",
    )
    args = parser.parse_args()

    archive_root = args.archive_root if args.archive_root.is_absolute() else ROOT / args.archive_root
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not archive_root.is_dir():
        parser.error(f"archive directory does not exist: {archive_root}")

    manifest = build_manifest(archive_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["totals"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
