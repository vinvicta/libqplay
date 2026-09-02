#!/usr/bin/env python3
"""Generate the focused static review of ZIP-backed resources.

The report ties the bundled minizip callers to the application resource and
script extraction paths. It records bounds and cleanup observations without
claiming that an archive made the native client crash or that a ZIP entry name
escapes the application's intended directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "symbols" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "zip_resource_security_review_20260902.json"
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
        "zip_resource_scanner": function_row(
            rows, 0xE8BAC, "TFileNameScan_scanZipResource_TResourceObject"
        ),
        "resource_stream_loader": function_row(
            rows, 0xEFE7C, "TResourceObject_getStream_void"
        ),
        "script_extract_callback": function_row(
            rows, 0xFCA80, "TFileScripting_script_decompressFile"
        ),
        "zip_open": function_row(rows, 0x24A624, "unzOpen2"),
        "zip_file_info": function_row(
            rows, 0x24840C, "minizip_unz64local_GetCurrentFileInfoInternal"
        ),
        "zip_open_current": function_row(
            rows, 0x24B6FC, "unzOpenCurrentFile3"
        ),
        "zip_read_current": function_row(
            rows, 0x24B174, "unzReadCurrentFile"
        ),
        "zip_close_current": function_row(
            rows, 0x24B620, "unzCloseCurrentFile"
        ),
        "stream_set_size": function_row(rows, 0xF0644, "TStream_setSize_int"),
        "string_set_size": function_row(
            rows, 0xF10B8, "TString_setSize_int_bool"
        ),
        "stream_save_file": function_row(
            rows, 0xF0AA8, "TStream_SaveToFile_TString_const_uint"
        ),
        "script_package_compile": function_row(
            rows,
            0x22CF78,
            "TScriptUniverse_compileZippedScripts_TString_const",
        ),
    }

    return {
        "artifact": "zip_resource_security_review_20260902",
        "schema": "libqplay.zip-resource-security-review.v1",
        "tool": "tools/generate_zip_resource_security_review.py",
        "tool_version": 1,
        "analysis_date": "2026-09-02",
        "analysis_scope": (
            "static review of the bundled minizip entrypoints, ZIP-backed "
            "resource streams, and the script-facing extraction callback"
        ),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "library_identity": {
            "minizip_release": "not recovered",
            "zlib_version": "1.2.5",
            "zlib_version_address": "0x289b50",
            "entrypoints_are_statically_embedded": True,
        },
        "functions": functions,
        "application_limits": {
            "zip_resource_entry_count_cap": 10000,
            "zip_resource_individual_reported_uncompressed_size_cap": 1073741824,
            "zip_resource_filename_buffer_bytes": 256,
            "minizip_deflate_work_buffer_bytes": 16384,
            "script_wildcard_behavior": (
                "decompressfile can walk every loaded child resource when its "
                "pattern argument is '*', subject to the resource list that "
                "was already created"
            ),
            "aggregate_decoded_byte_cap": None,
        },
        "flow": {
            "resource_zip": [
                "TFileNameScan_scanZipResource_TResourceObject",
                "unzOpen",
                "unzGetGlobalInfo",
                "unzGetCurrentFileInfo",
                "TResourceObject_addZipFile_TResourceObject",
                "TResourceObject_getStream_void",
                "TStream_setSize_int",
                "unzReadCurrentFile",
                "unzCloseCurrentFile",
            ],
            "signed_connector_zip": [
                "TScriptUniverse_compileZippedScripts_TString_const",
                "TEncryption_rsa_verify_TString_const_TString_const_TString_const",
                "unzOpen",
                "unzReadCurrentFile",
                "TScriptUniverse_addZippedScripts_TString_const_TSocketConnection",
            ],
            "script_extract": [
                "TFileScripting_script_decompressFile",
                "TResourceObject_getStream_void",
                "TStream_SaveToFile_TString_const_uint",
            ],
            "trust_distinction": (
                "The connector package is behind its outer RSA verification. "
                "Ordinary ZIP-backed resources use the resource and game-file "
                "trust path instead; this report does not assign either path a "
                "live remote reachability result."
            ),
        },
        "findings": [
            {
                "id": "ZIP-001",
                "severity": "availability and resource-policy gap, conditional",
                "addresses": [
                    "0xe8bac",
                    "0x24a55c",
                    "0x24a57c",
                    "0x24840c",
                    "0xefe7c",
                    "0xfca80",
                    "0xf0aa8",
                ],
                "instruction": (
                    "The ZIP resource scanner clamps the global entry count to "
                    "10000 and skips entries whose reported uncompressed size "
                    "exceeds 0x40000000. For each accepted entry it creates or "
                    "links a resource object. The stream loader then sizes a "
                    "native TString from the entry's recorded size before "
                    "reading it. The script decompressfile callback can select "
                    "one entry or use '*' to save every loaded child resource."
                ),
                "evidence": {
                    "entry_count_cap_address": "0xe8cbc",
                    "individual_size_check_address": "0xe8d58",
                    "stream_size_address": "0xeff74",
                    "unz_read_address": "0xeff90",
                    "wildcard_test_address": "0xfcbc8",
                    "save_address": "0xfcc64",
                },
                "assessment": (
                    "The two local limits reduce individual archive abuse but do "
                    "not impose an aggregate decoded-byte, cumulative stream, "
                    "or total extraction budget. Ten thousand entries can each "
                    "pass the individual check, and the wildcard script path can "
                    "turn the already-created resource set into many disk writes. "
                    "This is a conditional availability and resource-policy "
                    "finding, not a claim of arbitrary file write or a reproduced "
                    "remote denial of service."
                ),
            },
            {
                "id": "ZIP-002",
                "severity": "format-integrity and parser-robustness gap, conditional",
                "addresses": [
                    "0xefe7c",
                    "0xeff74",
                    "0xeff90",
                    "0x24b174",
                    "0xf0644",
                    "0xf10b8",
                ],
                "instruction": (
                    "TResourceObject_getStream_void copies the archive metadata "
                    "size into TStream_setSize_int, calls unzReadCurrentFile with "
                    "the resulting data pointer and capacity, and only tests the "
                    "sign bit of the returned count. It does not compare a "
                    "non-negative return value with the declared entry size. "
                    "TStream_setSize_int calls TString_setSize_int_bool with its "
                    "boolean argument set, so a newly extended buffer is cleared "
                    "before the ZIP read."
                ),
                "evidence": {
                    "declared_size_load_address": "0xeff6c",
                    "stream_set_size_call_address": "0xeff74",
                    "destination_capacity_load_address": "0xeff80",
                    "unz_read_call_address": "0xeff90",
                    "negative_only_test_address": "0xeff90",
                    "zero_fill_call_address": "0xf0668",
                },
                "assessment": (
                    "If minizip returns a short non-negative count for a stored or "
                    "otherwise truncated member, the logical stream length can "
                    "remain equal to the archive-declared size even though fewer "
                    "bytes were read. The cleared remainder can then be consumed "
                    "as zero padding by later resource parsers. The exact malformed "
                    "archive state that produces each return code still needs a "
                    "bounded harness."
                ),
            },
            {
                "id": "ZIP-003",
                "severity": "conditional resource leak on decoder initialization failure",
                "addresses": [
                    "0x24b6fc",
                    "0x24b760",
                    "0x24b76c",
                    "0x24b844",
                    "0x24ba80",
                    "0x24b620",
                ],
                "instruction": (
                    "unzOpenCurrentFile3 allocates a 0x120-byte current-file state "
                    "and a 0x4000-byte work buffer. For deflate entries it calls "
                    "inflateInit2_. If that call returns an error, the function "
                    "returns the error before assigning the state to the parent "
                    "ZIP handle. The normal unzCloseCurrentFile cleanup path can "
                    "therefore not see those allocations."
                ),
                "evidence": {
                    "state_allocation_address": "0x24b760",
                    "work_buffer_allocation_address": "0x24b76c",
                    "inflate_init_address": "0x24b844",
                    "error_return_address": "0x24ba80",
                    "parent_state_assignment_address": "0x24b87c",
                    "cleanup_entrypoint": "0x24b620",
                },
                "assessment": (
                    "Repeated entries that reach an inflate initialization error "
                    "can leak the temporary state and work buffer until process "
                    "termination. The failure may be caused by allocation pressure "
                    "or decoder initialization state. No malformed archive was "
                    "run, so the report treats this as a conditional cleanup "
                    "finding rather than a demonstrated leak loop."
                ),
            },
        ],
        "hardening_observations": [
            {
                "address": "0x24a624",
                "observation": (
                    "unzOpen2 allocates a 0x150-byte archive state and immediately "
                    "copies the file-function table into it at 0x24ac98 without a "
                    "visible null check. This is an allocation-failure crash "
                    "observation, not an archive-controlled memory-corruption claim."
                ),
            },
            {
                "address": "0xe8d44",
                "observation": (
                    "The scanner passes a 256-byte filename destination to "
                    "unzGetCurrentFileInfo. The path uses the entry name as a "
                    "virtual resource key; this review did not find a direct disk "
                    "write of the raw ZIP entry name in that scanner."
                ),
            },
        ],
        "not_claimed": [
            "That the exact minizip release or vendor patch level has been recovered.",
            "That ZIP-001 is reachable from an unsigned connector package; the connector path has an outer RSA gate.",
            "That a ZIP entry name escapes the application root in the reviewed resource scanner.",
            "That ZIP-002 produces a parser confusion state for every truncated archive form.",
            "That ZIP-003 was reproduced with an archive or allocation-failure harness.",
            "That any production endpoint was contacted during this review.",
        ],
        "fuzzing_performed": False,
        "runtime_reproduction": False,
        "network_contacted": False,
        "overall_assessment": (
            "The ZIP path has useful per-archive and per-entry limits, but it "
            "needs an aggregate decoded-byte budget, exact read-count validation, "
            "and cleanup on every decoder initialization error. Resource ZIPs and "
            "the signed connector ZIP should remain separate trust cases in a "
            "future bounded harness."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    inventory = args.inventory
    output = args.output
    if not inventory.is_absolute():
        inventory = ROOT / inventory
    if not output.is_absolute():
        output = ROOT / output
    if not inventory.is_file():
        raise SystemExit(f"IDA inventory does not exist: {inventory}")
    report = build_report(inventory)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": output.as_posix(),
                "findings": [item["id"] for item in report["findings"]],
                "inventory_rows": report["inventory"]["row_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
