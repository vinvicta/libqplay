#!/usr/bin/env python3
"""Generate the focused static security review for the embedded GIF path.

The source-role report identifies the unnamed LZW helper. This companion
report keeps the security interpretation separate from source attribution. It
records the exact ARM64 branch and memory-operation observations made in IDA,
then compares them with public upstream vulnerability descriptions without
assigning a giflib release that the binary does not prove.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT.parent / "analysis" / "libqplay.function_inventory.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "gif_decoder_security_review_20260902.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_report(inventory_path: Path) -> dict:
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("IDA inventory must be a JSON list")
    rows = {int(item["ea"]): item for item in document}

    decoder = rows.get(0x2ACB20)
    slurp = rows.get(0x2AE6EC)
    if decoder is None:
        raise ValueError("GIF LZW helper is absent from the inventory")
    if decoder.get("name") != "giflib_DGifDecompressLine":
        raise ValueError(
            "GIF LZW helper is not named giflib_DGifDecompressLine: "
            f"{decoder.get('name')}"
        )
    if slurp is None or slurp.get("name") != "DGifSlurp":
        raise ValueError("DGifSlurp is absent from the inventory")

    return {
        "artifact": "gif_decoder_security_review_20260902",
        "schema": "libqplay.gif-decoder-security-review.v2",
        "tool": "tools/generate_gif_decoder_security_review.py",
        "tool_version": 2,
        "analysis_date": "2026-09-02",
        "analysis_scope": (
            "static comparison of the embedded giflib-style GIF decoder and "
            "its DGifSlurp allocation path"
        ),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "inventory": {
            "path": inventory_path.as_posix(),
            "sha256": sha256_file(inventory_path),
            "row_count": len(document),
        },
        "functions": {
            "lzw_line_decoder": {
                "address": "0x2acb20",
                "ida_name": decoder["name"],
                "size": int(decoder.get("size", 0)),
                "callers": ["DGifGetLine", "DGifGetPixel"],
                "source_role": "DGifDecompressLine",
            },
            "high_level_decoder": {
                "address": "0x2ae6ec",
                "ida_name": slurp["name"],
                "size": int(slurp.get("size", 0)),
                "source_role": "DGifSlurp",
            },
        },
        "observed_lzw_checks": [
            {
                "id": "LZW-STACKPTR-BOUND",
                "addresses": ["0x2acb64"],
                "instruction": "B.GT loc_2ACC3C after comparing StackPtr with 0xFFF",
                "interpretation": (
                    "The saved pixel stack is rejected before it is drained "
                    "when its index is above the 4095-entry table."
                ),
            },
            {
                "id": "LZW-RUNNING-CODE-CAP",
                "addresses": ["0x2acd08", "0x2acd10", "0x2acd14"],
                "instruction": (
                    "CMP W3, #0x1000; B.GT loc_2ACD40; ADD W3, W3, #1"
                ),
                "interpretation": (
                    "The input loop stops increasing RunningCode once it is "
                    "above 4096. In the observed control flow this keeps the "
                    "later RunningCode - 2 table index at or below 4095."
                ),
            },
            {
                "id": "LZW-CODE-INDEX-BOUNDS",
                "addresses": [
                    "0x2ace98",
                    "0x2aceb4",
                    "0x2aceb8",
                    "0x2aced8",
                    "0x2acedc",
                ],
                "instruction": "CMP index, #0xFFF followed by B.GT before table loads",
                "interpretation": (
                    "The dictionary and suffix accesses in the main trace loop "
                    "have explicit upper-bound branches before dependent loads."
                ),
            },
            {
                "id": "LZW-CHAIN-BOUNDS",
                "addresses": [
                    "0x2ad008",
                    "0x2ad00c",
                    "0x2ad024",
                    "0x2ad028",
                    "0x2ad02c",
                    "0x2ad070",
                    "0x2ad074",
                    "0x2ad08c",
                    "0x2ad090",
                    "0x2ad098",
                ],
                "instruction": "0xFFF checks and a 0x1000 iteration counter surround Prefix walks",
                "interpretation": (
                    "Malformed dictionary chains are bounded by both an index "
                    "check and a finite walk count before Prefix is read again."
                ),
            },
            {
                "id": "LZW-STACK-WRITE-BOUNDS",
                "addresses": ["0x2aceac", "0x2aceb0", "0x2acee0", "0x2acee4"],
                "instruction": "CMP StackPtr, #0xFFE followed by B.GT before stack writes",
                "interpretation": (
                    "The decoder rejects a full pixel stack before adding more "
                    "decoded suffix bytes."
                ),
            },
        ],
        "observed_slurp_hardening_gap": {
            "id": "GIF-003",
            "severity": "availability and memory-pressure risk",
            "addresses": [
                "0x2ae808",
                "0x2ae80c",
                "0x2ae814",
                "0x2ae824",
                "0x2ae8b4",
                "0x2ae8b8",
            ],
            "instruction": (
                "DGifSlurp multiplies width and height in W20, sign-extends "
                "the 32-bit result for reallocarray, and separately multiplies "
                "width by a row index in W3 before sign-extending the offset."
            ),
            "assessment": (
                "The path has no application pixel or cumulative decoded-byte "
                "budget. Its 32-bit arithmetic should be treated as a hardening "
                "gap even though this static pass does not demonstrate a memory "
                "corruption primitive."
            ),
        },
        "observed_extension_accumulation": {
            "id": "GIF-004",
            "severity": "availability and memory-pressure risk",
            "addresses": [
                "0x2ae77c",
                "0x2ae7a0",
                "0x2ae914",
                "0x2af03c",
                "0x2af04c",
                "0x2af074",
            ],
            "instruction": (
                "DGifSlurp passes every nonempty extension block to "
                "GifAddExtensionBlock; that helper grows the extension array "
                "with reallocarray(count + 1, 24), increments the count, and "
                "allocates the one-byte block length without an aggregate "
                "extension count or byte limit."
            ),
            "assessment": (
                "Each individual extension payload is limited by the GIF "
                "sub-block length byte to 255 bytes, but a file can present "
                "many blocks. Repeated accepted blocks can therefore retain "
                "unbounded extension metadata and payload memory until the "
                "decoder or allocator fails. This is a static resource-budget "
                "finding, not a demonstrated memory corruption primitive."
            ),
        },
        "upstream_context": [
            {
                "id": "CVE-2018-11489",
                "status": "conditional_not_mapped",
                "description": (
                    "NVD describes a heap buffer overflow in DGifDecompressLine "
                    "caused by an unchecked CrntCode array index."
                ),
                "affected_versions": "giflib 3.0 through 3.1.1 are listed by NVD",
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-11489",
                "comparison": (
                    "The current body has explicit 0xFFF checks around the "
                    "observed dependent dictionary loads. The exact giflib "
                    "release and malformed-input behavior remain unproven."
                ),
            },
            {
                "id": "CVE-2018-11490",
                "status": "conditional_not_mapped",
                "description": (
                    "MITRE describes a heap buffer overflow in DGifDecompressLine "
                    "caused by an unchecked Private->RunningCode - 2 index."
                ),
                "affected_versions": "giflib 3.0 through 3.1.1 are associated with the record",
                "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11490",
                "comparison": (
                    "The current body caps RunningCode growth at the 0x1000 "
                    "boundary and caps the pixel stack before writes. This is "
                    "evidence against a direct copy of the vulnerable pattern, "
                    "not proof that all decoder states are safe."
                ),
            },
            {
                "id": "CVE-2019-15133",
                "status": "conditional_not_mapped",
                "description": (
                    "NVD describes a divide-by-zero in DGifSlurp for a malformed "
                    "GIF with an ImageSize height of zero in GIFLIB before "
                    "2019-02-16."
                ),
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-15133",
                "comparison": (
                    "No direct zero-height divider was identified in the current "
                    "DGifSlurp body. The body does contain the separate unchecked "
                    "32-bit dimension multiplication recorded as GIF-003."
                ),
            },
        ],
        "source_comparison_references": [
            {
                "description": "Pinned giflib-style DGifDecompressLine role reference",
                "url": (
                    "https://android.googlesource.com/platform/external/giflib/+"
                    "/9aef3ea079a57c98a9207f8c3b95a5dc08ee74b5/dgif_lib.c#669"
                ),
            },
            {
                "description": "Older public decoder source showing the historical unchecked RunningCode - 2 writes",
                "url": "https://android.googlesource.com/platform/external/giflib/+/froyo/dgif_lib.c#838",
            },
            {
                "description": "giflib NEWS entry recording the CVE-2018-11490 fix in 5.1.5",
                "url": "https://github.com/aseprite/giflib/blob/master/NEWS#L2464",
            },
        ],
        "overall_assessment": (
            "The current ARM64 GIF LZW helper is not statically assigned any of "
            "the three reviewed upstream CVEs. Its visible bounds checks make "
            "the two 2018 dictionary-index patterns less likely to be present, "
            "but the exact giflib release is unknown and no malformed-image "
            "fuzzing was performed. GIF-003 remains an independent resource and "
            "integer-arithmetic hardening item. GIF-004 adds an unbounded "
            "extension-accumulation concern in DGifSlurp."
        ),
        "network_contacted": False,
        "fuzzing_performed": False,
        "not_claimed": [
            "That the APK contains a uniquely identified giflib release.",
            "That the reviewed CVEs are exploitable or absent under every malformed GIF input.",
            "That GIF-003 is a demonstrated out-of-bounds write.",
            "That GIF-004 is exploitable without a bounded malformed-GIF test.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", nargs="?", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    inventory = args.inventory if args.inventory.is_absolute() else Path.cwd() / args.inventory
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not inventory.is_file():
        parser.error(f"IDA inventory does not exist: {inventory}")
    report = build_report(inventory)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": output.as_posix(),
                "lzw_decoder": report["functions"]["lzw_line_decoder"]["ida_name"],
                "lzw_size": report["functions"]["lzw_line_decoder"]["size"],
                "findings": [
                    report["observed_slurp_hardening_gap"]["id"],
                    report["observed_extension_accumulation"]["id"],
                ],
                "inventory_rows": report["inventory"]["row_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
