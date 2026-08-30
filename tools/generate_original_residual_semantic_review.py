#!/usr/bin/env python3
"""Build a compact semantic review for selected unnamed IDA functions.

The structural fields come from the final residual audit. The observations
were written after reviewing pseudocode and cross-references in the active
ARM64 IDA database. This report deliberately keeps source names unresolved
when the binary does not prove them, and it never contacts a network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT = ROOT / "artifacts" / "ida_final_residual_audit_20260830.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "original_residual_semantic_review_20260830.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8"


OBSERVATIONS = {
    "0x250e94": {
        "role": "FreeType face or driver cleanup helper",
        "confidence": "high",
        "reference_context": ["FT_Done_Face", "sub_252E90"],
        "observed_behavior": [
            "Invokes an object-local callback when the callback slot at object offset 16 is set.",
            "Invokes a driver callback reached through the object at offset 40 and vtable offset 120 when present.",
            "Frees the allocation at object offset 80, clears that field, and frees the object itself.",
        ],
        "source_name_status": "exact FreeType source name not established",
    },
    "0x25e504": {
        "role": "signed fixed-point multiplication helper",
        "confidence": "medium",
        "reference_context": ["TT_RunIns"],
        "observed_behavior": [
            "Takes the absolute values of both signed inputs and multiplies their high and low halves.",
            "Adds a 0x2000 rounding term and shifts the combined result by 14 bits.",
            "Restores the sign from the XOR of the original inputs.",
        ],
        "source_name_status": "FT_MulFix-like behavior, exact source name not established",
    },
    "0x25e618": {
        "role": "signed overflow-aware arithmetic helper",
        "confidence": "medium",
        "reference_context": ["TT_RunIns"],
        "observed_behavior": [
            "Uses subtraction when the first arithmetic input is negative and addition otherwise.",
            "Returns zero for the observed positive-result overflow cases and otherwise returns the computed value.",
        ],
        "source_name_status": "exact FreeType source name not established",
    },
    "0x25e640": {
        "role": "TrueType fixed-point projection or transform helper",
        "confidence": "medium",
        "reference_context": ["TT_RunIns", "sub_260050"],
        "observed_behavior": [
            "Reads two signed 16-bit coefficients from object offsets 538 and 540.",
            "Combines those coefficients with two 32-bit fixed-point inputs, including their high and low halves.",
            "Performs carry-aware addition, adds 0x2000 for rounding, and returns a value shifted by 14 bits.",
        ],
        "source_name_status": "exact TrueType source name not established",
    },
    "0x25e6cc": {
        "role": "TrueType interpreter identity callback",
        "confidence": "high",
        "reference_context": ["TT_RunIns", "sub_260050"],
        "observed_behavior": ["Returns its second argument unchanged."],
        "source_name_status": "compiler or library callback name unresolved",
    },
    "0x25e6d4": {
        "role": "TrueType interpreter identity callback",
        "confidence": "high",
        "reference_context": ["TT_RunIns", "sub_260050"],
        "observed_behavior": ["Returns its third argument unchanged."],
        "source_name_status": "compiler or library callback name unresolved",
    },
    "0x25e6dc": {
        "role": "TrueType stream vector reader",
        "confidence": "high",
        "reference_context": ["TT_RunIns"],
        "observed_behavior": [
            "Reads a count from the stream state and checks it against the remaining byte range.",
            "On success, consumes count big-endian 16-bit values and writes them as signed values to the caller buffer.",
            "Advances the stream position and updates the consumed-byte count; an invalid count stores error 130.",
        ],
        "source_name_status": "exact TrueType source name not established",
    },
    "0x25ec84": {
        "role": "TrueType projection delta accumulator",
        "confidence": "medium",
        "reference_context": ["TT_RunIns", "sub_260050"],
        "observed_behavior": [
            "Scales the input with FT_MulDiv using the signed coefficients at object offsets 542 and 544.",
            "Adds the scaled value to the x and y slots selected by the point index.",
            "Updates the interpreter point arrays without setting the per-point projection flags used by the paired helper.",
        ],
        "source_name_status": "exact TrueType source name not established",
    },
    "0x25ed14": {
        "role": "TrueType projection delta accumulator with flags",
        "confidence": "medium",
        "reference_context": ["TT_RunIns", "sub_260050"],
        "observed_behavior": [
            "Uses the same two signed projection coefficients and FT_MulDiv scaling as the paired helper at 0x25ec84.",
            "Adds the results to the selected x and y point slots.",
            "Sets flag bits 8 and 16 in the point state when the corresponding projection coefficient is active.",
        ],
        "source_name_status": "exact TrueType source name not established",
    },
    "0x256060": {
        "role": "FreeType diagnostic byte-string sanitizer",
        "confidence": "high",
        "reference_context": ["sub_25A8E0"],
        "observed_behavior": [
            "Reads a 16-bit length and source pointer from the input object.",
            "Reallocates a destination buffer for length plus a terminator and returns null on allocator error.",
            "Copies the bytes with NEON blocks where possible and replaces values outside the printable 0x20 through 0x7f range with '?'.",
            "Always writes a trailing null byte on the successful path.",
        ],
        "source_name_status": "exact FreeType trace helper name not established",
    },
    "0x2563d0": {
        "role": "FreeType diagnostic 16-bit string sanitizer",
        "confidence": "high",
        "reference_context": ["sub_25A8E0"],
        "observed_behavior": [
            "Reads a 16-bit byte length, treats the input as interleaved 16-bit character data, and allocates one output byte per code unit plus a terminator.",
            "Converts the selected byte from each code unit to a single-byte diagnostic string.",
            "Replaces values outside the printable 0x20 through 0x7f range with '?'.",
            "Writes a trailing null byte on the successful path.",
        ],
        "source_name_status": "exact FreeType trace helper name not established",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_report(audit_path: Path) -> dict:
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if audit.get("binary_sha256") != EXPECTED_BINARY_SHA256:
        raise ValueError("residual audit is for a different binary")
    rows = {row["ea"]: row for row in audit.get("residual_functions", [])}
    selected = []
    for ea, observation in OBSERVATIONS.items():
        row = rows.get(ea)
        if row is None:
            raise ValueError(f"selected residual is missing from audit: {ea}")
        selected.append({
            "address": ea,
            "ida_name": row.get("name", f"sub_{ea[2:].upper()}"),
            "size": row["size"],
            "xrefs_to": row.get("xrefs_to"),
            **observation,
        })
    selected.sort(key=lambda row: int(row["address"], 16))
    return {
        "schema": "libqplay.ida-residual-semantic-review.v1",
        "tool": "tools/generate_original_residual_semantic_review.py",
        "tool_version": 1,
        "analysis_date": "2026-08-30",
        "analysis_scope": "selected unnamed functions in the original ARM64 libqplay.so IDA database",
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "network_contacted": False,
        "method": [
            "Function sizes and xref counts are checked against the final residual audit.",
            "Semantic observations come from active-IDB pseudocode and xref review.",
            "No exact source name is added unless the binary provides enough evidence.",
        ],
        "coverage": {
            "total_default_sub_functions": len(audit.get("residual_functions", [])),
            "reviewed_functions": len(selected),
            "reviewed_regions": {
                "freetype_static_internal": 9,
                "freetype_diagnostic_helpers": 2,
            },
        },
        "observations": selected,
        "conclusions": [
            "The selected high-reference routines are embedded FreeType or TrueType support code, not new Android bridge functions.",
            "The xref context places the arithmetic and stream helpers under the TrueType interpreter tables and execution path.",
            "The cleanup helper is reached from FT_Done_Face, while the string helpers are reached from a FreeType internal object routine.",
            "These observations narrow the remaining symbol queue without changing the 418-function residual count or inventing names.",
        ],
        "not_claimed": [
            "An exact upstream FreeType 2.3.6 source identifier for each residual function.",
            "A security finding from these internal routines alone.",
            "Coverage of every residual JPEG or FreeType function.",
        ],
        "source_audit": {
            "path": audit_path.as_posix(),
            "sha256": sha256_file(audit_path),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", nargs="?", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    audit = args.audit if args.audit.is_absolute() else Path.cwd() / args.audit
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not audit.is_file():
        parser.error(f"residual audit does not exist: {audit}")
    report = build_report(audit)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "binary_sha256": report["binary_sha256"],
        "reviewed_functions": report["coverage"]["reviewed_functions"],
        "total_default_sub_functions": report["coverage"]["total_default_sub_functions"],
        "output": output.as_posix(),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
