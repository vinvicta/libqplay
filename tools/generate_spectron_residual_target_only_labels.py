#!/usr/bin/env python3
"""Create descriptive labels for the remaining Spectron residual functions.

The v317 cross-build pass exhausted the useful source-to-target matches.  The
remaining defaults are compiler-generated startup, cleanup, and resolver
entries.  This artifact gives them stable target-only labels so an IDA view
does not hide their behavior behind ``sub_`` names.  It does not pretend that
these labels restore source symbols.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ARTIFACT = "spectron_residual_target_only_labels_20260828"
EXPECTED_FUNCTION_COUNT = 11695
EXPECTED_DEFAULT_COUNT = 373

METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "return_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
    "register_detail_hash",
)

# These are the non-startup residuals classified from their reopened IDA
# pseudocode.  Tail-call wrappers do not appear in the compact feature export's
# direct-call list, so their address sets are kept explicitly here.
NONARRAY_ROLE_EAS = {
    "tstring_clear_wrapper": (
        "0xe431c",
        "0xe77e8",
        "0xe77f4",
        "0xe9168",
        "0xe9174",
        "0xe9184",
        "0xede0c",
        "0xede18",
        "0xede28",
        "0xede38",
        "0xf1a34",
        "0xf2414",
        "0xf2420",
        "0xf2430",
        "0xf2440",
        "0xf2450",
        "0xf2460",
        "0xf2470",
        "0xf2480",
        "0xf2490",
        "0xf24a0",
        "0xf68c8",
        "0xf68d4",
        "0xf68e4",
        "0x104de0",
        "0x106238",
        "0x1077b4",
        "0x10f7a0",
        "0x113b98",
        "0x11789c",
        "0x1178a8",
        "0x1178b8",
        "0x1178c8",
        "0x1178d8",
        "0x15dec8",
        "0x15ded4",
        "0x15dee4",
        "0x15def4",
        "0x160994",
        "0x1609a0",
        "0x1609b0",
        "0x169144",
        "0x169150",
        "0x17041c",
        "0x170428",
        "0x17fdac",
        "0x17fdbc",
        "0x17fdcc",
        "0x185128",
        "0x185134",
        "0x185144",
        "0x185154",
        "0x185164",
        "0x185174",
        "0x18f4ac",
        "0x1a46d0",
        "0x1a46dc",
        "0x1a46ec",
        "0x1a46fc",
        "0x1a470c",
        "0x1a471c",
        "0x1a472c",
        "0x1a473c",
        "0x1a474c",
        "0x1a475c",
        "0x1a476c",
        "0x1a477c",
        "0x1a478c",
        "0x1a479c",
        "0x1b0070",
        "0x1b0b70",
        "0x1b2184",
        "0x1b2190",
        "0x1b74dc",
        "0x1c0138",
        "0x1c4af8",
        "0x1ca730",
        "0x1d3e30",
        "0x1dded4",
        "0x1e0898",
        "0x1e3f60",
        "0x1e4d4c",
        "0x21b2e8",
        "0x21b2f4",
        "0x21b304",
        "0x21b314",
        "0x21f534",
        "0x22cc2c",
        "0x22cc38",
        "0x22f980",
        "0x22f990",
        "0x234b48",
        "0x234b54",
        "0x237700",
        "0x23a948",
        "0x23e12c",
        "0x242290",
        "0x24229c",
        "0x2422ac",
    ),
    "can_tfaz6bz_clear_wrapper": (
        "0x18f7d4",
        "0x18f7e4",
        "0x18f7f4",
        "0x213928",
        "0x213934",
        "0x213944",
        "0x213954",
        "0x213964",
        "0x213974",
        "0x213984",
        "0x213994",
        "0x21f478",
        "0x21f484",
        "0x21f494",
        "0x21f4a4",
        "0x21f4b4",
        "0x21f4c4",
        "0x21f4d4",
        "0x21f4e4",
        "0x21f4f4",
        "0x21f504",
        "0x21f514",
        "0x21f524",
        "0x22f8b4",
        "0x22f8c0",
        "0x22f8d0",
        "0x22f8e0",
        "0x22f8f0",
        "0x22f900",
        "0x22f910",
        "0x22f920",
        "0x22f930",
        "0x22f940",
        "0x22f950",
        "0x238ed0",
    ),
    "vuu_hgangcf_destructor_thunk": (
        "0xe36fc",
        "0xe9d74",
        "0x1d2f94",
        "0x234b18",
        "0x234b28",
        "0x234b38",
    ),
    "g0gxgajwbw_destructor_thunk": (
        "0x216058",
        "0x2387e4",
    ),
    "aarch64_plt_resolver": ("0xd1500",),
}

ROLE_METADATA = {
    "tstring_clear_wrapper": {
        "script_name": "TString.clear wrapper",
        "operation": "tail-calls C8THgaTQxF::clear on one fixed global TString-like object",
        "evidence": [
            "Reopened IDA pseudocode resolves the tail call to C8THgaTQxF::clear.",
            "The wrapper materializes one fixed global-object address before the tail call.",
            "The function is not a separately exported source routine; its label describes the generated cleanup wrapper role.",
        ],
    },
    "can_tfaz6bz_clear_wrapper": {
        "script_name": "CanTfaz6bZ.clear wrapper",
        "operation": "tail-calls CanTfaz6bZ::clear on one fixed global CanTfaz6bZ object",
        "evidence": [
            "Reopened IDA pseudocode resolves the tail call to CanTfaz6bZ::clear.",
            "The wrapper materializes one fixed global-object address before the tail call.",
            "The function is a generated cleanup wrapper, not an independently named upstream source routine.",
        ],
    },
    "vuu_hgangcf_destructor_thunk": {
        "script_name": "vuuHgangcF destructor thunk",
        "operation": "tail-calls the vuuHgangcF destructor for one fixed global object",
        "evidence": [
            "Reopened IDA pseudocode and disassembly resolve the tail call to vuuHgangcF::~vuuHgangcF.",
            "The wrapper materializes one fixed global-object address before the destructor call.",
            "The label records a compiler-generated destructor thunk rather than inventing a source method name.",
        ],
    },
    "g0gxgajwbw_destructor_thunk": {
        "script_name": "G0gxgajWBw destructor thunk",
        "operation": "tail-calls the G0gxgajWBw destructor for one fixed global object",
        "evidence": [
            "Reopened IDA pseudocode resolves the tail call to G0gxgajWBw::~G0gxgajWBw.",
            "The wrapper materializes one fixed global-object address before the destructor call.",
            "The label records a compiler-generated destructor thunk rather than inventing a source method name.",
        ],
    },
    "aarch64_plt_resolver": {
        "script_name": "AArch64 PLT resolver",
        "operation": "dispatches through the dynamic-linker resolver slot for lazy PLT binding",
        "evidence": [
            "The address is the first 20-byte entry in the target .plt section at 0xd1500.",
            "The body is the AArch64 lazy-binding resolver veneer and is not an imported application function.",
            "The target-only label makes the resolver explicit without treating it as a game routine.",
        ],
    },
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(document: dict) -> dict[str, dict]:
    return {row["ea"].lower(): row for row in document["functions"]}


def label_name(role: str, ea: str) -> str:
    if role == "aarch64_plt_resolver":
        return "spectron_aarch64_plt_resolver"
    return "spectron_%s_%s" % (role, ea)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spectron-binary-sha256", required=True)
    parser.add_argument("--artifact", default=ARTIFACT)
    args = parser.parse_args()

    document = load(args.spectron_features)
    if document.get("function_count") != EXPECTED_FUNCTION_COUNT:
        raise ValueError("unexpected Spectron function count")
    rows = by_ea(document)
    defaults = {
        ea: row for ea, row in rows.items() if row.get("is_default_name")
    }
    if len(defaults) != EXPECTED_DEFAULT_COUNT:
        raise ValueError("unexpected Spectron default-name count: %d" % len(defaults))

    classifications = {}
    for role, addresses in NONARRAY_ROLE_EAS.items():
        for ea in addresses:
            key = ea.lower()
            if key in classifications:
                raise ValueError("duplicate residual classification: %s" % ea)
            classifications[key] = role

    for ea in defaults:
        value = int(ea, 16)
        if 0xDFB64 <= value <= 0xE0470:
            if ea in classifications:
                raise ValueError("startup entry overlaps non-array classification: %s" % ea)
            role = "fini_array_entry"
        elif 0xE0480 <= value <= 0xE168C:
            if ea in classifications:
                raise ValueError("startup entry overlaps non-array classification: %s" % ea)
            role = "init_array_entry"
        else:
            role = classifications.get(ea)
            if role is None:
                raise ValueError("unclassified Spectron residual: %s" % ea)
        if ea not in classifications:
            classifications[ea] = role

    if set(classifications) != set(defaults):
        missing = sorted(set(defaults) - set(classifications))
        extra = sorted(set(classifications) - set(defaults))
        raise ValueError("classification mismatch, missing=%s extra=%s" % (missing, extra))

    labels = []
    for ea in sorted(classifications, key=lambda item: int(item, 16)):
        row = defaults[ea]
        role = classifications[ea]
        if role == "fini_array_entry":
            script_name = ".fini_array entry"
            operation = "runs as a compiler-generated global finalizer entry"
            evidence = [
                "The function pointer lies in the target .fini_array address range.",
                "The target ELF .fini_array table points at this function start.",
                "No independent upstream source symbol is claimed for this startup entry.",
            ]
        elif role == "init_array_entry":
            script_name = ".init_array entry"
            operation = "runs as a compiler-generated global initializer entry"
            evidence = [
                "The function pointer lies in the target .init_array address range.",
                "The target ELF .init_array table points at this function start.",
                "No independent upstream source symbol is claimed for this startup entry.",
            ]
        else:
            metadata = ROLE_METADATA[role]
            script_name = metadata["script_name"]
            operation = metadata["operation"]
            evidence = metadata["evidence"]
        labels.append(
            {
                "target_ea": ea,
                "current_name": row["name"],
                "function_end": row["end_ea"],
                "proposed_name": label_name(role, ea),
                "target_default_name": True,
                "target_metrics": {
                    field: row.get(field) for field in METRIC_FIELDS
                },
                "target_string_refs": row.get("string_refs", []),
                "target_direct_call_names": row.get("direct_call_names", []),
                "script_name": script_name,
                "role": role,
                "operation": operation,
                "source_counterpart": None,
                "source_counterpart_status": "not-demonstrated",
                "confidence": "high",
                "match_kind": "reviewed-target-only-residual-role",
                "evidence": evidence,
                "name_action": "rename-with-spectron-prefix",
            }
        )

    role_counts = {}
    for label in labels:
        role_counts[label["role"]] = role_counts.get(label["role"], 0) + 1

    result = {
        "schema_version": 1,
        "artifact": args.artifact,
        "scope": (
            "reviewed target-only labels for residual Spectron startup entries, "
            "compiler-generated cleanup wrappers, destructor thunks, a global "
            "initializer, and the AArch64 PLT resolver"
        ),
        "network_contacted": False,
        "inputs": {
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
        },
        "context": {
            "database_frontier": "v317 Spectron translated database",
            "startup_ranges": {
                ".fini_array": "0xdfb64 through 0xe0470",
                ".init_array": "0xe0480 through 0xe168c",
            },
            "plt_resolver": "0xd1500 through 0xd1514",
            "mapping_boundary": (
                "These are target-only behavior labels. They make residual IDA "
                "functions explicit but do not assert that a matching 1.8 source "
                "symbol exists."
            ),
            "role_resolution": (
                "reopened IDA pseudocode and disassembly for non-array entries, "
                "target ELF startup-table placement for array entries, and the "
                "known AArch64 PLT layout"
            ),
        },
        "summary": {
            "label_count": len(labels),
            "high_confidence_count": len(labels),
            "target_default_name_count": len(labels),
            "target_only_count": len(labels),
            "startup_array_count": role_counts.get("fini_array_entry", 0)
            + role_counts.get("init_array_entry", 0),
            "fini_array_entry_count": role_counts.get("fini_array_entry", 0),
            "init_array_entry_count": role_counts.get("init_array_entry", 0),
            "tstring_clear_wrapper_count": role_counts.get(
                "tstring_clear_wrapper", 0
            ),
            "can_tfaz6bz_clear_wrapper_count": role_counts.get(
                "can_tfaz6bz_clear_wrapper", 0
            ),
            "vuu_hgangcf_destructor_thunk_count": role_counts.get(
                "vuu_hgangcf_destructor_thunk", 0
            ),
            "g0gxgajwbw_destructor_thunk_count": role_counts.get(
                "g0gxgajwbw_destructor_thunk", 0
            ),
            "aarch64_plt_resolver_count": role_counts.get(
                "aarch64_plt_resolver", 0
            ),
        },
        "labels": labels,
        "interpretation": [
            "The spectron_ prefix marks a target-specific descriptive label rather than a restored source symbol.",
            "The 230 startup labels are indexed by their function address because the stripped target does not retain the global C++ object names.",
            "The cleanup-wrapper labels preserve the concrete class operation visible in reopened IDA pseudocode and leave each fixed object address in the target metrics and function location.",
            "The AArch64 PLT resolver is called out separately because it is linkage machinery, not a game function.",
            "After these labels are applied, the target should have no remaining auto-generated default sub_ names. That is a naming-coverage result, not proof that every original source symbol was recoverable.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
