#!/usr/bin/env python3
"""Export the evidence-backed labels applied to IDA residual functions.

The preserved ELF symbol pass already translated every retained symbol. This
report covers the remaining IDA-created functions with descriptive labels,
without presenting those labels as recovered upstream source names. It is
read-only and does not contact a service.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

import ida_auto
import ida_funcs
import ida_idaapi
import ida_name
import ida_nalt
import idautils


REPO = Path(__file__).resolve().parents[1]
PROFILE = REPO / "artifacts/ida_residual_profile.json"
OUTPUT = REPO / "artifacts/ida_descriptive_residual_labels_20260902.json"
SAVED_COPY = REPO.parent / "analysis/libqplay_translated_from_active_v14.i64"
PREFIXES = {
    "plt0_resolver": "ida_plt0_aarch64_resolver_",
    "init_or_fini_array_entry": "ida_init_fini_array_entry_",
    "tstring_static_cleanup_wrapper": "ida_tstring_static_cleanup_",
    "tstringlist_static_cleanup_wrapper": "ida_tstringlist_static_cleanup_",
    "tgraalvar_static_cleanup_wrapper": "ida_tgraalvar_static_cleanup_",
}


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    ida_auto.auto_wait()
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    rows = []
    failures = []
    for item in profile["residual_default_sub_functions"]:
        old_name = item["current_ida_name"]
        prefix = PREFIXES.get(item["category"])
        expected_name = prefix + old_name[len("sub_"):].lower() if prefix else ""
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, expected_name)
        if address == ida_idaapi.BADADDR:
            failures.append({"old_name": old_name, "error": "descriptive name not found"})
            continue
        name = ida_name.get_name(address) or ""
        function = ida_funcs.get_func(address)
        if function is None:
            failures.append({"old_name": old_name, "error": "function not found"})
            continue
        if name.startswith("sub_"):
            failures.append({"old_name": old_name, "error": "default name remains"})
            continue
        rows.append(
            {
                "address": item["ea"],
                "old_name": old_name,
                "name": name,
                "category": item["category"],
                "size": int(function.end_ea - function.start_ea),
                "comment": (
                    "Analyst label only. "
                    + item["category"]
                    + "; no preserved ELF source symbol was recovered."
                ),
            }
        )

    default_sub_count = sum(
        1
        for address in idautils.Functions()
        if (ida_name.get_name(address) or "").startswith("sub_")
    )
    report = {
        "schema": "libqplay.ida-descriptive-residual-labels.v1",
        "tool": "tools/ida_export_descriptive_residual_labels.py",
        "analysis_date": "2026-09-02",
        "input_path": ida_nalt.get_input_file_path(),
        "network_contacted": False,
        "saved_copy": {
            "path": "analysis/libqplay_translated_from_active_v14.i64",
            "bytes": SAVED_COPY.stat().st_size if SAVED_COPY.is_file() else None,
            "sha256": sha256_file(SAVED_COPY),
            "close_reopen_verified": False,
        },
        "profile_path": PROFILE.as_posix(),
        "profile_row_count": len(profile["residual_default_sub_functions"]),
        "exported_row_count": len(rows),
        "default_sub_count_after": default_sub_count,
        "failures": failures,
        "rows": rows,
        "interpretation": (
            "Each row is an evidence-backed descriptive label for a function "
            "that had no preserved ELF source name. The address suffix keeps "
            "the label stable and the category records the recovered role."
        ),
    }
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": OUTPUT.as_posix(),
                "profile_rows": len(profile["residual_default_sub_functions"]),
                "exported_rows": len(rows),
                "default_sub_count_after": default_sub_count,
                "failure_count": len(failures),
            },
            sort_keys=True,
        )
    )
    if failures or len(rows) != len(profile["residual_default_sub_functions"]):
        raise RuntimeError("descriptive residual label export failed")


if __name__ == "__main__":
    main()
