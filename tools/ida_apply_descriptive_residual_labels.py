#!/usr/bin/env python3
"""Apply stable descriptive labels to the residual IDA functions.

The ELF symbol pass translates every preserved symbol. This narrower pass
labels only the remaining IDA-created functions whose roles were already
classified in ``ida_residual_profile.json``. It never invents an upstream
source name, refuses a different input library, and does not contact a
service.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import ida_nalt


REPO = Path(__file__).resolve().parents[1]
PROFILE = REPO / "artifacts/ida_residual_profile.json"
EXPECTED_BINARY_SHA256 = "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8"
PREFIXES = {
    "plt0_resolver": "ida_plt0_aarch64_resolver_",
    "init_or_fini_array_entry": "ida_init_fini_array_entry_",
    "tstring_static_cleanup_wrapper": "ida_tstring_static_cleanup_",
    "tstringlist_static_cleanup_wrapper": "ida_tstringlist_static_cleanup_",
    "tgraalvar_static_cleanup_wrapper": "ida_tgraalvar_static_cleanup_",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    ida_auto.auto_wait()
    input_path = Path(ida_nalt.get_input_file_path())
    if not input_path.is_file():
        raise RuntimeError(f"IDA input is not a readable file: {input_path}")
    actual_hash = sha256_file(input_path)
    if actual_hash != EXPECTED_BINARY_SHA256:
        raise RuntimeError(
            f"refusing library hash {actual_hash}; expected {EXPECTED_BINARY_SHA256}"
        )

    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    changed = []
    failures = []
    for item in profile["residual_default_sub_functions"]:
        old_name = item["current_ida_name"]
        prefix = PREFIXES.get(item["category"])
        if prefix is None:
            failures.append({"old_name": old_name, "error": "unknown category"})
            continue
        new_name = prefix + old_name[len("sub_"):].lower()
        new_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, new_name)
        old_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, old_name)
        if new_ea != ida_idaapi.BADADDR:
            ea = new_ea
        elif old_ea != ida_idaapi.BADADDR:
            ea = old_ea
            if not ida_name.set_name(ea, new_name, ida_name.SN_NOCHECK):
                failures.append({"old_name": old_name, "new_name": new_name, "error": "rename failed"})
                continue
            changed.append({"address": item["ea"], "old_name": old_name, "name": new_name})
        else:
            failures.append({"old_name": old_name, "new_name": new_name, "error": "neither name found"})
            continue
        if ida_name.get_name(ea) != new_name or ida_funcs.get_func(ea) is None:
            failures.append({"old_name": old_name, "new_name": new_name, "error": "label verification failed"})
            continue
        ida_bytes.set_cmt(
            ea,
            "Analyst label only. "
            + item["category"]
            + "; no preserved ELF source symbol was recovered.",
            True,
        )

    print(
        json.dumps(
            {
                "input_path": input_path.as_posix(),
                "binary_sha256": actual_hash,
                "profile_rows": len(profile["residual_default_sub_functions"]),
                "renamed": len(changed),
                "failures": failures,
                "network_contacted": False,
            },
            sort_keys=True,
        )
    )
    if failures:
        raise RuntimeError("descriptive residual label application failed")


if __name__ == "__main__":
    main()
