"""Audit function-name coverage in a translated Spectron IDA database.

This is deliberately a read-only audit.  It separates names that look like
retained target names from names added by the translation work and from IDA's
default names.  The result is useful because a zero ``sub_`` count does not,
by itself, mean that the original source names were recovered.

Run it with IDALIB or from an open IDA database.  Set
``SPECTRON_NAME_COVERAGE_OUTPUT`` to choose the JSON output path.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_nalt
import ida_xref
import idc
import idautils


DEFAULT_PATTERNS = {
    "sub": re.compile(r"^sub_[0-9A-Fa-f]+$"),
    "nullsub": re.compile(r"^nullsub_[0-9A-Fa-f]+$"),
    "j": re.compile(r"^j_[0-9A-Fa-f]+$"),
    "loc": re.compile(r"^loc_[0-9A-Fa-f]+$"),
    "unk": re.compile(r"^unk_[0-9A-Fa-f]+$"),
}
OUTPUT_PATH = Path(
    os.environ.get(
        "SPECTRON_NAME_COVERAGE_OUTPUT",
        "/tmp/spectron_name_coverage_audit.json",
    )
)


def default_kind(name: str) -> str | None:
    for kind, pattern in DEFAULT_PATTERNS.items():
        if pattern.fullmatch(name):
            return kind
    return None


def name_origin(name: str, default: str | None) -> str:
    if default is not None:
        return "ida_default"
    if name.startswith("spectron_"):
        return "target_only_descriptive"
    if name.startswith("v18_"):
        return "translated_v18_alias"
    if name.startswith("Java_"):
        return "target_jni_export"
    if name.startswith("_Z") or name.startswith("CyaSSL"):
        return "target_named_export"
    return "ida_named_or_other"


def xrefs_to(ea: int) -> int:
    block = ida_xref.xrefblk_t()
    count = 0
    if block.first_to(ea, 0):
        count = 1
        while block.next_to():
            count += 1
    return count


def input_sha256() -> str | None:
    for method_name in ("retrieve_input_file_sha256", "get_input_file_sha256"):
        method = getattr(ida_nalt, method_name, None)
        if method is None:
            continue
        try:
            value = method()
        except Exception:
            continue
        if isinstance(value, bytes):
            return value.hex()
        if value:
            return str(value)
    return None


def main() -> None:
    ida_auto.auto_wait()
    rows = []
    origins = Counter()
    defaults = Counter()

    for ea in idautils.Functions():
        function = ida_funcs.get_func(ea)
        if function is None:
            continue
        name = ida_name.get_name(ea) or ""
        default = default_kind(name)
        origin = name_origin(name, default)

        origins[origin] += 1
        if default is not None:
            defaults[default] += 1
        rows.append(
            {
                "ea": hex(int(ea)),
                "name": name,
                "name_origin": origin,
                "default_kind": default,
                "size": int(function.end_ea - function.start_ea),
                "bytes_hex": (
                    ida_bytes.get_bytes(ea, min(32, function.end_ea - ea)) or b""
                ).hex(),
                "first_instruction": idc.generate_disasm_line(
                    ea, idc.GENDSM_FORCE_CODE
                ),
                "xrefs_to": xrefs_to(ea),
            }
        )

    rows.sort(key=lambda row: int(row["ea"], 16))
    result = {
        "artifact": "spectron_name_coverage_audit",
        "network_contacted": False,
        "input": ida_nalt.get_input_file_path(),
        "input_sha256": input_sha256(),
        "function_count": len(rows),
        "default_name_count": sum(defaults.values()),
        "default_name_kinds": dict(sorted(defaults.items())),
        "name_origins": dict(sorted(origins.items())),
        "rows": rows,
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, sort_keys=True))


if __name__ == "__main__":
    main()
