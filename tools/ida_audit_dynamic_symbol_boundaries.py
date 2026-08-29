"""Check whether retained Spectron dynamic function rows have IDA boundaries.

IDA may miss a function start even when the ELF dynamic table still records a
defined function symbol.  This read-only helper reports exact starts and
containing functions for that boundary audit.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_nalt
import idc


REPO = Path("/home/v/Desktop/graal-decomp/libqplay")
SYMBOL_AUDIT = Path(
    os.environ.get(
        "SPECTRON_SYMBOL_AUDIT",
        str(REPO / "artifacts/spectron_symbol_table_audit_20260827.json"),
    )
)
OUTPUT_PATH = Path(
    os.environ.get(
        "SPECTRON_BOUNDARY_AUDIT_OUTPUT",
        "/tmp/spectron_dynamic_symbol_boundaries.json",
    )
)


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
    document = json.loads(SYMBOL_AUDIT.read_text(encoding="utf-8"))
    target = document["spectron"]
    defined_indices = {
        row["index"] for row in target["defined_named_symbols"]
    }
    rows = []
    for symbol in target["named_symbols"]:
        if symbol["type_name"] != "FUNC" or symbol["index"] not in defined_indices:
            continue
        ea = int(symbol["value"])
        function = ida_funcs.get_func(ea)
        exact_start = function is not None and function.start_ea == ea
        rows.append(
            {
                "dynamic_index": symbol["index"],
                "dynamic_name": symbol["name"],
                "value": hex(ea),
                "size": symbol["size"],
                "ida_exact_start": exact_start,
                "ida_containing_start": (
                    hex(function.start_ea) if function is not None else None
                ),
                "ida_containing_end": (
                    hex(function.end_ea) if function is not None else None
                ),
                "ida_containing_name": (
                    ida_name.get_name(function.start_ea) if function is not None else None
                ),
                "instruction": idc.generate_disasm_line(ea, idc.GENDSM_FORCE_CODE),
                "bytes_hex": (ida_bytes.get_bytes(ea, 16) or b"").hex(),
            }
        )

    rows.sort(key=lambda row: int(row["value"], 16))
    result = {
        "artifact": "spectron_dynamic_symbol_boundary_audit",
        "network_contacted": False,
        "input": ida_nalt.get_input_file_path(),
        "input_sha256": input_sha256(),
        "dynamic_symbol_audit": str(SYMBOL_AUDIT),
        "defined_function_symbol_count": len(rows),
        "ida_exact_start_count": sum(row["ida_exact_start"] for row in rows),
        "ida_missing_exact_start_count": sum(
            not row["ida_exact_start"] for row in rows
        ),
        "rows": rows,
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "rows"}, sort_keys=True))


if __name__ == "__main__":
    main()
