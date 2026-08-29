"""Join retained Spectron dynamic symbols to the v320 IDA name inventory.

The Spectron ELF has no static symbol table or DWARF, but it does retain a
large dynamic table.  This report joins those rows to the translated IDA
database's name audit without guessing names for symbols that have no
function at their ELF value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ARTIFACT = "spectron_symbol_translation_inventory_20260828"
EXPECTED_BINARY_SHA256 = (
    "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219"
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--symbols", required=True, type=Path)
    parser.add_argument("--name-audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binary-sha256", default=EXPECTED_BINARY_SHA256)
    args = parser.parse_args()

    symbols_document = load(args.symbols)
    name_document = load(args.name_audit)
    target = symbols_document["spectron"]
    if target["input"]["sha256"] != args.binary_sha256:
        raise ValueError("dynamic-symbol input hash does not match target library")
    if name_document.get("input_sha256") != args.binary_sha256:
        raise ValueError("name-audit input hash does not match target library")

    dynamic_rows = target["named_symbols"]
    defined_indices = {
        row["index"] for row in target["defined_named_symbols"]
    }
    function_rows = {
        int(row["ea"], 16): row
        for row in name_document.get("rows", [])
    }

    status_counts = Counter()
    type_counts = Counter()
    rows = []
    for symbol in dynamic_rows:
        value = int(symbol["value"])
        function = function_rows.get(value)
        if function is None:
            status = "no_ida_function_at_symbol_value"
        elif function["name_origin"] == "translated_v18_alias":
            status = "source_backed_v18_alias"
        elif function["name_origin"] == "target_only_descriptive":
            status = "target_only_descriptive_label"
        elif function["name_origin"] == "ida_default":
            status = "ida_default_name"
        elif function["name_origin"] in {
            "target_named_export",
            "target_jni_export",
        }:
            status = "retained_target_name"
        else:
            status = "ida_named_or_other"

        defined = symbol["index"] in defined_indices
        type_name = symbol["type_name"]
        type_counts[type_name] += 1
        status_counts[status] += 1
        rows.append(
            {
                "dynamic_index": symbol["index"],
                "dynamic_name": symbol["name"],
                "binding": symbol["binding_name"],
                "type": type_name,
                "section_index": symbol["section_index"],
                "value": hex(value),
                "size": symbol["size"],
                "is_defined": defined,
                "ida_function_match": function is not None,
                "ida_name": function["name"] if function else None,
                "ida_name_origin": function["name_origin"] if function else None,
                "translation_status": status,
            }
        )

    rows.sort(key=lambda row: (int(row["value"], 16), row["dynamic_index"]))
    result = {
        "schema_version": 1,
        "artifact": ARTIFACT,
        "network_contacted": False,
        "scope": "complete retained Spectron named dynamic-symbol rows joined to the v320 IDA name audit",
        "inputs": {
            "spectron_symbol_table_audit": str(args.symbols),
            "spectron_symbol_table_audit_sha256": sha256_path(args.symbols),
            "spectron_name_audit": str(args.name_audit),
            "spectron_name_audit_sha256": sha256_path(args.name_audit),
            "spectron_binary_sha256": args.binary_sha256,
        },
        "summary": {
            "named_dynamic_symbol_count": len(dynamic_rows),
            "defined_named_symbol_count": sum(
                row["is_defined"] for row in rows
            ),
            "section_defined_function_count": target["dynamic_symbol_table"][
                "section_defined_type_counts"
            ]["FUNC"],
            "ida_function_match_count": sum(
                row["ida_function_match"] for row in rows
            ),
            "translation_status_counts": dict(sorted(status_counts.items())),
            "dynamic_type_counts": dict(sorted(type_counts.items())),
        },
        "interpretation": [
            "A source-backed v18 alias means the dynamic row's address is also named by a reviewed cross-build alias in the v319 IDA database.",
            "A retained target name means the target or IDA still exposes a target-style name; it is not a recovered 1.8 name.",
            "Target-only descriptive labels identify reviewed behavior where no source counterpart was demonstrated.",
            "Rows without an IDA function at the ELF value are commonly data symbols, undefined imports, or PLT-related rows and are retained without guessed function labels.",
            "This inventory describes the surviving dynamic symbols. It does not claim that the stripped static source-name table can be reconstructed exactly.",
        ],
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
