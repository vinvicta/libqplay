#!/usr/bin/env python3
"""Build a reviewable overlay for IDA-created default sub_ functions.

The ELF-backed names are already preserved in the exported symbol inventory.
This overlay joins the remaining IDA-created functions with exact script-table
names and the separate curated callback candidates. It does not modify IDA,
the binary, or any APK.
"""

from __future__ import annotations

import argparse
import json
import pathlib


DEFAULT_INVENTORY = "symbols/libqplay.function_inventory.json"
DEFAULT_SCRIPT_TABLES = "artifacts/script_table_inventory.json"
DEFAULT_CANDIDATES = "artifacts/native_callback_candidates.json"
DEFAULT_OUTPUT = "artifacts/symbol_translation_overlay.json"


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def load_candidates(document):
    result = {}
    for key, values in document.items():
        if key == "source" or not isinstance(values, list):
            continue
        for item in values:
            result[int(item["va"], 16)] = item
    return result


def build(args):
    inventory_path = pathlib.Path(args.inventory)
    script_path = pathlib.Path(args.script_tables)
    candidate_path = pathlib.Path(args.candidates)
    functions = load_json(inventory_path)
    script_document = load_json(script_path)
    candidate_document = load_json(candidate_path)
    script_by_va = {
        int(item["va"], 16): item
        for item in script_document.get("unique_callbacks", [])
    }
    candidate_by_va = load_candidates(candidate_document)

    default_functions = [
        item for item in functions if item.get("is_default_sub")
    ]
    function_addresses = {item["ea"] for item in functions}
    rows = []
    unresolved = []
    source_counts = {"exact_script_table": 0, "native_callback_candidate": 0, "untranslated": 0}

    for function in sorted(default_functions, key=lambda item: item["ea"]):
        ea = function["ea"]
        script_item = script_by_va.get(ea)
        candidate_item = candidate_by_va.get(ea)
        source = "untranslated"
        proposed_name = None
        evidence = {}

        if (
            script_item
            and script_item.get("status") == "untranslated_default_sub"
            and script_item.get("proposed_name")
        ):
            source = "exact_script_table"
            proposed_name = script_item["proposed_name"]
            evidence = {
                "roles": script_item.get("roles", []),
                "script_status": script_item.get("status"),
            }
        elif candidate_item and candidate_item.get("proposed_name"):
            source = "native_callback_candidate"
            proposed_name = candidate_item["proposed_name"]
            evidence = {
                "candidate_group": next(
                    (
                        key
                        for key, values in candidate_document.items()
                        if isinstance(values, list) and candidate_item in values
                    ),
                    None,
                ),
                "candidate_evidence": candidate_item.get("evidence", []),
                "candidate_review_note": candidate_item.get("review_note"),
                "script_roles": script_item.get("roles", []) if script_item else [],
            }
        else:
            unresolved.append(
                {
                    "ea": f"0x{ea:x}",
                    "current_ida_name": function.get("name"),
                    "size": function.get("size"),
                    "segment": function.get("segment"),
                }
            )

        source_counts[source] += 1
        rows.append(
            {
                "ea": f"0x{ea:x}",
                "current_ida_name": function.get("name"),
                "size": function.get("size"),
                "segment": function.get("segment"),
                "source": source,
                "proposed_name": proposed_name,
                "evidence": evidence,
            }
        )

    missing_script_boundaries = [
        {
            "va": item["va"],
            "proposed_name": item.get("proposed_name"),
            "eh_frame_boundary": item.get("eh_frame_boundary"),
            "roles": item.get("roles", []),
        }
        for item in script_document.get("unique_callbacks", [])
        if item.get("status") == "no_function_boundary"
    ]
    missing_candidate_boundaries = [
        {
            "va": f"0x{ea:x}",
            "proposed_name": item.get("proposed_name"),
            "review_note": item.get("review_note"),
            "evidence": item.get("evidence", []),
        }
        for ea, item in sorted(candidate_by_va.items())
        if ea not in function_addresses
    ]

    binary = script_document["binary"]
    result = {
        "binary": binary,
        "purpose": (
            "Translation overlay for IDA-created default sub_ functions. "
            "Exact table names are separated from curated candidates and "
            "untranslated functions."
        ),
        "sources": {
            "function_inventory": str(inventory_path),
            "script_table_inventory": str(script_path),
            "native_callback_candidates": str(candidate_path),
        },
        "summary": {
            "total_saved_functions": len(functions),
            "default_sub_functions": len(default_functions),
            "default_sub_functions_exact_script_table": source_counts[
                "exact_script_table"
            ],
            "default_sub_functions_native_callback_candidate": source_counts[
                "native_callback_candidate"
            ],
            "default_sub_functions_untranslated": source_counts["untranslated"],
            "exact_script_targets_without_saved_boundary": len(
                missing_script_boundaries
            ),
            "curated_candidates_without_saved_boundary": len(
                missing_candidate_boundaries
            ),
        },
        "default_sub_functions": rows,
        "unresolved_default_sub_functions": unresolved,
        "exact_script_targets_without_saved_boundary": missing_script_boundaries,
        "curated_candidates_without_saved_boundary": missing_candidate_boundaries,
        "network_contacted": False,
    }
    return result


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", default=DEFAULT_INVENTORY)
    parser.add_argument("--script-tables", default=DEFAULT_SCRIPT_TABLES)
    parser.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main():
    args = parse_args()
    result = build(args)
    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
