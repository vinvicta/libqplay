"""Check that the public analysis artifacts describe one consistent build.

This is an offline integrity check. It reads only JSON files already present in
the repository and does not open a network connection or require IDA.
"""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_json(relative_path):
    with (ROOT / relative_path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main():
    symbols = load_json("symbols/libqplay.symbols.summary.json")
    inventory = load_json("symbols/libqplay.function_inventory.summary.json")
    labels = load_json("artifacts/ida_semantic_labels.json")
    overlay = load_json("artifacts/symbol_translation_overlay.json")
    profile = load_json("artifacts/unresolved_function_profile.json")
    candidates = load_json("artifacts/unresolved_function_candidates.json")
    script_tables = load_json("artifacts/script_table_inventory.json")
    ida_validation = load_json("artifacts/ida_translation_validation.json")

    checks = []

    def check(label, actual, expected):
        if actual != expected:
            raise ValueError("%s: expected %r, got %r" % (label, expected, actual))
        checks.append(label)

    primary_hash = inventory["input_sha256"]
    check("symbol input", symbols["input"], "private original ARM64 libqplay.so")
    check("symbol row total", symbols["translated_symbols"], 8601)
    check(
        "symbol kind total",
        symbols["functions"]
        + symbols["plt_thunks"]
        + symbols["jump_thunks"]
        + symbols["data"],
        symbols["translated_symbols"],
    )
    check("ELF-backed function total", inventory["functions_backed_by_elf_symbols"], 8096)
    check("IDA function total", inventory["total_functions"], 11272)
    check("IDA default sub total", inventory["ida_default_sub_functions"], 1645)
    check("IDA named non-ELF total", inventory["ida_named_non_elf_functions"], 1531)
    check(
        "function inventory partition",
        inventory["functions_backed_by_elf_symbols"]
        + inventory["ida_default_sub_functions"]
        + inventory["ida_named_non_elf_functions"],
        inventory["total_functions"],
    )
    check("rename failures", symbols["rename_failures"], [])

    check("semantic-label input hash", labels["binary"]["libqplay_sha256"], primary_hash)
    check("semantic-label function total", labels["inventory_after_labels"]["total_functions"], 11272)
    check(
        "semantic-label count",
        labels["inventory_after_labels"]["semantic_label_total"],
        len(labels["labels"]),
    )
    check("semantic-label count checkpoint", len(labels["labels"]), 467)

    check("overlay input hash", overlay["binary"]["sha256"], primary_hash)
    overlay_summary = overlay["summary"]
    check("overlay saved function total", overlay_summary["total_saved_functions"], 11272)
    check("overlay default sub total", overlay_summary["default_sub_functions"], 1645)
    check(
        "overlay source partition",
        overlay_summary["default_sub_functions_exact_script_table"]
        + overlay_summary["default_sub_functions_native_callback_candidate"]
        + overlay_summary["default_sub_functions_untranslated"],
        overlay_summary["default_sub_functions"],
    )
    check("overlay default sub rows", len(overlay["default_sub_functions"]), 1645)
    check("overlay unresolved rows", len(overlay["unresolved_default_sub_functions"]), 488)

    check("profile input hash", profile["binary_sha256"], primary_hash)
    check("profile inventory total", profile["inventory_function_count"], 11272)
    check("profile default sub total", profile["default_sub_function_count"], 1645)
    check("profile unresolved total", profile["unresolved_default_sub_function_count"], 488)
    check(
        "profile category partition",
        sum(item["count"] for item in profile["category_summary"]),
        profile["unresolved_default_sub_function_count"],
    )

    check("candidate input hash", candidates["binary_sha256"], primary_hash)
    check("candidate count", candidates["candidate_count"], len(candidates["candidates"]))
    check("candidate count against profile", candidates["candidate_count"], 28)
    check("candidate coverage profile count", candidates["role_candidate_coverage"]["profile_count"], 28)
    check("candidate coverage candidate count", candidates["role_candidate_coverage"]["candidate_count"], 28)
    check("candidate coverage uncovered", candidates["role_candidate_coverage"]["uncovered"], [])
    check("candidate coverage extra", candidates["role_candidate_coverage"]["extra"], [])
    confidence_counts = {}
    for item in candidates["candidates"]:
        confidence = item["confidence"]
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
    check("high-confidence candidates", confidence_counts.get("high", 0), 27)
    check("medium-confidence candidates", confidence_counts.get("medium", 0), 1)

    table_summary = script_tables["summary"]
    check("script-table input hash", script_tables["binary"]["sha256"], primary_hash)
    check(
        "script-table declared record total",
        table_summary["declared_function_records"] + table_summary["declared_property_records"],
        1455,
    )
    check(
        "script-table static record total",
        table_summary["static_function_records"] + table_summary["static_property_records"],
        1454,
    )
    check(
        "script-table exact target partition",
        table_summary["exact_untranslated_with_function_boundary"]
        + table_summary["no_function_boundary_with_eh_frame"],
        906,
    )
    check("script-table exact target total", table_summary["exact_untranslated_targets"], 906)
    proposed_names = [
        item["proposed_name"]
        for item in script_tables["unique_callbacks"]
        if item.get("status") in {"untranslated_default_sub", "no_function_boundary"}
        and item.get("proposed_name")
    ]
    check("script-table proposed-name uniqueness", len(set(proposed_names)), len(proposed_names))
    check(
        "script-table table registration total",
        table_summary["function_tables"] + table_summary["property_tables"],
        132,
    )
    check("script-table registration calls", table_summary["registration_calls"], 132)
    check("script-table uncertain names", table_summary["records_with_uncertain_names"], 0)
    check("script-table review targets", table_summary["targets_requiring_name_review"], 0)
    check(
        "script-table callback status partition",
        sum(table_summary["unique_callback_statuses"].values()),
        table_summary["unique_callback_targets"],
    )

    check(
        "IDA validation input hash",
        ida_validation["binary"]["libqplay_sha256"],
        primary_hash,
    )
    check(
        "IDA validation source function total",
        ida_validation["database"]["source_saved_function_count"],
        11272,
    )
    check(
        "IDA validation function total",
        ida_validation["database"]["validated_function_count"],
        11297,
    )
    check(
        "IDA validation default sub total",
        ida_validation["database"]["validated_default_sub_count"],
        459,
    )
    check(
        "IDA validation live database marker",
        ida_validation["database"]["live_ida_database_changed"],
        False,
    )
    check(
        "IDA validation pass failures",
        sum(item["failures"] for item in ida_validation["passes"]),
        0,
    )
    check(
        "IDA validation renamed total",
        sum(item["renamed"] for item in ida_validation["passes"]),
        1211,
    )

    for document in (
        overlay,
        profile,
        candidates,
        script_tables,
        labels,
        ida_validation,
    ):
        check("offline artifact marker", document.get("network_contacted"), False)

    print("research archive validation: ok (%d checks)" % len(checks))


if __name__ == "__main__":
    main()
