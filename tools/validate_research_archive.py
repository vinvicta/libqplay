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
    ida_residual = load_json("artifacts/ida_residual_profile.json")
    arm64_revalidation = load_json(
        "artifacts/arm64_diagnostic_apk_revalidation_20260825.json"
    )
    spectron_signature = load_json("artifacts/spectron_function_signature_match.json")
    spectron_hooks = load_json("artifacts/spectron_hook_analysis.json")

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
    check("high-confidence candidates", confidence_counts.get("high", 0), 28)
    check("medium-confidence candidates", confidence_counts.get("medium", 0), 0)

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
        "IDA validation persisted-copy marker",
        ida_validation["database"]["persistent_database"]["close_reopen_verified"],
        True,
    )
    check(
        "IDA validation persisted-copy hash",
        ida_validation["database"]["persistent_database"]["sha256"],
        "0306a53f164fc9f860f24eb248039a94172959053daa6464d4a1effe35026a89",
    )
    check(
        "IDA validation persisted inventory total",
        ida_validation["database"]["persistent_database"]["inventory"]["total_functions"],
        11297,
    )
    check(
        "IDA validation persisted inventory defaults",
        ida_validation["database"]["persistent_database"]["inventory"]["ida_default_sub_functions"],
        459,
    )
    check(
        "IDA validation persisted inventory hash",
        ida_validation["database"]["persistent_database"]["inventory"]["sha256"],
        "2f9f4d2ddeeac15f52c64e5c5868190937f3559283ce19738ed576eeaa885e28",
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

    check("IDA residual artifact", ida_residual["artifact"], "ida_persisted_residual_profile")
    check("IDA residual network", ida_residual["network_contacted"], False)
    check("IDA residual input hash", ida_residual["binary_sha256"], primary_hash)
    check(
        "IDA residual database hash",
        ida_residual["database"]["sha256"],
        "0306a53f164fc9f860f24eb248039a94172959053daa6464d4a1effe35026a89",
    )
    check("IDA residual function total", ida_residual["database"]["function_count"], 11297)
    check(
        "IDA residual default total",
        ida_residual["remaining_default_sub_function_count"],
        459,
    )
    check(
        "IDA residual entry total",
        len(ida_residual["residual_default_sub_functions"]),
        459,
    )
    check(
        "IDA residual role removal total",
        ida_residual["applied_role_aliases"]["count"],
        28,
    )
    check(
        "IDA residual category partition",
        sum(item["count"] for item in ida_residual["category_summary"]),
        459,
    )
    check(
        "IDA residual category names",
        {item["category"] for item in ida_residual["category_summary"]}
        & {"app_or_engine_unknown"},
        set(),
    )
    residual_addresses = [item["ea"] for item in ida_residual["residual_default_sub_functions"]]
    check("IDA residual address uniqueness", len(set(residual_addresses)), 459)

    check(
        "ARM64 revalidation artifact",
        arm64_revalidation["artifact"],
        "arm64_diagnostic_apk_revalidation_20260825",
    )
    check("ARM64 revalidation network", arm64_revalidation["network_contacted"], False)
    check(
        "ARM64 revalidation APK hash",
        arm64_revalidation["client"]["apk_sha256"],
        "b1c52234b10fb5a4a2c6c58e85370ccab710b1c355574d295df30b5ed6edddcc",
    )
    check(
        "ARM64 revalidation native hash",
        arm64_revalidation["client"]["native_library_sha256"],
        "89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858",
    )
    check(
        "ARM64 revalidation connector requests",
        arm64_revalidation["runtime"]["connector"]["request_count"],
        1,
    )
    check(
        "ARM64 revalidation game connections",
        arm64_revalidation["runtime"]["game"]["connections"],
        2,
    )
    check(
        "ARM64 revalidation rendered world",
        arm64_revalidation["runtime"]["render_result"]["observed"],
        True,
    )
    check(
        "ARM64 revalidation screenshot",
        arm64_revalidation["runtime"]["render_result"]["screenshot_sha256"],
        "fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e",
    )
    check(
        "ARM64 revalidation fixture revision",
        arm64_revalidation["fixture_provenance"]["target_revision_match"],
        False,
    )
    check(
        "ARM64 revalidation placeholder marker",
        arm64_revalidation["fixture_provenance"]["placeholder"]["not_a_target_revision_file"],
        True,
    )
    check(
        "IDA validation status",
        ida_validation["status"],
        "validated_persisted_on_disposable_copy",
    )
    check(
        "Spectron signature artifact",
        spectron_signature["artifact"],
        "spectron_exact_function_signature_matches",
    )
    check("Spectron signature network", spectron_signature["network_contacted"], False)
    check(
        "Spectron signature exact matches",
        spectron_signature["summary"]["unique_exact_matches"],
        1,
    )
    check(
        "Spectron usable source matches",
        spectron_signature["summary"]["usable_source_name_matches"],
        0,
    )
    check(
        "Spectron hook artifact",
        spectron_hooks["schema_version"],
        1,
    )
    check("Spectron hook network", spectron_hooks["network_contacted"], False)
    check(
        "Spectron hook APK hash",
        spectron_hooks["inputs"]["spectron_apk_sha256"],
        "5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c",
    )
    check(
        "Spectron hook export count",
        len(spectron_hooks["hook_loader"]["resolved_qplay_exports"]),
        9,
    )
    check(
        "Spectron installed hook count",
        len(spectron_hooks["hook_loader"]["installed_hooks"]),
        3,
    )
    check(
        "Spectron dispatcher command count",
        len(spectron_hooks["webtop_dispatcher"]["commands"]),
        6,
    )
    check(
        "Spectron recovered URL",
        spectron_hooks["webtop"]["recovered_url"],
        "https://spectronnative-page.onrender.com?device=NOID",
    )

    for document in (
        overlay,
        profile,
        candidates,
        script_tables,
        labels,
        ida_validation,
        ida_residual,
        arm64_revalidation,
        spectron_signature,
        spectron_hooks,
    ):
        check("offline artifact marker", document.get("network_contacted"), False)

    print("research archive validation: ok (%d checks)" % len(checks))


if __name__ == "__main__":
    main()
