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
    cyassl_roles = load_json("artifacts/cyassl_static_role_audit_20260826.json")
    static_library_roles = load_json(
        "artifacts/static_library_role_audit_20260826.json"
    )
    arm64_revalidation = load_json(
        "artifacts/arm64_diagnostic_apk_revalidation_20260825.json"
    )
    arm64_native_only = load_json(
        "artifacts/arm64_native_only_original_script_replay_20260826.json"
    )
    arm64_native_stock = load_json(
        "artifacts/arm64_native_stock_original_script_control_20260826.json"
    )
    arm64_builder = load_json(
        "artifacts/arm64_reproducible_builder_validation_20260826.json"
    )
    elf_symbol_audit = load_json("artifacts/elf_symbol_table_audit_20260826.json")
    tls_parser = load_json("artifacts/connector_tls_parser_analysis_20260826.json")
    tls_expiry = load_json("artifacts/connector_tls_expiry_control_20260826.json")
    native_verified = load_json(
        "artifacts/arm64_native_verification_working_control_20260826.json"
    )
    spectron_signature = load_json("artifacts/spectron_function_signature_match.json")
    spectron_hooks = load_json("artifacts/spectron_hook_analysis.json")
    spectron_semantic = load_json(
        "artifacts/spectron_semantic_function_translation_20260826.json"
    )
    spectron_checkpoint = load_json(
        "artifacts/spectron_translation_checkpoint_20260826.json"
    )
    spectron_manual = load_json(
        "artifacts/spectron_manual_translation_anchors_20260826.json"
    )
    spectron_exact_names = load_json(
        "artifacts/spectron_exact_shared_name_anchors_20260826.json"
    )
    spectron_network_anchors = load_json(
        "artifacts/spectron_network_manual_translation_anchors_20260826.json"
    )
    spectron_core_anchors = load_json(
        "artifacts/spectron_core_manual_translation_anchors_20260826.json"
    )
    spectron_runtime_path_anchors = load_json(
        "artifacts/spectron_runtime_path_manual_translation_anchors_20260826.json"
    )
    spectron_update_protocol_anchors = load_json(
        "artifacts/spectron_update_protocol_manual_translation_anchors_20260826.json"
    )
    spectron_client_action_anchors = load_json(
        "artifacts/spectron_client_action_manual_translation_anchors_20260826.json"
    )
    spectron_client_outbound_anchors = load_json(
        "artifacts/spectron_client_outbound_manual_translation_anchors_20260826.json"
    )
    spectron_resource_anchors = load_json(
        "artifacts/spectron_resource_manual_translation_anchors_20260826.json"
    )
    spectron_script_bridge_anchors = load_json(
        "artifacts/spectron_script_bridge_manual_translation_anchors_20260826.json"
    )
    spectron_client_request_anchors = load_json(
        "artifacts/spectron_client_request_manual_translation_anchors_20260826.json"
    )
    spectron_client_inbound_anchors = load_json(
        "artifacts/spectron_client_inbound_manual_translation_anchors_20260826.json"
    )
    spectron_login_helper_anchors = load_json(
        "artifacts/spectron_login_helper_manual_translation_anchors_20260826.json"
    )
    spectron_parse_wrapper_anchors = load_json(
        "artifacts/spectron_parse_wrapper_manual_translation_anchor_20260826.json"
    )
    spectron_lookup_helper_anchors = load_json(
        "artifacts/spectron_lookup_helper_manual_translation_anchors_20260826.json"
    )
    spectron_runtime = load_json(
        "artifacts/spectron_runtime_crash_control_20260826.json"
    )
    spectron_safe_runtime = load_json(
        "artifacts/spectron_webtop_safe_runtime_20260826.json"
    )

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

    check(
        "ELF symbol audit artifact",
        elf_symbol_audit["artifact"],
        "elf_symbol_table_audit_20260826",
    )
    check(
        "ELF symbol audit input hash",
        elf_symbol_audit["binary"]["sha256"],
        "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
    )
    check(
        "ELF symbol audit dynamic total",
        elf_symbol_audit["defined_dynamic_symbol_rows"]["total"],
        6506,
    )
    check("ELF symbol audit no symtab", elf_symbol_audit["sections"]["symtab_present"], False)
    check("ELF symbol audit no debug sections", elf_symbol_audit["sections"]["debug_sections_present"], False)
    check(
        "ELF symbol audit alias total",
        elf_symbol_audit["translated_alias_inventory"]["total"],
        8601,
    )
    check(
        "ELF symbol audit alias failures",
        elf_symbol_audit["translated_alias_inventory"]["rename_failures"],
        0,
    )

    check(
        "TLS parser artifact",
        tls_parser["artifact"],
        "connector_tls_parser_analysis_20260826",
    )
    check("TLS parser network", tls_parser["network_contacted"], False)
    check("TLS parser input hash", tls_parser["binary"]["sha256"], primary_hash)
    check("TLS parser database reopen", tls_parser["database"]["close_reopen_verified"], True)
    parser_functions = {item["name"]: item for item in tls_parser["functions"]}
    check("TLS parser function count", len(parser_functions), 6)
    check(
        "TLS parser ValidateDate address",
        parser_functions["CyaInt_ValidateDate_uchar_const_uchar_int"]["va"],
        "0x2b53b8",
    )
    check(
        "TLS parser DecodeToKey address",
        parser_functions["CyaInt_DecodeToKey_CyaInt_DecodedCert_int"]["va"],
        "0x2b56cc",
    )
    check(
        "TLS parser notBefore error",
        parser_functions["CyaInt_DecodeToKey_CyaInt_DecodedCert_int"]["not_before_failure"],
        -140,
    )
    check(
        "TLS parser notAfter error",
        parser_functions["CyaInt_DecodeToKey_CyaInt_DecodedCert_int"]["not_after_failure_when_strict"],
        -151,
    )
    check(
        "TLS parser x509 field order",
        tls_parser["validity_mapping"]["x509_order"],
        ["notBefore", "notAfter"],
    )

    check("TLS expiry artifact", tls_expiry["artifact"], "connector_tls_expiry_control_20260826")
    check("TLS expiry network", tls_expiry["client"]["network_contacted"], False)
    check("TLS expiry valid HTTP", tls_expiry["valid_control_run"]["http_request_observed"], True)
    check("TLS expiry expired no HTTP", tls_expiry["expired_run"]["http_request_observed"], False)
    check("TLS expiry expired no handshake", tls_expiry["expired_run"]["tls_handshake_completed"], False)

    check(
        "native-verification artifact",
        native_verified["artifact"],
        "arm64_native_verification_working_control_20260826",
    )
    check("native-verification network", native_verified["network_contacted"], False)
    check(
        "native-verification input APK",
        native_verified["builder"]["input_apk_sha256"],
        "6d6c0428fe890d0f18fb1ce572798d7a8a95853b10078f693026164d6a5f56d7",
    )
    check(
        "native-verification native RSA",
        native_verified["builder"]["native_rsa_bypass_applied"],
        False,
    )
    check(
        "native-verification certificate path",
        native_verified["builder"]["native_certificate_verification_preserved"],
        True,
    )
    check(
        "native-verification loading branch",
        native_verified["builder"]["loading_branch_patch"]["address"],
        "0x15ca7c",
    )
    check(
        "native-verification connector requests",
        native_verified["connector"]["request_count"],
        1,
    )
    check(
        "native-verification game connections",
        native_verified["game_responder"]["connections"],
        2,
    )
    check(
        "native-verification resource set",
        native_verified["game_responder"]["resource_requests"],
        [
            "basepackage.gupd",
            "guigames_graymessage2.png",
            "classiciphone.gmap",
            "main_aa-02.nw",
            "main_ab-01.nw",
            "main_ab-02.nw",
            "pics1.png",
        ],
    )
    check(
        "native-verification render",
        native_verified["render_result"]["observed"],
        True,
    )
    check(
        "native-verification screenshot",
        native_verified["render_result"]["screenshot_sha256"],
        "fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e",
    )
    check(
        "native-verification stock control render",
        native_verified["isolation_comparison"]["control_render_observed"],
        False,
    )

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
    active_copy = ida_validation["database"]["active_snapshot_copy"]
    check(
        "IDA active snapshot source hash",
        active_copy["source_sha256"],
        "56da88101fe904ca298dcadf31e90433a69c43818c681ccb72364c66ac99eaa4",
    )
    check("IDA active snapshot source functions", active_copy["source_function_count"], 11272)
    check("IDA active snapshot source defaults", active_copy["source_default_sub_count"], 1645)
    check("IDA active snapshot live marker", active_copy["live_ida_database_changed"], False)
    check("IDA active snapshot close and reopen", active_copy["close_reopen_verified"], True)
    check("IDA active snapshot verified names", active_copy["verified_name_count"], 1211)
    check("IDA active snapshot verified functions", active_copy["verified_function_count"], 11297)
    check("IDA active snapshot verified defaults", active_copy["verified_default_sub_count"], 459)
    check("IDA active snapshot verification failures", active_copy["verification_failures"], 0)
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
        "089e588389206929cbcbd7d1d65dd477e0c69eed0841b430636bb7c947594ac3",
    )
    check(
        "IDA residual database path",
        ida_residual["database"]["path"],
        "analysis/libqplay_translated_all_v4.i64",
    )
    check("IDA residual function total", ida_residual["database"]["function_count"], 11297)
    check(
        "IDA residual default total",
        ida_residual["remaining_default_sub_function_count"],
        421,
    )
    check(
        "IDA residual entry total",
        len(ida_residual["residual_default_sub_functions"]),
        421,
    )
    check(
        "IDA residual role removal total",
        ida_residual["applied_role_aliases"]["count"],
        28,
    )
    check(
        "IDA residual static CyaSSL alias total",
        ida_residual["applied_static_role_aliases"]["count"],
        38,
    )
    check(
        "IDA residual category partition",
        sum(item["count"] for item in ida_residual["category_summary"]),
        421,
    )
    check(
        "IDA residual category names",
        {item["category"] for item in ida_residual["category_summary"]}
        & {"app_or_engine_unknown"},
        set(),
    )
    residual_addresses = [item["ea"] for item in ida_residual["residual_default_sub_functions"]]
    check("IDA residual address uniqueness", len(set(residual_addresses)), 421)

    check(
        "CyaSSL static role artifact",
        cyassl_roles["artifact"],
        "cyassl_static_role_audit_20260826",
    )
    check("CyaSSL static role status", cyassl_roles["status"], "aliases_applied_to_persisted_copy")
    check("CyaSSL static role network", cyassl_roles["network_contacted"], False)
    check("CyaSSL static role input hash", cyassl_roles["binary_sha256"], primary_hash)
    check("CyaSSL static role count", cyassl_roles["alias_count"], 11)
    check("CyaSSL static role high-confidence count", cyassl_roles["confidence_counts"]["high"], 7)
    check("CyaSSL static role medium-confidence count", cyassl_roles["confidence_counts"]["medium"], 4)
    check("CyaSSL static role database path", cyassl_roles["database"]["path"], "analysis/libqplay_translated_all_v3.i64")
    check(
        "CyaSSL static role database hash",
        cyassl_roles["database"]["sha256"],
        "1db52b8b2169250852fcd1a5a2acfda859b81038e92b47158029ecc886356874",
    )
    check("CyaSSL static role database inventory hash", cyassl_roles["database"]["inventory_sha256"], "e6045dc5b63f215c51e13ec3b62472ee415dee87533e225ced04812439959a87")
    check("CyaSSL static role function total", cyassl_roles["database"]["function_count"], 11297)
    check("CyaSSL static role defaults before", cyassl_roles["database"]["default_sub_function_count_before"], 459)
    check("CyaSSL static role defaults after", cyassl_roles["database"]["default_sub_function_count_after"], 448)
    check("CyaSSL static role verification names", cyassl_roles["database"]["verified_name_count"], 11)
    check("CyaSSL static role verification failures", cyassl_roles["database"]["verification_failures"], 0)
    check("CyaSSL static role application renamed", cyassl_roles["application"]["renamed_count"], 11)
    check("CyaSSL static role application comments", cyassl_roles["application"]["comments_added"], 11)
    check("CyaSSL static role application failures", cyassl_roles["application"]["failure_count"], 0)
    check("CyaSSL static role verification status", cyassl_roles["verification"]["status"], "ok")
    check("CyaSSL static role verification report names", cyassl_roles["verification"]["verified_name_count"], 11)
    check("CyaSSL static role verification report failures", cyassl_roles["verification"]["failure_count"], 0)
    alias_addresses = [item["va"] for item in cyassl_roles["aliases"]]
    check("CyaSSL static role address uniqueness", len(set(alias_addresses)), 11)

    check(
        "static-library role artifact",
        static_library_roles["artifact"],
        "static_library_role_audit_20260826",
    )
    check(
        "static-library role status",
        static_library_roles["status"],
        "aliases_applied_to_persisted_copy",
    )
    check("static-library role network", static_library_roles["network_contacted"], False)
    check("static-library role input hash", static_library_roles["binary_sha256"], primary_hash)
    check("static-library role count", static_library_roles["alias_count"], 27)
    check(
        "static-library role high-confidence count",
        static_library_roles["confidence_counts"]["high"],
        27,
    )
    check(
        "static-library role family counts",
        static_library_roles["family_counts"],
        {
            "bzip2": 4,
            "cyassl": 2,
            "gpc": 1,
            "minizip": 2,
            "tomcrypt": 1,
            "yajl": 3,
            "zlib": 14,
        },
    )
    check(
        "static-library role correction count",
        len(static_library_roles["classification_corrections"]),
        5,
    )
    check(
        "static-library role database path",
        static_library_roles["database"]["path"],
        "analysis/libqplay_translated_all_v4.i64",
    )
    check(
        "static-library role database hash",
        static_library_roles["database"]["sha256"],
        "089e588389206929cbcbd7d1d65dd477e0c69eed0841b430636bb7c947594ac3",
    )
    check(
        "static-library role inventory hash",
        static_library_roles["database"]["inventory_sha256"],
        "5d25001293e816e7a2d91261ba9140b9f891df952b3427fd67343c643ed87496",
    )
    check("static-library role function total", static_library_roles["database"]["function_count"], 11297)
    check(
        "static-library role defaults before",
        static_library_roles["database"]["default_sub_function_count_before"],
        448,
    )
    check(
        "static-library role defaults after",
        static_library_roles["database"]["default_sub_function_count_after"],
        421,
    )
    check(
        "static-library role verification names",
        static_library_roles["database"]["verified_name_count"],
        27,
    )
    check(
        "static-library role verification failures",
        static_library_roles["database"]["verification_failures"],
        0,
    )
    check(
        "static-library role application renamed",
        static_library_roles["application"]["renamed_count"],
        27,
    )
    check(
        "static-library role application comments",
        static_library_roles["application"]["comments_added"],
        27,
    )
    check(
        "static-library role application failures",
        static_library_roles["application"]["failure_count"],
        0,
    )
    check(
        "static-library role verification status",
        static_library_roles["verification"]["status"],
        "ok",
    )
    check(
        "static-library role verification names report",
        static_library_roles["verification"]["verified_name_count"],
        27,
    )
    check(
        "static-library role verification failures report",
        static_library_roles["verification"]["failure_count"],
        0,
    )
    static_alias_addresses = [item["va"] for item in static_library_roles["aliases"]]
    check(
        "static-library role address uniqueness",
        len(set(static_alias_addresses)),
        27,
    )

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
        "ARM64 native-only artifact",
        arm64_native_only["artifact"],
        "arm64_native_only_original_script_replay_20260826",
    )
    check("ARM64 native-only network", arm64_native_only["network_contacted"], False)
    check(
        "ARM64 native-only APK hash",
        arm64_native_only["client"]["apk_sha256"],
        "b1c52234b10fb5a4a2c6c58e85370ccab710b1c355574d295df30b5ed6edddcc",
    )
    check(
        "ARM64 native-only original script",
        arm64_native_only["client"]["connector_script_loading_clear_present"],
        False,
    )
    check(
        "ARM64 native-only render",
        arm64_native_only["isolation_result"]["native_only_candidate_rendered"],
        True,
    )
    check(
        "ARM64 native-only direct clear not required",
        arm64_native_only["isolation_result"]["direct_script_loading_clear_required_for_render"],
        False,
    )
    check(
        "ARM64 native-only screenshot",
        arm64_native_only["render_result"]["screenshot_sha256"],
        "fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e",
    )
    check(
        "ARM64 stock-control artifact",
        arm64_native_stock["artifact"],
        "arm64_native_stock_original_script_control_20260826",
    )
    check("ARM64 stock-control network", arm64_native_stock["network_contacted"], False)
    check(
        "ARM64 stock-control APK hash",
        arm64_native_stock["client"]["apk_sha256"],
        "fd7c8676939dcf83d929fd5707536d98dbfd8bae009aec9e4f80c71dbaad0031",
    )
    check(
        "ARM64 stock-control native hash",
        arm64_native_stock["client"]["native_library_sha256"],
        "f36ab1dc978861b26cb7ec3d9ebb9215b8450ffd73f957275a500de7f6492776",
    )
    check(
        "ARM64 stock-control branch",
        arm64_native_stock["client"]["native_loading_branch"]["bytes"],
        "2d 02 00 54",
    )
    check(
        "ARM64 stock-control resource replay",
        arm64_native_stock["control_result"]["original_script_reached_resource_replay"],
        True,
    )
    check(
        "ARM64 stock-control render result",
        arm64_native_stock["render_result"]["observed"],
        False,
    )
    check(
        "ARM64 stock-control screenshot",
        arm64_native_stock["render_result"]["screenshot_sha256"],
        "70e6573244e58125d4092d8265c8acc4e2074dd866bd9cd5897ddf079d39e135",
    )
    check(
        "ARM64 builder artifact",
        arm64_builder["artifact"],
        "arm64_reproducible_builder_validation_20260826",
    )
    check("ARM64 builder network", arm64_builder["network_contacted"], False)
    check(
        "ARM64 builder input APK",
        arm64_builder["builder"]["input_apk_sha256"],
        "6d6c0428fe890d0f18fb1ce572798d7a8a95853b10078f693026164d6a5f56d7",
    )
    check(
        "ARM64 builder native output",
        arm64_builder["builder"]["output_native_sha256"],
        "89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858",
    )
    check(
        "ARM64 builder APK output",
        arm64_builder["builder"]["output_apk_sha256"],
        "394d9ac33fe7b81638029064f2b8ff2183405729f9b5fd94f6808facc13221fc",
    )
    check(
        "ARM64 builder independent hashes",
        len(set(arm64_builder["builder"]["independent_build_hashes"])),
        1,
    )
    check(
        "ARM64 builder render",
        arm64_builder["render_result"]["observed"],
        True,
    )
    check(
        "ARM64 builder screenshot",
        arm64_builder["render_result"]["screenshot_sha256"],
        "fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e",
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
    check(
        "Spectron semantic artifact",
        spectron_semantic["artifact"],
        "spectron_semantic_function_translation",
    )
    check("Spectron semantic network", spectron_semantic["network_contacted"], False)
    check(
        "Spectron semantic original hash",
        spectron_semantic["inputs"]["original_binary_sha256"],
        "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
    )
    check(
        "Spectron semantic binary hash",
        spectron_semantic["inputs"]["spectron_binary_sha256"],
        "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    check("Spectron semantic original functions", spectron_semantic["summary"]["original_functions"], 11297)
    check("Spectron semantic target functions", spectron_semantic["summary"]["spectron_functions"], 11678)
    check("Spectron semantic mapped functions", spectron_semantic["summary"]["mapped_functions"], 3700)
    check("Spectron semantic high confidence", spectron_semantic["summary"]["mapped_high_confidence"], 3641)
    check("Spectron semantic medium confidence", spectron_semantic["summary"]["mapped_medium_confidence"], 59)
    check("Spectron semantic ambiguous functions", spectron_semantic["summary"]["ambiguous_functions"], 1019)
    check("Spectron semantic unmatched functions", spectron_semantic["summary"]["unmatched_functions"], 614)
    check("Spectron shared-name validation total", spectron_semantic["validation"]["shared_name_functions"], 396)
    check("Spectron shared-name validation correct", spectron_semantic["validation"]["shared_name_unique_correct"], 396)
    check("Spectron shared-name validation wrong", spectron_semantic["validation"]["shared_name_unique_wrong"], 0)
    check(
        "Spectron exact-name artifact",
        spectron_exact_names["artifact"],
        "spectron_exact_shared_name_anchors_20260826",
    )
    check("Spectron exact-name network", spectron_exact_names["network_contacted"], False)
    check("Spectron exact-name shared total", spectron_exact_names["summary"]["shared_exact_names"], 1008)
    check("Spectron exact-name semantic overlap", spectron_exact_names["summary"]["already_in_semantic_map"], 396)
    check("Spectron exact-name only total", spectron_exact_names["summary"]["exact_name_anchor_only"], 612)
    check("Spectron exact-name ambiguous total", spectron_exact_names["summary"]["ambiguous_shared_names"], 0)
    check(
        "Spectron exact-name JNI total",
        spectron_exact_names["summary"]["name_class_counts"]["shared_jni_name"],
        27,
    )
    check(
        "Spectron exact-name PLT total",
        spectron_exact_names["summary"]["name_class_counts"]["shared_plt_or_import_name"],
        381,
    )
    check(
        "Spectron exact-name readable total",
        spectron_exact_names["summary"]["name_class_counts"]["shared_readable_name"],
        600,
    )
    check(
        "Spectron network-anchor artifact",
        spectron_network_anchors["artifact"],
        "spectron_network_manual_translation_anchors_20260826",
    )
    check("Spectron network-anchor network", spectron_network_anchors["network_contacted"], False)
    check("Spectron network-anchor total", spectron_network_anchors["summary"]["anchor_count"], 6)
    check("Spectron network-anchor high confidence", spectron_network_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron network-anchor semantic overlap", spectron_network_anchors["summary"]["already_in_semantic_map"], 0)
    check(
        "Spectron core-anchor artifact",
        spectron_core_anchors["artifact"],
        "spectron_core_manual_translation_anchors_20260826",
    )
    check("Spectron core-anchor network", spectron_core_anchors["network_contacted"], False)
    check("Spectron core-anchor total", spectron_core_anchors["summary"]["anchor_count"], 16)
    check("Spectron core-anchor high confidence", spectron_core_anchors["summary"]["high_confidence_count"], 16)
    check("Spectron core-anchor semantic overlap", spectron_core_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron core-anchor default targets", spectron_core_anchors["summary"]["target_default_name_count"], 2)
    check(
        "Spectron runtime-path artifact",
        spectron_runtime_path_anchors["artifact"],
        "spectron_runtime_path_manual_translation_anchors_20260826",
    )
    check("Spectron runtime-path network", spectron_runtime_path_anchors["network_contacted"], False)
    check("Spectron runtime-path total", spectron_runtime_path_anchors["summary"]["anchor_count"], 13)
    check("Spectron runtime-path high confidence", spectron_runtime_path_anchors["summary"]["high_confidence_count"], 13)
    check("Spectron runtime-path semantic overlap", spectron_runtime_path_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron runtime-path default targets", spectron_runtime_path_anchors["summary"]["target_default_name_count"], 9)
    check(
        "Spectron update-protocol artifact",
        spectron_update_protocol_anchors["artifact"],
        "spectron_update_protocol_manual_translation_anchors_20260826",
    )
    check("Spectron update-protocol network", spectron_update_protocol_anchors["network_contacted"], False)
    check("Spectron update-protocol total", spectron_update_protocol_anchors["summary"]["anchor_count"], 5)
    check("Spectron update-protocol high confidence", spectron_update_protocol_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron update-protocol semantic overlap", spectron_update_protocol_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron update-protocol default targets", spectron_update_protocol_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron client-action artifact",
        spectron_client_action_anchors["artifact"],
        "spectron_client_action_manual_translation_anchors_20260826",
    )
    check("Spectron client-action network", spectron_client_action_anchors["network_contacted"], False)
    check("Spectron client-action total", spectron_client_action_anchors["summary"]["anchor_count"], 11)
    check("Spectron client-action high confidence", spectron_client_action_anchors["summary"]["high_confidence_count"], 11)
    check("Spectron client-action semantic overlap", spectron_client_action_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron client-action default targets", spectron_client_action_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron client-outbound artifact",
        spectron_client_outbound_anchors["artifact"],
        "spectron_client_outbound_manual_translation_anchors_20260826",
    )
    check("Spectron client-outbound network", spectron_client_outbound_anchors["network_contacted"], False)
    check("Spectron client-outbound total", spectron_client_outbound_anchors["summary"]["anchor_count"], 29)
    check("Spectron client-outbound high confidence", spectron_client_outbound_anchors["summary"]["high_confidence_count"], 29)
    check("Spectron client-outbound semantic overlap", spectron_client_outbound_anchors["summary"]["already_in_semantic_map"], 1)
    check("Spectron client-outbound default targets", spectron_client_outbound_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron resource-anchor artifact",
        spectron_resource_anchors["artifact"],
        "spectron_resource_manual_translation_anchors_20260826",
    )
    check("Spectron resource-anchor network", spectron_resource_anchors["network_contacted"], False)
    check("Spectron resource-anchor total", spectron_resource_anchors["summary"]["anchor_count"], 6)
    check("Spectron resource-anchor high confidence", spectron_resource_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron resource-anchor semantic overlap", spectron_resource_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron resource-anchor default targets", spectron_resource_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-bridge artifact",
        spectron_script_bridge_anchors["artifact"],
        "spectron_script_bridge_manual_translation_anchors_20260826",
    )
    check("Spectron script-bridge network", spectron_script_bridge_anchors["network_contacted"], False)
    check("Spectron script-bridge total", spectron_script_bridge_anchors["summary"]["anchor_count"], 13)
    check("Spectron script-bridge high confidence", spectron_script_bridge_anchors["summary"]["high_confidence_count"], 13)
    check("Spectron script-bridge semantic overlap", spectron_script_bridge_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-bridge default targets", spectron_script_bridge_anchors["summary"]["target_default_name_count"], 13)
    check(
        "Spectron client-request artifact",
        spectron_client_request_anchors["artifact"],
        "spectron_client_request_manual_translation_anchors_20260826",
    )
    check("Spectron client-request network", spectron_client_request_anchors["network_contacted"], False)
    check("Spectron client-request total", spectron_client_request_anchors["summary"]["anchor_count"], 11)
    check("Spectron client-request high confidence", spectron_client_request_anchors["summary"]["high_confidence_count"], 11)
    check("Spectron client-request semantic overlap", spectron_client_request_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron client-request default targets", spectron_client_request_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron client-inbound artifact",
        spectron_client_inbound_anchors["artifact"],
        "spectron_client_inbound_manual_translation_anchors_20260826",
    )
    check("Spectron client-inbound network", spectron_client_inbound_anchors["network_contacted"], False)
    check("Spectron client-inbound total", spectron_client_inbound_anchors["summary"]["anchor_count"], 8)
    check("Spectron client-inbound high confidence", spectron_client_inbound_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron client-inbound semantic overlap", spectron_client_inbound_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron client-inbound default targets", spectron_client_inbound_anchors["summary"]["target_default_name_count"], 6)
    check(
        "Spectron login-helper artifact",
        spectron_login_helper_anchors["artifact"],
        "spectron_login_helper_manual_translation_anchors_20260826",
    )
    check("Spectron login-helper network", spectron_login_helper_anchors["network_contacted"], False)
    check("Spectron login-helper total", spectron_login_helper_anchors["summary"]["anchor_count"], 8)
    check("Spectron login-helper high confidence", spectron_login_helper_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron login-helper semantic overlap", spectron_login_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron login-helper default targets", spectron_login_helper_anchors["summary"]["target_default_name_count"], 8)
    check(
        "Spectron parse-wrapper artifact",
        spectron_parse_wrapper_anchors["artifact"],
        "spectron_parse_wrapper_manual_translation_anchor_20260826",
    )
    check("Spectron parse-wrapper network", spectron_parse_wrapper_anchors["network_contacted"], False)
    check("Spectron parse-wrapper total", spectron_parse_wrapper_anchors["summary"]["anchor_count"], 1)
    check("Spectron parse-wrapper high confidence", spectron_parse_wrapper_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron parse-wrapper semantic overlap", spectron_parse_wrapper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron parse-wrapper target defaults", spectron_parse_wrapper_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron parse-wrapper tail-thunk count", spectron_parse_wrapper_anchors["summary"]["tail_thunk_count"], 1)
    check(
        "Spectron lookup-helper artifact",
        spectron_lookup_helper_anchors["artifact"],
        "spectron_lookup_helper_manual_translation_anchors_20260826",
    )
    check("Spectron lookup-helper network", spectron_lookup_helper_anchors["network_contacted"], False)
    check("Spectron lookup-helper total", spectron_lookup_helper_anchors["summary"]["anchor_count"], 3)
    check("Spectron lookup-helper high confidence", spectron_lookup_helper_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron lookup-helper semantic overlap", spectron_lookup_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron lookup-helper default targets", spectron_lookup_helper_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron checkpoint artifact",
        spectron_checkpoint["artifact"],
        "spectron_translation_checkpoint_20260826",
    )
    check("Spectron checkpoint network", spectron_checkpoint["network_contacted"], False)
    check("Spectron checkpoint database function count", spectron_checkpoint["database"]["function_count"], 11678)
    check("Spectron checkpoint database reopen", spectron_checkpoint["database"]["close_reopen_verified"], True)
    check("Spectron checkpoint high labels", spectron_checkpoint["translation"]["high_confidence_applied"], 3641)
    check("Spectron checkpoint manual anchor count", spectron_checkpoint["manual_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint network anchor count", spectron_checkpoint["network_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint core anchor count", spectron_checkpoint["core_anchors"]["verified_name_count"], 16)
    check("Spectron checkpoint runtime-path anchor count", spectron_checkpoint["runtime_path_anchors"]["verified_name_count"], 13)
    check("Spectron checkpoint update-protocol anchor count", spectron_checkpoint["update_protocol_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint client-action anchor count", spectron_checkpoint["client_action_anchors"]["verified_name_count"], 11)
    check("Spectron checkpoint client-outbound anchor count", spectron_checkpoint["client_outbound_anchors"]["verified_name_count"], 29)
    check("Spectron checkpoint resource anchor count", spectron_checkpoint["resource_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint script-bridge anchor count", spectron_checkpoint["script_bridge_anchors"]["verified_name_count"], 13)
    check("Spectron checkpoint client-request anchor count", spectron_checkpoint["client_request_anchors"]["verified_name_count"], 11)
    check("Spectron checkpoint client-inbound anchor count", spectron_checkpoint["client_inbound_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint login-helper anchor count", spectron_checkpoint["login_helper_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint parse-wrapper anchor count", spectron_checkpoint["parse_wrapper_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint lookup-helper anchor count", spectron_checkpoint["lookup_helper_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint database hash", spectron_checkpoint["database"]["sha256"], "d2cf2b3cdf701fcd0afc29a0f919b4db15f351f9dc9e4fe8ccb217702c56e40c")
    check(
        "Spectron manual artifact",
        spectron_manual["artifact"],
        "spectron_manual_translation_anchors_20260826",
    )
    check("Spectron manual network", spectron_manual["network_contacted"], False)
    check("Spectron manual anchor count", len(spectron_manual["anchors"]), 4)
    check(
        "Spectron runtime artifact",
        spectron_runtime["artifact"],
        "spectron_runtime_crash_control_20260826",
    )
    check("Spectron runtime network audit", spectron_runtime["network_audited"], False)
    check("Spectron runtime network marker", spectron_runtime["network_contacted"], None)
    check("Spectron runtime signal", spectron_runtime["observed"]["signal"], "SIGSEGV")
    check("Spectron runtime fault address", spectron_runtime["observed"]["fault_address"], "0x0")
    check("Spectron runtime faulting address", spectron_runtime["static_correlation"]["faulting_ea"], "0x84348")
    check("Spectron runtime static correlation", spectron_runtime["static_correlation"]["correlation_status"], "confirmed-by-IDA")
    check(
        "Spectron safe runtime artifact",
        spectron_safe_runtime["artifact"],
        "spectron_webtop_safe_runtime_20260826",
    )
    check("Spectron safe runtime network audit", spectron_safe_runtime["network_audited"], False)
    check("Spectron safe runtime network marker", spectron_safe_runtime["network_contacted"], None)
    check(
        "Spectron safe runtime APK hash",
        spectron_safe_runtime["inputs"]["output_apk_sha256"],
        "d8b44281f2c2a3e8ab6f40358e28d017052a967cdf2a5b9b0c3383535ef07de3",
    )
    check(
        "Spectron safe runtime library hash",
        spectron_safe_runtime["inputs"]["output_libxposed_sha256"],
        "ba6023c42e501c9f1dae17f7d65973d09b399f4f4c8f1acf1e43487b1b01a50c",
    )
    check("Spectron safe runtime process", spectron_safe_runtime["observed"]["process_alive_at_check"], True)
    check("Spectron safe runtime fatal crash", spectron_safe_runtime["observed"]["fatal_crash_observed"], False)
    check("Spectron safe runtime world", spectron_safe_runtime["observed"]["world_rendered"], True)
    check("Spectron safe runtime patch count", len(spectron_safe_runtime["patches"]), 3)

    for document in (
        overlay,
        profile,
        candidates,
        script_tables,
        labels,
        ida_validation,
        ida_residual,
        static_library_roles,
        arm64_revalidation,
        arm64_native_only,
        arm64_native_stock,
        arm64_builder,
        elf_symbol_audit,
        tls_parser,
        tls_expiry,
        spectron_signature,
        spectron_hooks,
        spectron_semantic,
        spectron_checkpoint,
        spectron_manual,
        spectron_exact_names,
        spectron_network_anchors,
        spectron_core_anchors,
        spectron_runtime_path_anchors,
        spectron_update_protocol_anchors,
        spectron_client_action_anchors,
        spectron_client_outbound_anchors,
        spectron_resource_anchors,
        spectron_script_bridge_anchors,
        spectron_client_request_anchors,
        spectron_client_inbound_anchors,
        spectron_login_helper_anchors,
        spectron_parse_wrapper_anchors,
        spectron_lookup_helper_anchors,
    ):
        check("offline artifact marker", document.get("network_contacted"), False)

    print("research archive validation: ok (%d checks)" % len(checks))


if __name__ == "__main__":
    main()
