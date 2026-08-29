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
    spectron_symbol_audit = load_json(
        "artifacts/spectron_symbol_table_audit_20260827.json"
    )
    spectron_connector_endpoints = load_json(
        "artifacts/spectron_connector_endpoint_audit_20260827.json"
    )
    spectron_loopback_patch_audit = load_json(
        "artifacts/spectron_loopback_patch_audit_20260828.json"
    )
    spectron_arm64_loopback_loading = load_json(
        "artifacts/spectron_arm64_loopback_loading_replay_20260828.json"
    )
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
    spectron_checkpoint_v219 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828.json"
    )
    spectron_checkpoint_v220 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v220.json"
    )
    spectron_checkpoint_v221 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v221.json"
    )
    spectron_checkpoint_v222 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v222.json"
    )
    spectron_checkpoint_v223 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v223.json"
    )
    spectron_checkpoint_v224 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v224.json"
    )
    spectron_checkpoint_v225 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v225.json"
    )
    spectron_checkpoint_v226 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v226.json"
    )
    spectron_checkpoint_v227 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v227.json"
    )
    spectron_checkpoint_v228 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v228.json"
    )
    spectron_checkpoint_v229 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v229.json"
    )
    spectron_checkpoint_v230 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v230.json"
    )
    spectron_checkpoint_v231 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v231.json"
    )
    spectron_checkpoint_v232 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v232.json"
    )
    spectron_checkpoint_v233 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v233.json"
    )
    spectron_checkpoint_v234 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v234.json"
    )
    spectron_checkpoint_v235 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v235.json"
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
    spectron_connection_helper_anchors = load_json(
        "artifacts/spectron_connection_helper_manual_translation_anchors_20260826.json"
    )
    spectron_client_state_helper_anchors = load_json(
        "artifacts/spectron_client_state_helper_manual_translation_anchors_20260826.json"
    )
    spectron_connection_state_anchors = load_json(
        "artifacts/spectron_connection_state_manual_translation_anchors_20260826.json"
    )
    spectron_http_request_anchors = load_json(
        "artifacts/spectron_http_request_manual_translation_anchors_20260826.json"
    )
    spectron_socket_state_anchors = load_json(
        "artifacts/spectron_socket_state_manual_translation_anchors_20260826.json"
    )
    spectron_socket_behavior = load_json(
        "artifacts/spectron_socket_behavior_comparison_20260826.json"
    )
    spectron_http_request_state_anchors = load_json(
        "artifacts/spectron_http_request_state_manual_translation_anchors_20260826.json"
    )
    spectron_npc_helper_anchors = load_json(
        "artifacts/spectron_npc_helper_manual_translation_anchors_20260826.json"
    )
    spectron_html_atom_anchors = load_json(
        "artifacts/spectron_html_atom_manual_translation_anchors_20260826.json"
    )
    spectron_html_page_anchors = load_json(
        "artifacts/spectron_html_page_manual_translation_anchors_20260827.json"
    )
    spectron_gui_text_list_anchors = load_json(
        "artifacts/spectron_gui_text_list_manual_translation_anchors_20260827.json"
    )
    spectron_gui_text_list_entry_anchors = load_json(
        "artifacts/spectron_gui_text_list_entry_manual_translation_anchors_20260827.json"
    )
    spectron_encryption_graalvar_anchors = load_json(
        "artifacts/spectron_encryption_graalvar_manual_translation_anchors_20260827.json"
    )
    spectron_compact_residual_anchors = load_json(
        "artifacts/spectron_compact_residual_manual_translation_anchors_20260827.json"
    )
    spectron_t2d_matrix_manager_anchors = load_json(
        "artifacts/spectron_t2d_matrix_manager_manual_translation_anchors_20260827.json"
    )
    spectron_mrandom_anchors = load_json(
        "artifacts/spectron_mrandom_family_manual_translation_anchors_20260827.json"
    )
    spectron_tstringlist_residual_anchors = load_json(
        "artifacts/spectron_tstringlist_residual_manual_translation_anchors_20260827.json"
    )
    spectron_server_object_lifecycle_anchors = load_json(
        "artifacts/spectron_server_object_lifecycle_manual_translation_anchors_20260827.json"
    )
    spectron_gui_ml_text_residual_anchors = load_json(
        "artifacts/spectron_gui_ml_text_residual_manual_translation_anchors_20260827.json"
    )
    spectron_gui_text_list_entry_property_anchors = load_json(
        "artifacts/spectron_gui_text_list_entry_property_manual_translation_anchors_20260828.json"
    )
    spectron_gui_text_list_residual_anchors = load_json(
        "artifacts/spectron_gui_text_list_residual_manual_translation_anchors_20260828.json"
    )
    spectron_gui_drawing_showimg_property_anchors = load_json(
        "artifacts/spectron_gui_drawing_showimg_property_manual_translation_anchors_20260828.json"
    )
    spectron_gui_browser_property_anchors = load_json(
        "artifacts/spectron_gui_browser_property_manual_translation_anchors_20260828.json"
    )
    spectron_gui_context_menu_property_anchors = load_json(
        "artifacts/spectron_gui_context_menu_property_manual_translation_anchors_20260828.json"
    )
    spectron_gui_array_popup_residual_anchors = load_json(
        "artifacts/spectron_gui_array_popup_residual_manual_translation_anchors_20260828.json"
    )
    spectron_gui_popup_rows_anchor = load_json(
        "artifacts/spectron_gui_popup_rows_manual_translation_anchor_20260828.json"
    )
    spectron_gui_progress_getter_anchor = load_json(
        "artifacts/spectron_gui_progress_getter_manual_translation_anchor_20260828.json"
    )
    spectron_gui_text_list_selection_script_anchors = load_json(
        "artifacts/spectron_gui_text_list_selection_script_manual_translation_anchors_20260828.json"
    )
    spectron_mrandom_property_residual_anchors = load_json(
        "artifacts/spectron_mrandom_property_residual_manual_translation_anchors_20260828.json"
    )
    spectron_gui_drawing_panel_script_anchors = load_json(
        "artifacts/spectron_gui_drawing_panel_script_manual_translation_anchors_20260828.json"
    )
    spectron_tclient_script_property_anchors = load_json(
        "artifacts/spectron_tclient_script_property_manual_translation_anchors_20260828.json"
    )
    spectron_file_cache_property_anchors = load_json(
        "artifacts/spectron_file_cache_property_manual_translation_anchors_20260828.json"
    )
    spectron_tclient_handler_anchors = load_json(
        "artifacts/spectron_tclient_handler_manual_translation_anchors_20260828.json"
    )
    spectron_target_only_labels = load_json(
        "artifacts/spectron_target_only_callback_labels_20260828.json"
    )
    spectron_tclient_playerhurt_anchor = load_json(
        "artifacts/spectron_tclient_playerhurt_property_manual_translation_anchor_20260828.json"
    )
    spectron_gsfunctions_property_anchors = load_json(
        "artifacts/spectron_gsfunctions_property_manual_translation_anchors_20260828.json"
    )
    spectron_time_files_input_anchors = load_json(
        "artifacts/spectron_time_files_input_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v236 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v236.json"
    )
    spectron_level_object_property_anchors = load_json(
        "artifacts/spectron_level_object_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v237 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v237.json"
    )
    spectron_gani_property_anchors = load_json(
        "artifacts/spectron_gani_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v238 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v238.json"
    )
    spectron_options_property_anchors = load_json(
        "artifacts/spectron_options_property_residual_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v239 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v239.json"
    )
    spectron_particle_emitter_property_anchors = load_json(
        "artifacts/spectron_particle_emitter_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v240 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v240.json"
    )
    spectron_particle_emitter_script_anchors = load_json(
        "artifacts/spectron_particle_emitter_script_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v241 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v241.json"
    )
    spectron_world_object_property_anchors = load_json(
        "artifacts/spectron_world_object_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v242 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v242.json"
    )
    spectron_player_translation_property_anchors = load_json(
        "artifacts/spectron_player_translation_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v243 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v243.json"
    )
    spectron_server_npc_property_anchors = load_json(
        "artifacts/spectron_server_npc_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v244 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v244.json"
    )
    spectron_server_npc_script_anchors = load_json(
        "artifacts/spectron_server_npc_script_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v245 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v245.json"
    )
    spectron_server_npc_showimg_anchors = load_json(
        "artifacts/spectron_server_npc_showimg_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v246 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v246.json"
    )
    spectron_tiles_layer_property_anchors = load_json(
        "artifacts/spectron_tiles_layer_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v247 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v247.json"
    )
    spectron_player_property_anchors = load_json(
        "artifacts/spectron_player_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v248 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v248.json"
    )
    spectron_gani_property_residual_anchors = load_json(
        "artifacts/spectron_gani_property_residual_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v249 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v249.json"
    )
    spectron_drawing_panel_property_residual_anchors = load_json(
        "artifacts/spectron_drawing_panel_property_residual_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v250 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v250.json"
    )
    spectron_tplayer_findweapon_anchors = load_json(
        "artifacts/spectron_tplayer_findweapon_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v251 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v251.json"
    )
    spectron_tgui_animation_property_residual_anchors = load_json(
        "artifacts/spectron_tgui_animation_property_residual_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v252 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v252.json"
    )
    spectron_gui_bitmap_property_anchors = load_json(
        "artifacts/spectron_gui_bitmap_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v253 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v253.json"
    )
    spectron_gui_bitmap_button_property_anchors = load_json(
        "artifacts/spectron_gui_bitmap_button_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v254 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v254.json"
    )
    spectron_guicontrol_property_tail_anchors = load_json(
        "artifacts/spectron_guicontrol_property_tail_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v255 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v255.json"
    )
    spectron_guigraalctrl_isrendering_anchors = load_json(
        "artifacts/spectron_guigraalctrl_isrendering_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v256 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v256.json"
    )
    spectron_guiscrollctrl_property_anchors = load_json(
        "artifacts/spectron_guiscrollctrl_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v257 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v257.json"
    )
    spectron_guistretchctrl_property_anchors = load_json(
        "artifacts/spectron_guistretchctrl_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v258 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v258.json"
    )
    spectron_guitexteditctrl_property_anchors = load_json(
        "artifacts/spectron_guitexteditctrl_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v259 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v259.json"
    )
    spectron_tgraalvar_property_residual_anchors = load_json(
        "artifacts/spectron_tgraalvar_property_residual_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v260 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v260.json"
    )
    spectron_tbodypanel_bodycacheperplayer_anchor = load_json(
        "artifacts/spectron_tbodypanel_bodycacheperplayer_manual_translation_anchor_20260828.json"
    )
    spectron_checkpoint_v261 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v261.json"
    )
    spectron_residual_property_anchors = load_json(
        "artifacts/spectron_residual_property_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v262 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v262.json"
    )
    spectron_gui_android_anchors = load_json(
        "artifacts/spectron_gui_android_manual_translation_anchors_20260828.json"
    )
    spectron_android_bridge_target_only_labels = load_json(
        "artifacts/spectron_android_bridge_target_only_labels_20260828.json"
    )
    spectron_checkpoint_v263_corrected = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v263_corrected.json"
    )
    spectron_checkpoint_v264_corrected = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v264_corrected.json"
    )
    spectron_android_legacy_anchors = load_json(
        "artifacts/spectron_android_legacy_manual_translation_anchors_20260828.json"
    )
    spectron_android_security_target_only_labels = load_json(
        "artifacts/spectron_android_security_target_only_labels_20260828.json"
    )
    spectron_checkpoint_v265 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v265.json"
    )
    spectron_checkpoint_v266 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v266.json"
    )
    spectron_android_security_target_only_labels_corrected = load_json(
        "artifacts/spectron_android_security_target_only_labels_corrected_20260828.json"
    )
    spectron_android_package_identity_labels = load_json(
        "artifacts/spectron_android_package_identity_labels_20260828.json"
    )
    spectron_checkpoint_v267 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v267.json"
    )
    spectron_checkpoint_v268 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v268.json"
    )
    spectron_tgraalvar_script_runtime_anchors = load_json(
        "artifacts/spectron_tgraalvar_script_runtime_manual_translation_anchors_20260828.json"
    )
    spectron_tgraalvar_target_only_labels = load_json(
        "artifacts/spectron_tgraalvar_target_only_labels_20260828.json"
    )
    spectron_checkpoint_v269 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v269.json"
    )
    spectron_script_table_surface_anchors = load_json(
        "artifacts/spectron_script_table_surface_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v270 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v270.json"
    )
    spectron_runtime_callback_residual_anchors = load_json(
        "artifacts/spectron_runtime_callback_residual_manual_translation_anchors_20260828.json"
    )
    spectron_tplayer_quattro_zoom_property_labels = load_json(
        "artifacts/spectron_tplayer_quattro_zoom_property_target_only_labels_20260828.json"
    )
    spectron_checkpoint_v271 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v271.json"
    )
    spectron_zlib_inflate_fast_anchor = load_json(
        "artifacts/spectron_zlib_inflate_fast_manual_translation_anchor_20260828.json"
    )
    spectron_checkpoint_v272 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v272.json"
    )
    spectron_jpeg_io_anchors = load_json(
        "artifacts/spectron_jpeg_io_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v273 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v273.json"
    )
    spectron_jdinput_controller_anchors = load_json(
        "artifacts/spectron_jpeg_input_controller_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v274 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v274.json"
    )
    spectron_jdmarker_anchors = load_json(
        "artifacts/spectron_jpeg_marker_reader_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v275 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v275.json"
    )
    spectron_jdmaster_jdmerge_anchors = load_json(
        "artifacts/spectron_jpeg_master_merge_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v276 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v276.json"
    )
    spectron_jdphuff_anchors = load_json(
        "artifacts/spectron_jpeg_progressive_huffman_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v277 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v277.json"
    )
    spectron_jdpostct_anchors = load_json(
        "artifacts/spectron_jpeg_postprocessing_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v278 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v278.json"
    )
    spectron_jdsample_anchors = load_json(
        "artifacts/spectron_jpeg_upsampler_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v279 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v279.json"
    )
    spectron_jerror_anchors = load_json(
        "artifacts/spectron_jpeg_error_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v280 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v280.json"
    )
    spectron_jmemmgr_anchors = load_json(
        "artifacts/spectron_jpeg_memory_manager_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v281 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v281.json"
    )
    spectron_jquant1_anchors = load_json(
        "artifacts/spectron_jpeg_one_pass_quantizer_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v282 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v282.json"
    )
    spectron_jquant2_anchors = load_json(
        "artifacts/spectron_jpeg_two_pass_quantizer_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v283 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v283.json"
    )
    spectron_jdcoefct_anchors = load_json(
        "artifacts/spectron_jpeg_coefficient_controller_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v284 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v284.json"
    )
    spectron_jdcolor_anchors = load_json(
        "artifacts/spectron_jpeg_color_deconverter_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v285 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v285.json"
    )
    spectron_jddctmgr_anchors = load_json(
        "artifacts/spectron_jpeg_inverse_dct_manager_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v286 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v286.json"
    )
    spectron_jdhuff_anchors = load_json(
        "artifacts/spectron_jpeg_baseline_huffman_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v287 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v287.json"
    )
    spectron_jdmainct_anchors = load_json(
        "artifacts/spectron_jpeg_main_controller_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v288 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v288.json"
    )
    spectron_jccolor_anchors = load_json(
        "artifacts/spectron_jpeg_compressor_color_converter_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v289 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v289.json"
    )
    spectron_jccoefct_anchors = load_json(
        "artifacts/spectron_jpeg_compressor_coefficient_controller_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v290 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v290.json"
    )
    spectron_jcdctmgr_anchors = load_json(
        "artifacts/spectron_jpeg_forward_dct_manager_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v291 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v291.json"
    )
    spectron_jchuff_anchors = load_json(
        "artifacts/spectron_jpeg_huffman_encoder_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v292 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v292.json"
    )
    spectron_jcphuff_encoder_anchors = load_json(
        "artifacts/spectron_jpeg_progressive_huffman_encoder_manual_translation_anchors_20260828.json"
    )
    spectron_jcmainct_jcmaster_anchors = load_json(
        "artifacts/spectron_jpeg_main_master_controller_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v293 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v293.json"
    )
    spectron_checkpoint_v294 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v294.json"
    )
    spectron_jcprepct_jcsample_anchors = load_json(
        "artifacts/spectron_jpeg_preprocessing_downsampling_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v295 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v295.json"
    )
    spectron_gif_lzw_line_decoder_anchors = load_json(
        "artifacts/spectron_gif_lzw_line_decoder_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v296 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v296.json"
    )
    spectron_fdct_literal_pool_repair = load_json(
        "artifacts/spectron_fdct_literal_pool_boundary_repair_20260828.json"
    )
    spectron_checkpoint_v297 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v297.json"
    )
    spectron_freetype_base_cleanup_anchors = load_json(
        "artifacts/spectron_freetype_base_cleanup_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v298 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v298.json"
    )
    spectron_freetype_sfnt_service_anchors = load_json(
        "artifacts/spectron_freetype_sfnt_service_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v299 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v299.json"
    )
    spectron_freetype_sfnt_interface_anchors = load_json(
        "artifacts/spectron_freetype_sfnt_interface_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v300 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v300.json"
    )
    spectron_freetype_smooth_anchors = load_json(
        "artifacts/spectron_freetype_smooth_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v301 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v301.json"
    )
    spectron_freetype_gray_internal_anchors = load_json(
        "artifacts/spectron_freetype_gray_internal_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v302 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v302.json"
    )
    spectron_freetype_tt_interpreter_anchors = load_json(
        "artifacts/spectron_freetype_tt_interpreter_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v303 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v303.json"
    )
    spectron_freetype_tt_runtime_anchors = load_json(
        "artifacts/spectron_freetype_tt_runtime_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v304 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v304.json"
    )
    spectron_freetype_tt_rounding_anchors = load_json(
        "artifacts/spectron_freetype_tt_rounding_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v305 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v305.json"
    )
    spectron_freetype_tt_opcode_state_anchors = load_json(
        "artifacts/spectron_freetype_tt_opcode_state_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v306 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v306.json"
    )
    spectron_freetype_tt_opcode_core_anchors = load_json(
        "artifacts/spectron_freetype_tt_opcode_core_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v307 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v307.json"
    )
    spectron_freetype_tt_runtime_tail_anchors = load_json(
        "artifacts/spectron_freetype_tt_runtime_tail_manual_translation_anchors_20260828.json"
    )
    spectron_freetype_tt_projection_correction = load_json(
        "artifacts/spectron_freetype_tt_projection_name_correction_20260828.json"
    )
    spectron_checkpoint_v308 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v308.json"
    )
    spectron_freetype_tt_glyph_loader_anchors = load_json(
        "artifacts/spectron_freetype_tt_glyph_loader_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v309 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v309.json"
    )
    spectron_freetype_autofit_anchors = load_json(
        "artifacts/spectron_freetype_autofit_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v310 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v310.json"
    )
    spectron_freetype_autofit_followup_anchors = load_json(
        "artifacts/spectron_freetype_autofit_followup_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v311 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v311.json"
    )
    spectron_freetype_autofit_metrics_anchors = load_json(
        "artifacts/spectron_freetype_autofit_metrics_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v312 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v312.json"
    )
    spectron_bzip2_helpers_anchors = load_json(
        "artifacts/spectron_bzip2_helpers_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v313 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v313.json"
    )
    spectron_freetype_apply_anchors = load_json(
        "artifacts/spectron_freetype_apply_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v314 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v314.json"
    )
    spectron_jcmarker_anchors = load_json(
        "artifacts/spectron_jpeg_marker_writer_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v315 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v315.json"
    )
    spectron_freetype_tt_size_reset_anchor = load_json(
        "artifacts/spectron_freetype_tt_size_reset_manual_translation_anchor_20260828.json"
    )
    spectron_checkpoint_v316 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v316.json"
    )
    spectron_jpeg_gpc_residual_anchors = load_json(
        "artifacts/spectron_jpeg_gpc_residual_manual_translation_anchors_20260828.json"
    )
    spectron_checkpoint_v317 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v317.json"
    )
    spectron_residual_target_only_labels = load_json(
        "artifacts/spectron_residual_target_only_labels_20260828.json"
    )
    spectron_checkpoint_v318 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v318.json"
    )
    spectron_name_coverage_v318 = load_json(
        "artifacts/spectron_name_coverage_audit_v318_20260828.json"
    )
    spectron_name_coverage_v319 = load_json(
        "artifacts/spectron_name_coverage_audit_20260828.json"
    )
    spectron_nullsub_labels = load_json(
        "artifacts/spectron_nullsub_target_only_labels_20260828.json"
    )
    spectron_checkpoint_v319 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v319.json"
    )
    spectron_name_coverage_v320 = load_json(
        "artifacts/spectron_name_coverage_audit_v320_20260828.json"
    )
    spectron_dynamic_function_application = load_json(
        "artifacts/spectron_dynamic_function_application_20260828.json"
    )
    spectron_dynamic_boundaries = load_json(
        "artifacts/spectron_dynamic_symbol_boundaries_20260828.json"
    )
    spectron_dynamic_symbol_coverage = load_json(
        "artifacts/spectron_dynamic_symbol_coverage_audit_20260828.json"
    )
    spectron_symbol_inventory_v320 = load_json(
        "artifacts/spectron_symbol_translation_inventory_20260828.json"
    )
    spectron_checkpoint_v320 = load_json(
        "artifacts/spectron_translation_checkpoint_20260828_v320.json"
    )
    spectron_player_helper_anchors = load_json(
        "artifacts/spectron_player_helper_manual_translation_anchors_20260826.json"
    )
    spectron_input_window_anchors = load_json(
        "artifacts/spectron_input_window_manual_translation_anchors_20260826.json"
    )
    spectron_visual_helper_anchors = load_json(
        "artifacts/spectron_visual_helper_manual_translation_anchors_20260826.json"
    )
    spectron_script_runtime_anchors = load_json(
        "artifacts/spectron_script_runtime_manual_translation_anchors_20260826.json"
    )
    spectron_core_helper_anchors = load_json(
        "artifacts/spectron_core_helper_manual_translation_anchors_20260826.json"
    )
    spectron_render_gui_anchors = load_json(
        "artifacts/spectron_render_gui_manual_translation_anchors_20260826.json"
    )
    spectron_json_folder_anchors = load_json(
        "artifacts/spectron_json_folder_manual_translation_anchors_20260826.json"
    )
    spectron_resource_object_anchors = load_json(
        "artifacts/spectron_resource_object_manual_translation_anchors_20260826.json"
    )
    spectron_script_machine_anchors = load_json(
        "artifacts/spectron_script_machine_manual_translation_anchors_20260826.json"
    )
    spectron_script_space_anchors = load_json(
        "artifacts/spectron_script_space_manual_translation_anchors_20260826.json"
    )
    spectron_script_execution_anchors = load_json(
        "artifacts/spectron_script_execution_manual_translation_anchors_20260826.json"
    )
    spectron_script_dispatch_anchors = load_json(
        "artifacts/spectron_script_dispatch_manual_translation_anchors_20260826.json"
    )
    spectron_script_scheduler_anchors = load_json(
        "artifacts/spectron_script_scheduler_manual_translation_anchors_20260826.json"
    )
    spectron_event_object_anchors = load_json(
        "artifacts/spectron_event_object_manual_translation_anchors_20260826.json"
    )
    spectron_script_action_anchors = load_json(
        "artifacts/spectron_script_action_manual_translation_anchors_20260826.json"
    )
    spectron_stack_entry_anchors = load_json(
        "artifacts/spectron_stack_entry_manual_translation_anchors_20260826.json"
    )
    spectron_machine_helper_anchors = load_json(
        "artifacts/spectron_machine_helper_manual_translation_anchors_20260826.json"
    )
    spectron_array_mutation_anchors = load_json(
        "artifacts/spectron_array_mutation_manual_translation_anchors_20260826.json"
    )
    spectron_string_search_anchors = load_json(
        "artifacts/spectron_string_search_manual_translation_anchors_20260826.json"
    )
    spectron_string_helper_anchors = load_json(
        "artifacts/spectron_string_helper_manual_translation_anchors_20260826.json"
    )
    spectron_variable_construction_anchors = load_json(
        "artifacts/spectron_variable_construction_manual_translation_anchors_20260826.json"
    )
    spectron_script_object_anchors = load_json(
        "artifacts/spectron_script_object_manual_translation_anchors_20260826.json"
    )
    spectron_script_state_anchors = load_json(
        "artifacts/spectron_script_state_manual_translation_anchors_20260826.json"
    )
    spectron_execution_dispatch_anchors = load_json(
        "artifacts/spectron_execution_dispatch_manual_translation_anchors_20260826.json"
    )
    spectron_tokenizer_anchors = load_json(
        "artifacts/spectron_tokenizer_manual_translation_anchors_20260826.json"
    )
    spectron_script_executor_anchors = load_json(
        "artifacts/spectron_script_executor_manual_translation_anchors_20260826.json"
    )
    spectron_script_property_anchors = load_json(
        "artifacts/spectron_script_property_manual_translation_anchors_20260826.json"
    )
    spectron_script_universe_anchors = load_json(
        "artifacts/spectron_script_universe_manual_translation_anchors_20260826.json"
    )
    spectron_static_json_tiles_anchors = load_json(
        "artifacts/spectron_static_json_tiles_manual_translation_anchors_20260826.json"
    )
    spectron_tiles_update_anchors = load_json(
        "artifacts/spectron_tiles_update_manual_translation_anchors_20260826.json"
    )
    spectron_particle_anchors = load_json(
        "artifacts/spectron_particle_manual_translation_anchors_20260826.json"
    )
    spectron_showimg_anchors = load_json(
        "artifacts/spectron_showimg_manual_translation_anchors_20260826.json"
    )
    spectron_showimg_property_anchors = load_json(
        "artifacts/spectron_showimg_property_manual_translation_anchors_20260827.json"
    )
    spectron_showimg_residual_anchors = load_json(
        "artifacts/spectron_showimg_residual_manual_translation_anchors_20260827.json"
    )
    spectron_server_object_scalar_anchors = load_json(
        "artifacts/spectron_server_object_scalar_manual_translation_anchors_20260827.json"
    )
    spectron_compression_anchors = load_json(
        "artifacts/spectron_compression_manual_translation_anchors_20260827.json"
    )
    spectron_files_anchors = load_json(
        "artifacts/spectron_files_manual_translation_anchors_20260827.json"
    )
    spectron_encryption_anchors = load_json(
        "artifacts/spectron_encryption_manual_translation_anchors_20260827.json"
    )
    spectron_tlist_anchors = load_json(
        "artifacts/spectron_tlist_manual_translation_anchors_20260827.json"
    )
    spectron_sounds_anchors = load_json(
        "artifacts/spectron_sounds_manual_translation_anchors_20260827.json"
    )
    spectron_hash_container_anchors = load_json(
        "artifacts/spectron_hash_container_manual_translation_anchors_20260827.json"
    )
    spectron_hash_lifecycle_anchors = load_json(
        "artifacts/spectron_hash_lifecycle_manual_translation_anchors_20260827.json"
    )
    spectron_tstring_anchors = load_json(
        "artifacts/spectron_tstring_manual_translation_anchors_20260827.json"
    )
    spectron_tstring_clear_anchors = load_json(
        "artifacts/spectron_tstring_clear_manual_translation_anchors_20260827.json"
    )
    spectron_static_clear_anchors = load_json(
        "artifacts/spectron_static_clear_manual_translation_anchors_20260827.json"
    )
    spectron_static_callback_role_correction = load_json(
        "artifacts/spectron_static_callback_role_correction_20260827.json"
    )
    spectron_http_request_receive_anchors = load_json(
        "artifacts/spectron_http_request_receive_manual_translation_anchors_20260827.json"
    )
    spectron_server_list_connection_anchors = load_json(
        "artifacts/spectron_server_list_connection_manual_translation_anchors_20260827.json"
    )
    spectron_server_list_state_anchors = load_json(
        "artifacts/spectron_server_list_state_manual_translation_anchors_20260827.json"
    )
    spectron_http_request_cleanup_anchors = load_json(
        "artifacts/spectron_http_request_cleanup_manual_translation_anchors_20260827.json"
    )
    spectron_tsocket_residual_anchors = load_json(
        "artifacts/spectron_tsocket_residual_manual_translation_anchors_20260827.json"
    )
    spectron_game_environment_anchors = load_json(
        "artifacts/spectron_game_environment_manual_translation_anchors_20260827.json"
    )
    spectron_client_environment_graphics_anchors = load_json(
        "artifacts/spectron_client_environment_graphics_manual_translation_anchors_20260827.json"
    )
    spectron_client_environment_static_clear_anchors = load_json(
        "artifacts/spectron_client_environment_static_clear_manual_translation_anchors_20260827.json"
    )
    spectron_client_environment_restart_state_anchors = load_json(
        "artifacts/spectron_client_environment_restart_state_manual_translation_anchors_20260827.json"
    )
    spectron_particle_emitter_anchors = load_json(
        "artifacts/spectron_particle_emitter_manual_translation_anchors_20260826.json"
    )
    spectron_particle_emitter_script_vars_anchors = load_json(
        "artifacts/spectron_particle_emitter_script_vars_manual_translation_anchors_20260827.json"
    )
    spectron_resource_link_lists_anchors = load_json(
        "artifacts/spectron_resource_link_lists_manual_translation_anchors_20260827.json"
    )
    spectron_clear_cur_anis_anchors = load_json(
        "artifacts/spectron_clear_cur_anis_manual_translation_anchors_20260827.json"
    )
    spectron_options_window_position_anchors = load_json(
        "artifacts/spectron_options_window_position_manual_translation_anchors_20260827.json"
    )
    spectron_displayed_gif_anchors = load_json(
        "artifacts/spectron_displayed_gif_manual_translation_anchors_20260827.json"
    )
    spectron_gui_button_types_anchors = load_json(
        "artifacts/spectron_gui_button_types_manual_translation_anchors_20260827.json"
    )
    spectron_gui_alignment_tables_anchors = load_json(
        "artifacts/spectron_gui_alignment_tables_manual_translation_anchors_20260827.json"
    )
    spectron_gui_stretch_modes_anchors = load_json(
        "artifacts/spectron_gui_stretch_modes_manual_translation_anchors_20260827.json"
    )
    spectron_tgui_render_colors_anchors = load_json(
        "artifacts/spectron_tgui_render_colors_manual_translation_anchors_20260827.json"
    )
    spectron_thtml_definitions_defaults_anchors = load_json(
        "artifacts/spectron_thtml_definitions_defaults_manual_translation_anchors_20260827.json"
    )
    spectron_tclient_static_strings_anchors = load_json(
        "artifacts/spectron_tclient_static_strings_manual_translation_anchors_20260827.json"
    )
    spectron_tsocket_static_strings_anchors = load_json(
        "artifacts/spectron_tsocket_static_state_manual_translation_anchors_20260827.json"
    )
    spectron_android_tapjoy_video_anchors = load_json(
        "artifacts/spectron_android_tapjoy_video_state_manual_translation_anchors_20260827.json"
    )
    spectron_sounds_music_state_anchors = load_json(
        "artifacts/spectron_sounds_music_state_manual_translation_anchors_20260827.json"
    )
    spectron_sounds_effect_anchors = load_json(
        "artifacts/spectron_sounds_effect_manual_translation_anchors_20260827.json"
    )
    spectron_sounds_control_anchors = load_json(
        "artifacts/spectron_sounds_control_manual_translation_anchors_20260827.json"
    )
    spectron_sounds_tail_anchors = load_json(
        "artifacts/spectron_sounds_tail_manual_translation_anchors_20260827.json"
    )
    spectron_tsound_effect_methods_anchors = load_json(
        "artifacts/spectron_tsound_effect_methods_manual_translation_anchors_20260827.json"
    )
    spectron_sound_java_small_methods_anchors = load_json(
        "artifacts/spectron_sound_java_small_methods_manual_translation_anchors_20260827.json"
    )
    spectron_sound_java_destructor_anchors = load_json(
        "artifacts/spectron_sound_java_destructor_manual_translation_anchors_20260827.json"
    )
    spectron_sound_java_d1_anchors = load_json(
        "artifacts/spectron_sound_java_d1_manual_translation_anchors_20260827.json"
    )
    spectron_sound_base_interface_anchors = load_json(
        "artifacts/spectron_sound_base_interface_manual_translation_anchors_20260827.json"
    )
    spectron_server_animation_anchors = load_json(
        "artifacts/spectron_server_animation_manual_translation_anchors_20260826.json"
    )
    spectron_player_lifecycle_anchors = load_json(
        "artifacts/spectron_player_lifecycle_manual_translation_anchors_20260826.json"
    )
    spectron_player_emoticon_anchors = load_json(
        "artifacts/spectron_player_emoticon_manual_translation_anchors_20260826.json"
    )
    spectron_player_level_entry_anchors = load_json(
        "artifacts/spectron_player_level_entry_manual_translation_anchors_20260826.json"
    )
    spectron_player_side_level_anchors = load_json(
        "artifacts/spectron_player_side_level_manual_translation_anchors_20260826.json"
    )
    spectron_player_map_position_anchors = load_json(
        "artifacts/spectron_player_map_position_manual_translation_anchors_20260826.json"
    )
    spectron_player_link_traversal_anchors = load_json(
        "artifacts/spectron_player_link_traversal_manual_translation_anchors_20260826.json"
    )
    spectron_player_weapon_state_anchors = load_json(
        "artifacts/spectron_player_weapon_state_manual_translation_anchors_20260826.json"
    )
    spectron_player_visual_setter_anchors = load_json(
        "artifacts/spectron_player_visual_setter_manual_translation_anchors_20260826.json"
    )
    spectron_player_movement_anchors = load_json(
        "artifacts/spectron_player_movement_manual_translation_anchors_20260826.json"
    )
    spectron_server_player_state_anchors = load_json(
        "artifacts/spectron_server_player_state_manual_translation_anchors_20260826.json"
    )
    spectron_server_npc_state_anchors = load_json(
        "artifacts/spectron_server_npc_state_manual_translation_anchors_20260826.json"
    )
    spectron_npc_accessor_anchors = load_json(
        "artifacts/spectron_npc_accessor_manual_translation_anchors_20260826.json"
    )
    spectron_npc_destructor_anchors = load_json(
        "artifacts/spectron_npc_destructor_manual_translation_anchors_20260826.json"
    )
    spectron_server_level_property_anchors = load_json(
        "artifacts/spectron_server_level_property_manual_translation_anchors_20260826.json"
    )
    spectron_server_level_interaction_anchors = load_json(
        "artifacts/spectron_server_level_interaction_manual_translation_anchors_20260826.json"
    )
    spectron_server_level_lifecycle_anchors = load_json(
        "artifacts/spectron_server_level_lifecycle_manual_translation_anchors_20260826.json"
    )
    spectron_server_level_side_helpers_anchors = load_json(
        "artifacts/spectron_server_level_side_helpers_manual_translation_anchors_20260826.json"
    )
    spectron_server_level_storage_anchors = load_json(
        "artifacts/spectron_server_level_storage_manual_translation_anchors_20260826.json"
    )
    spectron_hidden_testnpc_anchors = load_json(
        "artifacts/spectron_hidden_testnpc_manual_translation_anchor_20260826.json"
    )
    spectron_level_map_lookup_anchors = load_json(
        "artifacts/spectron_level_map_lookup_manual_translation_anchors_20260826.json"
    )
    spectron_gani_constructor_anchors = load_json(
        "artifacts/spectron_gani_constructor_manual_translation_anchor_20260826.json"
    )
    spectron_gani_helper_anchors = load_json(
        "artifacts/spectron_gani_helper_manual_translation_anchors_20260826.json"
    )
    spectron_gani_runtime_anchors = load_json(
        "artifacts/spectron_gani_runtime_manual_translation_anchors_20260826.json"
    )
    spectron_gani_render_anchors = load_json(
        "artifacts/spectron_gani_render_manual_translation_anchors_20260826.json"
    )
    spectron_gani_frame_playback_anchors = load_json(
        "artifacts/spectron_gani_frame_playback_manual_translation_anchors_20260826.json"
    )
    spectron_gani_lifecycle_anchors = load_json(
        "artifacts/spectron_gani_lifecycle_manual_translation_anchors_20260826.json"
    )
    spectron_tplayer_core_anchors = load_json(
        "artifacts/spectron_tplayer_core_manual_translation_anchors_20260826.json"
    )
    spectron_resource_parser_anchors = load_json(
        "artifacts/spectron_resource_parser_manual_translation_anchors_20260826.json"
    )
    spectron_static_utility_anchors = load_json(
        "artifacts/spectron_static_utility_manual_translation_anchors_20260826.json"
    )
    spectron_font_bitmap_anchors = load_json(
        "artifacts/spectron_font_bitmap_manual_translation_anchors_20260826.json"
    )
    spectron_mng_animation_anchors = load_json(
        "artifacts/spectron_mng_animation_manual_translation_anchor_20260826.json"
    )
    spectron_script_machine_tail_anchors = load_json(
        "artifacts/spectron_script_machine_tail_manual_translation_anchors_20260826.json"
    )
    spectron_script_stream_profile_anchors = load_json(
        "artifacts/spectron_script_stream_profile_manual_translation_anchors_20260826.json"
    )
    spectron_ani_lexer_anchors = load_json(
        "artifacts/spectron_ani_lexer_fatal_manual_translation_anchor_20260826.json"
    )
    spectron_number_array_string_anchors = load_json(
        "artifacts/spectron_number_array_string_manual_translation_anchors_20260826.json"
    )
    spectron_client_environment_clock_anchors = load_json(
        "artifacts/spectron_client_environment_clock_manual_translation_anchors_20260826.json"
    )
    spectron_client_var_core_anchors = load_json(
        "artifacts/spectron_client_var_core_manual_translation_anchors_20260826.json"
    )
    spectron_tstringlist_comma_anchors = load_json(
        "artifacts/spectron_tstringlist_comma_manual_translation_anchors_20260826.json"
    )
    spectron_tstringlist_extended_anchors = load_json(
        "artifacts/spectron_tstringlist_extended_manual_translation_anchors_20260826.json"
    )
    spectron_hash_family_anchors = load_json(
        "artifacts/spectron_hash_family_manual_translation_anchors_20260826.json"
    )
    spectron_options_anchors = load_json(
        "artifacts/spectron_options_manual_translation_anchors_20260826.json"
    )
    spectron_texture_anchors = load_json(
        "artifacts/spectron_texture_manual_translation_anchors_20260826.json"
    )
    spectron_drawing_panel_texture_anchors = load_json(
        "artifacts/spectron_drawing_panel_texture_manual_translation_anchors_20260826.json"
    )
    spectron_draw_texture_anchors = load_json(
        "artifacts/spectron_draw_texture_manual_translation_anchors_20260826.json"
    )
    spectron_bitmap_array_holder_anchors = load_json(
        "artifacts/spectron_bitmap_array_holder_manual_translation_anchors_20260826.json"
    )
    spectron_color_manager_anchors = load_json(
        "artifacts/spectron_color_manager_manual_translation_anchors_20260826.json"
    )
    spectron_font_runtime_anchors = load_json(
        "artifacts/spectron_font_runtime_manual_translation_anchors_20260826.json"
    )
    spectron_window_input_anchors = load_json(
        "artifacts/spectron_window_input_manual_translation_anchors_20260826.json"
    )
    spectron_drawing_panel_residual_anchors = load_json(
        "artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260826.json"
    )
    spectron_image_html_anchors = load_json(
        "artifacts/spectron_image_html_manual_translation_anchors_20260826.json"
    )
    spectron_panel_bitmap_anchors = load_json(
        "artifacts/spectron_panel_bitmap_manual_translation_anchors_20260826.json"
    )
    spectron_gif_decoder_anchors = load_json(
        "artifacts/spectron_gif_decoder_manual_translation_anchor_20260826.json"
    )
    spectron_window_residual_anchors = load_json(
        "artifacts/spectron_window_residual_manual_translation_anchors_20260826.json"
    )
    spectron_sound_runtime_anchors = load_json(
        "artifacts/spectron_sound_runtime_manual_translation_anchors_20260826.json"
    )
    spectron_pixelbuffer_residual_anchors = load_json(
        "artifacts/spectron_pixelbuffer_residual_manual_translation_anchors_20260826.json"
    )
    spectron_pixelbuffer_bitmap_lifecycle_anchors = load_json(
        "artifacts/spectron_pixelbuffer_bitmap_lifecycle_correction_anchors_20260826.json"
    )
    spectron_animation_palette_residual_anchors = load_json(
        "artifacts/spectron_animation_palette_residual_manual_translation_anchors_20260826.json"
    )
    spectron_panel_virtual_renderer_residual_anchors = load_json(
        "artifacts/spectron_panel_virtual_renderer_residual_manual_translation_anchors_20260826.json"
    )
    spectron_dummy_panel_residual_anchors = load_json(
        "artifacts/spectron_dummy_panel_residual_manual_translation_anchors_20260826.json"
    )
    spectron_screen_panel_renderer_residual_anchors = load_json(
        "artifacts/spectron_screen_panel_renderer_residual_manual_translation_anchors_20260826.json"
    )
    spectron_screen_panel_window_gles_residual_anchors = load_json(
        "artifacts/spectron_screen_panel_window_gles_residual_manual_translation_anchors_20260826.json"
    )
    spectron_font_manager_font_residual_anchors = load_json(
        "artifacts/spectron_font_manager_font_residual_manual_translation_anchors_20260826.json"
    )
    spectron_font_options_font_data_residual_anchors = load_json(
        "artifacts/spectron_font_options_font_data_residual_manual_translation_anchors_20260826.json"
    )
    spectron_gui_control_profile_accessor_anchors = load_json(
        "artifacts/spectron_gui_control_profile_accessor_manual_translation_anchors_20260826.json"
    )
    spectron_gui_control_profile_destructor_anchors = load_json(
        "artifacts/spectron_gui_control_profile_destructor_manual_translation_anchors_20260826.json"
    )
    spectron_guicontrol_property_residual_anchors = load_json(
        "artifacts/spectron_guicontrol_property_residual_manual_translation_anchors_20260826.json"
    )
    spectron_guicontrol_virtual_residual_anchors = load_json(
        "artifacts/spectron_guicontrol_virtual_residual_manual_translation_anchors_20260826.json"
    )
    spectron_guicontrol_event_sizing_residual_anchors = load_json(
        "artifacts/spectron_guicontrol_event_sizing_residual_manual_translation_anchors_20260826.json"
    )
    spectron_guicontrol_style_bounds_residual_anchors = load_json(
        "artifacts/spectron_guicontrol_style_bounds_residual_manual_translation_anchors_20260826.json"
    )
    spectron_guicontrol_event_dispatch_residual_anchors = load_json(
        "artifacts/spectron_guicontrol_event_dispatch_residual_manual_translation_anchors_20260826.json"
    )
    spectron_guicontrol_initialization_residual_anchors = load_json(
        "artifacts/spectron_guicontrol_initialization_residual_manual_translation_anchors_20260826.json"
    )
    spectron_guicontrol_create_residual_anchors = load_json(
        "artifacts/spectron_guicontrol_create_residual_manual_translation_anchors_20260826.json"
    )
    spectron_tsocket_accessor_residual_anchors = load_json(
        "artifacts/spectron_tsocket_accessor_residual_manual_translation_anchors_20260826.json"
    )
    spectron_tsocket_ssl_residual_anchors = load_json(
        "artifacts/spectron_tsocket_ssl_residual_manual_translation_anchors_20260826.json"
    )
    spectron_tsocket_receive_residual_anchors = load_json(
        "artifacts/spectron_tsocket_receive_residual_manual_translation_anchors_20260826.json"
    )
    spectron_tsocket_lifecycle_residual_anchors = load_json(
        "artifacts/spectron_tsocket_lifecycle_residual_manual_translation_anchors_20260826.json"
    )
    spectron_tsocket_host_residual_anchors = load_json(
        "artifacts/spectron_tsocket_host_residual_manual_translation_anchors_20260826.json"
    )
    spectron_tsocket_properties_residual_anchors = load_json(
        "artifacts/spectron_tsocket_properties_residual_manual_translation_anchors_20260826.json"
    )
    spectron_socket_cache_residual_anchors = load_json(
        "artifacts/spectron_socket_cache_residual_manual_translation_anchors_20260826.json"
    )
    spectron_url_cache_residual_anchors = load_json(
        "artifacts/spectron_url_cache_residual_manual_translation_anchors_20260826.json"
    )
    spectron_player_list_residual_anchors = load_json(
        "artifacts/spectron_player_list_residual_manual_translation_anchors_20260826.json"
    )
    spectron_client_thread_residual_anchors = load_json(
        "artifacts/spectron_client_thread_residual_manual_translation_anchors_20260826.json"
    )
    spectron_update_package_accessor_residual_anchors = load_json(
        "artifacts/spectron_update_package_accessor_residual_manual_translation_anchors_20260826.json"
    )
    spectron_update_package_destructor_residual_anchors = load_json(
        "artifacts/spectron_update_package_destructor_residual_manual_translation_anchors_20260826.json"
    )
    spectron_update_package_wrapper_residual_anchors = load_json(
        "artifacts/spectron_update_package_wrapper_residual_manual_translation_anchors_20260826.json"
    )
    spectron_update_package_properties_residual_anchors = load_json(
        "artifacts/spectron_update_package_properties_residual_manual_translation_anchors_20260826.json"
    )
    spectron_gsfunctions_math_string_residual_anchors = load_json(
        "artifacts/spectron_gsfunctions_math_string_residual_manual_translation_anchors_20260826.json"
    )
    spectron_gsfunctions_callback_residual_anchors = load_json(
        "artifacts/spectron_gsfunctions_callback_residual_manual_translation_anchors_20260826.json"
    )
    spectron_gsfunctions_randomstring_residual_anchors = load_json(
        "artifacts/spectron_gsfunctions_randomstring_residual_manual_translation_anchors_20260826.json"
    )
    spectron_gsfunctions_client_exact_residual_anchors = load_json(
        "artifacts/spectron_gsfunctions_client_exact_residual_manual_translation_anchors_20260826.json"
    )
    spectron_gsfunctions_client_exact_residual_v2_anchors = load_json(
        "artifacts/spectron_gsfunctions_client_exact_residual_v2_manual_translation_anchors_20260826.json"
    )
    spectron_gsfunctions_client_exact_residual_v3_anchors = load_json(
        "artifacts/spectron_gsfunctions_client_exact_residual_v3_manual_translation_anchors_20260826.json"
    )
    spectron_gsfunctions_client_boundary_residual_anchors = load_json(
        "artifacts/spectron_gsfunctions_client_boundary_residual_manual_translation_anchors_20260826.json"
    )
    spectron_gsfunctions_client_exact_residual_v4_anchors = load_json(
        "artifacts/spectron_gsfunctions_client_exact_residual_v4_manual_translation_anchors_20260826.json"
    )
    spectron_cyaint_tls_residual_anchors = load_json(
        "artifacts/spectron_cyaint_tls_residual_manual_translation_anchors_20260826.json"
    )
    spectron_cyaint_tls_residual_v2_anchors = load_json(
        "artifacts/spectron_cyaint_tls_residual_v2_manual_translation_anchors_20260826.json"
    )
    spectron_tserverplayer_accessor_anchors = load_json(
        "artifacts/spectron_tserverplayer_accessor_manual_translation_anchors_20260826.json"
    )
    spectron_tplayer_scalar_setter_anchors = load_json(
        "artifacts/spectron_tplayer_scalar_setter_manual_translation_anchors_20260826.json"
    )
    spectron_tplayer_scalar_getter_anchors = load_json(
        "artifacts/spectron_tplayer_scalar_getter_manual_translation_anchors_20260826.json"
    )
    spectron_tplayer_flag_setter_anchors = load_json(
        "artifacts/spectron_tplayer_flag_setter_manual_translation_anchors_20260826.json"
    )
    spectron_tserverplayer_property_block_anchors = load_json(
        "artifacts/spectron_tserverplayer_property_block_manual_translation_anchors_20260826.json"
    )
    spectron_tserverplayer_residual_anchors = load_json(
        "artifacts/spectron_tserverplayer_residual_manual_translation_anchors_20260826.json"
    )
    spectron_tserverplayer_tail_anchors = load_json(
        "artifacts/spectron_tserverplayer_tail_manual_translation_anchors_20260826.json"
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
        "Spectron dynamic-symbol audit artifact",
        spectron_symbol_audit["artifact"],
        "spectron_symbol_table_audit_20260827",
    )
    check("Spectron dynamic-symbol audit network", spectron_symbol_audit["network_contacted"], False)
    check(
        "Spectron dynamic-symbol audit original hash",
        spectron_symbol_audit["original"]["input"]["sha256"],
        "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
    )
    check(
        "Spectron dynamic-symbol audit target hash",
        spectron_symbol_audit["spectron"]["input"]["sha256"],
        "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    target_table = spectron_symbol_audit["spectron"]["dynamic_symbol_table"]
    check("Spectron dynamic table entries", target_table["table_entries"], 6773)
    check("Spectron dynamic named entries", target_table["named_entries"], 6770)
    check("Spectron dynamic defined entries", target_table["defined_entries"], 6602)
    check(
        "Spectron dynamic section-defined entries",
        target_table["section_defined_entries"],
        6595,
    )
    check(
        "Spectron dynamic section-defined functions",
        target_table["section_defined_type_counts"]["FUNC"],
        5782,
    )
    target_sections = spectron_symbol_audit["spectron"]["sections"]
    check("Spectron dynamic audit has dynsym", target_sections["selected"][".dynsym"] is not None, True)
    check("Spectron dynamic audit has dynstr", target_sections["selected"][".dynstr"] is not None, True)
    check("Spectron dynamic audit no symtab", target_sections["symtab_present"], False)
    check("Spectron dynamic audit no static strtab", target_sections["static_string_table_present"], False)
    check("Spectron dynamic audit no debug", target_sections["debug_sections_present"], False)
    check("Spectron dynamic audit no debuglink", target_sections["gnu_debuglink_present"], False)
    check(
        "Spectron dynamic JNI family",
        spectron_symbol_audit["spectron"]["export_families"]["jni"]["count"],
        28,
    )
    check(
        "Spectron dynamic CyaInt family",
        spectron_symbol_audit["spectron"]["export_families"]["cyassl_or_cyaint"]["function_count"],
        256,
    )
    check(
        "Spectron dynamic exact-name overlap",
        spectron_symbol_audit["exact_name_overlap"]["shared_name_count"],
        1036,
    )
    check(
        "Spectron dynamic complete named rows",
        len(spectron_symbol_audit["spectron"]["named_symbols"]),
        6770,
    )

    check(
        "Spectron connector endpoint artifact",
        spectron_connector_endpoints["artifact"],
        "spectron_connector_endpoint_audit_20260827",
    )
    check(
        "Spectron connector endpoint network",
        spectron_connector_endpoints["network_contacted"],
        False,
    )
    check(
        "Spectron connector endpoint original hash",
        spectron_connector_endpoints["original"]["input"]["sha256"],
        "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
    )
    check(
        "Spectron connector endpoint target hash",
        spectron_connector_endpoints["spectron"]["input"]["sha256"],
        "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    check(
        "Spectron connector endpoint original first hosts",
        [row["first"] for row in spectron_connector_endpoints["original"]["endpoints"]],
        [
            "https://con.quattroplay.com/con.png",
            "https://con.quattroplay.com/con.gs",
            "http://con.quattroplay.com/conf.gs",
        ],
    )
    check(
        "Spectron connector endpoint target first hosts",
        [row["first"] for row in spectron_connector_endpoints["spectron"]["endpoints"]],
        [
            "https://cong.quattroplay.com/con.png",
            "https://cong.quattroplay.com/con.gs",
            "http://cong.quattroplay.com/conf.gs",
        ],
    )
    check(
        "Spectron connector endpoint target retry hosts",
        [row["retry"] for row in spectron_connector_endpoints["spectron"]["endpoints"]],
        [
            "https://cong2.quattroplay.com/con.png",
            "https://cong2.quattroplay.com/con.gs",
            "http://cong2.quattroplay.com/conf.gs",
        ],
    )
    check(
        "Spectron connector endpoint domain unchanged",
        spectron_connector_endpoints["comparison"]["domain_unchanged"],
        True,
    )
    check(
        "Spectron connector endpoint paths unchanged",
        spectron_connector_endpoints["comparison"]["paths_unchanged"],
        True,
    )
    check(
        "Spectron connector endpoint host fragment",
        spectron_connector_endpoints["spectron"]["fragments"]["first_host"]["decoded"],
        "cong",
    )
    check(
        "Spectron connector endpoint retry fragment",
        spectron_connector_endpoints["spectron"]["fragments"]["retry_host"]["decoded"],
        "cong2",
    )

    check(
        "Spectron loopback patch artifact",
        spectron_loopback_patch_audit["artifact"],
        "spectron_loopback_patch_audit_20260828",
    )
    check(
        "Spectron loopback patch network",
        spectron_loopback_patch_audit["network_contacted"],
        False,
    )
    check(
        "Spectron loopback APK hash",
        spectron_loopback_patch_audit["input"]["apk_sha256"],
        "5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c",
    )
    check(
        "Spectron loopback native hash",
        spectron_loopback_patch_audit["input"]["arm64_libqplay_sha256"],
        "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    check(
        "Spectron loopback resolver offset",
        spectron_loopback_patch_audit["resolver_patch"]["file_offset"],
        "0x20c20c",
    )
    check(
        "Spectron loopback resolver replacement",
        spectron_loopback_patch_audit["resolver_patch"]["replacement"],
        "e00f80520020a072c0035fd6",
    )
    check(
        "Spectron loopback HTTPS port offsets",
        [item["file_offset"] for item in spectron_loopback_patch_audit["https_port_patches"]],
        ["0x2065e0", "0x206764"],
    )
    check(
        "Spectron loopback trust offset",
        spectron_loopback_patch_audit["trust_patch"]["file_offset"],
        "0x2ea9e0",
    )
    check(
        "Spectron loopback RC4 cave",
        spectron_loopback_patch_audit["rc4_patch"]["cave_input_sha256"],
        "38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca",
    )
    check(
        "Spectron loopback WebTop patch count",
        len(spectron_loopback_patch_audit["webtop_safe_patch"]["patches"]),
        3,
    )

    check(
        "Spectron ARM64 loading replay artifact",
        spectron_arm64_loopback_loading["artifact"],
        "spectron_arm64_loopback_loading_replay_20260828",
    )
    check(
        "Spectron ARM64 loading replay network",
        spectron_arm64_loopback_loading["network_contacted"],
        False,
    )
    check(
        "Spectron ARM64 loading replay source APK",
        spectron_arm64_loopback_loading["inputs"]["source_apk_sha256"],
        "5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c",
    )
    check(
        "Spectron ARM64 loading replay target DB",
        spectron_arm64_loopback_loading["inputs"]["target_database_sha256"],
        "00d08f743e7e01ac77b6eb8ccec266db89be0c8cc2382ebd542e23f2d80a4077",
    )
    check(
        "Spectron ARM64 loading replay branch offset",
        spectron_arm64_loopback_loading["build"]["patches"][-1]["location"],
        "0x15fad8",
    )
    check(
        "Spectron ARM64 loading replay branch bytes",
        spectron_arm64_loopback_loading["build"]["patches"][-1]["replacement"],
        "11000014",
    )
    check(
        "Spectron ARM64 loading replay RSA branch",
        spectron_arm64_loopback_loading["build"]["native_rsa_result_branch_preserved"],
        True,
    )
    check(
        "Spectron ARM64 loading replay TLS checks",
        spectron_arm64_loopback_loading["build"]["native_tls_peer_and_hostname_verification_preserved"],
        True,
    )
    check(
        "Spectron ARM64 loading replay connector request",
        spectron_arm64_loopback_loading["runtime"]["connector"]["tls_request_observed"],
        True,
    )
    check(
        "Spectron ARM64 loading replay connector host",
        spectron_arm64_loopback_loading["runtime"]["connector"]["host_header"],
        "cong.quattroplay.com:18443",
    )
    check(
        "Spectron ARM64 loading replay certificate result",
        spectron_arm64_loopback_loading["runtime"]["connector"]["certificate_error_observed"],
        False,
    )
    check(
        "Spectron ARM64 loading replay game connections",
        spectron_arm64_loopback_loading["runtime"]["game"]["encrypted_connections"],
        2,
    )
    check(
        "Spectron ARM64 loading replay login",
        spectron_arm64_loopback_loading["runtime"]["game"]["encrypted_login_completed"],
        True,
    )
    check(
        "Spectron ARM64 loading replay resource set",
        spectron_arm64_loopback_loading["runtime"]["game"]["requested_files"],
        [
            "basepackage.gupd",
            "guigames_graymessage2.png",
            "classiciphone.gmap",
            "main_aa-02.nw",
            "main_ab-01.nw",
            "main_ab-02.nw",
            "main_ac-01.nw",
            "main_ac-02.nw",
        ],
    )
    check(
        "Spectron ARM64 loading replay heartbeats",
        spectron_arm64_loopback_loading["runtime"]["game"]["heartbeats_observed"],
        True,
    )
    check(
        "Spectron ARM64 loading replay rendered",
        spectron_arm64_loopback_loading["runtime"]["process_reached_rendered_world"],
        True,
    )
    check(
        "Spectron ARM64 loading replay title state",
        spectron_arm64_loopback_loading["runtime"]["screen"]["title_loading_artwork_present"],
        False,
    )
    check(
        "Spectron ARM64 loading replay reverse cleanup",
        spectron_arm64_loopback_loading["runtime"]["reverse_ports_removed_after_test"],
        True,
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
        "Spectron connection-helper artifact",
        spectron_connection_helper_anchors["artifact"],
        "spectron_connection_helper_manual_translation_anchors_20260826",
    )
    check("Spectron connection-helper network", spectron_connection_helper_anchors["network_contacted"], False)
    check("Spectron connection-helper total", spectron_connection_helper_anchors["summary"]["anchor_count"], 18)
    check("Spectron connection-helper high confidence", spectron_connection_helper_anchors["summary"]["high_confidence_count"], 18)
    check("Spectron connection-helper semantic overlap", spectron_connection_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron connection-helper default targets", spectron_connection_helper_anchors["summary"]["target_default_name_count"], 7)
    check(
        "Spectron client-state-helper artifact",
        spectron_client_state_helper_anchors["artifact"],
        "spectron_client_state_helper_manual_translation_anchors_20260826",
    )
    check("Spectron client-state-helper network", spectron_client_state_helper_anchors["network_contacted"], False)
    check("Spectron client-state-helper total", spectron_client_state_helper_anchors["summary"]["anchor_count"], 7)
    check("Spectron client-state-helper high confidence", spectron_client_state_helper_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron client-state-helper semantic overlap", spectron_client_state_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron client-state-helper default targets", spectron_client_state_helper_anchors["summary"]["target_default_name_count"], 7)
    check(
        "Spectron connection-state artifact",
        spectron_connection_state_anchors["artifact"],
        "spectron_connection_state_manual_translation_anchors_20260826",
    )
    check("Spectron connection-state network", spectron_connection_state_anchors["network_contacted"], False)
    check("Spectron connection-state total", spectron_connection_state_anchors["summary"]["anchor_count"], 5)
    check("Spectron connection-state high confidence", spectron_connection_state_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron connection-state semantic overlap", spectron_connection_state_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron connection-state default targets", spectron_connection_state_anchors["summary"]["target_default_name_count"], 5)
    check(
        "Spectron HTTP request artifact",
        spectron_http_request_anchors["artifact"],
        "spectron_http_request_manual_translation_anchors_20260826",
    )
    check("Spectron HTTP request network", spectron_http_request_anchors["network_contacted"], False)
    check("Spectron HTTP request total", spectron_http_request_anchors["summary"]["anchor_count"], 12)
    check("Spectron HTTP request high confidence", spectron_http_request_anchors["summary"]["high_confidence_count"], 12)
    check("Spectron HTTP request semantic overlap", spectron_http_request_anchors["summary"]["already_in_semantic_map"], 1)
    check("Spectron HTTP request default targets", spectron_http_request_anchors["summary"]["target_default_name_count"], 10)
    check(
        "Spectron socket-state artifact",
        spectron_socket_state_anchors["artifact"],
        "spectron_socket_state_manual_translation_anchors_20260826",
    )
    check("Spectron socket-state network", spectron_socket_state_anchors["network_contacted"], False)
    check("Spectron socket-state total", spectron_socket_state_anchors["summary"]["anchor_count"], 5)
    check("Spectron socket-state high confidence", spectron_socket_state_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron socket-state semantic overlap", spectron_socket_state_anchors["summary"]["already_in_semantic_map"], 1)
    check("Spectron socket-state default targets", spectron_socket_state_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron socket behavior artifact",
        spectron_socket_behavior["artifact"],
        "spectron_socket_behavior_comparison_20260826",
    )
    check("Spectron socket behavior network", spectron_socket_behavior["network_contacted"], False)
    check("Spectron socket behavior pair count", spectron_socket_behavior["summary"]["pair_count"], 3)
    check("Spectron socket behavior size changes", spectron_socket_behavior["summary"]["size_changed_count"], 3)
    check("Spectron socket behavior exact matches", spectron_socket_behavior["summary"]["exact_shape_match_count"], 0)
    check(
        "Spectron HTTP request-state artifact",
        spectron_http_request_state_anchors["artifact"],
        "spectron_http_request_state_manual_translation_anchors_20260826",
    )
    check("Spectron HTTP request-state network", spectron_http_request_state_anchors["network_contacted"], False)
    check("Spectron HTTP request-state total", spectron_http_request_state_anchors["summary"]["anchor_count"], 4)
    check("Spectron HTTP request-state high confidence", spectron_http_request_state_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron HTTP request-state semantic overlap", spectron_http_request_state_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron HTTP request-state default targets", spectron_http_request_state_anchors["summary"]["target_default_name_count"], 3)
    check(
        "Spectron NPC helper artifact",
        spectron_npc_helper_anchors["artifact"],
        "spectron_npc_helper_manual_translation_anchors_20260826",
    )
    check("Spectron NPC helper network", spectron_npc_helper_anchors["network_contacted"], False)
    check("Spectron NPC helper total", spectron_npc_helper_anchors["summary"]["anchor_count"], 15)
    check("Spectron NPC helper high confidence", spectron_npc_helper_anchors["summary"]["high_confidence_count"], 15)
    check("Spectron NPC helper semantic overlap", spectron_npc_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron NPC helper default targets", spectron_npc_helper_anchors["summary"]["target_default_name_count"], 14)
    check(
        "Spectron HTML atom artifact",
        spectron_html_atom_anchors["artifact"],
        "spectron_html_atom_manual_translation_anchors_20260826",
    )
    check("Spectron HTML atom network", spectron_html_atom_anchors["network_contacted"], False)
    check("Spectron HTML atom total", spectron_html_atom_anchors["summary"]["anchor_count"], 5)
    check("Spectron HTML atom high confidence", spectron_html_atom_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron HTML atom semantic overlap", spectron_html_atom_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron HTML atom default targets", spectron_html_atom_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player helper artifact",
        spectron_player_helper_anchors["artifact"],
        "spectron_player_helper_manual_translation_anchors_20260826",
    )
    check("Spectron player helper network", spectron_player_helper_anchors["network_contacted"], False)
    check("Spectron player helper total", spectron_player_helper_anchors["summary"]["anchor_count"], 5)
    check("Spectron player helper high confidence", spectron_player_helper_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron player helper semantic overlap", spectron_player_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player helper default targets", spectron_player_helper_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron input/window artifact",
        spectron_input_window_anchors["artifact"],
        "spectron_input_window_manual_translation_anchors_20260826",
    )
    check("Spectron input/window network", spectron_input_window_anchors["network_contacted"], False)
    check("Spectron input/window total", spectron_input_window_anchors["summary"]["anchor_count"], 8)
    check("Spectron input/window high confidence", spectron_input_window_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron input/window semantic overlap", spectron_input_window_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron input/window default targets", spectron_input_window_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron visual helper artifact",
        spectron_visual_helper_anchors["artifact"],
        "spectron_visual_helper_manual_translation_anchors_20260826",
    )
    check("Spectron visual helper network", spectron_visual_helper_anchors["network_contacted"], False)
    check("Spectron visual helper total", spectron_visual_helper_anchors["summary"]["anchor_count"], 11)
    check("Spectron visual helper high confidence", spectron_visual_helper_anchors["summary"]["high_confidence_count"], 11)
    check("Spectron visual helper semantic overlap", spectron_visual_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron visual helper default targets", spectron_visual_helper_anchors["summary"]["target_default_name_count"], 5)
    check(
        "Spectron script-runtime artifact",
        spectron_script_runtime_anchors["artifact"],
        "spectron_script_runtime_manual_translation_anchors_20260826",
    )
    check("Spectron script-runtime network", spectron_script_runtime_anchors["network_contacted"], False)
    check("Spectron script-runtime total", spectron_script_runtime_anchors["summary"]["anchor_count"], 12)
    check("Spectron script-runtime high confidence", spectron_script_runtime_anchors["summary"]["high_confidence_count"], 12)
    check("Spectron script-runtime semantic overlap", spectron_script_runtime_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-runtime default targets", spectron_script_runtime_anchors["summary"]["target_default_name_count"], 2)
    check(
        "Spectron core-helper artifact",
        spectron_core_helper_anchors["artifact"],
        "spectron_core_helper_manual_translation_anchors_20260826",
    )
    check("Spectron core-helper network", spectron_core_helper_anchors["network_contacted"], False)
    check("Spectron core-helper total", spectron_core_helper_anchors["summary"]["anchor_count"], 30)
    check("Spectron core-helper high confidence", spectron_core_helper_anchors["summary"]["high_confidence_count"], 30)
    check("Spectron core-helper semantic overlap", spectron_core_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron core-helper default targets", spectron_core_helper_anchors["summary"]["target_default_name_count"], 7)
    check(
        "Spectron render/GUI artifact",
        spectron_render_gui_anchors["artifact"],
        "spectron_render_gui_manual_translation_anchors_20260826",
    )
    check("Spectron render/GUI network", spectron_render_gui_anchors["network_contacted"], False)
    check("Spectron render/GUI total", spectron_render_gui_anchors["summary"]["anchor_count"], 20)
    check("Spectron render/GUI high confidence", spectron_render_gui_anchors["summary"]["high_confidence_count"], 20)
    check("Spectron render/GUI semantic overlap", spectron_render_gui_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron render/GUI default targets", spectron_render_gui_anchors["summary"]["target_default_name_count"], 6)
    check(
        "Spectron JSON/folder artifact",
        spectron_json_folder_anchors["artifact"],
        "spectron_json_folder_manual_translation_anchors_20260826",
    )
    check("Spectron JSON/folder network", spectron_json_folder_anchors["network_contacted"], False)
    check("Spectron JSON/folder total", spectron_json_folder_anchors["summary"]["anchor_count"], 8)
    check("Spectron JSON/folder high confidence", spectron_json_folder_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron JSON/folder semantic overlap", spectron_json_folder_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron JSON/folder default targets", spectron_json_folder_anchors["summary"]["target_default_name_count"], 8)
    check("Spectron JSON/folder exact normalized", spectron_json_folder_anchors["summary"]["exact_normalized_count"], 1)
    check("Spectron JSON/folder exact context", spectron_json_folder_anchors["summary"]["exact_context_count"], 2)
    check("Spectron JSON/folder changed class context", spectron_json_folder_anchors["summary"]["changed_size_context_count"], 1)
    check("Spectron JSON/folder changed callback table", spectron_json_folder_anchors["summary"]["changed_size_callback_table_count"], 4)
    check(
        "Spectron resource-object artifact",
        spectron_resource_object_anchors["artifact"],
        "spectron_resource_object_manual_translation_anchors_20260826",
    )
    check("Spectron resource-object network", spectron_resource_object_anchors["network_contacted"], False)
    check("Spectron resource-object total", spectron_resource_object_anchors["summary"]["anchor_count"], 11)
    check("Spectron resource-object high confidence", spectron_resource_object_anchors["summary"]["high_confidence_count"], 11)
    check("Spectron resource-object semantic overlap", spectron_resource_object_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron resource-object default targets", spectron_resource_object_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-machine artifact",
        spectron_script_machine_anchors["artifact"],
        "spectron_script_machine_manual_translation_anchors_20260826",
    )
    check("Spectron script-machine network", spectron_script_machine_anchors["network_contacted"], False)
    check("Spectron script-machine total", spectron_script_machine_anchors["summary"]["anchor_count"], 7)
    check("Spectron script-machine high confidence", spectron_script_machine_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron script-machine semantic overlap", spectron_script_machine_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-machine default targets", spectron_script_machine_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-space artifact",
        spectron_script_space_anchors["artifact"],
        "spectron_script_space_manual_translation_anchors_20260826",
    )
    check("Spectron script-space network", spectron_script_space_anchors["network_contacted"], False)
    check("Spectron script-space total", spectron_script_space_anchors["summary"]["anchor_count"], 8)
    check("Spectron script-space high confidence", spectron_script_space_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron script-space semantic overlap", spectron_script_space_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-space default targets", spectron_script_space_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-execution artifact",
        spectron_script_execution_anchors["artifact"],
        "spectron_script_execution_manual_translation_anchors_20260826",
    )
    check("Spectron script-execution network", spectron_script_execution_anchors["network_contacted"], False)
    check("Spectron script-execution total", spectron_script_execution_anchors["summary"]["anchor_count"], 6)
    check("Spectron script-execution high confidence", spectron_script_execution_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron script-execution semantic overlap", spectron_script_execution_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-execution default targets", spectron_script_execution_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-dispatch artifact",
        spectron_script_dispatch_anchors["artifact"],
        "spectron_script_dispatch_manual_translation_anchors_20260826",
    )
    check("Spectron script-dispatch network", spectron_script_dispatch_anchors["network_contacted"], False)
    check("Spectron script-dispatch total", spectron_script_dispatch_anchors["summary"]["anchor_count"], 3)
    check("Spectron script-dispatch high confidence", spectron_script_dispatch_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron script-dispatch semantic overlap", spectron_script_dispatch_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-dispatch default targets", spectron_script_dispatch_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-scheduler artifact",
        spectron_script_scheduler_anchors["artifact"],
        "spectron_script_scheduler_manual_translation_anchors_20260826",
    )
    check("Spectron script-scheduler network", spectron_script_scheduler_anchors["network_contacted"], False)
    check("Spectron script-scheduler total", spectron_script_scheduler_anchors["summary"]["anchor_count"], 6)
    check("Spectron script-scheduler high confidence", spectron_script_scheduler_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron script-scheduler semantic overlap", spectron_script_scheduler_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-scheduler default targets", spectron_script_scheduler_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron event-object artifact",
        spectron_event_object_anchors["artifact"],
        "spectron_event_object_manual_translation_anchors_20260826",
    )
    check("Spectron event-object network", spectron_event_object_anchors["network_contacted"], False)
    check("Spectron event-object total", spectron_event_object_anchors["summary"]["anchor_count"], 6)
    check("Spectron event-object high confidence", spectron_event_object_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron event-object semantic overlap", spectron_event_object_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron event-object default targets", spectron_event_object_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-action artifact",
        spectron_script_action_anchors["artifact"],
        "spectron_script_action_manual_translation_anchors_20260826",
    )
    check("Spectron script-action network", spectron_script_action_anchors["network_contacted"], False)
    check("Spectron script-action total", spectron_script_action_anchors["summary"]["anchor_count"], 2)
    check("Spectron script-action high confidence", spectron_script_action_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron script-action semantic overlap", spectron_script_action_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-action default targets", spectron_script_action_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron stack-entry artifact",
        spectron_stack_entry_anchors["artifact"],
        "spectron_stack_entry_manual_translation_anchors_20260826",
    )
    check("Spectron stack-entry network", spectron_stack_entry_anchors["network_contacted"], False)
    check("Spectron stack-entry total", spectron_stack_entry_anchors["summary"]["anchor_count"], 3)
    check("Spectron stack-entry high confidence", spectron_stack_entry_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron stack-entry semantic overlap", spectron_stack_entry_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron stack-entry default targets", spectron_stack_entry_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron machine-helper artifact",
        spectron_machine_helper_anchors["artifact"],
        "spectron_machine_helper_manual_translation_anchors_20260826",
    )
    check("Spectron machine-helper network", spectron_machine_helper_anchors["network_contacted"], False)
    check("Spectron machine-helper total", spectron_machine_helper_anchors["summary"]["anchor_count"], 4)
    check("Spectron machine-helper high confidence", spectron_machine_helper_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron machine-helper semantic overlap", spectron_machine_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron machine-helper default targets", spectron_machine_helper_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron array-mutation artifact",
        spectron_array_mutation_anchors["artifact"],
        "spectron_array_mutation_manual_translation_anchors_20260826",
    )
    check("Spectron array-mutation network", spectron_array_mutation_anchors["network_contacted"], False)
    check("Spectron array-mutation total", spectron_array_mutation_anchors["summary"]["anchor_count"], 3)
    check("Spectron array-mutation high confidence", spectron_array_mutation_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron array-mutation semantic overlap", spectron_array_mutation_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron array-mutation default targets", spectron_array_mutation_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron string-search artifact",
        spectron_string_search_anchors["artifact"],
        "spectron_string_search_manual_translation_anchors_20260826",
    )
    check("Spectron string-search network", spectron_string_search_anchors["network_contacted"], False)
    check("Spectron string-search total", spectron_string_search_anchors["summary"]["anchor_count"], 2)
    check("Spectron string-search high confidence", spectron_string_search_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron string-search semantic overlap", spectron_string_search_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron string-search default targets", spectron_string_search_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron string-helper artifact",
        spectron_string_helper_anchors["artifact"],
        "spectron_string_helper_manual_translation_anchors_20260826",
    )
    check("Spectron string-helper network", spectron_string_helper_anchors["network_contacted"], False)
    check("Spectron string-helper total", spectron_string_helper_anchors["summary"]["anchor_count"], 3)
    check("Spectron string-helper high confidence", spectron_string_helper_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron string-helper semantic overlap", spectron_string_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron string-helper default targets", spectron_string_helper_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron variable-construction artifact",
        spectron_variable_construction_anchors["artifact"],
        "spectron_variable_construction_manual_translation_anchors_20260826",
    )
    check("Spectron variable-construction network", spectron_variable_construction_anchors["network_contacted"], False)
    check("Spectron variable-construction total", spectron_variable_construction_anchors["summary"]["anchor_count"], 2)
    check("Spectron variable-construction high confidence", spectron_variable_construction_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron variable-construction semantic overlap", spectron_variable_construction_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron variable-construction default targets", spectron_variable_construction_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-object artifact",
        spectron_script_object_anchors["artifact"],
        "spectron_script_object_manual_translation_anchors_20260826",
    )
    check("Spectron script-object network", spectron_script_object_anchors["network_contacted"], False)
    check("Spectron script-object total", spectron_script_object_anchors["summary"]["anchor_count"], 2)
    check("Spectron script-object high confidence", spectron_script_object_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron script-object semantic overlap", spectron_script_object_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-object default targets", spectron_script_object_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-state artifact",
        spectron_script_state_anchors["artifact"],
        "spectron_script_state_manual_translation_anchors_20260826",
    )
    check("Spectron script-state network", spectron_script_state_anchors["network_contacted"], False)
    check("Spectron script-state total", spectron_script_state_anchors["summary"]["anchor_count"], 2)
    check("Spectron script-state high confidence", spectron_script_state_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron script-state semantic overlap", spectron_script_state_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-state default targets", spectron_script_state_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron execution-dispatch artifact",
        spectron_execution_dispatch_anchors["artifact"],
        "spectron_execution_dispatch_manual_translation_anchors_20260826",
    )
    check("Spectron execution-dispatch network", spectron_execution_dispatch_anchors["network_contacted"], False)
    check("Spectron execution-dispatch total", spectron_execution_dispatch_anchors["summary"]["anchor_count"], 2)
    check("Spectron execution-dispatch high confidence", spectron_execution_dispatch_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron execution-dispatch semantic overlap", spectron_execution_dispatch_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron execution-dispatch default targets", spectron_execution_dispatch_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron tokenizer artifact",
        spectron_tokenizer_anchors["artifact"],
        "spectron_tokenizer_manual_translation_anchors_20260826",
    )
    check("Spectron tokenizer network", spectron_tokenizer_anchors["network_contacted"], False)
    check("Spectron tokenizer total", spectron_tokenizer_anchors["summary"]["anchor_count"], 1)
    check("Spectron tokenizer high confidence", spectron_tokenizer_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron tokenizer semantic overlap", spectron_tokenizer_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron tokenizer default targets", spectron_tokenizer_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-executor artifact",
        spectron_script_executor_anchors["artifact"],
        "spectron_script_executor_manual_translation_anchors_20260826",
    )
    check("Spectron script-executor network", spectron_script_executor_anchors["network_contacted"], False)
    check("Spectron script-executor total", spectron_script_executor_anchors["summary"]["anchor_count"], 1)
    check("Spectron script-executor high confidence", spectron_script_executor_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron script-executor semantic overlap", spectron_script_executor_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-executor default targets", spectron_script_executor_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-property artifact",
        spectron_script_property_anchors["artifact"],
        "spectron_script_property_manual_translation_anchors_20260826",
    )
    check("Spectron script-property network", spectron_script_property_anchors["network_contacted"], False)
    check("Spectron script-property total", spectron_script_property_anchors["summary"]["anchor_count"], 9)
    check("Spectron script-property high confidence", spectron_script_property_anchors["summary"]["high_confidence_count"], 9)
    check("Spectron script-property semantic overlap", spectron_script_property_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-property default targets", spectron_script_property_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-universe artifact",
        spectron_script_universe_anchors["artifact"],
        "spectron_script_universe_manual_translation_anchors_20260826",
    )
    check("Spectron script-universe network", spectron_script_universe_anchors["network_contacted"], False)
    check("Spectron script-universe total", spectron_script_universe_anchors["summary"]["anchor_count"], 8)
    check("Spectron script-universe high confidence", spectron_script_universe_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron script-universe semantic overlap", spectron_script_universe_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-universe default targets", spectron_script_universe_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron static/JSON/tiles artifact",
        spectron_static_json_tiles_anchors["artifact"],
        "spectron_static_json_tiles_manual_translation_anchors_20260826",
    )
    check("Spectron static/JSON/tiles network", spectron_static_json_tiles_anchors["network_contacted"], False)
    check("Spectron static/JSON/tiles total", spectron_static_json_tiles_anchors["summary"]["anchor_count"], 3)
    check("Spectron static/JSON/tiles high confidence", spectron_static_json_tiles_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron static/JSON/tiles semantic overlap", spectron_static_json_tiles_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron static/JSON/tiles default targets", spectron_static_json_tiles_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron tiles-update artifact",
        spectron_tiles_update_anchors["artifact"],
        "spectron_tiles_update_manual_translation_anchors_20260826",
    )
    check("Spectron tiles-update network", spectron_tiles_update_anchors["network_contacted"], False)
    check("Spectron tiles-update total", spectron_tiles_update_anchors["summary"]["anchor_count"], 8)
    check("Spectron tiles-update high confidence", spectron_tiles_update_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron tiles-update semantic overlap", spectron_tiles_update_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron tiles-update default targets", spectron_tiles_update_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron particle artifact",
        spectron_particle_anchors["artifact"],
        "spectron_particle_manual_translation_anchors_20260826",
    )
    check("Spectron particle network", spectron_particle_anchors["network_contacted"], False)
    check("Spectron particle total", spectron_particle_anchors["summary"]["anchor_count"], 5)
    check("Spectron particle high confidence", spectron_particle_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron particle semantic overlap", spectron_particle_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron particle default targets", spectron_particle_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron ShowImg artifact",
        spectron_showimg_anchors["artifact"],
        "spectron_showimg_manual_translation_anchors_20260826",
    )
    check("Spectron ShowImg network", spectron_showimg_anchors["network_contacted"], False)
    check("Spectron ShowImg total", spectron_showimg_anchors["summary"]["anchor_count"], 3)
    check("Spectron ShowImg high confidence", spectron_showimg_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron ShowImg semantic overlap", spectron_showimg_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron ShowImg default targets", spectron_showimg_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron ShowImg property artifact",
        spectron_showimg_property_anchors["artifact"],
        "spectron_showimg_property_manual_translation_anchors_20260827",
    )
    check("Spectron ShowImg property network", spectron_showimg_property_anchors["network_contacted"], False)
    check("Spectron ShowImg property count", spectron_showimg_property_anchors["summary"]["property_count"], 48)
    check("Spectron ShowImg property non-null callbacks", spectron_showimg_property_anchors["summary"]["non_null_callback_count"], 93)
    check("Spectron ShowImg property total", spectron_showimg_property_anchors["summary"]["anchor_count"], 85)
    check("Spectron ShowImg property high confidence", spectron_showimg_property_anchors["summary"]["high_confidence_count"], 85)
    check("Spectron ShowImg property semantic overlap", spectron_showimg_property_anchors["summary"]["already_in_semantic_map"], 8)
    check("Spectron ShowImg property default targets", spectron_showimg_property_anchors["summary"]["target_default_name_count"], 69)
    check("Spectron ShowImg property exact-shape count", spectron_showimg_property_anchors["summary"]["exact_shape_anchor_count"], 84)
    check("Spectron ShowImg property layout-change count", spectron_showimg_property_anchors["summary"]["layout_change_anchor_count"], 1)
    check("Spectron ShowImg property existing context count", spectron_showimg_property_anchors["summary"]["existing_context_count"], 8)
    check("Spectron ShowImg property shared target count", spectron_showimg_property_anchors["summary"]["shared_target_context_count"], 1)
    check(
        "Spectron ShowImg residual artifact",
        spectron_showimg_residual_anchors["artifact"],
        "spectron_showimg_residual_manual_translation_anchors_20260827",
    )
    check("Spectron ShowImg residual network", spectron_showimg_residual_anchors["network_contacted"], False)
    check("Spectron ShowImg residual total", spectron_showimg_residual_anchors["summary"]["anchor_count"], 24)
    check("Spectron ShowImg residual high confidence", spectron_showimg_residual_anchors["summary"]["high_confidence_count"], 24)
    check("Spectron ShowImg residual exact-shape count", spectron_showimg_residual_anchors["summary"]["exact_shape_anchor_count"], 22)
    check("Spectron ShowImg residual layout-change count", spectron_showimg_residual_anchors["summary"]["layout_change_anchor_count"], 2)
    check("Spectron ShowImg residual default targets", spectron_showimg_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron server-object scalar artifact",
        spectron_server_object_scalar_anchors["artifact"],
        "spectron_server_object_scalar_manual_translation_anchors_20260827",
    )
    check("Spectron server-object scalar network", spectron_server_object_scalar_anchors["network_contacted"], False)
    check("Spectron server-object scalar total", spectron_server_object_scalar_anchors["summary"]["anchor_count"], 12)
    check("Spectron server-object scalar high confidence", spectron_server_object_scalar_anchors["summary"]["high_confidence_count"], 12)
    check("Spectron server-object scalar exact-shape count", spectron_server_object_scalar_anchors["summary"]["exact_shape_anchor_count"], 12)
    check("Spectron server-object scalar layout-change count", spectron_server_object_scalar_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron server-object scalar default targets", spectron_server_object_scalar_anchors["summary"]["target_default_name_count"], 8)
    check(
        "Spectron compression artifact",
        spectron_compression_anchors["artifact"],
        "spectron_compression_manual_translation_anchors_20260827",
    )
    check("Spectron compression network", spectron_compression_anchors["network_contacted"], False)
    check("Spectron compression total", spectron_compression_anchors["summary"]["anchor_count"], 5)
    check("Spectron compression high confidence", spectron_compression_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron compression exact-shape count", spectron_compression_anchors["summary"]["exact_shape_anchor_count"], 5)
    check("Spectron compression layout-change count", spectron_compression_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron compression default targets", spectron_compression_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron files artifact",
        spectron_files_anchors["artifact"],
        "spectron_files_manual_translation_anchors_20260827",
    )
    check("Spectron files network", spectron_files_anchors["network_contacted"], False)
    check("Spectron files total", spectron_files_anchors["summary"]["anchor_count"], 6)
    check("Spectron files high confidence", spectron_files_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron files exact-shape count", spectron_files_anchors["summary"]["exact_shape_anchor_count"], 6)
    check("Spectron files layout-change count", spectron_files_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron files default targets", spectron_files_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron encryption artifact",
        spectron_encryption_anchors["artifact"],
        "spectron_encryption_manual_translation_anchors_20260827",
    )
    check("Spectron encryption network", spectron_encryption_anchors["network_contacted"], False)
    check("Spectron encryption total", spectron_encryption_anchors["summary"]["anchor_count"], 9)
    check("Spectron encryption high confidence", spectron_encryption_anchors["summary"]["high_confidence_count"], 9)
    check("Spectron encryption exact-shape count", spectron_encryption_anchors["summary"]["exact_shape_anchor_count"], 9)
    check("Spectron encryption layout-change count", spectron_encryption_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron encryption default targets", spectron_encryption_anchors["summary"]["target_default_name_count"], 1)
    check(
        "Spectron TList artifact",
        spectron_tlist_anchors["artifact"],
        "spectron_tlist_manual_translation_anchors_20260827",
    )
    check("Spectron TList network", spectron_tlist_anchors["network_contacted"], False)
    check("Spectron TList total", spectron_tlist_anchors["summary"]["anchor_count"], 6)
    check("Spectron TList high confidence", spectron_tlist_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron TList exact-shape count", spectron_tlist_anchors["summary"]["exact_shape_anchor_count"], 6)
    check("Spectron TList layout-change count", spectron_tlist_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TList default targets", spectron_tlist_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron sounds artifact",
        spectron_sounds_anchors["artifact"],
        "spectron_sounds_manual_translation_anchors_20260827",
    )
    check("Spectron sounds network", spectron_sounds_anchors["network_contacted"], False)
    check("Spectron sounds total", spectron_sounds_anchors["summary"]["anchor_count"], 8)
    check("Spectron sounds high confidence", spectron_sounds_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron sounds exact-shape count", spectron_sounds_anchors["summary"]["exact_shape_anchor_count"], 8)
    check("Spectron sounds layout-change count", spectron_sounds_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron sounds default targets", spectron_sounds_anchors["summary"]["target_default_name_count"], 5)
    check(
        "Spectron hash-container artifact",
        spectron_hash_container_anchors["artifact"],
        "spectron_hash_container_manual_translation_anchors_20260827",
    )
    check("Spectron hash-container network", spectron_hash_container_anchors["network_contacted"], False)
    check("Spectron hash-container total", spectron_hash_container_anchors["summary"]["anchor_count"], 5)
    check("Spectron hash-container high confidence", spectron_hash_container_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron hash-container exact-shape count", spectron_hash_container_anchors["summary"]["exact_shape_anchor_count"], 5)
    check("Spectron hash-container layout-change count", spectron_hash_container_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron hash-container default targets", spectron_hash_container_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron hash-lifecycle artifact",
        spectron_hash_lifecycle_anchors["artifact"],
        "spectron_hash_lifecycle_manual_translation_anchors_20260827",
    )
    check("Spectron hash-lifecycle network", spectron_hash_lifecycle_anchors["network_contacted"], False)
    check("Spectron hash-lifecycle total", spectron_hash_lifecycle_anchors["summary"]["anchor_count"], 6)
    check("Spectron hash-lifecycle high confidence", spectron_hash_lifecycle_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron hash-lifecycle exact-shape count", spectron_hash_lifecycle_anchors["summary"]["exact_shape_anchor_count"], 6)
    check("Spectron hash-lifecycle full-metric exact count", spectron_hash_lifecycle_anchors["summary"]["full_metric_exact_count"], 5)
    check("Spectron hash-lifecycle register-detail difference count", spectron_hash_lifecycle_anchors["summary"]["register_detail_difference_count"], 1)
    check("Spectron hash-lifecycle default targets", spectron_hash_lifecycle_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron GUI text-list entry artifact",
        spectron_gui_text_list_entry_anchors["artifact"],
        "spectron_gui_text_list_entry_manual_translation_anchors_20260827",
    )
    check("Spectron GUI text-list entry network", spectron_gui_text_list_entry_anchors["network_contacted"], False)
    check("Spectron GUI text-list entry total", spectron_gui_text_list_entry_anchors["summary"]["anchor_count"], 3)
    check("Spectron GUI text-list entry high confidence", spectron_gui_text_list_entry_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron GUI text-list entry exact-shape count", spectron_gui_text_list_entry_anchors["summary"]["exact_shape_anchor_count"], 3)
    check("Spectron GUI text-list entry full-metric exact count", spectron_gui_text_list_entry_anchors["summary"]["full_metric_exact_count"], 3)
    check("Spectron GUI text-list entry default targets", spectron_gui_text_list_entry_anchors["summary"]["target_default_name_count"], 3)
    check(
        "Spectron encryption-GraalVar artifact",
        spectron_encryption_graalvar_anchors["artifact"],
        "spectron_encryption_graalvar_manual_translation_anchors_20260827",
    )
    check("Spectron encryption-GraalVar network", spectron_encryption_graalvar_anchors["network_contacted"], False)
    check("Spectron encryption-GraalVar total", spectron_encryption_graalvar_anchors["summary"]["anchor_count"], 3)
    check("Spectron encryption-GraalVar high confidence", spectron_encryption_graalvar_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron encryption-GraalVar exact-shape count", spectron_encryption_graalvar_anchors["summary"]["exact_shape_anchor_count"], 3)
    check("Spectron encryption-GraalVar full-metric exact count", spectron_encryption_graalvar_anchors["summary"]["full_metric_exact_count"], 3)
    check("Spectron encryption-GraalVar default targets", spectron_encryption_graalvar_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron compact-residual artifact",
        spectron_compact_residual_anchors["artifact"],
        "spectron_compact_residual_manual_translation_anchors_20260827",
    )
    check("Spectron compact-residual network", spectron_compact_residual_anchors["network_contacted"], False)
    check("Spectron compact-residual total", spectron_compact_residual_anchors["summary"]["anchor_count"], 13)
    check("Spectron compact-residual high confidence", spectron_compact_residual_anchors["summary"]["high_confidence_count"], 13)
    check("Spectron compact-residual exact-shape count", spectron_compact_residual_anchors["summary"]["exact_shape_anchor_count"], 13)
    check("Spectron compact-residual full-metric exact count", spectron_compact_residual_anchors["summary"]["full_metric_exact_count"], 2)
    check("Spectron compact-residual register-detail differences", spectron_compact_residual_anchors["summary"]["register_detail_difference_count"], 11)
    check("Spectron compact-residual layout-change count", spectron_compact_residual_anchors["summary"]["layout_change_anchor_count"], 1)
    check("Spectron compact-residual default targets", spectron_compact_residual_anchors["summary"]["target_default_name_count"], 12)
    check(
        "Spectron compact-residual folded canDownload note",
        any("canDownload" in item for item in spectron_compact_residual_anchors["interpretation"]),
        True,
    )
    check(
        "Spectron T2DMatrixManager artifact",
        spectron_t2d_matrix_manager_anchors["artifact"],
        "spectron_t2d_matrix_manager_manual_translation_anchors_20260827",
    )
    check("Spectron T2DMatrixManager network", spectron_t2d_matrix_manager_anchors["network_contacted"], False)
    check("Spectron T2DMatrixManager total", spectron_t2d_matrix_manager_anchors["summary"]["anchor_count"], 4)
    check("Spectron T2DMatrixManager high confidence", spectron_t2d_matrix_manager_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron T2DMatrixManager exact-shape count", spectron_t2d_matrix_manager_anchors["summary"]["exact_shape_anchor_count"], 4)
    check("Spectron T2DMatrixManager full-metric exact count", spectron_t2d_matrix_manager_anchors["summary"]["full_metric_exact_count"], 0)
    check("Spectron T2DMatrixManager register-detail differences", spectron_t2d_matrix_manager_anchors["summary"]["register_detail_difference_count"], 4)
    check("Spectron T2DMatrixManager default targets", spectron_t2d_matrix_manager_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron T2DMatrixManager deferred initializer",
        spectron_t2d_matrix_manager_anchors["deferred_review"][0]["original_name"],
        "T2DMatrixManager_initStaticVars_void",
    )
    check(
        "Spectron MRandom artifact",
        spectron_mrandom_anchors["artifact"],
        "spectron_mrandom_family_manual_translation_anchors_20260827",
    )
    check("Spectron MRandom network", spectron_mrandom_anchors["network_contacted"], False)
    check("Spectron MRandom total", spectron_mrandom_anchors["summary"]["anchor_count"], 29)
    check("Spectron MRandom high confidence", spectron_mrandom_anchors["summary"]["high_confidence_count"], 29)
    check("Spectron MRandom semantic overlap", spectron_mrandom_anchors["summary"]["already_in_semantic_map"], 1)
    check("Spectron MRandom new-context count", spectron_mrandom_anchors["summary"]["new_context_anchor_count"], 28)
    check("Spectron MRandom exact-shape count", spectron_mrandom_anchors["summary"]["exact_shape_anchor_count"], 29)
    check("Spectron MRandom full-metric exact count", spectron_mrandom_anchors["summary"]["full_metric_exact_count"], 8)
    check("Spectron MRandom register-detail differences", spectron_mrandom_anchors["summary"]["register_detail_difference_count"], 21)
    check("Spectron MRandom default targets", spectron_mrandom_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron MRandom static generator global",
        spectron_mrandom_anchors["context"]["static_generator_global"]["target"],
        "Lry_xa0Aed",
    )
    mrandom_by_name = {row["original_name"]: row for row in spectron_mrandom_anchors["anchors"]}
    check(
        "Spectron MRandom static initializer target",
        mrandom_by_name["MRandomGenerator_initStaticVars_void"]["spectron_ea"],
        "0x1e7a58",
    )
    check(
        "Spectron MRandom LCG class target",
        spectron_mrandom_anchors["context"]["target_classes"][1],
        "Vx2_xajLEd",
    )
    check(
        "Spectron residual TStringList artifact",
        spectron_tstringlist_residual_anchors["artifact"],
        "spectron_tstringlist_residual_manual_translation_anchors_20260827",
    )
    check(
        "Spectron residual TStringList network",
        spectron_tstringlist_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron residual TStringList total",
        spectron_tstringlist_residual_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron residual TStringList high confidence",
        spectron_tstringlist_residual_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron residual TStringList exact-shape count",
        spectron_tstringlist_residual_anchors["summary"]["exact_shape_anchor_count"],
        3,
    )
    check(
        "Spectron residual TStringList full-metric exact count",
        spectron_tstringlist_residual_anchors["summary"]["full_metric_exact_count"],
        3,
    )
    check(
        "Spectron residual TStringList layout-change count",
        spectron_tstringlist_residual_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron residual TStringList default targets",
        spectron_tstringlist_residual_anchors["summary"]["target_default_name_count"],
        0,
    )
    check(
        "Spectron residual TStringList target class",
        spectron_tstringlist_residual_anchors["context"]["target_class"],
        "vuuHgangcF",
    )
    residual_tstringlist_by_name = {
        row["original_name"]: row
        for row in spectron_tstringlist_residual_anchors["anchors"]
    }
    check(
        "Spectron residual TStringList case-insensitive target",
        residual_tstringlist_by_name["TStringList_indexOfIgnoreCase_TString_const"]["spectron_ea"],
        "0xf6f9c",
    )
    check(
        "Spectron server-object lifecycle artifact",
        spectron_server_object_lifecycle_anchors["artifact"],
        "spectron_server_object_lifecycle_manual_translation_anchors_20260827",
    )
    check(
        "Spectron server-object lifecycle network",
        spectron_server_object_lifecycle_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron server-object lifecycle total",
        spectron_server_object_lifecycle_anchors["summary"]["anchor_count"],
        49,
    )
    check(
        "Spectron server-object lifecycle high confidence",
        spectron_server_object_lifecycle_anchors["summary"]["high_confidence_count"],
        49,
    )
    check(
        "Spectron server-object lifecycle exact-shape count",
        spectron_server_object_lifecycle_anchors["summary"]["exact_shape_anchor_count"],
        49,
    )
    check(
        "Spectron server-object lifecycle full-metric exact count",
        spectron_server_object_lifecycle_anchors["summary"]["full_metric_exact_count"],
        9,
    )
    check(
        "Spectron server-object lifecycle register-detail differences",
        spectron_server_object_lifecycle_anchors["summary"]["register_detail_difference_count"],
        40,
    )
    check(
        "Spectron server-object lifecycle default targets",
        spectron_server_object_lifecycle_anchors["summary"]["target_default_name_count"],
        7,
    )
    check(
        "Spectron server-object lifecycle target class count",
        len(spectron_server_object_lifecycle_anchors["context"]["target_classes"]),
        7,
    )
    server_object_by_name = {
        row["original_name"]: row
        for row in spectron_server_object_lifecycle_anchors["anchors"]
    }
    check(
        "Spectron server-object lifecycle Bomb constructor target",
        server_object_by_name["TServerBomb_TServerBomb_TServerLevel"]["spectron_ea"],
        "0x247194",
    )
    check(
        "Spectron server-object lifecycle Sign destructor target",
        server_object_by_name["TServerSign_TServerSign"]["spectron_ea"],
        "0x24a11c",
    )
    check(
        "Spectron GuiMLTextCtrl residual artifact",
        spectron_gui_ml_text_residual_anchors["artifact"],
        "spectron_gui_ml_text_residual_manual_translation_anchors_20260827",
    )
    check(
        "Spectron GuiMLTextCtrl residual network",
        spectron_gui_ml_text_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GuiMLTextCtrl residual total",
        spectron_gui_ml_text_residual_anchors["summary"]["anchor_count"],
        39,
    )
    check(
        "Spectron GuiMLTextCtrl residual high confidence",
        spectron_gui_ml_text_residual_anchors["summary"]["high_confidence_count"],
        39,
    )
    check(
        "Spectron GuiMLTextCtrl residual exact-shape count",
        spectron_gui_ml_text_residual_anchors["summary"]["exact_shape_anchor_count"],
        30,
    )
    check(
        "Spectron GuiMLTextCtrl residual full-metric exact count",
        spectron_gui_ml_text_residual_anchors["summary"]["full_metric_exact_count"],
        27,
    )
    check(
        "Spectron GuiMLTextCtrl residual layout-change count",
        spectron_gui_ml_text_residual_anchors["summary"]["layout_change_anchor_count"],
        9,
    )
    check(
        "Spectron GuiMLTextCtrl residual default targets",
        spectron_gui_ml_text_residual_anchors["summary"]["target_default_name_count"],
        26,
    )
    gui_ml_by_name = {
        row["original_name"]: row
        for row in spectron_gui_ml_text_residual_anchors["anchors"]
    }
    check(
        "Spectron GuiMLTextCtrl mouse-down target",
        gui_ml_by_name["GuiMLTextCtrl_onMouseDown_GuiEvent_const"]["spectron_ea"],
        "0x1c2ad8",
    )
    check(
        "Spectron GuiMLTextCtrl property destructor target",
        gui_ml_by_name["GuiMLTextCtrlProperties_GuiMLTextCtrlProperties__2"]["spectron_ea"],
        "0x1c4724",
    )
    check(
        "Spectron GUI text-list property artifact",
        spectron_gui_text_list_entry_property_anchors["artifact"],
        "spectron_gui_text_list_entry_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GUI text-list property network",
        spectron_gui_text_list_entry_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI text-list property total",
        spectron_gui_text_list_entry_property_anchors["summary"]["anchor_count"],
        30,
    )
    check(
        "Spectron GUI text-list property high confidence",
        spectron_gui_text_list_entry_property_anchors["summary"]["high_confidence_count"],
        30,
    )
    check(
        "Spectron GUI text-list property exact-shape count",
        spectron_gui_text_list_entry_property_anchors["summary"]["normalized_shape_exact_count"],
        30,
    )
    check(
        "Spectron GUI text-list property full-metric count",
        spectron_gui_text_list_entry_property_anchors["summary"]["full_metric_exact_count"],
        30,
    )
    check(
        "Spectron GUI text-list property default targets",
        spectron_gui_text_list_entry_property_anchors["summary"]["target_default_name_count"],
        30,
    )
    gui_text_list_property_by_name = {
        row["original_name"]: row
        for row in spectron_gui_text_list_entry_property_anchors["anchors"]
    }
    check(
        "Spectron GUI text-list active getter target",
        gui_text_list_property_by_name["GuiTextListEntry_get_active"]["spectron_ea"],
        "0x1e05c8",
    )
    check(
        "Spectron GUI text-list sort-column getter target",
        gui_text_list_property_by_name["GuiTextListCtrl_get_sortcolumn"]["spectron_ea"],
        "0x1e06ec",
    )
    check(
        "Spectron GUI text-list residual artifact",
        spectron_gui_text_list_residual_anchors["artifact"],
        "spectron_gui_text_list_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GUI text-list residual network",
        spectron_gui_text_list_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI text-list residual total",
        spectron_gui_text_list_residual_anchors["summary"]["anchor_count"],
        10,
    )
    check(
        "Spectron GUI text-list residual high confidence",
        spectron_gui_text_list_residual_anchors["summary"]["high_confidence_count"],
        10,
    )
    check(
        "Spectron GUI text-list residual exact-shape count",
        spectron_gui_text_list_residual_anchors["summary"]["normalized_shape_exact_count"],
        10,
    )
    check(
        "Spectron GUI text-list residual full-metric count",
        spectron_gui_text_list_residual_anchors["summary"]["full_metric_exact_count"],
        4,
    )
    check(
        "Spectron GUI text-list residual default targets",
        spectron_gui_text_list_residual_anchors["summary"]["target_default_name_count"],
        10,
    )
    gui_text_list_residual_by_name = {
        row["original_name"]: row
        for row in spectron_gui_text_list_residual_anchors["anchors"]
    }
    check(
        "Spectron GUI text-list sort-order getter target",
        gui_text_list_residual_by_name["GuiTextListCtrl_get_sortorder"]["spectron_ea"],
        "0x1e07e4",
    )
    check(
        "Spectron GUI text-list profile setter target",
        gui_text_list_residual_by_name["GuiTextListEntry_set_profile"]["spectron_ea"],
        "0x1e16e8",
    )
    check(
        "Spectron GUI drawing/ShowImg property artifact",
        spectron_gui_drawing_showimg_property_anchors["artifact"],
        "spectron_gui_drawing_showimg_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GUI drawing/ShowImg property network",
        spectron_gui_drawing_showimg_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI drawing/ShowImg property total",
        spectron_gui_drawing_showimg_property_anchors["summary"]["anchor_count"],
        16,
    )
    check(
        "Spectron GUI drawing/ShowImg property high confidence",
        spectron_gui_drawing_showimg_property_anchors["summary"]["high_confidence_count"],
        16,
    )
    check(
        "Spectron GUI drawing/ShowImg property exact-shape count",
        spectron_gui_drawing_showimg_property_anchors["summary"]["normalized_shape_exact_count"],
        16,
    )
    check(
        "Spectron GUI drawing/ShowImg property full-metric count",
        spectron_gui_drawing_showimg_property_anchors["summary"]["full_metric_exact_count"],
        15,
    )
    check(
        "Spectron GUI drawing/ShowImg property default targets",
        spectron_gui_drawing_showimg_property_anchors["summary"]["target_default_name_count"],
        16,
    )
    drawing_showimg_by_name = {
        row["original_name"]: row
        for row in spectron_gui_drawing_showimg_property_anchors["anchors"]
    }
    check(
        "Spectron GUI drawing partx target",
        drawing_showimg_by_name["GuiDrawingPanel_get_partx"]["spectron_ea"],
        "0x1e3f24",
    )
    check(
        "Spectron GUI available-filters target",
        drawing_showimg_by_name["GuiDrawingPanel_get_availablefilters"]["spectron_ea"],
        "0x1e3f84",
    )
    check(
        "Spectron GUI ShowImg offsetx target",
        drawing_showimg_by_name["GuiShowImgCtrl_get_offsetx"]["spectron_ea"],
        "0x1e4d3c",
    )
    check(
        "Spectron GUI ShowImg animation setter target",
        drawing_showimg_by_name["GuiShowImgCtrl_set_ani"]["spectron_ea"],
        "0x1e4fc4",
    )
    check(
        "Spectron GUI drawing/ShowImg target-only review count",
        len(spectron_gui_drawing_showimg_property_anchors["reviewed_target_only_rows"]),
        2,
    )
    check(
        "Spectron GUI browser property artifact",
        spectron_gui_browser_property_anchors["artifact"],
        "spectron_gui_browser_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GUI browser property network",
        spectron_gui_browser_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI browser property total",
        spectron_gui_browser_property_anchors["summary"]["anchor_count"],
        3,
    )
    check(
        "Spectron GUI browser property high confidence",
        spectron_gui_browser_property_anchors["summary"]["high_confidence_count"],
        3,
    )
    check(
        "Spectron GUI browser property exact-shape count",
        spectron_gui_browser_property_anchors["summary"]["normalized_shape_exact_count"],
        3,
    )
    check(
        "Spectron GUI browser property full-metric count",
        spectron_gui_browser_property_anchors["summary"]["full_metric_exact_count"],
        3,
    )
    check(
        "Spectron GUI browser property default targets",
        spectron_gui_browser_property_anchors["summary"]["target_default_name_count"],
        3,
    )
    browser_by_name = {
        row["original_name"]: row
        for row in spectron_gui_browser_property_anchors["anchors"]
    }
    check(
        "Spectron GUI browser allowzoom target",
        browser_by_name["GuiBrowserCtrl_get_allowzoom"]["spectron_ea"],
        "0x1e57e4",
    )
    check(
        "Spectron GUI browser URL target",
        browser_by_name["GuiBrowserCtrl_get_url"]["spectron_ea"],
        "0x1e57ec",
    )
    check(
        "Spectron GUI browser text target",
        browser_by_name["GuiBrowserCtrl_get_text"]["spectron_ea"],
        "0x1e581c",
    )
    check(
        "Spectron GUI context-menu property artifact",
        spectron_gui_context_menu_property_anchors["artifact"],
        "spectron_gui_context_menu_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GUI context-menu property network",
        spectron_gui_context_menu_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI context-menu property total",
        spectron_gui_context_menu_property_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron GUI context-menu property high confidence",
        spectron_gui_context_menu_property_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron GUI context-menu property exact-shape count",
        spectron_gui_context_menu_property_anchors["summary"]["normalized_shape_exact_count"],
        5,
    )
    check(
        "Spectron GUI context-menu property full-metric count",
        spectron_gui_context_menu_property_anchors["summary"]["full_metric_exact_count"],
        5,
    )
    check(
        "Spectron GUI context-menu property default targets",
        spectron_gui_context_menu_property_anchors["summary"]["target_default_name_count"],
        5,
    )
    context_menu_by_name = {
        row["original_name"]: row
        for row in spectron_gui_context_menu_property_anchors["anchors"]
    }
    check(
        "Spectron GUI context-menu max-height getter target",
        context_menu_by_name["GuiContextMenuCtrl_get_maxpopupheight"]["spectron_ea"],
        "0x1dc974",
    )
    check(
        "Spectron GUI context-menu close target",
        context_menu_by_name["GuiContextMenuCtrl_script_close"]["spectron_ea"],
        "0x1dc984",
    )
    check(
        "Spectron GUI context-menu width target",
        context_menu_by_name["GuiContextMenuCtrl_get_width"]["spectron_ea"],
        "0x1dc9ac",
    )
    check(
        "Spectron GUI array/popup residual artifact",
        spectron_gui_array_popup_residual_anchors["artifact"],
        "spectron_gui_array_popup_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GUI array/popup residual network",
        spectron_gui_array_popup_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI array/popup residual total",
        spectron_gui_array_popup_residual_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron GUI array/popup residual high confidence",
        spectron_gui_array_popup_residual_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron GUI array/popup residual exact-shape count",
        spectron_gui_array_popup_residual_anchors["summary"]["normalized_shape_exact_count"],
        5,
    )
    check(
        "Spectron GUI array/popup residual full-metric count",
        spectron_gui_array_popup_residual_anchors["summary"]["full_metric_exact_count"],
        5,
    )
    check(
        "Spectron GUI array/popup residual layout-change count",
        spectron_gui_array_popup_residual_anchors["summary"]["layout_change_count"],
        1,
    )
    check(
        "Spectron GUI array/popup residual default targets",
        spectron_gui_array_popup_residual_anchors["summary"]["target_default_name_count"],
        6,
    )
    array_popup_by_name = {
        row["original_name"]: row
        for row in spectron_gui_array_popup_residual_anchors["anchors"]
    }
    check(
        "Spectron GUI array allow-multiple target",
        array_popup_by_name["GuiArrayCtrl_get_allowmultipleselections"]["spectron_ea"],
        "0x1dab5c",
    )
    check(
        "Spectron GUI context rows target",
        array_popup_by_name["GuiContextMenuCtrl_get_rows"]["spectron_ea"],
        "0x1dd334",
    )
    check(
        "Spectron GUI popup rowcount target",
        array_popup_by_name["GuiPopUpMenuCtrl_script_rowcount"]["spectron_ea"],
        "0x1ddf20",
    )
    check(
        "Spectron GUI array/popup target-only review count",
        len(spectron_gui_array_popup_residual_anchors["reviewed_target_only_rows"]),
        1,
    )
    check(
        "Spectron GUI popup rows artifact",
        spectron_gui_popup_rows_anchor["artifact"],
        "spectron_gui_popup_rows_manual_translation_anchor_20260828",
    )
    check(
        "Spectron GUI popup rows network",
        spectron_gui_popup_rows_anchor["network_contacted"],
        False,
    )
    check(
        "Spectron GUI popup rows total",
        spectron_gui_popup_rows_anchor["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron GUI popup rows high confidence",
        spectron_gui_popup_rows_anchor["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron GUI popup rows exact-shape count",
        spectron_gui_popup_rows_anchor["summary"]["normalized_shape_exact_count"],
        0,
    )
    check(
        "Spectron GUI popup rows full-metric count",
        spectron_gui_popup_rows_anchor["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron GUI popup rows layout-change count",
        spectron_gui_popup_rows_anchor["summary"]["layout_change_count"],
        1,
    )
    check(
        "Spectron GUI popup rows default targets",
        spectron_gui_popup_rows_anchor["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron GUI popup rows target",
        spectron_gui_popup_rows_anchor["anchors"][0]["spectron_ea"],
        "0x1de3c4",
    )
    check(
        "Spectron GUI progress getter artifact",
        spectron_gui_progress_getter_anchor["artifact"],
        "spectron_gui_progress_getter_manual_translation_anchor_20260828",
    )
    check(
        "Spectron GUI progress getter network",
        spectron_gui_progress_getter_anchor["network_contacted"],
        False,
    )
    check(
        "Spectron GUI progress getter total",
        spectron_gui_progress_getter_anchor["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron GUI progress getter high confidence",
        spectron_gui_progress_getter_anchor["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron GUI progress getter exact-shape count",
        spectron_gui_progress_getter_anchor["summary"]["normalized_shape_exact_count"],
        1,
    )
    check(
        "Spectron GUI progress getter full-metric count",
        spectron_gui_progress_getter_anchor["summary"]["full_metric_exact_count"],
        1,
    )
    check(
        "Spectron GUI progress getter default targets",
        spectron_gui_progress_getter_anchor["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron GUI progress getter target",
        spectron_gui_progress_getter_anchor["anchors"][0]["spectron_ea"],
        "0x1dfd3c",
    )
    check(
        "Spectron GUI text-list selection script artifact",
        spectron_gui_text_list_selection_script_anchors["artifact"],
        "spectron_gui_text_list_selection_script_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GUI text-list selection script network",
        spectron_gui_text_list_selection_script_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI text-list selection script total",
        spectron_gui_text_list_selection_script_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron GUI text-list selection script high confidence",
        spectron_gui_text_list_selection_script_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron GUI text-list selection script exact-shape count",
        spectron_gui_text_list_selection_script_anchors["summary"]["normalized_shape_exact_count"],
        0,
    )
    check(
        "Spectron GUI text-list selection script full-metric count",
        spectron_gui_text_list_selection_script_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron GUI text-list selection script layout-change count",
        spectron_gui_text_list_selection_script_anchors["summary"]["layout_change_count"],
        2,
    )
    check(
        "Spectron GUI text-list selection script default targets",
        spectron_gui_text_list_selection_script_anchors["summary"]["target_default_name_count"],
        2,
    )
    selection_by_name = {
        row["original_name"]: row
        for row in spectron_gui_text_list_selection_script_anchors["anchors"]
    }
    check(
        "Spectron GUI set-selected-rows target",
        selection_by_name["GuiTextListCtrl_script_setselectedrows"]["spectron_ea"],
        "0x1e3794",
    )
    check(
        "Spectron GUI set-selected-by-IDs target",
        selection_by_name["GuiTextListCtrl_script_setselectedbyids"]["spectron_ea"],
        "0x1e38c8",
    )
    check(
        "Spectron MRandom property residual artifact",
        spectron_mrandom_property_residual_anchors["artifact"],
        "spectron_mrandom_property_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron MRandom property residual network",
        spectron_mrandom_property_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron MRandom property residual total",
        spectron_mrandom_property_residual_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron MRandom property residual high confidence",
        spectron_mrandom_property_residual_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron MRandom property residual exact-shape count",
        spectron_mrandom_property_residual_anchors["summary"]["normalized_shape_exact_count"],
        4,
    )
    check(
        "Spectron MRandom property residual full-metric count",
        spectron_mrandom_property_residual_anchors["summary"]["full_metric_exact_count"],
        4,
    )
    check(
        "Spectron MRandom property residual default targets",
        spectron_mrandom_property_residual_anchors["summary"]["target_default_name_count"],
        4,
    )
    mrandom_by_name = {
        row["original_name"]: row
        for row in spectron_mrandom_property_residual_anchors["anchors"]
    }
    check(
        "Spectron MRandom seed getter target",
        mrandom_by_name["MRandomGenerator_get_seed"]["spectron_ea"],
        "0x1e70f0",
    )
    check(
        "Spectron MRandom randint target",
        mrandom_by_name["MRandomGenerator_script_randint"]["spectron_ea"],
        "0x1e7118",
    )
    check(
        "Spectron MRandom randfloat target",
        mrandom_by_name["MRandomGenerator_script_randfloat"]["spectron_ea"],
        "0x1e7138",
    )
    check(
        "Spectron drawing-panel script artifact",
        spectron_gui_drawing_panel_script_anchors["artifact"],
        "spectron_gui_drawing_panel_script_manual_translation_anchors_20260828",
    )
    check(
        "Spectron drawing-panel script network",
        spectron_gui_drawing_panel_script_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron drawing-panel script total",
        spectron_gui_drawing_panel_script_anchors["summary"]["anchor_count"],
        3,
    )
    check(
        "Spectron drawing-panel script high confidence",
        spectron_gui_drawing_panel_script_anchors["summary"]["high_confidence_count"],
        3,
    )
    check(
        "Spectron drawing-panel script exact-shape count",
        spectron_gui_drawing_panel_script_anchors["summary"]["normalized_shape_exact_count"],
        3,
    )
    check(
        "Spectron drawing-panel script full-metric count",
        spectron_gui_drawing_panel_script_anchors["summary"]["full_metric_exact_count"],
        3,
    )
    check(
        "Spectron drawing-panel script default targets",
        spectron_gui_drawing_panel_script_anchors["summary"]["target_default_name_count"],
        3,
    )
    drawing_panel_script_by_name = {
        row["original_name"]: row
        for row in spectron_gui_drawing_panel_script_anchors["anchors"]
    }
    check(
        "Spectron set-draw-palette target",
        drawing_panel_script_by_name["GuiDrawingPanel_script_setdrawpalette"]["spectron_ea"],
        "0x1e3fd8",
    )
    check(
        "Spectron mask-image target",
        drawing_panel_script_by_name["GuiDrawingPanel_script_maskimage"]["spectron_ea"],
        "0x1e3fe0",
    )
    check(
        "Spectron filter-rectangle target",
        drawing_panel_script_by_name["GuiDrawingPanel_script_filterrectangle"]["spectron_ea"],
        "0x1e3fe8",
    )
    check(
        "Spectron TClient script-property artifact",
        spectron_tclient_script_property_anchors["artifact"],
        "spectron_tclient_script_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron TClient script-property network",
        spectron_tclient_script_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron TClient script-property total",
        spectron_tclient_script_property_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron TClient script-property high confidence",
        spectron_tclient_script_property_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron TClient script-property exact-shape count",
        spectron_tclient_script_property_anchors["summary"]["normalized_shape_exact_count"],
        3,
    )
    check(
        "Spectron TClient script-property full-metric count",
        spectron_tclient_script_property_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron TClient script-property layout-change count",
        spectron_tclient_script_property_anchors["summary"]["layout_change_count"],
        2,
    )
    check(
        "Spectron TClient script-property default targets",
        spectron_tclient_script_property_anchors["summary"]["target_default_name_count"],
        5,
    )
    tclient_script_property_by_name = {
        row["original_name"]: row
        for row in spectron_tclient_script_property_anchors["anchors"]
    }
    check(
        "Spectron TClient download-size target",
        tclient_script_property_by_name["TClient_setBigFileSizeAndContinue"]["spectron_ea"],
        "0x1ef660",
    )
    check(
        "Spectron server-list connect target",
        tclient_script_property_by_name["TGUIScriptLoader_finishServerListConnect"]["spectron_ea"],
        "0x1efb64",
    )
    check(
        "Spectron TClient set-weapon target",
        tclient_script_property_by_name["TClient_addWeaponForActivePlayer"]["spectron_ea"],
        "0x1eff94",
    )
    check(
        "Spectron file-cache property artifact",
        spectron_file_cache_property_anchors["artifact"],
        "spectron_file_cache_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron file-cache property network",
        spectron_file_cache_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron file-cache property total",
        spectron_file_cache_property_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron file-cache property high confidence",
        spectron_file_cache_property_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron file-cache property exact-shape count",
        spectron_file_cache_property_anchors["summary"]["normalized_shape_exact_count"],
        6,
    )
    check(
        "Spectron file-cache property full-metric count",
        spectron_file_cache_property_anchors["summary"]["full_metric_exact_count"],
        1,
    )
    check(
        "Spectron file-cache property layout-change count",
        spectron_file_cache_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron file-cache property default targets",
        spectron_file_cache_property_anchors["summary"]["target_default_name_count"],
        6,
    )
    check(
        "Spectron file-cache property target-only count",
        len(spectron_file_cache_property_anchors["reviewed_target_only_rows"]),
        3,
    )
    file_cache_property_by_name = {
        row["original_name"]: row
        for row in spectron_file_cache_property_anchors["anchors"]
    }
    check(
        "Spectron password getter target",
        file_cache_property_by_name["TClient_getGraalPassword"]["spectron_ea"],
        "0x1f01e4",
    )
    check(
        "Spectron minimum cache getter target",
        file_cache_property_by_name["TCachedStream_get_minfilecachesize"]["spectron_ea"],
        "0x1ffcac",
    )
    check(
        "Spectron last-download getter target",
        file_cache_property_by_name["TFileDownload_get_lastdownloadfile"]["spectron_ea"],
        "0x201420",
    )
    check(
        "Spectron TString artifact",
        spectron_tstring_anchors["artifact"],
        "spectron_tstring_manual_translation_anchors_20260827",
    )
    check("Spectron TString network", spectron_tstring_anchors["network_contacted"], False)
    check("Spectron TString total", spectron_tstring_anchors["summary"]["anchor_count"], 6)
    check("Spectron TString high confidence", spectron_tstring_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron TString exact-shape count", spectron_tstring_anchors["summary"]["exact_shape_anchor_count"], 6)
    check("Spectron TString layout-change count", spectron_tstring_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TString default targets", spectron_tstring_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron TString clear artifact",
        spectron_tstring_clear_anchors["artifact"],
        "spectron_tstring_clear_manual_translation_anchors_20260827",
    )
    check("Spectron TString clear network", spectron_tstring_clear_anchors["network_contacted"], False)
    check("Spectron TString clear total", spectron_tstring_clear_anchors["summary"]["anchor_count"], 1)
    check("Spectron TString clear high confidence", spectron_tstring_clear_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron TString clear exact-shape count", spectron_tstring_clear_anchors["summary"]["exact_shape_anchor_count"], 1)
    check("Spectron TString clear layout-change count", spectron_tstring_clear_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TString clear default targets", spectron_tstring_clear_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron static-clear artifact",
        spectron_static_clear_anchors["artifact"],
        "spectron_static_clear_manual_translation_anchors_20260827",
    )
    check("Spectron static-clear network", spectron_static_clear_anchors["network_contacted"], False)
    check("Spectron static-clear total", spectron_static_clear_anchors["summary"]["anchor_count"], 2)
    check("Spectron static-clear high confidence", spectron_static_clear_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron static-clear exact-shape count", spectron_static_clear_anchors["summary"]["exact_shape_anchor_count"], 0)
    check("Spectron static-clear layout-change count", spectron_static_clear_anchors["summary"]["layout_change_anchor_count"], 2)
    check("Spectron static-clear default targets", spectron_static_clear_anchors["summary"]["target_default_name_count"], 2)
    check(
        "Spectron static-clear delta groups",
        spectron_static_clear_anchors["summary"]["address_delta_groups"],
        {"-0x428": 1, "-0x4c4": 1},
    )
    check(
        "Spectron static callback correction artifact",
        spectron_static_callback_role_correction["artifact"],
        "spectron_static_callback_role_correction_20260827",
    )
    check(
        "Spectron static callback correction network",
        spectron_static_callback_role_correction["network_contacted"],
        False,
    )
    check(
        "Spectron static callback correction source claims",
        spectron_static_callback_role_correction["summary"]["source_claims_corrected"],
        1,
    )
    check(
        "Spectron static callback correction source globals",
        spectron_static_callback_role_correction["summary"]["source_global_group_count"],
        3,
    )
    check(
        "Spectron static callback correction target rejections",
        spectron_static_callback_role_correction["summary"]["target_candidates_rejected"],
        2,
    )
    check(
        "Spectron static callback correction target assignments",
        spectron_static_callback_role_correction["summary"]["target_assignments"],
        0,
    )
    check(
        "Spectron static callback correction animate refs",
        spectron_static_callback_role_correction["summary"]["source_animate_forbidden_group_refs"],
        0,
    )
    check(
        "Spectron static callback correction old role",
        spectron_static_callback_role_correction["historical_candidate"]["candidate_proposed_name"],
        "TServerFlying_clearStaticStrings",
    )
    check(
        "Spectron static callback correction new role",
        spectron_static_callback_role_correction["corrected_source_role"]["recommended_descriptive_name"],
        "Android_TapJoy_video_clearStaticStrings",
    )
    check(
        "Spectron static callback correction target status",
        spectron_static_callback_role_correction["target_review"]["target_assignment_status"],
        "unresolved",
    )
    check(
        "Spectron HTTP response artifact",
        spectron_http_request_receive_anchors["artifact"],
        "spectron_http_request_receive_manual_translation_anchors_20260827",
    )
    check(
        "Spectron HTTP response network",
        spectron_http_request_receive_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron HTTP response total",
        spectron_http_request_receive_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron HTTP response high confidence",
        spectron_http_request_receive_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron HTTP response layout changes",
        spectron_http_request_receive_anchors["summary"]["layout_change_anchor_count"],
        2,
    )
    check(
        "Spectron HTTP response default targets",
        spectron_http_request_receive_anchors["summary"]["target_default_name_count"],
        0,
    )
    response_anchors = {
        row["original_name"]: row
        for row in spectron_http_request_receive_anchors["anchors"]
    }
    check(
        "Spectron HTTP read target",
        response_anchors["THTTPRequest_read_void"]["spectron_ea"],
        "0x206414",
    )
    check(
        "Spectron HTTP parse target",
        response_anchors["THTTPRequest_parseData_void"]["spectron_ea"],
        "0x207bec",
    )
    check(
        "Spectron server-list connection artifact",
        spectron_server_list_connection_anchors["artifact"],
        "spectron_server_list_connection_manual_translation_anchors_20260827",
    )
    check(
        "Spectron server-list connection network",
        spectron_server_list_connection_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron server-list connection total",
        spectron_server_list_connection_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron server-list connection high confidence",
        spectron_server_list_connection_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron server-list connection exact-shape count",
        spectron_server_list_connection_anchors["summary"]["exact_shape_anchor_count"],
        4,
    )
    check(
        "Spectron server-list connection layout-change count",
        spectron_server_list_connection_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron server-list connection default targets",
        spectron_server_list_connection_anchors["summary"]["target_default_name_count"],
        4,
    )
    server_list_anchors = {
        row["original_name"]: row
        for row in spectron_server_list_connection_anchors["anchors"]
    }
    check(
        "Spectron server-list start-params target",
        server_list_anchors["TServerList_getServerStartParams"]["spectron_ea"],
        "0x208318",
    )
    check(
        "Spectron server-list start-connect target",
        server_list_anchors["TServerList_getServerStartConnect"]["spectron_ea"],
        "0x208350",
    )
    check(
        "Spectron server-list name target",
        server_list_anchors["TServerList_getServerName"]["spectron_ea"],
        "0x208388",
    )
    check(
        "Spectron server-list handoff target",
        server_list_anchors[
            "TServerList_setConnectionAttributes_TString_const_TString_const_int"
        ]["spectron_ea"],
        "0x20a1f4",
    )
    check(
        "Spectron server-list state artifact",
        spectron_server_list_state_anchors["artifact"],
        "spectron_server_list_state_manual_translation_anchors_20260827",
    )
    check(
        "Spectron server-list state network",
        spectron_server_list_state_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron server-list state total",
        spectron_server_list_state_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron server-list state high confidence",
        spectron_server_list_state_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron server-list state exact-shape count",
        spectron_server_list_state_anchors["summary"]["exact_shape_anchor_count"],
        4,
    )
    check(
        "Spectron server-list state layout-change count",
        spectron_server_list_state_anchors["summary"]["layout_change_anchor_count"],
        0,
    )
    check(
        "Spectron server-list state default targets",
        spectron_server_list_state_anchors["summary"]["target_default_name_count"],
        4,
    )
    server_list_state_anchors = {
        row["original_name"]: row
        for row in spectron_server_list_state_anchors["anchors"]
    }
    check(
        "Spectron server-list remove-vars target",
        server_list_state_anchors["TServerList_setRemoveVarsOnLogout"]["spectron_ea"],
        "0x2082b0",
    )
    check(
        "Spectron server-list reconnect getter target",
        server_list_state_anchors["TServerList_getAllowLoginReconnect"]["spectron_ea"],
        "0x2082c0",
    )
    check(
        "Spectron server-list start-params setter target",
        server_list_state_anchors["TServerList_setServerStartParams"]["spectron_ea"],
        "0x2082f0",
    )
    check(
        "Spectron server-list start-connect setter target",
        server_list_state_anchors["TServerList_setServerStartConnect"]["spectron_ea"],
        "0x208304",
    )
    check(
        "Spectron HTTP cleanup artifact",
        spectron_http_request_cleanup_anchors["artifact"],
        "spectron_http_request_cleanup_manual_translation_anchors_20260827",
    )
    check(
        "Spectron HTTP cleanup network",
        spectron_http_request_cleanup_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron HTTP cleanup total",
        spectron_http_request_cleanup_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron HTTP cleanup high confidence",
        spectron_http_request_cleanup_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron HTTP cleanup exact-shape count",
        spectron_http_request_cleanup_anchors["summary"]["exact_shape_anchor_count"],
        4,
    )
    check(
        "Spectron HTTP cleanup layout-change count",
        spectron_http_request_cleanup_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron HTTP cleanup default targets",
        spectron_http_request_cleanup_anchors["summary"]["target_default_name_count"],
        0,
    )
    http_cleanup_anchors = {
        row["original_name"]: row
        for row in spectron_http_request_cleanup_anchors["anchors"]
    }
    check(
        "Spectron HTTP cleanup target",
        http_cleanup_anchors["THTTPRequest_clearRequest_void"]["spectron_ea"],
        "0x204d5c",
    )
    check(
        "Spectron HTTP properties D2 target",
        http_cleanup_anchors["THTTPRequestProperties_THTTPRequestProperties"]["spectron_ea"],
        "0x208248",
    )
    check(
        "Spectron HTTP properties D0 target",
        http_cleanup_anchors["THTTPRequestProperties_THTTPRequestProperties__2"]["spectron_ea"],
        "0x20826c",
    )
    check(
        "Spectron TSocket residual artifact",
        spectron_tsocket_residual_anchors["artifact"],
        "spectron_tsocket_residual_manual_translation_anchors_20260827",
    )
    check(
        "Spectron TSocket residual network",
        spectron_tsocket_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron TSocket residual total",
        spectron_tsocket_residual_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron TSocket residual high confidence",
        spectron_tsocket_residual_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron TSocket residual exact-shape count",
        spectron_tsocket_residual_anchors["summary"]["exact_shape_anchor_count"],
        3,
    )
    check(
        "Spectron TSocket residual layout-change count",
        spectron_tsocket_residual_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron TSocket residual default targets",
        spectron_tsocket_residual_anchors["summary"]["target_default_name_count"],
        2,
    )
    tsocket_residual = {
        row["original_name"]: row
        for row in spectron_tsocket_residual_anchors["anchors"]
    }
    check(
        "Spectron TSocket client-list target",
        tsocket_residual["TSocket_removeFromClientList_void"]["spectron_ea"],
        "0x20ab0c",
    )
    check(
        "Spectron TSocket D0 target",
        tsocket_residual["TSocket_TSocket__2"]["spectron_ea"],
        "0x20ac44",
    )
    check(
        "Spectron TSocket error adapter target",
        tsocket_residual["TSocket_getError"]["spectron_ea"],
        "0x20ad1c",
    )
    check(
        "Spectron TSocket IP adapter target",
        tsocket_residual["TSocket_getIP"]["spectron_ea"],
        "0x20ad78",
    )
    check(
        "Spectron game-environment artifact",
        spectron_game_environment_anchors["artifact"],
        "spectron_game_environment_manual_translation_anchors_20260827",
    )
    check(
        "Spectron game-environment network",
        spectron_game_environment_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron game-environment total",
        spectron_game_environment_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron game-environment high confidence",
        spectron_game_environment_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron game-environment exact-shape count",
        spectron_game_environment_anchors["summary"]["exact_shape_anchor_count"],
        3,
    )
    check(
        "Spectron game-environment layout-change count",
        spectron_game_environment_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron game-environment default targets",
        spectron_game_environment_anchors["summary"]["target_default_name_count"],
        2,
    )
    game_environment = {
        row["original_name"]: row
        for row in spectron_game_environment_anchors["anchors"]
    }
    check(
        "Spectron all-players-count target",
        game_environment["TGameEnvironment_getAllPlayersCount"]["spectron_ea"],
        "0xea84c",
    )
    check(
        "Spectron premium-version target",
        game_environment["TGameEnvironment_isPremiumVersion_void"]["spectron_ea"],
        "0xea860",
    )
    check(
        "Spectron demo-version target",
        game_environment["TGameEnvironment_isDemoVersion_void"]["spectron_ea"],
        "0xea868",
    )
    check(
        "Spectron adventure-quit target",
        game_environment["TGameEnvironment_script_adventureQuit"]["spectron_ea"],
        "0xea870",
    )
    check(
        "Spectron client-environment graphics artifact",
        spectron_client_environment_graphics_anchors["artifact"],
        "spectron_client_environment_graphics_manual_translation_anchors_20260827",
    )
    check(
        "Spectron client-environment graphics network",
        spectron_client_environment_graphics_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron client-environment graphics total",
        spectron_client_environment_graphics_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron client-environment graphics high confidence",
        spectron_client_environment_graphics_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron client-environment graphics exact-shape count",
        spectron_client_environment_graphics_anchors["summary"]["exact_shape_anchor_count"],
        1,
    )
    check(
        "Spectron client-environment graphics target",
        {
            row["original_name"]: row
            for row in spectron_client_environment_graphics_anchors["anchors"]
        }["TClientEnvironment_initGraphics_void"]["spectron_ea"],
        "0x15fe84",
    )
    check(
        "Spectron client-environment static-clear artifact",
        spectron_client_environment_static_clear_anchors["artifact"],
        "spectron_client_environment_static_clear_manual_translation_anchors_20260827",
    )
    check(
        "Spectron client-environment static-clear network",
        spectron_client_environment_static_clear_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron client-environment static-clear total",
        spectron_client_environment_static_clear_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron client-environment static-clear high confidence",
        spectron_client_environment_static_clear_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron client-environment static-clear exact-shape count",
        spectron_client_environment_static_clear_anchors["summary"]["exact_shape_anchor_count"],
        2,
    )
    check(
        "Spectron client-environment static-clear default targets",
        spectron_client_environment_static_clear_anchors["summary"]["target_default_name_count"],
        2,
    )
    client_environment_static_clear = {
        row["original_name"]: row
        for row in spectron_client_environment_static_clear_anchors["anchors"]
    }
    check(
        "Spectron runTimers profiler-clear target",
        client_environment_static_clear[
            "TClientEnvironment_clearStaticString38D428"
        ]["spectron_ea"],
        "0x15f678",
    )
    check(
        "Spectron drawGame profiler-clear target",
        client_environment_static_clear[
            "TClientEnvironment_clearStaticString38D460"
        ]["spectron_ea"],
        "0x15f684",
    )
    check(
        "Spectron client-environment restart-state artifact",
        spectron_client_environment_restart_state_anchors["artifact"],
        "spectron_client_environment_restart_state_manual_translation_anchors_20260827",
    )
    check(
        "Spectron client-environment restart-state network",
        spectron_client_environment_restart_state_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron client-environment restart-state total",
        spectron_client_environment_restart_state_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron client-environment restart-state high confidence",
        spectron_client_environment_restart_state_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron client-environment restart-state exact-shape count",
        spectron_client_environment_restart_state_anchors["summary"]["exact_shape_anchor_count"],
        0,
    )
    check(
        "Spectron client-environment restart-state layout-change count",
        spectron_client_environment_restart_state_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron client-environment restart-state default target",
        spectron_client_environment_restart_state_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron client-environment restart-state target",
        {
            row["original_name"]: row
            for row in spectron_client_environment_restart_state_anchors["anchors"]
        }["TClientEnvironment_clearRestartState"]["spectron_ea"],
        "0xdfdb4",
    )
    check(
        "Spectron particle-emitter artifact",
        spectron_particle_emitter_anchors["artifact"],
        "spectron_particle_emitter_manual_translation_anchors_20260826",
    )
    check("Spectron particle-emitter network", spectron_particle_emitter_anchors["network_contacted"], False)
    check("Spectron particle-emitter total", spectron_particle_emitter_anchors["summary"]["anchor_count"], 2)
    check("Spectron particle-emitter high confidence", spectron_particle_emitter_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron particle-emitter semantic overlap", spectron_particle_emitter_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron particle-emitter default targets", spectron_particle_emitter_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron particle-emitter script-vars artifact",
        spectron_particle_emitter_script_vars_anchors["artifact"],
        "spectron_particle_emitter_script_vars_manual_translation_anchors_20260827",
    )
    check(
        "Spectron particle-emitter script-vars network",
        spectron_particle_emitter_script_vars_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron particle-emitter script-vars total",
        spectron_particle_emitter_script_vars_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron particle-emitter script-vars high confidence",
        spectron_particle_emitter_script_vars_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron particle-emitter script-vars semantic overlap",
        spectron_particle_emitter_script_vars_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron particle-emitter script-vars exact-shape count",
        spectron_particle_emitter_script_vars_anchors["summary"]["exact_shape_anchor_count"],
        1,
    )
    check(
        "Spectron particle-emitter script-vars default targets",
        spectron_particle_emitter_script_vars_anchors["summary"]["target_default_name_count"],
        0,
    )
    check(
        "Spectron particle-emitter script-vars target",
        {
            row["original_name"]: row
            for row in spectron_particle_emitter_script_vars_anchors["anchors"]
        }["TParticleEmitter_initStaticScriptVars_void"]["spectron_ea"],
        "0x2451f4",
    )
    check(
        "Spectron resource link-lists artifact",
        spectron_resource_link_lists_anchors["artifact"],
        "spectron_resource_link_lists_manual_translation_anchors_20260827",
    )
    check(
        "Spectron resource link-lists network",
        spectron_resource_link_lists_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron resource link-lists total",
        spectron_resource_link_lists_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron resource link-lists high confidence",
        spectron_resource_link_lists_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron resource link-lists semantic overlap",
        spectron_resource_link_lists_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron resource link-lists exact-shape count",
        spectron_resource_link_lists_anchors["summary"]["exact_shape_anchor_count"],
        1,
    )
    check(
        "Spectron resource link-lists default target",
        spectron_resource_link_lists_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron resource link-lists target",
        {
            row["original_name"]: row
            for row in spectron_resource_link_lists_anchors["anchors"]
        }["TResource_initializeLinkLists"]["spectron_ea"],
        "0xe0564",
    )
    check(
        "Spectron clear-cur-anis artifact",
        spectron_clear_cur_anis_anchors["artifact"],
        "spectron_clear_cur_anis_manual_translation_anchors_20260827",
    )
    check(
        "Spectron clear-cur-anis network",
        spectron_clear_cur_anis_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron clear-cur-anis total",
        spectron_clear_cur_anis_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron clear-cur-anis high confidence",
        spectron_clear_cur_anis_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron clear-cur-anis exact-shape count",
        spectron_clear_cur_anis_anchors["summary"]["exact_shape_anchor_count"],
        0,
    )
    check(
        "Spectron clear-cur-anis layout-change count",
        spectron_clear_cur_anis_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron clear-cur-anis default target",
        spectron_clear_cur_anis_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron clear-cur-anis target",
        {
            row["original_name"]: row
            for row in spectron_clear_cur_anis_anchors["anchors"]
        }["clearCurAnis"]["spectron_ea"],
        "0xdfe08",
    )
    check(
        "Spectron options window-position artifact",
        spectron_options_window_position_anchors["artifact"],
        "spectron_options_window_position_manual_translation_anchors_20260827",
    )
    check(
        "Spectron options window-position network",
        spectron_options_window_position_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron options window-position total",
        spectron_options_window_position_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron options window-position high confidence",
        spectron_options_window_position_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron options window-position semantic overlap",
        spectron_options_window_position_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron options window-position exact-shape count",
        spectron_options_window_position_anchors["summary"]["exact_shape_anchor_count"],
        0,
    )
    check(
        "Spectron options window-position layout-change count",
        spectron_options_window_position_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron options window-position default target",
        spectron_options_window_position_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron options window-position target",
        {
            row["original_name"]: row
            for row in spectron_options_window_position_anchors["anchors"]
        }["TOptions_initializeWindowPosition"]["spectron_ea"],
        "0xe0b3c",
    )
    check(
        "Spectron displayed-GIF artifact",
        spectron_displayed_gif_anchors["artifact"],
        "spectron_displayed_gif_manual_translation_anchors_20260827",
    )
    check(
        "Spectron displayed-GIF network",
        spectron_displayed_gif_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron displayed-GIF total",
        spectron_displayed_gif_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron displayed-GIF high confidence",
        spectron_displayed_gif_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron displayed-GIF semantic overlap",
        spectron_displayed_gif_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron displayed-GIF exact-shape count",
        spectron_displayed_gif_anchors["summary"]["exact_shape_anchor_count"],
        0,
    )
    check(
        "Spectron displayed-GIF layout-change count",
        spectron_displayed_gif_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron displayed-GIF default target",
        spectron_displayed_gif_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron displayed-GIF target",
        {
            row["original_name"]: row
            for row in spectron_displayed_gif_anchors["anchors"]
        }["initializeDisplayedGif"]["spectron_ea"],
        "0xe0b80",
    )
    check(
        "Spectron GUI button-types artifact",
        spectron_gui_button_types_anchors["artifact"],
        "spectron_gui_button_types_manual_translation_anchors_20260827",
    )
    check(
        "Spectron GUI button-types network",
        spectron_gui_button_types_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI button-types total",
        spectron_gui_button_types_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron GUI button-types high confidence",
        spectron_gui_button_types_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron GUI button-types semantic overlap",
        spectron_gui_button_types_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron GUI button-types exact-shape count",
        spectron_gui_button_types_anchors["summary"]["exact_shape_anchor_count"],
        0,
    )
    check(
        "Spectron GUI button-types layout-change count",
        spectron_gui_button_types_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron GUI button-types default target",
        spectron_gui_button_types_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron GUI button-types target",
        {
            row["original_name"]: row
            for row in spectron_gui_button_types_anchors["anchors"]
        }["sub_E090C"]["spectron_ea"],
        "0xe0d10",
    )
    check(
        "Spectron GUI alignment-tables artifact",
        spectron_gui_alignment_tables_anchors["artifact"],
        "spectron_gui_alignment_tables_manual_translation_anchors_20260827",
    )
    check(
        "Spectron GUI alignment-tables network",
        spectron_gui_alignment_tables_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI alignment-tables total",
        spectron_gui_alignment_tables_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron GUI alignment-tables high confidence",
        spectron_gui_alignment_tables_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron GUI alignment-tables semantic overlap",
        spectron_gui_alignment_tables_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron GUI alignment-tables exact-shape count",
        spectron_gui_alignment_tables_anchors["summary"]["exact_shape_anchor_count"],
        0,
    )
    check(
        "Spectron GUI alignment-tables layout-change count",
        spectron_gui_alignment_tables_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron GUI alignment-tables default target",
        spectron_gui_alignment_tables_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron GUI alignment-tables target",
        {
            row["original_name"]: row
            for row in spectron_gui_alignment_tables_anchors["anchors"]
        }["sub_E0930"]["spectron_ea"],
        "0xe0dac",
    )
    check(
        "Spectron GUI stretch-modes artifact",
        spectron_gui_stretch_modes_anchors["artifact"],
        "spectron_gui_stretch_modes_manual_translation_anchors_20260827",
    )
    check(
        "Spectron GUI stretch-modes network",
        spectron_gui_stretch_modes_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI stretch-modes total",
        spectron_gui_stretch_modes_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron GUI stretch-modes high confidence",
        spectron_gui_stretch_modes_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron GUI stretch-modes semantic overlap",
        spectron_gui_stretch_modes_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron GUI stretch-modes exact-shape count",
        spectron_gui_stretch_modes_anchors["summary"]["exact_shape_anchor_count"],
        0,
    )
    check(
        "Spectron GUI stretch-modes layout-change count",
        spectron_gui_stretch_modes_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron GUI stretch-modes default target",
        spectron_gui_stretch_modes_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron GUI stretch-modes target",
        {
            row["original_name"]: row
            for row in spectron_gui_stretch_modes_anchors["anchors"]
        }["sub_E0960"]["spectron_ea"],
        "0xe0e54",
    )
    check(
        "Spectron TGUIRender colors artifact",
        spectron_tgui_render_colors_anchors["artifact"],
        "spectron_tgui_render_colors_manual_translation_anchors_20260827",
    )
    check(
        "Spectron TGUIRender colors network",
        spectron_tgui_render_colors_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron TGUIRender colors total",
        spectron_tgui_render_colors_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron TGUIRender colors high confidence",
        spectron_tgui_render_colors_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron TGUIRender colors semantic overlap",
        spectron_tgui_render_colors_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron TGUIRender colors exact-shape count",
        spectron_tgui_render_colors_anchors["summary"]["exact_shape_anchor_count"],
        0,
    )
    check(
        "Spectron TGUIRender colors layout-change count",
        spectron_tgui_render_colors_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron TGUIRender colors default target",
        spectron_tgui_render_colors_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron TGUIRender colors target",
        {
            row["original_name"]: row
            for row in spectron_tgui_render_colors_anchors["anchors"]
        }["sub_E0984"]["spectron_ea"],
        "0xe0f0c",
    )
    check(
        "Spectron THTMLDefinitions defaults artifact",
        spectron_thtml_definitions_defaults_anchors["artifact"],
        "spectron_thtml_definitions_defaults_manual_translation_anchors_20260827",
    )
    check(
        "Spectron THTMLDefinitions defaults network",
        spectron_thtml_definitions_defaults_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron THTMLDefinitions defaults total",
        spectron_thtml_definitions_defaults_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron THTMLDefinitions defaults high confidence",
        spectron_thtml_definitions_defaults_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron THTMLDefinitions defaults semantic overlap",
        spectron_thtml_definitions_defaults_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron THTMLDefinitions defaults exact-shape count",
        spectron_thtml_definitions_defaults_anchors["summary"]["exact_shape_anchor_count"],
        1,
    )
    check(
        "Spectron THTMLDefinitions defaults layout-change count",
        spectron_thtml_definitions_defaults_anchors["summary"]["layout_change_anchor_count"],
        0,
    )
    check(
        "Spectron THTMLDefinitions defaults register-detail difference",
        spectron_thtml_definitions_defaults_anchors["summary"]["register_detail_only_difference_count"],
        1,
    )
    check(
        "Spectron THTMLDefinitions defaults default target",
        spectron_thtml_definitions_defaults_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron THTMLDefinitions defaults target",
        {
            row["original_name"]: row
            for row in spectron_thtml_definitions_defaults_anchors["anchors"]
        }["sub_E09F4"]["spectron_ea"],
        "0xe0fc4",
    )
    check(
        "Spectron TClient static strings artifact",
        spectron_tclient_static_strings_anchors["artifact"],
        "spectron_tclient_static_strings_manual_translation_anchors_20260827",
    )
    check(
        "Spectron TClient static strings network",
        spectron_tclient_static_strings_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron TClient static strings total",
        spectron_tclient_static_strings_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron TClient static strings high confidence",
        spectron_tclient_static_strings_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron TClient static strings semantic overlap",
        spectron_tclient_static_strings_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron TClient static strings layout-change count",
        spectron_tclient_static_strings_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron TClient static strings field count",
        spectron_tclient_static_strings_anchors["summary"]["field_count"],
        11,
    )
    check(
        "Spectron TClient static strings default target",
        spectron_tclient_static_strings_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron TClient static strings target",
        {
            row["original_name"]: row
            for row in spectron_tclient_static_strings_anchors["anchors"]
        }["sub_E0A2C"]["spectron_ea"],
        "0xe1118",
    )
    check(
        "Spectron TSocket static strings artifact",
        spectron_tsocket_static_strings_anchors["artifact"],
        "spectron_tsocket_static_state_manual_translation_anchors_20260827",
    )
    check(
        "Spectron TSocket static strings network",
        spectron_tsocket_static_strings_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron TSocket static strings total",
        spectron_tsocket_static_strings_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron TSocket static strings high confidence",
        spectron_tsocket_static_strings_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron TSocket static strings semantic overlap",
        spectron_tsocket_static_strings_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron TSocket static strings layout-change count",
        spectron_tsocket_static_strings_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron TSocket static strings field count",
        spectron_tsocket_static_strings_anchors["summary"]["field_count"],
        2,
    )
    check(
        "Spectron TSocket static strings default target",
        spectron_tsocket_static_strings_anchors["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron TSocket static strings target",
        {
            row["original_name"]: row
            for row in spectron_tsocket_static_strings_anchors["anchors"]
        }["sub_E0AB4"]["spectron_ea"],
        "0xe12dc",
    )
    check(
        "Spectron Android TapJoy/video artifact",
        spectron_android_tapjoy_video_anchors["artifact"],
        "spectron_android_tapjoy_video_state_manual_translation_anchors_20260827",
    )
    check(
        "Spectron Android TapJoy/video network",
        spectron_android_tapjoy_video_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron Android TapJoy/video total",
        spectron_android_tapjoy_video_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron Android TapJoy/video high confidence",
        spectron_android_tapjoy_video_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron Android TapJoy/video semantic overlap",
        spectron_android_tapjoy_video_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron Android TapJoy/video layout-change count",
        spectron_android_tapjoy_video_anchors["summary"]["layout_change_anchor_count"],
        2,
    )
    check(
        "Spectron Android TapJoy/video source default count",
        spectron_android_tapjoy_video_anchors["summary"]["source_default_name_count"],
        1,
    )
    check(
        "Spectron Android TapJoy/video target default count",
        spectron_android_tapjoy_video_anchors["summary"]["target_default_name_count"],
        2,
    )
    check(
        "Spectron Android TapJoy/video state field count",
        spectron_android_tapjoy_video_anchors["summary"]["state_field_count"],
        7,
    )
    android_tapjoy_video_targets = {
        row["original_name"]: row
        for row in spectron_android_tapjoy_video_anchors["anchors"]
    }
    check(
        "Spectron Android TapJoy/video initializer target",
        android_tapjoy_video_targets["sub_E0AD0"]["spectron_ea"],
        "0xe1640",
    )
    check(
        "Spectron Android TapJoy/video cleanup target",
        android_tapjoy_video_targets["TServerFlying_clearStaticStrings"][
            "spectron_ea"
        ],
        "0xe0438",
    )
    check(
        "Spectron sounds music-state artifact",
        spectron_sounds_music_state_anchors["artifact"],
        "spectron_sounds_music_state_manual_translation_anchors_20260827",
    )
    check(
        "Spectron sounds music-state network",
        spectron_sounds_music_state_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron sounds music-state total",
        spectron_sounds_music_state_anchors["summary"]["anchor_count"],
        3,
    )
    check(
        "Spectron sounds music-state high confidence",
        spectron_sounds_music_state_anchors["summary"]["high_confidence_count"],
        3,
    )
    check(
        "Spectron sounds music-state semantic overlap",
        spectron_sounds_music_state_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron sounds music-state exact-shape count",
        spectron_sounds_music_state_anchors["summary"]["exact_shape_anchor_count"],
        3,
    )
    check(
        "Spectron sounds music-state target default count",
        spectron_sounds_music_state_anchors["summary"]["target_default_name_count"],
        1,
    )
    sounds_music_state_targets = {
        row["original_name"]: row
        for row in spectron_sounds_music_state_anchors["anchors"]
    }
    check(
        "Spectron sounds isMusicPlaying target",
        sounds_music_state_targets["TSounds_isMusicPlaying"]["spectron_ea"],
        "0xe16a8",
    )
    check(
        "Spectron sounds getMusicPos target",
        sounds_music_state_targets["TSounds_getMusicPos_void"]["spectron_ea"],
        "0xe16ec",
    )
    check(
        "Spectron sounds getMusicLen target",
        sounds_music_state_targets["TSounds_getMusicLen_void"]["spectron_ea"],
        "0xe172c",
    )
    check(
        "Spectron sounds effect artifact",
        spectron_sounds_effect_anchors["artifact"],
        "spectron_sounds_effect_manual_translation_anchors_20260827",
    )
    check(
        "Spectron sounds effect network",
        spectron_sounds_effect_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron sounds effect total",
        spectron_sounds_effect_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron sounds effect high confidence",
        spectron_sounds_effect_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron sounds effect semantic overlap",
        spectron_sounds_effect_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron sounds effect exact-shape count",
        spectron_sounds_effect_anchors["summary"]["exact_shape_anchor_count"],
        1,
    )
    check(
        "Spectron sounds effect layout-change count",
        spectron_sounds_effect_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron sounds effect target default count",
        spectron_sounds_effect_anchors["summary"]["target_default_name_count"],
        0,
    )
    sounds_effect_targets = {
        row["original_name"]: row
        for row in spectron_sounds_effect_anchors["anchors"]
    }
    check(
        "Spectron TSoundEffect constructor target",
        sounds_effect_targets["TSoundEffect_TSoundEffect_TString_const"][
            "spectron_ea"
        ],
        "0xe1970",
    )
    check(
        "Spectron TSounds getSoundEffect target",
        sounds_effect_targets["TSounds_getSoundEffect_TString_const"][
            "spectron_ea"
        ],
        "0xe1a1c",
    )
    check(
        "Spectron sounds control artifact",
        spectron_sounds_control_anchors["artifact"],
        "spectron_sounds_control_manual_translation_anchors_20260827",
    )
    check(
        "Spectron sounds control network",
        spectron_sounds_control_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron sounds control total",
        spectron_sounds_control_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron sounds control high confidence",
        spectron_sounds_control_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron sounds control semantic overlap",
        spectron_sounds_control_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron sounds control exact-shape count",
        spectron_sounds_control_anchors["summary"]["exact_shape_anchor_count"],
        2,
    )
    check(
        "Spectron sounds control full-feature count",
        spectron_sounds_control_anchors["summary"]["full_metric_exact_count"],
        1,
    )
    sounds_control_targets = {
        row["original_name"]: row
        for row in spectron_sounds_control_anchors["anchors"]
    }
    check(
        "Spectron sounds setMusicVolume target",
        sounds_control_targets["TSounds_setMusicVolume"]["spectron_ea"],
        "0xe1f28",
    )
    check(
        "Spectron sounds updateMusic target",
        sounds_control_targets["TSounds_updateMusic_void"]["spectron_ea"],
        "0xe2470",
    )
    check(
        "Spectron sounds tail artifact",
        spectron_sounds_tail_anchors["artifact"],
        "spectron_sounds_tail_manual_translation_anchors_20260827",
    )
    check(
        "Spectron sounds tail network",
        spectron_sounds_tail_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron sounds tail total",
        spectron_sounds_tail_anchors["summary"]["anchor_count"],
        3,
    )
    check(
        "Spectron sounds tail high confidence",
        spectron_sounds_tail_anchors["summary"]["high_confidence_count"],
        3,
    )
    check(
        "Spectron sounds tail semantic overlap",
        spectron_sounds_tail_anchors["summary"]["already_in_semantic_map"],
        1,
    )
    check(
        "Spectron sounds tail new context count",
        spectron_sounds_tail_anchors["summary"]["new_context_anchor_count"],
        2,
    )
    check(
        "Spectron sounds tail exact-shape count",
        spectron_sounds_tail_anchors["summary"]["exact_shape_anchor_count"],
        2,
    )
    check(
        "Spectron sounds tail full-feature count",
        spectron_sounds_tail_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron sounds tail layout-change count",
        spectron_sounds_tail_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron sounds tail register-detail difference count",
        spectron_sounds_tail_anchors["summary"]["register_detail_difference_count"],
        1,
    )
    check(
        "Spectron sounds tail target default count",
        spectron_sounds_tail_anchors["summary"]["target_default_name_count"],
        1,
    )
    sounds_tail_targets = {
        row["original_name"]: row
        for row in spectron_sounds_tail_anchors["anchors"]
    }
    for source_name, target_ea in {
        "TSounds_stopSFX_TString_const": "0xe1a78",
        "TSounds_script_setSoundPitch": "0xe366c",
        "TSounds_initStaticVars_void": "0xe3678",
    }.items():
        check(
            "Spectron sounds tail target " + source_name,
            sounds_tail_targets[source_name]["spectron_ea"],
            target_ea,
        )
    check(
        "Spectron TSoundEffect methods artifact",
        spectron_tsound_effect_methods_anchors["artifact"],
        "spectron_tsound_effect_methods_manual_translation_anchors_20260827",
    )
    check(
        "Spectron TSoundEffect methods network",
        spectron_tsound_effect_methods_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron TSoundEffect methods total",
        spectron_tsound_effect_methods_anchors["summary"]["anchor_count"],
        7,
    )
    check(
        "Spectron TSoundEffect methods high confidence",
        spectron_tsound_effect_methods_anchors["summary"]["high_confidence_count"],
        7,
    )
    check(
        "Spectron TSoundEffect methods semantic overlap",
        spectron_tsound_effect_methods_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron TSoundEffect methods exact-shape count",
        spectron_tsound_effect_methods_anchors["summary"]["exact_shape_anchor_count"],
        7,
    )
    check(
        "Spectron TSoundEffect methods full-feature count",
        spectron_tsound_effect_methods_anchors["summary"]["full_metric_exact_count"],
        7,
    )
    check(
        "Spectron TSoundEffect methods target default count",
        spectron_tsound_effect_methods_anchors["summary"]["target_default_name_count"],
        0,
    )
    tsound_effect_method_targets = {
        row["original_name"]: row
        for row in spectron_tsound_effect_methods_anchors["anchors"]
    }
    check(
        "Spectron TSoundEffect hasChannel target",
        tsound_effect_method_targets["TSoundEffect_hasChannel_void"]["spectron_ea"],
        "0xe3714",
    )
    check(
        "Spectron TSoundEffect getLength target",
        tsound_effect_method_targets["TSoundEffect_getLength_void"]["spectron_ea"],
        "0xe373c",
    )
    check(
        "Spectron Java sound small-method artifact",
        spectron_sound_java_small_methods_anchors["artifact"],
        "spectron_sound_java_small_methods_manual_translation_anchors_20260827",
    )
    check(
        "Spectron Java sound small-method network",
        spectron_sound_java_small_methods_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron Java sound small-method total",
        spectron_sound_java_small_methods_anchors["summary"]["anchor_count"],
        7,
    )
    check(
        "Spectron Java sound small-method high confidence",
        spectron_sound_java_small_methods_anchors["summary"]["high_confidence_count"],
        7,
    )
    check(
        "Spectron Java sound small-method semantic overlap",
        spectron_sound_java_small_methods_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron Java sound small-method exact-shape count",
        spectron_sound_java_small_methods_anchors["summary"]["exact_shape_anchor_count"],
        7,
    )
    check(
        "Spectron Java sound small-method full-feature count",
        spectron_sound_java_small_methods_anchors["summary"]["full_metric_exact_count"],
        7,
    )
    check(
        "Spectron Java sound small-method layout-change count",
        spectron_sound_java_small_methods_anchors["summary"]["layout_change_anchor_count"],
        0,
    )
    check(
        "Spectron Java sound small-method target default count",
        spectron_sound_java_small_methods_anchors["summary"]["target_default_name_count"],
        0,
    )
    sound_java_small_method_targets = {
        row["original_name"]: row
        for row in spectron_sound_java_small_methods_anchors["anchors"]
    }
    for source_name, target_ea in {
        "TSoundPlayerJava_stopMidi_void": "0xe3748",
        "TSoundPlayerJava_setMusicVolumeAndPan_int_int": "0xe3768",
        "TSoundEffectJava_freeResource_void": "0xe3788",
        "TSoundEffectJava_load_void": "0xe3790",
        "TSoundEffectJava_setVolume_int": "0xe3794",
        "TSoundEffectJava_setPan_int": "0xe379c",
        "TSoundEffectJava_stop_void": "0xe37a4",
    }.items():
        check(
            "Spectron Java sound target " + source_name,
            sound_java_small_method_targets[source_name]["spectron_ea"],
            target_ea,
        )
    check(
        "Spectron Java sound destructor artifact",
        spectron_sound_java_destructor_anchors["artifact"],
        "spectron_sound_java_destructor_manual_translation_anchors_20260827",
    )
    check(
        "Spectron Java sound destructor network",
        spectron_sound_java_destructor_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron Java sound destructor total",
        spectron_sound_java_destructor_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron Java sound destructor high confidence",
        spectron_sound_java_destructor_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron Java sound destructor semantic overlap",
        spectron_sound_java_destructor_anchors["summary"]["already_in_semantic_map"],
        1,
    )
    check(
        "Spectron Java sound destructor new context count",
        spectron_sound_java_destructor_anchors["summary"]["new_context_anchor_count"],
        1,
    )
    check(
        "Spectron Java sound destructor exact-shape count",
        spectron_sound_java_destructor_anchors["summary"]["exact_shape_anchor_count"],
        2,
    )
    check(
        "Spectron Java sound destructor full-feature count",
        spectron_sound_java_destructor_anchors["summary"]["full_metric_exact_count"],
        1,
    )
    check(
        "Spectron Java sound destructor register-detail difference count",
        spectron_sound_java_destructor_anchors["summary"]["register_detail_difference_count"],
        1,
    )
    sound_java_destructor_targets = {
        row["original_name"]: row
        for row in spectron_sound_java_destructor_anchors["anchors"]
    }
    for source_name, target_ea in {
        "TSoundEffectJava_TSoundEffectJava__2": "0xe3804",
        "TSoundPlayerJava_TSoundPlayerJava__2": "0xe4190",
    }.items():
        check(
            "Spectron Java sound destructor target " + source_name,
            sound_java_destructor_targets[source_name]["spectron_ea"],
            target_ea,
        )
    check(
        "Spectron Java sound D1 artifact",
        spectron_sound_java_d1_anchors["artifact"],
        "spectron_sound_java_d1_manual_translation_anchors_20260827",
    )
    check(
        "Spectron Java sound D1 network",
        spectron_sound_java_d1_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron Java sound D1 total",
        spectron_sound_java_d1_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron Java sound D1 high confidence",
        spectron_sound_java_d1_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron Java sound D1 semantic overlap",
        spectron_sound_java_d1_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron Java sound D1 exact-shape count",
        spectron_sound_java_d1_anchors["summary"]["exact_shape_anchor_count"],
        1,
    )
    check(
        "Spectron Java sound D1 full-feature count",
        spectron_sound_java_d1_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron Java sound D1 register-detail difference count",
        spectron_sound_java_d1_anchors["summary"]["register_detail_difference_count"],
        1,
    )
    sound_java_d1_targets = {
        row["original_name"]: row
        for row in spectron_sound_java_d1_anchors["anchors"]
    }
    check(
        "Spectron Java sound D1 target",
        sound_java_d1_targets["TSoundPlayerJava_TSoundPlayerJava"]["spectron_ea"],
        "0xe417c",
    )
    check(
        "Spectron sound base-interface artifact",
        spectron_sound_base_interface_anchors["artifact"],
        "spectron_sound_base_interface_manual_translation_anchors_20260827",
    )
    check(
        "Spectron sound base-interface network",
        spectron_sound_base_interface_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron sound base-interface total",
        spectron_sound_base_interface_anchors["summary"]["anchor_count"],
        18,
    )
    check(
        "Spectron sound base-interface high confidence",
        spectron_sound_base_interface_anchors["summary"]["high_confidence_count"],
        18,
    )
    check(
        "Spectron sound base-interface semantic overlap",
        spectron_sound_base_interface_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron sound base-interface exact-shape count",
        spectron_sound_base_interface_anchors["summary"]["exact_shape_anchor_count"],
        18,
    )
    check(
        "Spectron sound base-interface full-feature count",
        spectron_sound_base_interface_anchors["summary"]["full_metric_exact_count"],
        18,
    )
    check(
        "Spectron sound base-interface target default count",
        spectron_sound_base_interface_anchors["summary"]["target_default_name_count"],
        0,
    )
    sound_base_interface_targets = {
        row["original_name"]: row
        for row in spectron_sound_base_interface_anchors["anchors"]
    }
    for source_name, target_ea in {
        "TSoundPlayer_canPlayMusic_void": "0xe410c",
        "TSoundPlayer_set3DPosition_T3DFloatPoint_const_T3DFloatPoint_const_T3DFloatPoint_const_T3DFloatPoint_const": "0xe4158",
        "TSoundEffectJava_isLoaded_void": "0xe415c",
        "TSoundPlayerJava_canPlaySoundEffects_void": "0xe4174",
    }.items():
        check(
            "Spectron sound base-interface target " + source_name,
            sound_base_interface_targets[source_name]["spectron_ea"],
            target_ea,
        )
    check(
        "Spectron server-animation artifact",
        spectron_server_animation_anchors["artifact"],
        "spectron_server_animation_manual_translation_anchors_20260826",
    )
    check("Spectron server-animation network", spectron_server_animation_anchors["network_contacted"], False)
    check("Spectron server-animation total", spectron_server_animation_anchors["summary"]["anchor_count"], 3)
    check("Spectron server-animation high confidence", spectron_server_animation_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron server-animation semantic overlap", spectron_server_animation_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron server-animation default targets", spectron_server_animation_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-lifecycle artifact",
        spectron_player_lifecycle_anchors["artifact"],
        "spectron_player_lifecycle_manual_translation_anchors_20260826",
    )
    check("Spectron player-lifecycle network", spectron_player_lifecycle_anchors["network_contacted"], False)
    check("Spectron player-lifecycle total", spectron_player_lifecycle_anchors["summary"]["anchor_count"], 2)
    check("Spectron player-lifecycle high confidence", spectron_player_lifecycle_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron player-lifecycle semantic overlap", spectron_player_lifecycle_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-lifecycle default targets", spectron_player_lifecycle_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-emoticon artifact",
        spectron_player_emoticon_anchors["artifact"],
        "spectron_player_emoticon_manual_translation_anchors_20260826",
    )
    check("Spectron player-emoticon network", spectron_player_emoticon_anchors["network_contacted"], False)
    check("Spectron player-emoticon total", spectron_player_emoticon_anchors["summary"]["anchor_count"], 2)
    check("Spectron player-emoticon high confidence", spectron_player_emoticon_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron player-emoticon semantic overlap", spectron_player_emoticon_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-emoticon default targets", spectron_player_emoticon_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-level-entry artifact",
        spectron_player_level_entry_anchors["artifact"],
        "spectron_player_level_entry_manual_translation_anchors_20260826",
    )
    check("Spectron player-level-entry network", spectron_player_level_entry_anchors["network_contacted"], False)
    check("Spectron player-level-entry total", spectron_player_level_entry_anchors["summary"]["anchor_count"], 2)
    check("Spectron player-level-entry high confidence", spectron_player_level_entry_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron player-level-entry semantic overlap", spectron_player_level_entry_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-level-entry default targets", spectron_player_level_entry_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-side-level artifact",
        spectron_player_side_level_anchors["artifact"],
        "spectron_player_side_level_manual_translation_anchors_20260826",
    )
    check("Spectron player-side-level network", spectron_player_side_level_anchors["network_contacted"], False)
    check("Spectron player-side-level total", spectron_player_side_level_anchors["summary"]["anchor_count"], 4)
    check("Spectron player-side-level high confidence", spectron_player_side_level_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron player-side-level semantic overlap", spectron_player_side_level_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-side-level default targets", spectron_player_side_level_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-map-position artifact",
        spectron_player_map_position_anchors["artifact"],
        "spectron_player_map_position_manual_translation_anchors_20260826",
    )
    check("Spectron player-map-position network", spectron_player_map_position_anchors["network_contacted"], False)
    check("Spectron player-map-position total", spectron_player_map_position_anchors["summary"]["anchor_count"], 2)
    check("Spectron player-map-position high confidence", spectron_player_map_position_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron player-map-position semantic overlap", spectron_player_map_position_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-map-position default targets", spectron_player_map_position_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-link-traversal artifact",
        spectron_player_link_traversal_anchors["artifact"],
        "spectron_player_link_traversal_manual_translation_anchors_20260826",
    )
    check("Spectron player-link-traversal network", spectron_player_link_traversal_anchors["network_contacted"], False)
    check("Spectron player-link-traversal total", spectron_player_link_traversal_anchors["summary"]["anchor_count"], 3)
    check("Spectron player-link-traversal high confidence", spectron_player_link_traversal_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron player-link-traversal semantic overlap", spectron_player_link_traversal_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-link-traversal default targets", spectron_player_link_traversal_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-weapon-state artifact",
        spectron_player_weapon_state_anchors["artifact"],
        "spectron_player_weapon_state_manual_translation_anchors_20260826",
    )
    check("Spectron player-weapon-state network", spectron_player_weapon_state_anchors["network_contacted"], False)
    check("Spectron player-weapon-state total", spectron_player_weapon_state_anchors["summary"]["anchor_count"], 4)
    check("Spectron player-weapon-state high confidence", spectron_player_weapon_state_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron player-weapon-state semantic overlap", spectron_player_weapon_state_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-weapon-state default targets", spectron_player_weapon_state_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-visual-setter artifact",
        spectron_player_visual_setter_anchors["artifact"],
        "spectron_player_visual_setter_manual_translation_anchors_20260826",
    )
    check("Spectron player-visual-setter network", spectron_player_visual_setter_anchors["network_contacted"], False)
    check("Spectron player-visual-setter total", spectron_player_visual_setter_anchors["summary"]["anchor_count"], 5)
    check("Spectron player-visual-setter high confidence", spectron_player_visual_setter_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron player-visual-setter semantic overlap", spectron_player_visual_setter_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-visual-setter default targets", spectron_player_visual_setter_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron player-movement artifact",
        spectron_player_movement_anchors["artifact"],
        "spectron_player_movement_manual_translation_anchors_20260826",
    )
    check("Spectron player-movement network", spectron_player_movement_anchors["network_contacted"], False)
    check("Spectron player-movement total", spectron_player_movement_anchors["summary"]["anchor_count"], 8)
    check("Spectron player-movement high confidence", spectron_player_movement_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron player-movement semantic overlap", spectron_player_movement_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-movement default targets", spectron_player_movement_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron server-player-state artifact",
        spectron_server_player_state_anchors["artifact"],
        "spectron_server_player_state_manual_translation_anchors_20260826",
    )
    check("Spectron server-player-state network", spectron_server_player_state_anchors["network_contacted"], False)
    check("Spectron server-player-state total", spectron_server_player_state_anchors["summary"]["anchor_count"], 6)
    check("Spectron server-player-state high confidence", spectron_server_player_state_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron server-player-state semantic overlap", spectron_server_player_state_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron server-player-state default targets", spectron_server_player_state_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron server-NPC-state artifact",
        spectron_server_npc_state_anchors["artifact"],
        "spectron_server_npc_state_manual_translation_anchors_20260826",
    )
    check("Spectron server-NPC-state network", spectron_server_npc_state_anchors["network_contacted"], False)
    check("Spectron server-NPC-state total", spectron_server_npc_state_anchors["summary"]["anchor_count"], 7)
    check("Spectron server-NPC-state high confidence", spectron_server_npc_state_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron server-NPC-state semantic overlap", spectron_server_npc_state_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron server-NPC-state default targets", spectron_server_npc_state_anchors["summary"]["target_default_name_count"], 1)
    check(
        "Spectron NPC accessor artifact",
        spectron_npc_accessor_anchors["artifact"],
        "spectron_npc_accessor_manual_translation_anchors_20260826",
    )
    check("Spectron NPC accessor network", spectron_npc_accessor_anchors["network_contacted"], False)
    check("Spectron NPC accessor total", spectron_npc_accessor_anchors["summary"]["anchor_count"], 17)
    check("Spectron NPC accessor high confidence", spectron_npc_accessor_anchors["summary"]["high_confidence_count"], 17)
    check("Spectron NPC accessor semantic overlap", spectron_npc_accessor_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron NPC accessor default targets", spectron_npc_accessor_anchors["summary"]["target_default_name_count"], 17)
    check(
        "Spectron NPC destructor artifact",
        spectron_npc_destructor_anchors["artifact"],
        "spectron_npc_destructor_manual_translation_anchors_20260826",
    )
    check("Spectron NPC destructor network", spectron_npc_destructor_anchors["network_contacted"], False)
    check("Spectron NPC destructor total", spectron_npc_destructor_anchors["summary"]["anchor_count"], 2)
    check("Spectron NPC destructor high confidence", spectron_npc_destructor_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron NPC destructor semantic overlap", spectron_npc_destructor_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron NPC destructor default targets", spectron_npc_destructor_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron server-level-property artifact",
        spectron_server_level_property_anchors["artifact"],
        "spectron_server_level_property_manual_translation_anchors_20260826",
    )
    check("Spectron server-level-property network", spectron_server_level_property_anchors["network_contacted"], False)
    check("Spectron server-level-property total", spectron_server_level_property_anchors["summary"]["anchor_count"], 8)
    check("Spectron server-level-property high confidence", spectron_server_level_property_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron server-level-property semantic overlap", spectron_server_level_property_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron server-level-property default targets", spectron_server_level_property_anchors["summary"]["target_default_name_count"], 8)
    check(
        "Spectron server-level-interaction artifact",
        spectron_server_level_interaction_anchors["artifact"],
        "spectron_server_level_interaction_manual_translation_anchors_20260826",
    )
    check("Spectron server-level-interaction network", spectron_server_level_interaction_anchors["network_contacted"], False)
    check("Spectron server-level-interaction total", spectron_server_level_interaction_anchors["summary"]["anchor_count"], 5)
    check("Spectron server-level-interaction high confidence", spectron_server_level_interaction_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron server-level-interaction semantic overlap", spectron_server_level_interaction_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron server-level-interaction default targets", spectron_server_level_interaction_anchors["summary"]["target_default_name_count"], 5)
    check(
        "Spectron server-level-lifecycle artifact",
        spectron_server_level_lifecycle_anchors["artifact"],
        "spectron_server_level_lifecycle_manual_translation_anchors_20260826",
    )
    check("Spectron server-level-lifecycle network", spectron_server_level_lifecycle_anchors["network_contacted"], False)
    check("Spectron server-level-lifecycle total", spectron_server_level_lifecycle_anchors["summary"]["anchor_count"], 7)
    check("Spectron server-level-lifecycle high confidence", spectron_server_level_lifecycle_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron server-level-lifecycle semantic overlap", spectron_server_level_lifecycle_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron server-level-lifecycle default targets", spectron_server_level_lifecycle_anchors["summary"]["target_default_name_count"], 3)
    check(
        "Spectron server-level-side-helpers artifact",
        spectron_server_level_side_helpers_anchors["artifact"],
        "spectron_server_level_side_helpers_manual_translation_anchors_20260826",
    )
    check("Spectron server-level-side-helpers network", spectron_server_level_side_helpers_anchors["network_contacted"], False)
    check("Spectron server-level-side-helpers total", spectron_server_level_side_helpers_anchors["summary"]["anchor_count"], 4)
    check("Spectron server-level-side-helpers high confidence", spectron_server_level_side_helpers_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron server-level-side-helpers semantic overlap", spectron_server_level_side_helpers_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron server-level-side-helpers default targets", spectron_server_level_side_helpers_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron server-level-storage artifact",
        spectron_server_level_storage_anchors["artifact"],
        "spectron_server_level_storage_manual_translation_anchors_20260826",
    )
    check("Spectron server-level-storage network", spectron_server_level_storage_anchors["network_contacted"], False)
    check("Spectron server-level-storage total", spectron_server_level_storage_anchors["summary"]["anchor_count"], 4)
    check("Spectron server-level-storage high confidence", spectron_server_level_storage_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron server-level-storage semantic overlap", spectron_server_level_storage_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron server-level-storage default targets", spectron_server_level_storage_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron hidden-testnpc artifact",
        spectron_hidden_testnpc_anchors["artifact"],
        "spectron_hidden_testnpc_manual_translation_anchor_20260826",
    )
    check("Spectron hidden-testnpc network", spectron_hidden_testnpc_anchors["network_contacted"], False)
    check("Spectron hidden-testnpc total", spectron_hidden_testnpc_anchors["summary"]["anchor_count"], 1)
    check("Spectron hidden-testnpc high confidence", spectron_hidden_testnpc_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron hidden-testnpc semantic overlap", spectron_hidden_testnpc_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron hidden-testnpc default targets", spectron_hidden_testnpc_anchors["summary"]["target_default_name_count"], 1)
    check("Spectron hidden-testnpc materialized boundary", spectron_hidden_testnpc_anchors["summary"]["target_boundary_materialized_count"], 1)
    check(
        "Spectron level-map-lookup artifact",
        spectron_level_map_lookup_anchors["artifact"],
        "spectron_level_map_lookup_manual_translation_anchors_20260826",
    )
    check("Spectron level-map-lookup network", spectron_level_map_lookup_anchors["network_contacted"], False)
    check("Spectron level-map-lookup total", spectron_level_map_lookup_anchors["summary"]["anchor_count"], 6)
    check("Spectron level-map-lookup high confidence", spectron_level_map_lookup_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron level-map-lookup semantic overlap", spectron_level_map_lookup_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron level-map-lookup default targets", spectron_level_map_lookup_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron Gani-constructor artifact",
        spectron_gani_constructor_anchors["artifact"],
        "spectron_gani_constructor_manual_translation_anchor_20260826",
    )
    check("Spectron Gani-constructor network", spectron_gani_constructor_anchors["network_contacted"], False)
    check("Spectron Gani-constructor total", spectron_gani_constructor_anchors["summary"]["anchor_count"], 1)
    check("Spectron Gani-constructor high confidence", spectron_gani_constructor_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron Gani-constructor semantic overlap", spectron_gani_constructor_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron Gani-constructor default targets", spectron_gani_constructor_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron Gani-helper artifact",
        spectron_gani_helper_anchors["artifact"],
        "spectron_gani_helper_manual_translation_anchors_20260826",
    )
    check("Spectron Gani-helper network", spectron_gani_helper_anchors["network_contacted"], False)
    check("Spectron Gani-helper total", spectron_gani_helper_anchors["summary"]["anchor_count"], 2)
    check("Spectron Gani-helper high confidence", spectron_gani_helper_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron Gani-helper semantic overlap", spectron_gani_helper_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron Gani-helper default targets", spectron_gani_helper_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron Gani-runtime artifact",
        spectron_gani_runtime_anchors["artifact"],
        "spectron_gani_runtime_manual_translation_anchors_20260826",
    )
    check("Spectron Gani-runtime network", spectron_gani_runtime_anchors["network_contacted"], False)
    check("Spectron Gani-runtime total", spectron_gani_runtime_anchors["summary"]["anchor_count"], 4)
    check("Spectron Gani-runtime high confidence", spectron_gani_runtime_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron Gani-runtime semantic overlap", spectron_gani_runtime_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron Gani-runtime default targets", spectron_gani_runtime_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron Gani-render artifact",
        spectron_gani_render_anchors["artifact"],
        "spectron_gani_render_manual_translation_anchors_20260826",
    )
    check("Spectron Gani-render network", spectron_gani_render_anchors["network_contacted"], False)
    check("Spectron Gani-render total", spectron_gani_render_anchors["summary"]["anchor_count"], 3)
    check("Spectron Gani-render high confidence", spectron_gani_render_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron Gani-render semantic overlap", spectron_gani_render_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron Gani-render default targets", spectron_gani_render_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron Gani-frame-playback artifact",
        spectron_gani_frame_playback_anchors["artifact"],
        "spectron_gani_frame_playback_manual_translation_anchors_20260826",
    )
    check("Spectron Gani-frame-playback network", spectron_gani_frame_playback_anchors["network_contacted"], False)
    check("Spectron Gani-frame-playback total", spectron_gani_frame_playback_anchors["summary"]["anchor_count"], 2)
    check("Spectron Gani-frame-playback high confidence", spectron_gani_frame_playback_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron Gani-frame-playback semantic overlap", spectron_gani_frame_playback_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron Gani-frame-playback default targets", spectron_gani_frame_playback_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron Gani-lifecycle artifact",
        spectron_gani_lifecycle_anchors["artifact"],
        "spectron_gani_lifecycle_manual_translation_anchors_20260826",
    )
    check("Spectron Gani-lifecycle network", spectron_gani_lifecycle_anchors["network_contacted"], False)
    check("Spectron Gani-lifecycle total", spectron_gani_lifecycle_anchors["summary"]["anchor_count"], 50)
    check("Spectron Gani-lifecycle high confidence", spectron_gani_lifecycle_anchors["summary"]["high_confidence_count"], 50)
    check("Spectron Gani-lifecycle semantic overlap", spectron_gani_lifecycle_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron Gani-lifecycle default targets", spectron_gani_lifecycle_anchors["summary"]["target_default_name_count"], 9)
    check(
        "Spectron TPlayer-core artifact",
        spectron_tplayer_core_anchors["artifact"],
        "spectron_tplayer_core_manual_translation_anchors_20260826",
    )
    check("Spectron TPlayer-core network", spectron_tplayer_core_anchors["network_contacted"], False)
    check("Spectron TPlayer-core total", spectron_tplayer_core_anchors["summary"]["anchor_count"], 2)
    check("Spectron TPlayer-core high confidence", spectron_tplayer_core_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron TPlayer-core semantic overlap", spectron_tplayer_core_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TPlayer-core default targets", spectron_tplayer_core_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron resource-parser artifact",
        spectron_resource_parser_anchors["artifact"],
        "spectron_resource_parser_manual_translation_anchors_20260826",
    )
    check("Spectron resource-parser network", spectron_resource_parser_anchors["network_contacted"], False)
    check("Spectron resource-parser total", spectron_resource_parser_anchors["summary"]["anchor_count"], 3)
    check("Spectron resource-parser high confidence", spectron_resource_parser_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron resource-parser semantic overlap", spectron_resource_parser_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron resource-parser default targets", spectron_resource_parser_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron static-utility artifact",
        spectron_static_utility_anchors["artifact"],
        "spectron_static_utility_manual_translation_anchors_20260826",
    )
    check("Spectron static-utility network", spectron_static_utility_anchors["network_contacted"], False)
    check("Spectron static-utility total", spectron_static_utility_anchors["summary"]["anchor_count"], 5)
    check("Spectron static-utility high confidence", spectron_static_utility_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron static-utility semantic overlap", spectron_static_utility_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron static-utility default targets", spectron_static_utility_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron font-bitmap artifact",
        spectron_font_bitmap_anchors["artifact"],
        "spectron_font_bitmap_manual_translation_anchors_20260826",
    )
    check("Spectron font-bitmap network", spectron_font_bitmap_anchors["network_contacted"], False)
    check("Spectron font-bitmap total", spectron_font_bitmap_anchors["summary"]["anchor_count"], 4)
    check("Spectron font-bitmap high confidence", spectron_font_bitmap_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron font-bitmap semantic overlap", spectron_font_bitmap_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron font-bitmap default targets", spectron_font_bitmap_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron MNG-animation artifact",
        spectron_mng_animation_anchors["artifact"],
        "spectron_mng_animation_manual_translation_anchor_20260826",
    )
    check("Spectron MNG-animation network", spectron_mng_animation_anchors["network_contacted"], False)
    check("Spectron MNG-animation total", spectron_mng_animation_anchors["summary"]["anchor_count"], 1)
    check("Spectron MNG-animation high confidence", spectron_mng_animation_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron MNG-animation semantic overlap", spectron_mng_animation_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron MNG-animation default targets", spectron_mng_animation_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-machine-tail artifact",
        spectron_script_machine_tail_anchors["artifact"],
        "spectron_script_machine_tail_manual_translation_anchors_20260826",
    )
    check("Spectron script-machine-tail network", spectron_script_machine_tail_anchors["network_contacted"], False)
    check("Spectron script-machine-tail total", spectron_script_machine_tail_anchors["summary"]["anchor_count"], 2)
    check("Spectron script-machine-tail high confidence", spectron_script_machine_tail_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron script-machine-tail semantic overlap", spectron_script_machine_tail_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-machine-tail default targets", spectron_script_machine_tail_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron script-stream-profile artifact",
        spectron_script_stream_profile_anchors["artifact"],
        "spectron_script_stream_profile_manual_translation_anchors_20260826",
    )
    check("Spectron script-stream-profile network", spectron_script_stream_profile_anchors["network_contacted"], False)
    check("Spectron script-stream-profile total", spectron_script_stream_profile_anchors["summary"]["anchor_count"], 2)
    check("Spectron script-stream-profile high confidence", spectron_script_stream_profile_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron script-stream-profile semantic overlap", spectron_script_stream_profile_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron script-stream-profile default targets", spectron_script_stream_profile_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron animation-lexer artifact",
        spectron_ani_lexer_anchors["artifact"],
        "spectron_ani_lexer_fatal_manual_translation_anchor_20260826",
    )
    check("Spectron animation-lexer network", spectron_ani_lexer_anchors["network_contacted"], False)
    check("Spectron animation-lexer total", spectron_ani_lexer_anchors["summary"]["anchor_count"], 1)
    check("Spectron animation-lexer high confidence", spectron_ani_lexer_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron animation-lexer semantic overlap", spectron_ani_lexer_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron animation-lexer default targets", spectron_ani_lexer_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron number-array-string artifact",
        spectron_number_array_string_anchors["artifact"],
        "spectron_number_array_string_manual_translation_anchors_20260826",
    )
    check("Spectron number-array-string network", spectron_number_array_string_anchors["network_contacted"], False)
    check("Spectron number-array-string total", spectron_number_array_string_anchors["summary"]["anchor_count"], 8)
    check("Spectron number-array-string high confidence", spectron_number_array_string_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron number-array-string semantic overlap", spectron_number_array_string_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron number-array-string default targets", spectron_number_array_string_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron client-environment-clock artifact",
        spectron_client_environment_clock_anchors["artifact"],
        "spectron_client_environment_clock_manual_translation_anchors_20260826",
    )
    check("Spectron client-environment-clock network", spectron_client_environment_clock_anchors["network_contacted"], False)
    check("Spectron client-environment-clock total", spectron_client_environment_clock_anchors["summary"]["anchor_count"], 2)
    check("Spectron client-environment-clock high confidence", spectron_client_environment_clock_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron client-environment-clock semantic overlap", spectron_client_environment_clock_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron client-environment-clock default targets", spectron_client_environment_clock_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron client-var-core artifact",
        spectron_client_var_core_anchors["artifact"],
        "spectron_client_var_core_manual_translation_anchors_20260826",
    )
    check("Spectron client-var-core network", spectron_client_var_core_anchors["network_contacted"], False)
    check("Spectron client-var-core total", spectron_client_var_core_anchors["summary"]["anchor_count"], 3)
    check("Spectron client-var-core high confidence", spectron_client_var_core_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron client-var-core semantic overlap", spectron_client_var_core_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron client-var-core default targets", spectron_client_var_core_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron TStringList comma artifact",
        spectron_tstringlist_comma_anchors["artifact"],
        "spectron_tstringlist_comma_manual_translation_anchors_20260826",
    )
    check("Spectron TStringList comma network", spectron_tstringlist_comma_anchors["network_contacted"], False)
    check("Spectron TStringList comma total", spectron_tstringlist_comma_anchors["summary"]["anchor_count"], 4)
    check("Spectron TStringList comma high confidence", spectron_tstringlist_comma_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron TStringList comma semantic overlap", spectron_tstringlist_comma_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TStringList comma default targets", spectron_tstringlist_comma_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron extended TStringList artifact",
        spectron_tstringlist_extended_anchors["artifact"],
        "spectron_tstringlist_extended_manual_translation_anchors_20260826",
    )
    check("Spectron extended TStringList network", spectron_tstringlist_extended_anchors["network_contacted"], False)
    check("Spectron extended TStringList total", spectron_tstringlist_extended_anchors["summary"]["anchor_count"], 7)
    check("Spectron extended TStringList high confidence", spectron_tstringlist_extended_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron extended TStringList semantic overlap", spectron_tstringlist_extended_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron extended TStringList default targets", spectron_tstringlist_extended_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron hash-family artifact",
        spectron_hash_family_anchors["artifact"],
        "spectron_hash_family_manual_translation_anchors_20260826",
    )
    check("Spectron hash-family network", spectron_hash_family_anchors["network_contacted"], False)
    check("Spectron hash-family total", spectron_hash_family_anchors["summary"]["anchor_count"], 9)
    check("Spectron hash-family high confidence", spectron_hash_family_anchors["summary"]["high_confidence_count"], 9)
    check("Spectron hash-family semantic overlap", spectron_hash_family_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron hash-family default targets", spectron_hash_family_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron options artifact",
        spectron_options_anchors["artifact"],
        "spectron_options_manual_translation_anchors_20260826",
    )
    check("Spectron options network", spectron_options_anchors["network_contacted"], False)
    check("Spectron options total", spectron_options_anchors["summary"]["anchor_count"], 7)
    check("Spectron options high confidence", spectron_options_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron options semantic overlap", spectron_options_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron options default targets", spectron_options_anchors["summary"]["target_default_name_count"], 2)
    check(
        "Spectron texture artifact",
        spectron_texture_anchors["artifact"],
        "spectron_texture_manual_translation_anchors_20260826",
    )
    check("Spectron texture network", spectron_texture_anchors["network_contacted"], False)
    check("Spectron texture total", spectron_texture_anchors["summary"]["anchor_count"], 10)
    check("Spectron texture high confidence", spectron_texture_anchors["summary"]["high_confidence_count"], 10)
    check("Spectron texture semantic overlap", spectron_texture_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron texture default targets", spectron_texture_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron drawing-panel texture artifact",
        spectron_drawing_panel_texture_anchors["artifact"],
        "spectron_drawing_panel_texture_manual_translation_anchors_20260826",
    )
    check("Spectron drawing-panel texture network", spectron_drawing_panel_texture_anchors["network_contacted"], False)
    check("Spectron drawing-panel texture total", spectron_drawing_panel_texture_anchors["summary"]["anchor_count"], 5)
    check("Spectron drawing-panel texture high confidence", spectron_drawing_panel_texture_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron drawing-panel texture semantic overlap", spectron_drawing_panel_texture_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron drawing-panel texture default targets", spectron_drawing_panel_texture_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron draw-texture artifact",
        spectron_draw_texture_anchors["artifact"],
        "spectron_draw_texture_manual_translation_anchors_20260826",
    )
    check("Spectron draw-texture network", spectron_draw_texture_anchors["network_contacted"], False)
    check("Spectron draw-texture total", spectron_draw_texture_anchors["summary"]["anchor_count"], 4)
    check("Spectron draw-texture high confidence", spectron_draw_texture_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron draw-texture semantic overlap", spectron_draw_texture_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron draw-texture default targets", spectron_draw_texture_anchors["summary"]["target_default_name_count"], 1)
    check(
        "Spectron bitmap-array holder artifact",
        spectron_bitmap_array_holder_anchors["artifact"],
        "spectron_bitmap_array_holder_manual_translation_anchors_20260826",
    )
    check("Spectron bitmap-array holder network", spectron_bitmap_array_holder_anchors["network_contacted"], False)
    check("Spectron bitmap-array holder total", spectron_bitmap_array_holder_anchors["summary"]["anchor_count"], 5)
    check("Spectron bitmap-array holder high confidence", spectron_bitmap_array_holder_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron bitmap-array holder semantic overlap", spectron_bitmap_array_holder_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron bitmap-array holder default targets", spectron_bitmap_array_holder_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron color-manager artifact",
        spectron_color_manager_anchors["artifact"],
        "spectron_color_manager_manual_translation_anchors_20260826",
    )
    check("Spectron color-manager network", spectron_color_manager_anchors["network_contacted"], False)
    check("Spectron color-manager total", spectron_color_manager_anchors["summary"]["anchor_count"], 5)
    check("Spectron color-manager high confidence", spectron_color_manager_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron color-manager semantic overlap", spectron_color_manager_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron color-manager default targets", spectron_color_manager_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron font-runtime artifact",
        spectron_font_runtime_anchors["artifact"],
        "spectron_font_runtime_manual_translation_anchors_20260826",
    )
    check("Spectron font-runtime network", spectron_font_runtime_anchors["network_contacted"], False)
    check("Spectron font-runtime total", spectron_font_runtime_anchors["summary"]["anchor_count"], 6)
    check("Spectron font-runtime high confidence", spectron_font_runtime_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron font-runtime semantic overlap", spectron_font_runtime_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron font-runtime default targets", spectron_font_runtime_anchors["summary"]["target_default_name_count"], 1)
    check(
        "Spectron window-input artifact",
        spectron_window_input_anchors["artifact"],
        "spectron_window_input_manual_translation_anchors_20260826",
    )
    check("Spectron window-input network", spectron_window_input_anchors["network_contacted"], False)
    check("Spectron window-input total", spectron_window_input_anchors["summary"]["anchor_count"], 2)
    check("Spectron window-input high confidence", spectron_window_input_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron window-input semantic overlap", spectron_window_input_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron window-input default targets", spectron_window_input_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron drawing-panel residual artifact",
        spectron_drawing_panel_residual_anchors["artifact"],
        "spectron_drawing_panel_residual_manual_translation_anchors_20260826",
    )
    check("Spectron drawing-panel residual network", spectron_drawing_panel_residual_anchors["network_contacted"], False)
    check("Spectron drawing-panel residual total", spectron_drawing_panel_residual_anchors["summary"]["anchor_count"], 6)
    check("Spectron drawing-panel residual high confidence", spectron_drawing_panel_residual_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron drawing-panel residual semantic overlap", spectron_drawing_panel_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron drawing-panel residual default targets", spectron_drawing_panel_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron image/html artifact",
        spectron_image_html_anchors["artifact"],
        "spectron_image_html_manual_translation_anchors_20260826",
    )
    check("Spectron image/html network", spectron_image_html_anchors["network_contacted"], False)
    check("Spectron image/html total", spectron_image_html_anchors["summary"]["anchor_count"], 4)
    check("Spectron image/html high confidence", spectron_image_html_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron image/html semantic overlap", spectron_image_html_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron image/html default targets", spectron_image_html_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron panel/bitmap artifact",
        spectron_panel_bitmap_anchors["artifact"],
        "spectron_panel_bitmap_manual_translation_anchors_20260826",
    )
    check("Spectron panel/bitmap network", spectron_panel_bitmap_anchors["network_contacted"], False)
    check("Spectron panel/bitmap total", spectron_panel_bitmap_anchors["summary"]["anchor_count"], 4)
    check("Spectron panel/bitmap high confidence", spectron_panel_bitmap_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron panel/bitmap semantic overlap", spectron_panel_bitmap_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron panel/bitmap default targets", spectron_panel_bitmap_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron GIF decoder artifact",
        spectron_gif_decoder_anchors["artifact"],
        "spectron_gif_decoder_manual_translation_anchor_20260826",
    )
    check("Spectron GIF decoder network", spectron_gif_decoder_anchors["network_contacted"], False)
    check("Spectron GIF decoder total", spectron_gif_decoder_anchors["summary"]["anchor_count"], 1)
    check("Spectron GIF decoder high confidence", spectron_gif_decoder_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron GIF decoder semantic overlap", spectron_gif_decoder_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GIF decoder default targets", spectron_gif_decoder_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron window residual artifact",
        spectron_window_residual_anchors["artifact"],
        "spectron_window_residual_manual_translation_anchors_20260826",
    )
    check("Spectron window residual network", spectron_window_residual_anchors["network_contacted"], False)
    check("Spectron window residual total", spectron_window_residual_anchors["summary"]["anchor_count"], 2)
    check("Spectron window residual high confidence", spectron_window_residual_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron window residual semantic overlap", spectron_window_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron window residual default targets", spectron_window_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron sound-runtime artifact",
        spectron_sound_runtime_anchors["artifact"],
        "spectron_sound_runtime_manual_translation_anchors_20260826",
    )
    check("Spectron sound-runtime network", spectron_sound_runtime_anchors["network_contacted"], False)
    check("Spectron sound-runtime total", spectron_sound_runtime_anchors["summary"]["anchor_count"], 3)
    check("Spectron sound-runtime high confidence", spectron_sound_runtime_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron sound-runtime semantic overlap", spectron_sound_runtime_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron sound-runtime default targets", spectron_sound_runtime_anchors["summary"]["target_default_name_count"], 1)
    check(
        "Spectron pixelbuffer residual artifact",
        spectron_pixelbuffer_residual_anchors["artifact"],
        "spectron_pixelbuffer_residual_manual_translation_anchors_20260826",
    )
    check("Spectron pixelbuffer residual network", spectron_pixelbuffer_residual_anchors["network_contacted"], False)
    check("Spectron pixelbuffer residual total", spectron_pixelbuffer_residual_anchors["summary"]["anchor_count"], 10)
    check("Spectron pixelbuffer residual high confidence", spectron_pixelbuffer_residual_anchors["summary"]["high_confidence_count"], 10)
    check("Spectron pixelbuffer residual semantic overlap", spectron_pixelbuffer_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron pixelbuffer residual default targets", spectron_pixelbuffer_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron pixelbuffer bitmap-lifecycle artifact",
        spectron_pixelbuffer_bitmap_lifecycle_anchors["artifact"],
        "spectron_pixelbuffer_bitmap_lifecycle_correction_anchors_20260826",
    )
    check("Spectron pixelbuffer bitmap-lifecycle network", spectron_pixelbuffer_bitmap_lifecycle_anchors["network_contacted"], False)
    check("Spectron pixelbuffer bitmap-lifecycle total", spectron_pixelbuffer_bitmap_lifecycle_anchors["summary"]["anchor_count"], 4)
    check("Spectron pixelbuffer bitmap-lifecycle high confidence", spectron_pixelbuffer_bitmap_lifecycle_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron pixelbuffer bitmap-lifecycle semantic overlap", spectron_pixelbuffer_bitmap_lifecycle_anchors["summary"]["already_in_semantic_map"], 1)
    check("Spectron pixelbuffer bitmap-lifecycle default targets", spectron_pixelbuffer_bitmap_lifecycle_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron pixelbuffer bitmap-lifecycle superseded matches", spectron_pixelbuffer_bitmap_lifecycle_anchors["summary"]["superseded_medium_match_count"], 1)
    check(
        "Spectron animation-palette residual artifact",
        spectron_animation_palette_residual_anchors["artifact"],
        "spectron_animation_palette_residual_manual_translation_anchors_20260826",
    )
    check("Spectron animation-palette residual network", spectron_animation_palette_residual_anchors["network_contacted"], False)
    check("Spectron animation-palette residual total", spectron_animation_palette_residual_anchors["summary"]["anchor_count"], 4)
    check("Spectron animation-palette residual high confidence", spectron_animation_palette_residual_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron animation-palette residual semantic overlap", spectron_animation_palette_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron animation-palette residual default targets", spectron_animation_palette_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron panel virtual renderer residual artifact",
        spectron_panel_virtual_renderer_residual_anchors["artifact"],
        "spectron_panel_virtual_renderer_residual_manual_translation_anchors_20260826",
    )
    check("Spectron panel virtual renderer residual network", spectron_panel_virtual_renderer_residual_anchors["network_contacted"], False)
    check("Spectron panel virtual renderer residual total", spectron_panel_virtual_renderer_residual_anchors["summary"]["anchor_count"], 23)
    check("Spectron panel virtual renderer residual high confidence", spectron_panel_virtual_renderer_residual_anchors["summary"]["high_confidence_count"], 23)
    check("Spectron panel virtual renderer residual semantic overlap", spectron_panel_virtual_renderer_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron panel virtual renderer residual default targets", spectron_panel_virtual_renderer_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron panel virtual renderer residual target-only gap", spectron_panel_virtual_renderer_residual_anchors["context"]["target_only_inserted_method"]["spectron_ea"], "0x100980")
    check(
        "Spectron dummy-panel residual artifact",
        spectron_dummy_panel_residual_anchors["artifact"],
        "spectron_dummy_panel_residual_manual_translation_anchors_20260826",
    )
    check("Spectron dummy-panel residual network", spectron_dummy_panel_residual_anchors["network_contacted"], False)
    check("Spectron dummy-panel residual total", spectron_dummy_panel_residual_anchors["summary"]["anchor_count"], 14)
    check("Spectron dummy-panel residual high confidence", spectron_dummy_panel_residual_anchors["summary"]["high_confidence_count"], 14)
    check("Spectron dummy-panel residual semantic overlap", spectron_dummy_panel_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron dummy-panel residual default targets", spectron_dummy_panel_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron screen-panel renderer residual artifact",
        spectron_screen_panel_renderer_residual_anchors["artifact"],
        "spectron_screen_panel_renderer_residual_manual_translation_anchors_20260826",
    )
    check("Spectron screen-panel renderer residual network", spectron_screen_panel_renderer_residual_anchors["network_contacted"], False)
    check("Spectron screen-panel renderer residual total", spectron_screen_panel_renderer_residual_anchors["summary"]["anchor_count"], 10)
    check("Spectron screen-panel renderer residual high confidence", spectron_screen_panel_renderer_residual_anchors["summary"]["high_confidence_count"], 10)
    check("Spectron screen-panel renderer residual semantic overlap", spectron_screen_panel_renderer_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron screen-panel renderer residual default targets", spectron_screen_panel_renderer_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron screen-panel window GLES residual artifact",
        spectron_screen_panel_window_gles_residual_anchors["artifact"],
        "spectron_screen_panel_window_gles_residual_manual_translation_anchors_20260826",
    )
    check("Spectron screen-panel window GLES residual network", spectron_screen_panel_window_gles_residual_anchors["network_contacted"], False)
    check("Spectron screen-panel window GLES residual total", spectron_screen_panel_window_gles_residual_anchors["summary"]["anchor_count"], 7)
    check("Spectron screen-panel window GLES residual high confidence", spectron_screen_panel_window_gles_residual_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron screen-panel window GLES residual semantic overlap", spectron_screen_panel_window_gles_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron screen-panel window GLES residual default targets", spectron_screen_panel_window_gles_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron font-manager font residual artifact",
        spectron_font_manager_font_residual_anchors["artifact"],
        "spectron_font_manager_font_residual_manual_translation_anchors_20260826",
    )
    check("Spectron font-manager font residual network", spectron_font_manager_font_residual_anchors["network_contacted"], False)
    check("Spectron font-manager font residual total", spectron_font_manager_font_residual_anchors["summary"]["anchor_count"], 9)
    check("Spectron font-manager font residual high confidence", spectron_font_manager_font_residual_anchors["summary"]["high_confidence_count"], 9)
    check("Spectron font-manager font residual semantic overlap", spectron_font_manager_font_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron font-manager font residual default targets", spectron_font_manager_font_residual_anchors["summary"]["target_default_name_count"], 0)
    check(
        "Spectron font-options font-data residual artifact",
        spectron_font_options_font_data_residual_anchors["artifact"],
        "spectron_font_options_font_data_residual_manual_translation_anchors_20260826",
    )
    check("Spectron font-options font-data residual network", spectron_font_options_font_data_residual_anchors["network_contacted"], False)
    check("Spectron font-options font-data residual total", spectron_font_options_font_data_residual_anchors["summary"]["anchor_count"], 16)
    check("Spectron font-options font-data residual high confidence", spectron_font_options_font_data_residual_anchors["summary"]["high_confidence_count"], 16)
    check("Spectron font-options font-data residual semantic overlap", spectron_font_options_font_data_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron font-options font-data residual default targets", spectron_font_options_font_data_residual_anchors["summary"]["target_default_name_count"], 6)
    check(
        "Spectron GUI control profile accessor artifact",
        spectron_gui_control_profile_accessor_anchors["artifact"],
        "spectron_gui_control_profile_accessor_manual_translation_anchors_20260826",
    )
    check("Spectron GUI control profile accessor network", spectron_gui_control_profile_accessor_anchors["network_contacted"], False)
    check("Spectron GUI control profile accessor total", spectron_gui_control_profile_accessor_anchors["summary"]["anchor_count"], 89)
    check("Spectron GUI control profile accessor high confidence", spectron_gui_control_profile_accessor_anchors["summary"]["high_confidence_count"], 89)
    check("Spectron GUI control profile accessor semantic overlap", spectron_gui_control_profile_accessor_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GUI control profile accessor default targets", spectron_gui_control_profile_accessor_anchors["summary"]["target_default_name_count"], 88)
    check(
        "Spectron GUI control profile destructor artifact",
        spectron_gui_control_profile_destructor_anchors["artifact"],
        "spectron_gui_control_profile_destructor_manual_translation_anchors_20260826",
    )
    check("Spectron GUI control profile destructor network", spectron_gui_control_profile_destructor_anchors["network_contacted"], False)
    check("Spectron GUI control profile destructor total", spectron_gui_control_profile_destructor_anchors["summary"]["anchor_count"], 6)
    check("Spectron GUI control profile destructor high confidence", spectron_gui_control_profile_destructor_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron GUI control profile destructor semantic overlap", spectron_gui_control_profile_destructor_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GUI control profile destructor default targets", spectron_gui_control_profile_destructor_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron GUI control profile destructor exact-shape count", spectron_gui_control_profile_destructor_anchors["summary"]["exact_shape_anchor_count"], 4)
    check("Spectron GUI control profile destructor layout-change count", spectron_gui_control_profile_destructor_anchors["summary"]["layout_change_anchor_count"], 2)
    check(
        "Spectron GuiControl property residual artifact",
        spectron_guicontrol_property_residual_anchors["artifact"],
        "spectron_guicontrol_property_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GuiControl property residual network", spectron_guicontrol_property_residual_anchors["network_contacted"], False)
    check("Spectron GuiControl property residual total", spectron_guicontrol_property_residual_anchors["summary"]["anchor_count"], 61)
    check("Spectron GuiControl property residual high confidence", spectron_guicontrol_property_residual_anchors["summary"]["high_confidence_count"], 61)
    check("Spectron GuiControl property residual semantic overlap", spectron_guicontrol_property_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GuiControl property residual default targets", spectron_guicontrol_property_residual_anchors["summary"]["target_default_name_count"], 61)
    check("Spectron GuiControl property residual exact-shape count", spectron_guicontrol_property_residual_anchors["summary"]["exact_shape_anchor_count"], 61)
    check(
        "Spectron GuiControl virtual residual artifact",
        spectron_guicontrol_virtual_residual_anchors["artifact"],
        "spectron_guicontrol_virtual_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GuiControl virtual residual network", spectron_guicontrol_virtual_residual_anchors["network_contacted"], False)
    check("Spectron GuiControl virtual residual total", spectron_guicontrol_virtual_residual_anchors["summary"]["anchor_count"], 13)
    check("Spectron GuiControl virtual residual high confidence", spectron_guicontrol_virtual_residual_anchors["summary"]["high_confidence_count"], 13)
    check("Spectron GuiControl virtual residual semantic overlap", spectron_guicontrol_virtual_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GuiControl virtual residual default targets", spectron_guicontrol_virtual_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron GuiControl virtual residual exact-shape count", spectron_guicontrol_virtual_residual_anchors["summary"]["exact_shape_anchor_count"], 13)
    check(
        "Spectron GuiControl event and sizing residual artifact",
        spectron_guicontrol_event_sizing_residual_anchors["artifact"],
        "spectron_guicontrol_event_sizing_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GuiControl event and sizing residual network", spectron_guicontrol_event_sizing_residual_anchors["network_contacted"], False)
    check("Spectron GuiControl event and sizing residual total", spectron_guicontrol_event_sizing_residual_anchors["summary"]["anchor_count"], 8)
    check("Spectron GuiControl event and sizing residual high confidence", spectron_guicontrol_event_sizing_residual_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron GuiControl event and sizing residual semantic overlap", spectron_guicontrol_event_sizing_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GuiControl event and sizing residual default targets", spectron_guicontrol_event_sizing_residual_anchors["summary"]["target_default_name_count"], 3)
    check("Spectron GuiControl event and sizing residual exact-shape count", spectron_guicontrol_event_sizing_residual_anchors["summary"]["exact_shape_anchor_count"], 8)
    check(
        "Spectron GuiControl style and bounds residual artifact",
        spectron_guicontrol_style_bounds_residual_anchors["artifact"],
        "spectron_guicontrol_style_bounds_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GuiControl style and bounds residual network", spectron_guicontrol_style_bounds_residual_anchors["network_contacted"], False)
    check("Spectron GuiControl style and bounds residual total", spectron_guicontrol_style_bounds_residual_anchors["summary"]["anchor_count"], 12)
    check("Spectron GuiControl style and bounds residual high confidence", spectron_guicontrol_style_bounds_residual_anchors["summary"]["high_confidence_count"], 12)
    check("Spectron GuiControl style and bounds residual semantic overlap", spectron_guicontrol_style_bounds_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GuiControl style and bounds residual default targets", spectron_guicontrol_style_bounds_residual_anchors["summary"]["target_default_name_count"], 12)
    check("Spectron GuiControl style and bounds residual exact-shape count", spectron_guicontrol_style_bounds_residual_anchors["summary"]["exact_shape_anchor_count"], 11)
    check("Spectron GuiControl style and bounds residual layout-change count", spectron_guicontrol_style_bounds_residual_anchors["summary"]["layout_change_anchor_count"], 1)
    check(
        "Spectron GuiControl event dispatch residual artifact",
        spectron_guicontrol_event_dispatch_residual_anchors["artifact"],
        "spectron_guicontrol_event_dispatch_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GuiControl event dispatch residual network", spectron_guicontrol_event_dispatch_residual_anchors["network_contacted"], False)
    check("Spectron GuiControl event dispatch residual total", spectron_guicontrol_event_dispatch_residual_anchors["summary"]["anchor_count"], 8)
    check("Spectron GuiControl event dispatch residual high confidence", spectron_guicontrol_event_dispatch_residual_anchors["summary"]["high_confidence_count"], 8)
    check("Spectron GuiControl event dispatch residual semantic overlap", spectron_guicontrol_event_dispatch_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GuiControl event dispatch residual default targets", spectron_guicontrol_event_dispatch_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron GuiControl event dispatch residual exact-shape count", spectron_guicontrol_event_dispatch_residual_anchors["summary"]["exact_shape_anchor_count"], 2)
    check("Spectron GuiControl event dispatch residual layout-change count", spectron_guicontrol_event_dispatch_residual_anchors["summary"]["layout_change_anchor_count"], 6)
    check(
        "Spectron GuiControl initialization residual artifact",
        spectron_guicontrol_initialization_residual_anchors["artifact"],
        "spectron_guicontrol_initialization_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GuiControl initialization residual network", spectron_guicontrol_initialization_residual_anchors["network_contacted"], False)
    check("Spectron GuiControl initialization residual total", spectron_guicontrol_initialization_residual_anchors["summary"]["anchor_count"], 2)
    check("Spectron GuiControl initialization residual high confidence", spectron_guicontrol_initialization_residual_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron GuiControl initialization residual semantic overlap", spectron_guicontrol_initialization_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GuiControl initialization residual default targets", spectron_guicontrol_initialization_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron GuiControl initialization residual exact-shape count", spectron_guicontrol_initialization_residual_anchors["summary"]["exact_shape_anchor_count"], 0)
    check("Spectron GuiControl initialization residual layout-change count", spectron_guicontrol_initialization_residual_anchors["summary"]["layout_change_anchor_count"], 2)
    check(
        "Spectron GuiControl create residual artifact",
        spectron_guicontrol_create_residual_anchors["artifact"],
        "spectron_guicontrol_create_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GuiControl create residual network", spectron_guicontrol_create_residual_anchors["network_contacted"], False)
    check("Spectron GuiControl create residual total", spectron_guicontrol_create_residual_anchors["summary"]["anchor_count"], 1)
    check("Spectron GuiControl create residual high confidence", spectron_guicontrol_create_residual_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron GuiControl create residual semantic overlap", spectron_guicontrol_create_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GuiControl create residual default targets", spectron_guicontrol_create_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron GuiControl create residual exact-shape count", spectron_guicontrol_create_residual_anchors["summary"]["exact_shape_anchor_count"], 1)
    check("Spectron GuiControl create residual layout-change count", spectron_guicontrol_create_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check(
        "Spectron TSocket accessor residual artifact",
        spectron_tsocket_accessor_residual_anchors["artifact"],
        "spectron_tsocket_accessor_residual_manual_translation_anchors_20260826",
    )
    check("Spectron TSocket accessor residual network", spectron_tsocket_accessor_residual_anchors["network_contacted"], False)
    check("Spectron TSocket accessor residual total", spectron_tsocket_accessor_residual_anchors["summary"]["anchor_count"], 19)
    check("Spectron TSocket accessor residual high confidence", spectron_tsocket_accessor_residual_anchors["summary"]["high_confidence_count"], 19)
    check("Spectron TSocket accessor residual semantic overlap", spectron_tsocket_accessor_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TSocket accessor residual default targets", spectron_tsocket_accessor_residual_anchors["summary"]["target_default_name_count"], 17)
    check("Spectron TSocket accessor residual exact-shape count", spectron_tsocket_accessor_residual_anchors["summary"]["exact_shape_anchor_count"], 18)
    check("Spectron TSocket accessor residual layout-change count", spectron_tsocket_accessor_residual_anchors["summary"]["layout_change_anchor_count"], 1)
    check(
        "Spectron TSocket SSL residual artifact",
        spectron_tsocket_ssl_residual_anchors["artifact"],
        "spectron_tsocket_ssl_residual_manual_translation_anchors_20260826",
    )
    check("Spectron TSocket SSL residual network", spectron_tsocket_ssl_residual_anchors["network_contacted"], False)
    check("Spectron TSocket SSL residual total", spectron_tsocket_ssl_residual_anchors["summary"]["anchor_count"], 4)
    check("Spectron TSocket SSL residual high confidence", spectron_tsocket_ssl_residual_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron TSocket SSL residual semantic overlap", spectron_tsocket_ssl_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TSocket SSL residual default targets", spectron_tsocket_ssl_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron TSocket SSL residual exact-shape count", spectron_tsocket_ssl_residual_anchors["summary"]["exact_shape_anchor_count"], 4)
    check("Spectron TSocket SSL residual layout-change count", spectron_tsocket_ssl_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check(
        "Spectron TSocket receive residual artifact",
        spectron_tsocket_receive_residual_anchors["artifact"],
        "spectron_tsocket_receive_residual_manual_translation_anchors_20260826",
    )
    check("Spectron TSocket receive residual network", spectron_tsocket_receive_residual_anchors["network_contacted"], False)
    check("Spectron TSocket receive residual total", spectron_tsocket_receive_residual_anchors["summary"]["anchor_count"], 2)
    check("Spectron TSocket receive residual high confidence", spectron_tsocket_receive_residual_anchors["summary"]["high_confidence_count"], 2)
    check("Spectron TSocket receive residual semantic overlap", spectron_tsocket_receive_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TSocket receive residual default targets", spectron_tsocket_receive_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron TSocket receive residual exact-shape count", spectron_tsocket_receive_residual_anchors["summary"]["exact_shape_anchor_count"], 0)
    check("Spectron TSocket receive residual layout-change count", spectron_tsocket_receive_residual_anchors["summary"]["layout_change_anchor_count"], 2)
    check(
        "Spectron TSocket lifecycle residual artifact",
        spectron_tsocket_lifecycle_residual_anchors["artifact"],
        "spectron_tsocket_lifecycle_residual_manual_translation_anchors_20260826",
    )
    check("Spectron TSocket lifecycle residual network", spectron_tsocket_lifecycle_residual_anchors["network_contacted"], False)
    check("Spectron TSocket lifecycle residual total", spectron_tsocket_lifecycle_residual_anchors["summary"]["anchor_count"], 4)
    check("Spectron TSocket lifecycle residual high confidence", spectron_tsocket_lifecycle_residual_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron TSocket lifecycle residual semantic overlap", spectron_tsocket_lifecycle_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TSocket lifecycle residual default targets", spectron_tsocket_lifecycle_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron TSocket lifecycle residual exact-shape count", spectron_tsocket_lifecycle_residual_anchors["summary"]["exact_shape_anchor_count"], 1)
    check("Spectron TSocket lifecycle residual layout-change count", spectron_tsocket_lifecycle_residual_anchors["summary"]["layout_change_anchor_count"], 3)
    check(
        "Spectron TSocket host residual artifact",
        spectron_tsocket_host_residual_anchors["artifact"],
        "spectron_tsocket_host_residual_manual_translation_anchors_20260826",
    )
    check("Spectron TSocket host residual network", spectron_tsocket_host_residual_anchors["network_contacted"], False)
    check("Spectron TSocket host residual total", spectron_tsocket_host_residual_anchors["summary"]["anchor_count"], 3)
    check("Spectron TSocket host residual high confidence", spectron_tsocket_host_residual_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron TSocket host residual semantic overlap", spectron_tsocket_host_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TSocket host residual default targets", spectron_tsocket_host_residual_anchors["summary"]["target_default_name_count"], 2)
    check("Spectron TSocket host residual exact-shape count", spectron_tsocket_host_residual_anchors["summary"]["exact_shape_anchor_count"], 0)
    check("Spectron TSocket host residual layout-change count", spectron_tsocket_host_residual_anchors["summary"]["layout_change_anchor_count"], 3)
    check(
        "Spectron TSocketProperties residual artifact",
        spectron_tsocket_properties_residual_anchors["artifact"],
        "spectron_tsocket_properties_residual_manual_translation_anchors_20260826",
    )
    check("Spectron TSocketProperties residual network", spectron_tsocket_properties_residual_anchors["network_contacted"], False)
    check("Spectron TSocketProperties residual total", spectron_tsocket_properties_residual_anchors["summary"]["anchor_count"], 4)
    check("Spectron TSocketProperties residual high confidence", spectron_tsocket_properties_residual_anchors["summary"]["high_confidence_count"], 4)
    check("Spectron TSocketProperties residual semantic overlap", spectron_tsocket_properties_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TSocketProperties residual default targets", spectron_tsocket_properties_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron TSocketProperties residual exact-shape count", spectron_tsocket_properties_residual_anchors["summary"]["exact_shape_anchor_count"], 4)
    check("Spectron TSocketProperties residual layout-change count", spectron_tsocket_properties_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check(
        "Spectron socket-cache residual artifact",
        spectron_socket_cache_residual_anchors["artifact"],
        "spectron_socket_cache_residual_manual_translation_anchors_20260826",
    )
    check("Spectron socket-cache residual network", spectron_socket_cache_residual_anchors["network_contacted"], False)
    check("Spectron socket-cache residual total", spectron_socket_cache_residual_anchors["summary"]["anchor_count"], 5)
    check("Spectron socket-cache residual high confidence", spectron_socket_cache_residual_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron socket-cache residual semantic overlap", spectron_socket_cache_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron socket-cache residual default targets", spectron_socket_cache_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron socket-cache residual exact-shape count", spectron_socket_cache_residual_anchors["summary"]["exact_shape_anchor_count"], 2)
    check("Spectron socket-cache residual layout-change count", spectron_socket_cache_residual_anchors["summary"]["layout_change_anchor_count"], 3)
    check(
        "Spectron URL-cache residual artifact",
        spectron_url_cache_residual_anchors["artifact"],
        "spectron_url_cache_residual_manual_translation_anchors_20260826",
    )
    check("Spectron URL-cache residual network", spectron_url_cache_residual_anchors["network_contacted"], False)
    check("Spectron URL-cache residual total", spectron_url_cache_residual_anchors["summary"]["anchor_count"], 5)
    check("Spectron URL-cache residual high confidence", spectron_url_cache_residual_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron URL-cache residual semantic overlap", spectron_url_cache_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron URL-cache residual default targets", spectron_url_cache_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron URL-cache residual exact-shape count", spectron_url_cache_residual_anchors["summary"]["exact_shape_anchor_count"], 3)
    check("Spectron URL-cache residual layout-change count", spectron_url_cache_residual_anchors["summary"]["layout_change_anchor_count"], 2)
    check(
        "Spectron player-list residual artifact",
        spectron_player_list_residual_anchors["artifact"],
        "spectron_player_list_residual_manual_translation_anchors_20260826",
    )
    check("Spectron player-list residual network", spectron_player_list_residual_anchors["network_contacted"], False)
    check("Spectron player-list residual total", spectron_player_list_residual_anchors["summary"]["anchor_count"], 3)
    check("Spectron player-list residual high confidence", spectron_player_list_residual_anchors["summary"]["high_confidence_count"], 3)
    check("Spectron player-list residual semantic overlap", spectron_player_list_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron player-list residual default targets", spectron_player_list_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron player-list residual exact-shape count", spectron_player_list_residual_anchors["summary"]["exact_shape_anchor_count"], 2)
    check("Spectron player-list residual layout-change count", spectron_player_list_residual_anchors["summary"]["layout_change_anchor_count"], 1)
    check(
        "Spectron client-thread residual artifact",
        spectron_client_thread_residual_anchors["artifact"],
        "spectron_client_thread_residual_manual_translation_anchors_20260826",
    )
    check("Spectron client-thread residual network", spectron_client_thread_residual_anchors["network_contacted"], False)
    check("Spectron client-thread residual total", spectron_client_thread_residual_anchors["summary"]["anchor_count"], 7)
    check("Spectron client-thread residual high confidence", spectron_client_thread_residual_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron client-thread residual semantic overlap", spectron_client_thread_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron client-thread residual default targets", spectron_client_thread_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron client-thread residual exact-shape count", spectron_client_thread_residual_anchors["summary"]["exact_shape_anchor_count"], 7)
    check("Spectron client-thread residual layout-change count", spectron_client_thread_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check(
        "Spectron update-package accessor residual artifact",
        spectron_update_package_accessor_residual_anchors["artifact"],
        "spectron_update_package_accessor_residual_manual_translation_anchors_20260826",
    )
    check("Spectron update-package accessor residual network", spectron_update_package_accessor_residual_anchors["network_contacted"], False)
    check("Spectron update-package accessor residual total", spectron_update_package_accessor_residual_anchors["summary"]["anchor_count"], 20)
    check("Spectron update-package accessor residual high confidence", spectron_update_package_accessor_residual_anchors["summary"]["high_confidence_count"], 20)
    check("Spectron update-package accessor residual semantic overlap", spectron_update_package_accessor_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron update-package accessor residual default targets", spectron_update_package_accessor_residual_anchors["summary"]["target_default_name_count"], 20)
    check("Spectron update-package accessor residual exact-shape count", spectron_update_package_accessor_residual_anchors["summary"]["exact_shape_anchor_count"], 20)
    check("Spectron update-package accessor residual layout-change count", spectron_update_package_accessor_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check(
        "Spectron update-package destructor residual artifact",
        spectron_update_package_destructor_residual_anchors["artifact"],
        "spectron_update_package_destructor_residual_manual_translation_anchors_20260826",
    )
    check("Spectron update-package destructor residual network", spectron_update_package_destructor_residual_anchors["network_contacted"], False)
    check("Spectron update-package destructor residual total", spectron_update_package_destructor_residual_anchors["summary"]["anchor_count"], 1)
    check("Spectron update-package destructor residual high confidence", spectron_update_package_destructor_residual_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron update-package destructor residual semantic overlap", spectron_update_package_destructor_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron update-package destructor residual default targets", spectron_update_package_destructor_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron update-package destructor residual exact-shape count", spectron_update_package_destructor_residual_anchors["summary"]["exact_shape_anchor_count"], 1)
    check("Spectron update-package destructor residual layout-change count", spectron_update_package_destructor_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check(
        "Spectron update-package wrapper residual artifact",
        spectron_update_package_wrapper_residual_anchors["artifact"],
        "spectron_update_package_wrapper_residual_manual_translation_anchors_20260826",
    )
    check("Spectron update-package wrapper residual network", spectron_update_package_wrapper_residual_anchors["network_contacted"], False)
    check("Spectron update-package wrapper residual total", spectron_update_package_wrapper_residual_anchors["summary"]["anchor_count"], 6)
    check("Spectron update-package wrapper residual high confidence", spectron_update_package_wrapper_residual_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron update-package wrapper residual semantic overlap", spectron_update_package_wrapper_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron update-package wrapper residual default targets", spectron_update_package_wrapper_residual_anchors["summary"]["target_default_name_count"], 2)
    check("Spectron update-package wrapper residual exact-shape count", spectron_update_package_wrapper_residual_anchors["summary"]["exact_shape_anchor_count"], 4)
    check("Spectron update-package wrapper residual layout-change count", spectron_update_package_wrapper_residual_anchors["summary"]["layout_change_anchor_count"], 2)
    check(
        "Spectron update-package-properties residual artifact",
        spectron_update_package_properties_residual_anchors["artifact"],
        "spectron_update_package_properties_residual_manual_translation_anchors_20260826",
    )
    check("Spectron update-package-properties residual network", spectron_update_package_properties_residual_anchors["network_contacted"], False)
    check("Spectron update-package-properties residual total", spectron_update_package_properties_residual_anchors["summary"]["anchor_count"], 5)
    check("Spectron update-package-properties residual high confidence", spectron_update_package_properties_residual_anchors["summary"]["high_confidence_count"], 5)
    check("Spectron update-package-properties residual semantic overlap", spectron_update_package_properties_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron update-package-properties residual default targets", spectron_update_package_properties_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron update-package-properties residual exact-shape count", spectron_update_package_properties_residual_anchors["summary"]["exact_shape_anchor_count"], 5)
    check("Spectron update-package-properties residual layout-change count", spectron_update_package_properties_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check(
        "Spectron GSFunctions math-string residual artifact",
        spectron_gsfunctions_math_string_residual_anchors["artifact"],
        "spectron_gsfunctions_math_string_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GSFunctions math-string residual network", spectron_gsfunctions_math_string_residual_anchors["network_contacted"], False)
    check("Spectron GSFunctions math-string residual total", spectron_gsfunctions_math_string_residual_anchors["summary"]["anchor_count"], 6)
    check("Spectron GSFunctions math-string residual high confidence", spectron_gsfunctions_math_string_residual_anchors["summary"]["high_confidence_count"], 6)
    check("Spectron GSFunctions math-string residual semantic overlap", spectron_gsfunctions_math_string_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GSFunctions math-string residual default targets", spectron_gsfunctions_math_string_residual_anchors["summary"]["target_default_name_count"], 5)
    check("Spectron GSFunctions math-string residual exact-shape count", spectron_gsfunctions_math_string_residual_anchors["summary"]["exact_shape_anchor_count"], 6)
    check("Spectron GSFunctions math-string residual layout-change count", spectron_gsfunctions_math_string_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron GSFunctions math-string residual materialized targets", spectron_gsfunctions_math_string_residual_anchors["summary"]["materialized_target_function_count"], 1)
    check(
        "Spectron GSFunctions callback residual artifact",
        spectron_gsfunctions_callback_residual_anchors["artifact"],
        "spectron_gsfunctions_callback_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GSFunctions callback residual network", spectron_gsfunctions_callback_residual_anchors["network_contacted"], False)
    check("Spectron GSFunctions callback residual total", spectron_gsfunctions_callback_residual_anchors["summary"]["anchor_count"], 13)
    check("Spectron GSFunctions callback residual high confidence", spectron_gsfunctions_callback_residual_anchors["summary"]["high_confidence_count"], 13)
    check("Spectron GSFunctions callback residual semantic overlap", spectron_gsfunctions_callback_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GSFunctions callback residual default targets", spectron_gsfunctions_callback_residual_anchors["summary"]["target_default_name_count"], 13)
    check("Spectron GSFunctions callback residual exact-shape count", spectron_gsfunctions_callback_residual_anchors["summary"]["exact_shape_anchor_count"], 8)
    check("Spectron GSFunctions callback residual layout-change count", spectron_gsfunctions_callback_residual_anchors["summary"]["layout_change_anchor_count"], 5)
    check("Spectron GSFunctions callback residual materialized targets", spectron_gsfunctions_callback_residual_anchors["summary"]["materialized_target_function_count"], 1)
    check(
        "Spectron GSFunctions randomstring residual artifact",
        spectron_gsfunctions_randomstring_residual_anchors["artifact"],
        "spectron_gsfunctions_randomstring_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GSFunctions randomstring residual network", spectron_gsfunctions_randomstring_residual_anchors["network_contacted"], False)
    check("Spectron GSFunctions randomstring residual total", spectron_gsfunctions_randomstring_residual_anchors["summary"]["anchor_count"], 1)
    check("Spectron GSFunctions randomstring residual high confidence", spectron_gsfunctions_randomstring_residual_anchors["summary"]["high_confidence_count"], 1)
    check("Spectron GSFunctions randomstring residual semantic overlap", spectron_gsfunctions_randomstring_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GSFunctions randomstring residual default targets", spectron_gsfunctions_randomstring_residual_anchors["summary"]["target_default_name_count"], 1)
    check("Spectron GSFunctions randomstring residual exact-shape count", spectron_gsfunctions_randomstring_residual_anchors["summary"]["exact_shape_anchor_count"], 0)
    check("Spectron GSFunctions randomstring residual layout-change count", spectron_gsfunctions_randomstring_residual_anchors["summary"]["layout_change_anchor_count"], 1)
    check(
        "Spectron GSFunctionsClient exact residual artifact",
        spectron_gsfunctions_client_exact_residual_anchors["artifact"],
        "spectron_gsfunctions_client_exact_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GSFunctionsClient exact residual network", spectron_gsfunctions_client_exact_residual_anchors["network_contacted"], False)
    check("Spectron GSFunctionsClient exact residual total", spectron_gsfunctions_client_exact_residual_anchors["summary"]["anchor_count"], 20)
    check("Spectron GSFunctionsClient exact residual high confidence", spectron_gsfunctions_client_exact_residual_anchors["summary"]["high_confidence_count"], 20)
    check("Spectron GSFunctionsClient exact residual semantic overlap", spectron_gsfunctions_client_exact_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GSFunctionsClient exact residual default targets", spectron_gsfunctions_client_exact_residual_anchors["summary"]["target_default_name_count"], 20)
    check("Spectron GSFunctionsClient exact residual exact-shape count", spectron_gsfunctions_client_exact_residual_anchors["summary"]["exact_shape_anchor_count"], 20)
    check("Spectron GSFunctionsClient exact residual layout-change count", spectron_gsfunctions_client_exact_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron GSFunctionsClient exact residual materialized targets", spectron_gsfunctions_client_exact_residual_anchors["summary"]["materialized_target_function_count"], 0)
    check(
        "Spectron GSFunctionsClient exact residual v2 artifact",
        spectron_gsfunctions_client_exact_residual_v2_anchors["artifact"],
        "spectron_gsfunctions_client_exact_residual_v2_manual_translation_anchors_20260826",
    )
    check("Spectron GSFunctionsClient exact residual v2 network", spectron_gsfunctions_client_exact_residual_v2_anchors["network_contacted"], False)
    check("Spectron GSFunctionsClient exact residual v2 total", spectron_gsfunctions_client_exact_residual_v2_anchors["summary"]["anchor_count"], 20)
    check("Spectron GSFunctionsClient exact residual v2 high confidence", spectron_gsfunctions_client_exact_residual_v2_anchors["summary"]["high_confidence_count"], 20)
    check("Spectron GSFunctionsClient exact residual v2 semantic overlap", spectron_gsfunctions_client_exact_residual_v2_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GSFunctionsClient exact residual v2 default targets", spectron_gsfunctions_client_exact_residual_v2_anchors["summary"]["target_default_name_count"], 20)
    check("Spectron GSFunctionsClient exact residual v2 exact-shape count", spectron_gsfunctions_client_exact_residual_v2_anchors["summary"]["exact_shape_anchor_count"], 20)
    check("Spectron GSFunctionsClient exact residual v2 layout-change count", spectron_gsfunctions_client_exact_residual_v2_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron GSFunctionsClient exact residual v2 materialized targets", spectron_gsfunctions_client_exact_residual_v2_anchors["summary"]["materialized_target_function_count"], 0)
    check(
        "Spectron GSFunctionsClient exact residual v3 artifact",
        spectron_gsfunctions_client_exact_residual_v3_anchors["artifact"],
        "spectron_gsfunctions_client_exact_residual_v3_manual_translation_anchors_20260826",
    )
    check("Spectron GSFunctionsClient exact residual v3 network", spectron_gsfunctions_client_exact_residual_v3_anchors["network_contacted"], False)
    check("Spectron GSFunctionsClient exact residual v3 total", spectron_gsfunctions_client_exact_residual_v3_anchors["summary"]["anchor_count"], 9)
    check("Spectron GSFunctionsClient exact residual v3 high confidence", spectron_gsfunctions_client_exact_residual_v3_anchors["summary"]["high_confidence_count"], 9)
    check("Spectron GSFunctionsClient exact residual v3 semantic overlap", spectron_gsfunctions_client_exact_residual_v3_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GSFunctionsClient exact residual v3 default targets", spectron_gsfunctions_client_exact_residual_v3_anchors["summary"]["target_default_name_count"], 9)
    check("Spectron GSFunctionsClient exact residual v3 exact-shape count", spectron_gsfunctions_client_exact_residual_v3_anchors["summary"]["exact_shape_anchor_count"], 9)
    check("Spectron GSFunctionsClient exact residual v3 layout-change count", spectron_gsfunctions_client_exact_residual_v3_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron GSFunctionsClient exact residual v3 materialized targets", spectron_gsfunctions_client_exact_residual_v3_anchors["summary"]["materialized_target_function_count"], 0)
    check(
        "Spectron GSFunctionsClient boundary residual artifact",
        spectron_gsfunctions_client_boundary_residual_anchors["artifact"],
        "spectron_gsfunctions_client_boundary_residual_manual_translation_anchors_20260826",
    )
    check("Spectron GSFunctionsClient boundary residual network", spectron_gsfunctions_client_boundary_residual_anchors["network_contacted"], False)
    check("Spectron GSFunctionsClient boundary residual total", spectron_gsfunctions_client_boundary_residual_anchors["summary"]["anchor_count"], 12)
    check("Spectron GSFunctionsClient boundary residual high confidence", spectron_gsfunctions_client_boundary_residual_anchors["summary"]["high_confidence_count"], 12)
    check("Spectron GSFunctionsClient boundary residual semantic overlap", spectron_gsfunctions_client_boundary_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GSFunctionsClient boundary residual default targets", spectron_gsfunctions_client_boundary_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron GSFunctionsClient boundary residual materialized targets", spectron_gsfunctions_client_boundary_residual_anchors["summary"]["materialized_target_function_count"], 12)
    check("Spectron GSFunctionsClient boundary residual raw boundary count", spectron_gsfunctions_client_boundary_residual_anchors["summary"]["raw_boundary_anchor_count"], 12)
    check("Spectron GSFunctionsClient boundary residual raw return count", spectron_gsfunctions_client_boundary_residual_anchors["summary"]["raw_return_count"], 17)
    check(
        "Spectron GSFunctionsClient exact residual v4 artifact",
        spectron_gsfunctions_client_exact_residual_v4_anchors["artifact"],
        "spectron_gsfunctions_client_exact_residual_v4_manual_translation_anchors_20260826",
    )
    check("Spectron GSFunctionsClient exact residual v4 network", spectron_gsfunctions_client_exact_residual_v4_anchors["network_contacted"], False)
    check("Spectron GSFunctionsClient exact residual v4 total", spectron_gsfunctions_client_exact_residual_v4_anchors["summary"]["anchor_count"], 11)
    check("Spectron GSFunctionsClient exact residual v4 high confidence", spectron_gsfunctions_client_exact_residual_v4_anchors["summary"]["high_confidence_count"], 11)
    check("Spectron GSFunctionsClient exact residual v4 semantic overlap", spectron_gsfunctions_client_exact_residual_v4_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron GSFunctionsClient exact residual v4 default targets", spectron_gsfunctions_client_exact_residual_v4_anchors["summary"]["target_default_name_count"], 11)
    check("Spectron GSFunctionsClient exact residual v4 exact-shape count", spectron_gsfunctions_client_exact_residual_v4_anchors["summary"]["exact_shape_anchor_count"], 11)
    check("Spectron GSFunctionsClient exact residual v4 layout-change count", spectron_gsfunctions_client_exact_residual_v4_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron GSFunctionsClient exact residual v4 materialized targets", spectron_gsfunctions_client_exact_residual_v4_anchors["summary"]["materialized_target_function_count"], 0)
    check(
        "Spectron CyaInt TLS residual artifact",
        spectron_cyaint_tls_residual_anchors["artifact"],
        "spectron_cyaint_tls_residual_manual_translation_anchors_20260826",
    )
    check("Spectron CyaInt TLS residual network", spectron_cyaint_tls_residual_anchors["network_contacted"], False)
    check("Spectron CyaInt TLS residual total", spectron_cyaint_tls_residual_anchors["summary"]["anchor_count"], 30)
    check("Spectron CyaInt TLS residual high confidence", spectron_cyaint_tls_residual_anchors["summary"]["high_confidence_count"], 30)
    check("Spectron CyaInt TLS residual semantic overlap", spectron_cyaint_tls_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron CyaInt TLS residual default targets", spectron_cyaint_tls_residual_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron CyaInt TLS residual exact-shape count", spectron_cyaint_tls_residual_anchors["summary"]["exact_shape_anchor_count"], 30)
    check("Spectron CyaInt TLS residual layout-change count", spectron_cyaint_tls_residual_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron CyaInt TLS residual relocation", spectron_cyaint_tls_residual_anchors["summary"]["constant_target_delta"], "+0xd590")
    check(
        "Spectron CyaInt TLS residual v2 artifact",
        spectron_cyaint_tls_residual_v2_anchors["artifact"],
        "spectron_cyaint_tls_residual_v2_manual_translation_anchors_20260826",
    )
    check("Spectron CyaInt TLS residual v2 network", spectron_cyaint_tls_residual_v2_anchors["network_contacted"], False)
    check("Spectron CyaInt TLS residual v2 total", spectron_cyaint_tls_residual_v2_anchors["summary"]["anchor_count"], 53)
    check("Spectron CyaInt TLS residual v2 high confidence", spectron_cyaint_tls_residual_v2_anchors["summary"]["high_confidence_count"], 53)
    check("Spectron CyaInt TLS residual v2 semantic overlap", spectron_cyaint_tls_residual_v2_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron CyaInt TLS residual v2 prior overlap", spectron_cyaint_tls_residual_v2_anchors["summary"]["already_in_prior_anchor"], 0)
    check("Spectron CyaInt TLS residual v2 default targets", spectron_cyaint_tls_residual_v2_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron CyaInt TLS residual v2 exact-shape count", spectron_cyaint_tls_residual_v2_anchors["summary"]["exact_shape_anchor_count"], 53)
    check("Spectron CyaInt TLS residual v2 layout-change count", spectron_cyaint_tls_residual_v2_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron CyaInt TLS residual v2 relocation", spectron_cyaint_tls_residual_v2_anchors["summary"]["constant_target_delta"], "+0xd590")
    check(
        "Spectron TServerPlayer accessor artifact",
        spectron_tserverplayer_accessor_anchors["artifact"],
        "spectron_tserverplayer_accessor_manual_translation_anchors_20260826",
    )
    check("Spectron TServerPlayer accessor network", spectron_tserverplayer_accessor_anchors["network_contacted"], False)
    check("Spectron TServerPlayer accessor total", spectron_tserverplayer_accessor_anchors["summary"]["anchor_count"], 37)
    check("Spectron TServerPlayer accessor high confidence", spectron_tserverplayer_accessor_anchors["summary"]["high_confidence_count"], 37)
    check("Spectron TServerPlayer accessor semantic overlap", spectron_tserverplayer_accessor_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TServerPlayer accessor default targets", spectron_tserverplayer_accessor_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron TServerPlayer accessor exact-shape count", spectron_tserverplayer_accessor_anchors["summary"]["exact_shape_anchor_count"], 37)
    check("Spectron TServerPlayer accessor layout-change count", spectron_tserverplayer_accessor_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TServerPlayer accessor address relocation", spectron_tserverplayer_accessor_anchors["summary"]["constant_target_delta"], "+0x47e8")
    check("Spectron TServerPlayer accessor field relocation", spectron_tserverplayer_accessor_anchors["summary"]["constant_field_offset_delta"], 24)
    check(
        "Spectron TPlayer scalar setter artifact",
        spectron_tplayer_scalar_setter_anchors["artifact"],
        "spectron_tplayer_scalar_setter_manual_translation_anchors_20260826",
    )
    check("Spectron TPlayer scalar setter network", spectron_tplayer_scalar_setter_anchors["network_contacted"], False)
    check("Spectron TPlayer scalar setter total", spectron_tplayer_scalar_setter_anchors["summary"]["anchor_count"], 10)
    check("Spectron TPlayer scalar setter high confidence", spectron_tplayer_scalar_setter_anchors["summary"]["high_confidence_count"], 10)
    check("Spectron TPlayer scalar setter semantic overlap", spectron_tplayer_scalar_setter_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TPlayer scalar setter default targets", spectron_tplayer_scalar_setter_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron TPlayer scalar setter exact-shape count", spectron_tplayer_scalar_setter_anchors["summary"]["exact_shape_anchor_count"], 10)
    check("Spectron TPlayer scalar setter layout-change count", spectron_tplayer_scalar_setter_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TPlayer scalar setter address relocation", spectron_tplayer_scalar_setter_anchors["summary"]["constant_target_delta"], "+0x3c00")
    check(
        "Spectron TPlayer scalar getter artifact",
        spectron_tplayer_scalar_getter_anchors["artifact"],
        "spectron_tplayer_scalar_getter_manual_translation_anchors_20260826",
    )
    check("Spectron TPlayer scalar getter network", spectron_tplayer_scalar_getter_anchors["network_contacted"], False)
    check("Spectron TPlayer scalar getter total", spectron_tplayer_scalar_getter_anchors["summary"]["anchor_count"], 21)
    check("Spectron TPlayer scalar getter high confidence", spectron_tplayer_scalar_getter_anchors["summary"]["high_confidence_count"], 21)
    check("Spectron TPlayer scalar getter semantic overlap", spectron_tplayer_scalar_getter_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TPlayer scalar getter default targets", spectron_tplayer_scalar_getter_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron TPlayer scalar getter exact-shape count", spectron_tplayer_scalar_getter_anchors["summary"]["exact_shape_anchor_count"], 21)
    check("Spectron TPlayer scalar getter layout-change count", spectron_tplayer_scalar_getter_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TPlayer scalar getter address relocation", spectron_tplayer_scalar_getter_anchors["summary"]["constant_target_delta"], "+0x43a4")
    check("Spectron TPlayer scalar getter storage relocation", spectron_tplayer_scalar_getter_anchors["summary"]["constant_storage_offset_delta"], 24)
    check("Spectron TPlayer scalar getter mask relocation", spectron_tplayer_scalar_getter_anchors["summary"]["constant_mask_offset_delta"], 24)
    check(
        "Spectron TPlayer flag setter artifact",
        spectron_tplayer_flag_setter_anchors["artifact"],
        "spectron_tplayer_flag_setter_manual_translation_anchors_20260826",
    )
    check("Spectron TPlayer flag setter network", spectron_tplayer_flag_setter_anchors["network_contacted"], False)
    check("Spectron TPlayer flag setter total", spectron_tplayer_flag_setter_anchors["summary"]["anchor_count"], 7)
    check("Spectron TPlayer flag setter high confidence", spectron_tplayer_flag_setter_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron TPlayer flag setter semantic overlap", spectron_tplayer_flag_setter_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TPlayer flag setter default targets", spectron_tplayer_flag_setter_anchors["summary"]["target_default_name_count"], 0)
    check("Spectron TPlayer flag setter exact-shape count", spectron_tplayer_flag_setter_anchors["summary"]["exact_shape_anchor_count"], 7)
    check("Spectron TPlayer flag setter layout-change count", spectron_tplayer_flag_setter_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TPlayer flag setter address relocation", spectron_tplayer_flag_setter_anchors["summary"]["constant_target_delta"], "+0x43a4")
    check("Spectron TPlayer flag setter interstitial count", spectron_tplayer_flag_setter_anchors["summary"]["existing_interstitial_count"], 1)
    check(
        "Spectron TServerPlayer property-block artifact",
        spectron_tserverplayer_property_block_anchors["artifact"],
        "spectron_tserverplayer_property_block_manual_translation_anchors_20260826",
    )
    check("Spectron TServerPlayer property-block network", spectron_tserverplayer_property_block_anchors["network_contacted"], False)
    check("Spectron TServerPlayer property-block total", spectron_tserverplayer_property_block_anchors["summary"]["anchor_count"], 39)
    check("Spectron TServerPlayer property-block high confidence", spectron_tserverplayer_property_block_anchors["summary"]["high_confidence_count"], 39)
    check("Spectron TServerPlayer property-block semantic overlap", spectron_tserverplayer_property_block_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TServerPlayer property-block default targets", spectron_tserverplayer_property_block_anchors["summary"]["target_default_name_count"], 38)
    check("Spectron TServerPlayer property-block exact-shape count", spectron_tserverplayer_property_block_anchors["summary"]["exact_shape_anchor_count"], 39)
    check("Spectron TServerPlayer property-block layout-change count", spectron_tserverplayer_property_block_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TServerPlayer property-block address relocation", spectron_tserverplayer_property_block_anchors["summary"]["constant_target_delta"], "+0x4860")
    check("Spectron TServerPlayer property-block existing context count", spectron_tserverplayer_property_block_anchors["summary"]["existing_context_count"], 4)
    check(
        "Spectron TServerPlayer residual artifact",
        spectron_tserverplayer_residual_anchors["artifact"],
        "spectron_tserverplayer_residual_manual_translation_anchors_20260826",
    )
    check("Spectron TServerPlayer residual network", spectron_tserverplayer_residual_anchors["network_contacted"], False)
    check("Spectron TServerPlayer residual total", spectron_tserverplayer_residual_anchors["summary"]["anchor_count"], 25)
    check("Spectron TServerPlayer residual high confidence", spectron_tserverplayer_residual_anchors["summary"]["high_confidence_count"], 25)
    check("Spectron TServerPlayer residual semantic overlap", spectron_tserverplayer_residual_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TServerPlayer residual default targets", spectron_tserverplayer_residual_anchors["summary"]["target_default_name_count"], 25)
    check("Spectron TServerPlayer residual exact-shape count", spectron_tserverplayer_residual_anchors["summary"]["exact_shape_anchor_count"], 23)
    check("Spectron TServerPlayer residual layout-change count", spectron_tserverplayer_residual_anchors["summary"]["layout_change_anchor_count"], 2)
    check("Spectron TServerPlayer residual boundary count", spectron_tserverplayer_residual_anchors["summary"]["boundary_anchor_count"], 3)
    check("Spectron TServerPlayer residual shared context count", spectron_tserverplayer_residual_anchors["summary"]["shared_context_count"], 2)
    check(
        "Spectron TServerPlayer tail artifact",
        spectron_tserverplayer_tail_anchors["artifact"],
        "spectron_tserverplayer_tail_manual_translation_anchors_20260826",
    )
    check("Spectron TServerPlayer tail network", spectron_tserverplayer_tail_anchors["network_contacted"], False)
    check("Spectron TServerPlayer tail total", spectron_tserverplayer_tail_anchors["summary"]["anchor_count"], 7)
    check("Spectron TServerPlayer tail high confidence", spectron_tserverplayer_tail_anchors["summary"]["high_confidence_count"], 7)
    check("Spectron TServerPlayer tail semantic overlap", spectron_tserverplayer_tail_anchors["summary"]["already_in_semantic_map"], 0)
    check("Spectron TServerPlayer tail default targets", spectron_tserverplayer_tail_anchors["summary"]["target_default_name_count"], 1)
    check("Spectron TServerPlayer tail exact-shape count", spectron_tserverplayer_tail_anchors["summary"]["exact_shape_anchor_count"], 7)
    check("Spectron TServerPlayer tail layout-change count", spectron_tserverplayer_tail_anchors["summary"]["layout_change_anchor_count"], 0)
    check("Spectron TServerPlayer tail boundary count", spectron_tserverplayer_tail_anchors["summary"]["boundary_anchor_count"], 0)
    check(
        "Spectron checkpoint artifact",
        spectron_checkpoint["artifact"],
        "spectron_translation_checkpoint_20260826",
    )
    check("Spectron checkpoint network", spectron_checkpoint["network_contacted"], False)
    check("Spectron checkpoint database function count", spectron_checkpoint["database"]["function_count"], 11694)
    check("Spectron checkpoint database default sub count", spectron_checkpoint["database"]["default_sub_function_count"], 1165)
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
    check("Spectron checkpoint connection-helper anchor count", spectron_checkpoint["connection_helper_anchors"]["verified_name_count"], 18)
    check("Spectron checkpoint client-state-helper anchor count", spectron_checkpoint["client_state_helper_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint connection-state anchor count", spectron_checkpoint["connection_state_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint HTTP request anchor count", spectron_checkpoint["http_request_anchors"]["verified_name_count"], 12)
    check("Spectron checkpoint socket-state anchor count", spectron_checkpoint["socket_state_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint HTTP request-state anchor count", spectron_checkpoint["http_request_state_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint NPC helper anchor count", spectron_checkpoint["npc_helper_anchors"]["verified_name_count"], 15)
    check("Spectron checkpoint HTML atom anchor count", spectron_checkpoint["html_atom_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint player helper anchor count", spectron_checkpoint["player_helper_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint input/window anchor count", spectron_checkpoint["input_window_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint visual helper anchor count", spectron_checkpoint["visual_helper_anchors"]["verified_name_count"], 11)
    check("Spectron checkpoint script-runtime anchor count", spectron_checkpoint["script_runtime_anchors"]["verified_name_count"], 12)
    check("Spectron checkpoint core-helper anchor count", spectron_checkpoint["core_helper_anchors"]["verified_name_count"], 30)
    check("Spectron checkpoint render/GUI anchor count", spectron_checkpoint["render_gui_anchors"]["verified_name_count"], 20)
    check("Spectron checkpoint JSON/folder anchor count", spectron_checkpoint["json_folder_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint resource-object anchor count", spectron_checkpoint["resource_object_anchors"]["verified_name_count"], 11)
    check("Spectron checkpoint script-machine anchor count", spectron_checkpoint["script_machine_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint script-space anchor count", spectron_checkpoint["script_space_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint script-execution anchor count", spectron_checkpoint["script_execution_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint script-dispatch anchor count", spectron_checkpoint["script_dispatch_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint script-scheduler anchor count", spectron_checkpoint["script_scheduler_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint event-object anchor count", spectron_checkpoint["event_object_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint script-action anchor count", spectron_checkpoint["script_action_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint stack-entry anchor count", spectron_checkpoint["stack_entry_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint machine-helper anchor count", spectron_checkpoint["machine_helper_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint array-mutation anchor count", spectron_checkpoint["array_mutation_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint string-search anchor count", spectron_checkpoint["string_search_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint string-helper anchor count", spectron_checkpoint["string_helper_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint variable-construction anchor count", spectron_checkpoint["variable_construction_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint script-object anchor count", spectron_checkpoint["script_object_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint script-state anchor count", spectron_checkpoint["script_state_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint execution-dispatch anchor count", spectron_checkpoint["execution_dispatch_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint tokenizer anchor count", spectron_checkpoint["tokenizer_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint script-executor anchor count", spectron_checkpoint["script_executor_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint script-property anchor count", spectron_checkpoint["script_property_anchors"]["verified_name_count"], 9)
    check("Spectron checkpoint script-universe anchor count", spectron_checkpoint["script_universe_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint static/JSON/tiles anchor count", spectron_checkpoint["static_json_tiles_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint tiles-update anchor count", spectron_checkpoint["tiles_update_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint particle anchor count", spectron_checkpoint["particle_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint ShowImg anchor count", spectron_checkpoint["showimg_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint ShowImg property anchor count", spectron_checkpoint["showimg_property_anchors"]["verified_name_count"], 85)
    check("Spectron checkpoint ShowImg residual anchor count", spectron_checkpoint["showimg_residual_anchors"]["verified_name_count"], 24)
    check("Spectron checkpoint particle-emitter anchor count", spectron_checkpoint["particle_emitter_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint server-animation anchor count", spectron_checkpoint["server_animation_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint player-lifecycle anchor count", spectron_checkpoint["player_lifecycle_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint player-emoticon anchor count", spectron_checkpoint["player_emoticon_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint player-level-entry anchor count", spectron_checkpoint["player_level_entry_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint player-side-level anchor count", spectron_checkpoint["player_side_level_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint player-map-position anchor count", spectron_checkpoint["player_map_position_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint player-link-traversal anchor count", spectron_checkpoint["player_link_traversal_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint player-weapon-state anchor count", spectron_checkpoint["player_weapon_state_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint player-visual-setter anchor count", spectron_checkpoint["player_visual_setter_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint player-movement anchor count", spectron_checkpoint["player_movement_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint server-player-state anchor count", spectron_checkpoint["server_player_state_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint server-NPC-state anchor count", spectron_checkpoint["server_npc_state_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint NPC accessor anchor count", spectron_checkpoint["npc_accessor_anchors"]["verified_name_count"], 17)
    check("Spectron checkpoint NPC destructor anchor count", spectron_checkpoint["npc_destructor_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint server-level-property anchor count", spectron_checkpoint["server_level_property_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint server-level-interaction anchor count", spectron_checkpoint["server_level_interaction_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint server-level-lifecycle anchor count", spectron_checkpoint["server_level_lifecycle_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint server-level-side-helpers anchor count", spectron_checkpoint["server_level_side_helpers_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint server-level-storage anchor count", spectron_checkpoint["server_level_storage_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint hidden-testnpc anchor count", spectron_checkpoint["hidden_testnpc_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint level-map-lookup anchor count", spectron_checkpoint["level_map_lookup_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint Gani-constructor anchor count", spectron_checkpoint["gani_constructor_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint Gani-helper anchor count", spectron_checkpoint["gani_helper_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint Gani-runtime anchor count", spectron_checkpoint["gani_runtime_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint Gani-render anchor count", spectron_checkpoint["gani_render_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint Gani-frame-playback anchor count", spectron_checkpoint["gani_frame_playback_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint Gani-lifecycle anchor count", spectron_checkpoint["gani_lifecycle_anchors"]["verified_name_count"], 50)
    check("Spectron checkpoint TPlayer-core anchor count", spectron_checkpoint["tplayer_core_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint resource-parser anchor count", spectron_checkpoint["resource_parser_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint static-utility anchor count", spectron_checkpoint["static_utility_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint font-bitmap anchor count", spectron_checkpoint["font_bitmap_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint MNG-animation anchor count", spectron_checkpoint["mng_animation_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint script-machine-tail anchor count", spectron_checkpoint["script_machine_tail_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint script-stream-profile anchor count", spectron_checkpoint["script_stream_profile_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint animation-lexer anchor count", spectron_checkpoint["ani_lexer_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint number-array-string anchor count", spectron_checkpoint["number_array_string_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint client-environment-clock anchor count", spectron_checkpoint["client_environment_clock_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint client-var-core anchor count", spectron_checkpoint["client_var_core_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint TStringList comma anchor count", spectron_checkpoint["tstringlist_comma_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint extended TStringList anchor count", spectron_checkpoint["tstringlist_extended_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint hash-family anchor count", spectron_checkpoint["hash_family_anchors"]["verified_name_count"], 9)
    check("Spectron checkpoint options anchor count", spectron_checkpoint["options_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint texture anchor count", spectron_checkpoint["texture_anchors"]["verified_name_count"], 10)
    check("Spectron checkpoint drawing-panel texture anchor count", spectron_checkpoint["drawing_panel_texture_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint draw-texture anchor count", spectron_checkpoint["draw_texture_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint bitmap-array holder anchor count", spectron_checkpoint["bitmap_array_holder_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint color-manager anchor count", spectron_checkpoint["color_manager_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint font-runtime anchor count", spectron_checkpoint["font_runtime_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint window-input anchor count", spectron_checkpoint["window_input_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint drawing-panel residual anchor count", spectron_checkpoint["drawing_panel_residual_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint image/html anchor count", spectron_checkpoint["image_html_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint panel/bitmap anchor count", spectron_checkpoint["panel_bitmap_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint GIF decoder anchor count", spectron_checkpoint["gif_decoder_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint window residual anchor count", spectron_checkpoint["window_residual_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint sound-runtime anchor count", spectron_checkpoint["sound_runtime_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint pixelbuffer residual anchor count", spectron_checkpoint["pixelbuffer_residual_anchors"]["verified_name_count"], 10)
    check("Spectron checkpoint pixelbuffer bitmap-lifecycle anchor count", spectron_checkpoint["pixelbuffer_bitmap_lifecycle_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint animation-palette residual anchor count", spectron_checkpoint["animation_palette_residual_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint panel virtual renderer residual anchor count", spectron_checkpoint["panel_virtual_renderer_residual_anchors"]["verified_name_count"], 23)
    check("Spectron checkpoint dummy-panel residual anchor count", spectron_checkpoint["dummy_panel_residual_anchors"]["verified_name_count"], 14)
    check("Spectron checkpoint screen-panel renderer residual anchor count", spectron_checkpoint["screen_panel_renderer_residual_anchors"]["verified_name_count"], 10)
    check("Spectron checkpoint screen-panel window GLES residual anchor count", spectron_checkpoint["screen_panel_window_gles_residual_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint font-manager font residual anchor count", spectron_checkpoint["font_manager_font_residual_anchors"]["verified_name_count"], 9)
    check("Spectron checkpoint font-options font-data residual anchor count", spectron_checkpoint["font_options_font_data_residual_anchors"]["verified_name_count"], 16)
    check("Spectron checkpoint GUI control profile accessor anchor count", spectron_checkpoint["gui_control_profile_accessor_anchors"]["verified_name_count"], 89)
    check("Spectron checkpoint GUI control profile destructor anchor count", spectron_checkpoint["gui_control_profile_destructor_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint GuiControl property residual anchor count", spectron_checkpoint["gui_control_property_residual_anchors"]["verified_name_count"], 61)
    check("Spectron checkpoint GuiControl virtual residual anchor count", spectron_checkpoint["gui_control_virtual_residual_anchors"]["verified_name_count"], 13)
    check("Spectron checkpoint GuiControl event and sizing residual anchor count", spectron_checkpoint["gui_control_event_sizing_residual_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint GuiControl style and bounds residual anchor count", spectron_checkpoint["gui_control_style_bounds_residual_anchors"]["verified_name_count"], 12)
    check("Spectron checkpoint GuiControl event dispatch residual anchor count", spectron_checkpoint["gui_control_event_dispatch_residual_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint GuiControl initialization residual anchor count", spectron_checkpoint["gui_control_initialization_residual_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint GuiControl create residual anchor count", spectron_checkpoint["gui_control_create_residual_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint TSocket accessor residual anchor count", spectron_checkpoint["tsocket_accessor_residual_anchors"]["verified_name_count"], 19)
    check("Spectron checkpoint TSocket SSL residual anchor count", spectron_checkpoint["tsocket_ssl_residual_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint TSocket receive residual anchor count", spectron_checkpoint["tsocket_receive_residual_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint TSocket lifecycle residual anchor count", spectron_checkpoint["tsocket_lifecycle_residual_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint TSocket host residual anchor count", spectron_checkpoint["tsocket_host_residual_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint TSocketProperties residual anchor count", spectron_checkpoint["tsocket_properties_residual_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint socket-cache residual anchor count", spectron_checkpoint["socket_cache_residual_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint URL-cache residual anchor count", spectron_checkpoint["url_cache_residual_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint player-list residual anchor count", spectron_checkpoint["player_list_residual_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint client-thread residual anchor count", spectron_checkpoint["client_thread_residual_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint update-package accessor residual anchor count", spectron_checkpoint["update_package_accessor_residual_anchors"]["verified_name_count"], 20)
    check("Spectron checkpoint update-package destructor residual anchor count", spectron_checkpoint["update_package_destructor_residual_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint update-package wrapper residual anchor count", spectron_checkpoint["update_package_wrapper_residual_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint update-package-properties residual anchor count", spectron_checkpoint["update_package_properties_residual_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint GSFunctions math-string residual anchor count", spectron_checkpoint["gsfunctions_math_string_residual_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint GSFunctions callback residual anchor count", spectron_checkpoint["gsfunctions_callback_residual_anchors"]["verified_name_count"], 13)
    check("Spectron checkpoint GSFunctions randomstring residual anchor count", spectron_checkpoint["gsfunctions_randomstring_residual_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint GSFunctionsClient exact residual anchor count", spectron_checkpoint["gsfunctions_client_exact_residual_anchors"]["verified_name_count"], 20)
    check("Spectron checkpoint GSFunctionsClient exact residual v2 anchor count", spectron_checkpoint["gsfunctions_client_exact_residual_v2_anchors"]["verified_name_count"], 20)
    check("Spectron checkpoint GSFunctionsClient exact residual v3 anchor count", spectron_checkpoint["gsfunctions_client_exact_residual_v3_anchors"]["verified_name_count"], 9)
    check("Spectron checkpoint GSFunctionsClient boundary residual anchor count", spectron_checkpoint["gsfunctions_client_boundary_residual_anchors"]["verified_name_count"], 12)
    check("Spectron checkpoint GSFunctionsClient exact residual v4 anchor count", spectron_checkpoint["gsfunctions_client_exact_residual_v4_anchors"]["verified_name_count"], 11)
    check("Spectron checkpoint CyaInt TLS residual anchor count", spectron_checkpoint["cyaint_tls_residual_anchors"]["verified_name_count"], 30)
    check("Spectron checkpoint CyaInt TLS residual v2 anchor count", spectron_checkpoint["cyaint_tls_residual_v2_anchors"]["verified_name_count"], 53)
    check("Spectron checkpoint TServerPlayer accessor anchor count", spectron_checkpoint["tserverplayer_accessor_anchors"]["verified_name_count"], 37)
    check("Spectron checkpoint TPlayer scalar setter anchor count", spectron_checkpoint["tplayer_scalar_setter_anchors"]["verified_name_count"], 10)
    check("Spectron checkpoint TPlayer scalar getter anchor count", spectron_checkpoint["tplayer_scalar_getter_anchors"]["verified_name_count"], 21)
    check("Spectron checkpoint TPlayer flag setter anchor count", spectron_checkpoint["tplayer_flag_setter_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint TServerPlayer property-block anchor count", spectron_checkpoint["tserverplayer_property_block_anchors"]["verified_name_count"], 39)
    check("Spectron checkpoint TServerPlayer residual anchor count", spectron_checkpoint["tserverplayer_residual_anchors"]["verified_name_count"], 25)
    check("Spectron checkpoint TServerPlayer tail anchor count", spectron_checkpoint["tserverplayer_tail_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint server-object scalar anchor count", spectron_checkpoint["server_object_scalar_anchors"]["verified_name_count"], 12)
    check("Spectron checkpoint compression anchor count", spectron_checkpoint["compression_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint files anchor count", spectron_checkpoint["files_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint encryption anchor count", spectron_checkpoint["encryption_anchors"]["verified_name_count"], 9)
    check("Spectron checkpoint TList anchor count", spectron_checkpoint["tlist_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint sounds anchor count", spectron_checkpoint["sounds_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint hash-container anchor count", spectron_checkpoint["hash_container_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint hash-lifecycle anchor count", spectron_checkpoint["hash_lifecycle_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint TString anchor count", spectron_checkpoint["tstring_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint TString clear anchor count", spectron_checkpoint["tstring_clear_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint static-clear anchor count", spectron_checkpoint["static_clear_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint HTTP response anchor count", spectron_checkpoint["http_request_receive_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint server-list connection anchor count", spectron_checkpoint["server_list_connection_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint server-list state anchor count", spectron_checkpoint["server_list_state_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint HTTP cleanup anchor count", spectron_checkpoint["http_request_cleanup_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint TSocket residual anchor count", spectron_checkpoint["tsocket_residual_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint game-environment anchor count", spectron_checkpoint["game_environment_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint client-environment graphics anchor count", spectron_checkpoint["client_environment_graphics_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint client-environment static-clear anchor count", spectron_checkpoint["client_environment_static_clear_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint client-environment restart-state anchor count", spectron_checkpoint["client_environment_restart_state_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint particle-emitter script-vars anchor count", spectron_checkpoint["particle_emitter_script_vars_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint resource link-lists anchor count", spectron_checkpoint["resource_link_lists_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint clear-cur-anis anchor count", spectron_checkpoint["clear_cur_anis_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint options window-position anchor count", spectron_checkpoint["options_window_position_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint displayed-GIF anchor count", spectron_checkpoint["displayed_gif_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint GUI button-types anchor count", spectron_checkpoint["gui_button_types_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint GUI alignment-tables anchor count", spectron_checkpoint["gui_alignment_tables_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint GUI stretch-modes anchor count", spectron_checkpoint["gui_stretch_modes_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint TGUIRender colors anchor count", spectron_checkpoint["tgui_render_colors_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint THTMLDefinitions defaults anchor count", spectron_checkpoint["thtml_definitions_defaults_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint TClient static strings anchor count", spectron_checkpoint["tclient_static_strings_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint TSocket static strings anchor count", spectron_checkpoint["tsocket_static_strings_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint Android TapJoy/video anchor count", spectron_checkpoint["android_tapjoy_video_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint sounds music-state anchor count", spectron_checkpoint["sounds_music_state_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint sounds effect anchor count", spectron_checkpoint["sounds_effect_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint sounds control anchor count", spectron_checkpoint["sounds_control_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint sounds tail anchor count", spectron_checkpoint["sounds_tail_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint TSoundEffect methods anchor count", spectron_checkpoint["tsound_effect_methods_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint sound Java small-method anchor count", spectron_checkpoint["sound_java_small_methods_anchors"]["verified_name_count"], 7)
    check("Spectron checkpoint sound Java destructor anchor count", spectron_checkpoint["sound_java_destructor_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint sound Java D1 anchor count", spectron_checkpoint["sound_java_d1_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint sound base-interface anchor count", spectron_checkpoint["sound_base_interface_anchors"]["verified_name_count"], 18)
    check("Spectron checkpoint HTML page anchor count", spectron_checkpoint["html_page_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint GUI text-list anchor count", spectron_checkpoint["gui_text_list_anchors"]["verified_name_count"], 8)
    check("Spectron checkpoint GUI text-list entry anchor count", spectron_checkpoint["gui_text_list_entry_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint encryption-GraalVar anchor count", spectron_checkpoint["encryption_graalvar_anchors"]["verified_name_count"], 3)
    check("Spectron checkpoint compact-residual anchor count", spectron_checkpoint["compact_residual_anchors"]["verified_name_count"], 13)
    check("Spectron checkpoint T2DMatrixManager anchor count", spectron_checkpoint["t2d_matrix_manager_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint MRandom anchor count", spectron_checkpoint["mrandom_anchors"]["verified_name_count"], 29)
    check("Spectron checkpoint residual TStringList anchor count", spectron_checkpoint["tstringlist_residual_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint server-object lifecycle anchor count", spectron_checkpoint["server_object_lifecycle_anchors"]["verified_name_count"], 49)
    check("Spectron checkpoint GuiMLTextCtrl residual anchor count", spectron_checkpoint["gui_ml_text_residual_anchors"]["verified_name_count"], 39)
    check("Spectron checkpoint database hash", spectron_checkpoint["database"]["sha256"], "d82c297a781db70c75d56b9dad679db224127653c55a5c312542ab698e5b53b5")
    check(
        "Spectron v219 checkpoint artifact",
        spectron_checkpoint_v219["artifact"],
        "spectron_translation_checkpoint_20260828",
    )
    check(
        "Spectron v219 checkpoint parent",
        spectron_checkpoint_v219["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260826",
    )
    check(
        "Spectron v219 checkpoint database hash",
        spectron_checkpoint_v219["database"]["sha256"],
        "bf219383ca3b9d99ca0fc8133b61c8204263458dc916f3f0cf846e41f9383097",
    )
    check(
        "Spectron v219 checkpoint default sub count",
        spectron_checkpoint_v219["database"]["default_sub_function_count"],
        1135,
    )
    check(
        "Spectron v219 checkpoint GUI property count",
        spectron_checkpoint_v219["gui_text_list_entry_property_anchors"]["verified_name_count"],
        30,
    )
    check(
        "Spectron v220 checkpoint artifact",
        spectron_checkpoint_v220["artifact"],
        "spectron_translation_checkpoint_20260828_v220",
    )
    check(
        "Spectron v220 checkpoint parent",
        spectron_checkpoint_v220["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828",
    )
    check(
        "Spectron v220 checkpoint database hash",
        spectron_checkpoint_v220["database"]["sha256"],
        "8ed23c3f19d77413dd044e64b810352c66dc76660e34b7c205d9648a82edd09f",
    )
    check(
        "Spectron v220 checkpoint default sub count",
        spectron_checkpoint_v220["database"]["default_sub_function_count"],
        1125,
    )
    check(
        "Spectron v220 checkpoint residual count",
        spectron_checkpoint_v220["gui_text_list_residual_anchors"]["verified_name_count"],
        10,
    )
    check(
        "Spectron v221 checkpoint artifact",
        spectron_checkpoint_v221["artifact"],
        "spectron_translation_checkpoint_20260828_v221",
    )
    check(
        "Spectron v221 checkpoint parent",
        spectron_checkpoint_v221["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v220",
    )
    check(
        "Spectron v221 checkpoint database hash",
        spectron_checkpoint_v221["database"]["sha256"],
        "8fccf4d07bcb149f4a682144c450b8ae36fe854a15dcc6e5491ea19c85c4e1f6",
    )
    check(
        "Spectron v221 checkpoint default sub count",
        spectron_checkpoint_v221["database"]["default_sub_function_count"],
        1109,
    )
    check(
        "Spectron v221 checkpoint property count",
        spectron_checkpoint_v221["gui_drawing_showimg_property_anchors"]["verified_name_count"],
        16,
    )
    check(
        "Spectron v222 checkpoint artifact",
        spectron_checkpoint_v222["artifact"],
        "spectron_translation_checkpoint_20260828_v222",
    )
    check(
        "Spectron v222 checkpoint parent",
        spectron_checkpoint_v222["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v221",
    )
    check(
        "Spectron v222 checkpoint database hash",
        spectron_checkpoint_v222["database"]["sha256"],
        "858a8ded6274a0bc186fdbade4beab3951e6e5d6b6814b467afa4b4626431b6f",
    )
    check(
        "Spectron v222 checkpoint default sub count",
        spectron_checkpoint_v222["database"]["default_sub_function_count"],
        1106,
    )
    check(
        "Spectron v222 checkpoint property count",
        spectron_checkpoint_v222["gui_browser_property_anchors"]["verified_name_count"],
        3,
    )
    check(
        "Spectron v223 checkpoint artifact",
        spectron_checkpoint_v223["artifact"],
        "spectron_translation_checkpoint_20260828_v223",
    )
    check(
        "Spectron v223 checkpoint parent",
        spectron_checkpoint_v223["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v222",
    )
    check(
        "Spectron v223 checkpoint database hash",
        spectron_checkpoint_v223["database"]["sha256"],
        "c0d1c3257745f841a4b24393828905c83a0ba8778f312d1471fae8f48969fe05",
    )
    check(
        "Spectron v223 checkpoint default sub count",
        spectron_checkpoint_v223["database"]["default_sub_function_count"],
        1101,
    )
    check(
        "Spectron v223 checkpoint property count",
        spectron_checkpoint_v223["gui_context_menu_property_anchors"]["verified_name_count"],
        5,
    )
    check(
        "Spectron v224 checkpoint artifact",
        spectron_checkpoint_v224["artifact"],
        "spectron_translation_checkpoint_20260828_v224",
    )
    check(
        "Spectron v224 checkpoint parent",
        spectron_checkpoint_v224["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v223",
    )
    check(
        "Spectron v224 checkpoint database hash",
        spectron_checkpoint_v224["database"]["sha256"],
        "aed4f3fe539b4616519dfefdda98c5eed7a7357efd740ed9bc44cfcaa24d0547",
    )
    check(
        "Spectron v224 checkpoint default sub count",
        spectron_checkpoint_v224["database"]["default_sub_function_count"],
        1095,
    )
    check(
        "Spectron v224 checkpoint residual count",
        spectron_checkpoint_v224["gui_array_popup_residual_anchors"]["verified_name_count"],
        6,
    )
    check(
        "Spectron v225 checkpoint artifact",
        spectron_checkpoint_v225["artifact"],
        "spectron_translation_checkpoint_20260828_v225",
    )
    check(
        "Spectron v225 checkpoint parent",
        spectron_checkpoint_v225["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v224",
    )
    check(
        "Spectron v225 checkpoint database hash",
        spectron_checkpoint_v225["database"]["sha256"],
        "a6626fec1ef58be22f30e2f23c83ce2573602b556c1f140c9da1530f19aa9f1b",
    )
    check(
        "Spectron v225 checkpoint default sub count",
        spectron_checkpoint_v225["database"]["default_sub_function_count"],
        1094,
    )
    check(
        "Spectron v225 checkpoint popup rows count",
        spectron_checkpoint_v225["gui_popup_rows_anchor"]["verified_name_count"],
        1,
    )
    check(
        "Spectron v226 checkpoint artifact",
        spectron_checkpoint_v226["artifact"],
        "spectron_translation_checkpoint_20260828_v226",
    )
    check(
        "Spectron v226 checkpoint parent",
        spectron_checkpoint_v226["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v225",
    )
    check(
        "Spectron v226 checkpoint database hash",
        spectron_checkpoint_v226["database"]["sha256"],
        "ae8ab50751ac9f82e108fff9de5ae0274b857c44db27522821ac7c5cdefad45a",
    )
    check(
        "Spectron v226 checkpoint default sub count",
        spectron_checkpoint_v226["database"]["default_sub_function_count"],
        1093,
    )
    check(
        "Spectron v226 checkpoint progress getter count",
        spectron_checkpoint_v226["gui_progress_getter_anchor"]["verified_name_count"],
        1,
    )
    check(
        "Spectron v227 checkpoint artifact",
        spectron_checkpoint_v227["artifact"],
        "spectron_translation_checkpoint_20260828_v227",
    )
    check(
        "Spectron v227 checkpoint parent",
        spectron_checkpoint_v227["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v226",
    )
    check(
        "Spectron v227 checkpoint database hash",
        spectron_checkpoint_v227["database"]["sha256"],
        "150ad989b94e83ebcd6287aeb935961c0b4081c99856a59ce4d789ce1d275276",
    )
    check(
        "Spectron v227 checkpoint default sub count",
        spectron_checkpoint_v227["database"]["default_sub_function_count"],
        1091,
    )
    check(
        "Spectron v227 checkpoint selection count",
        spectron_checkpoint_v227["gui_text_list_selection_script_anchors"]["verified_name_count"],
        2,
    )
    check(
        "Spectron v228 checkpoint artifact",
        spectron_checkpoint_v228["artifact"],
        "spectron_translation_checkpoint_20260828_v228",
    )
    check(
        "Spectron v228 checkpoint parent",
        spectron_checkpoint_v228["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v227",
    )
    check(
        "Spectron v228 checkpoint database hash",
        spectron_checkpoint_v228["database"]["sha256"],
        "eeea668d6fa3eb549c41b9dbec001b5c6a7c7e0a44c17a14faea45664004b06b",
    )
    check(
        "Spectron v228 checkpoint default sub count",
        spectron_checkpoint_v228["database"]["default_sub_function_count"],
        1087,
    )
    check(
        "Spectron v228 checkpoint MRandom count",
        spectron_checkpoint_v228["mrandom_property_residual_anchors"]["verified_name_count"],
        4,
    )
    check(
        "Spectron v229 checkpoint artifact",
        spectron_checkpoint_v229["artifact"],
        "spectron_translation_checkpoint_20260828_v229",
    )
    check(
        "Spectron v229 checkpoint parent",
        spectron_checkpoint_v229["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v228",
    )
    check(
        "Spectron v229 checkpoint database hash",
        spectron_checkpoint_v229["database"]["sha256"],
        "a2f715b293c1bd6bd0a29d8299ad6d492af6e23a8459b549486de756dcab79c8",
    )
    check(
        "Spectron v229 checkpoint default sub count",
        spectron_checkpoint_v229["database"]["default_sub_function_count"],
        1084,
    )
    check(
        "Spectron v229 checkpoint drawing-panel script count",
        spectron_checkpoint_v229["gui_drawing_panel_script_anchors"]["verified_name_count"],
        3,
    )
    check(
        "Spectron v230 checkpoint artifact",
        spectron_checkpoint_v230["artifact"],
        "spectron_translation_checkpoint_20260828_v230",
    )
    check(
        "Spectron v230 checkpoint parent",
        spectron_checkpoint_v230["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v229",
    )
    check(
        "Spectron v230 checkpoint database hash",
        spectron_checkpoint_v230["database"]["sha256"],
        "220e9fe71bb8e93472ed7892b4b16363559e1d24a3733bb876fd6abb393023ba",
    )
    check(
        "Spectron v230 checkpoint default sub count",
        spectron_checkpoint_v230["database"]["default_sub_function_count"],
        1079,
    )
    check(
        "Spectron v230 checkpoint TClient script-property count",
        spectron_checkpoint_v230["tclient_script_property_anchors"]["verified_name_count"],
        5,
    )
    check(
        "Spectron v231 checkpoint artifact",
        spectron_checkpoint_v231["artifact"],
        "spectron_translation_checkpoint_20260828_v231",
    )
    check(
        "Spectron v231 checkpoint parent",
        spectron_checkpoint_v231["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v230",
    )
    check(
        "Spectron v231 checkpoint database hash",
        spectron_checkpoint_v231["database"]["sha256"],
        "329596637abe0446019eb80c952e4536157bed027dce3c5f40fc6b8a68cf2fa2",
    )
    check(
        "Spectron v231 checkpoint default sub count",
        spectron_checkpoint_v231["database"]["default_sub_function_count"],
        1073,
    )
    check(
        "Spectron v231 checkpoint file-cache property count",
        spectron_checkpoint_v231["file_cache_property_anchors"]["verified_name_count"],
        6,
    )
    check(
        "Spectron v232 TClient handler artifact",
        spectron_tclient_handler_anchors["artifact"],
        "spectron_tclient_handler_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v232 TClient handler network",
        spectron_tclient_handler_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v232 TClient handler anchor count",
        spectron_tclient_handler_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron v232 TClient handler correction count",
        spectron_tclient_handler_anchors["summary"]["correction_count"],
        1,
    )
    check(
        "Spectron v232 TClient handler high-confidence count",
        spectron_tclient_handler_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron v232 TClient handler target defaults",
        spectron_tclient_handler_anchors["summary"]["target_default_name_count"],
        2,
    )
    check(
        "Spectron v232 TClient handler normalized exact count",
        spectron_tclient_handler_anchors["summary"]["normalized_shape_exact_count"],
        0,
    )
    check(
        "Spectron v232 TClient handler layout count",
        spectron_tclient_handler_anchors["summary"]["layout_change_count"],
        2,
    )
    handler_rows = {
        row["original_name"]: row
        for row in spectron_tclient_handler_anchors["anchors"]
    }
    check(
        "Spectron v232 server-login target",
        handler_rows["TClient_handleServerLoginPacket"]["spectron_ea"],
        "0x1f37e0",
    )
    check(
        "Spectron v232 server-modifies target",
        handler_rows["TClient_processServerModifies"]["spectron_ea"],
        "0x1eefa0",
    )
    correction = spectron_tclient_handler_anchors["corrections"][0]
    check("Spectron v232 correction target", correction["target_ea"], "0xecba0")
    check(
        "Spectron v232 correction old alias",
        correction["current_name"],
        "v18_TClient_processServerModifies",
    )
    check(
        "Spectron v232 correction restored symbol",
        correction["restored_name"],
        "_ZN10yL3_IaDMFt10XEm8Ta8FEQEP10vuuHgangcFRK10C8THgaTQxF",
    )
    check(
        "Spectron v232 checkpoint artifact",
        spectron_checkpoint_v232["artifact"],
        "spectron_translation_checkpoint_20260828_v232",
    )
    check(
        "Spectron v232 checkpoint parent",
        spectron_checkpoint_v232["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v231",
    )
    check(
        "Spectron v232 checkpoint database hash",
        spectron_checkpoint_v232["database"]["sha256"],
        "51b76f3945f282bc62c1fb72a5749115315db1e6d5fac5e04ef4208c816a3bf6",
    )
    check(
        "Spectron v232 checkpoint default sub count",
        spectron_checkpoint_v232["database"]["default_sub_function_count"],
        1071,
    )
    check(
        "Spectron v232 checkpoint TClient handler count",
        spectron_checkpoint_v232["tclient_handler_anchors"]["verified_name_count"],
        2,
    )
    check(
        "Spectron v233 target-only label artifact",
        spectron_target_only_labels["artifact"],
        "spectron_target_only_callback_labels_20260828",
    )
    check(
        "Spectron v233 target-only label network",
        spectron_target_only_labels["network_contacted"],
        False,
    )
    check(
        "Spectron v233 target-only label count",
        spectron_target_only_labels["summary"]["label_count"],
        3,
    )
    check(
        "Spectron v233 target-only high-confidence count",
        spectron_target_only_labels["summary"]["high_confidence_count"],
        3,
    )
    check(
        "Spectron v233 target-only default count",
        spectron_target_only_labels["summary"]["target_default_name_count"],
        3,
    )
    check(
        "Spectron v233 target-only source counterpart count",
        spectron_target_only_labels["summary"]["source_counterpart_count"],
        0,
    )
    check(
        "Spectron v233 target-only debug-handler count",
        spectron_target_only_labels["summary"]["debug_handler_count"],
        2,
    )
    check(
        "Spectron v233 target-only adapter count",
        spectron_target_only_labels["summary"]["adapter_count"],
        1,
    )
    target_only_rows = {
        row["script_name"]: row for row in spectron_target_only_labels["labels"]
    }
    check(
        "Spectron v233 debug-handler target",
        target_only_rows["setdebugdatahandlers"]["target_ea"],
        "0x1f00f8",
    )
    check(
        "Spectron v233 debug-handler authorization target",
        target_only_rows["adventure_setdebugdatahandlersauthorization"]["target_ea"],
        "0x1f0010",
    )
    check(
        "Spectron v233 other-player adapter target",
        target_only_rows["tclient_setotherplayerprops"]["target_ea"],
        "0x1f2160",
    )
    check(
        "Spectron v233 target-only source mappings",
        [row["source_counterpart"] for row in spectron_target_only_labels["labels"]],
        [None, None, None],
    )
    check(
        "Spectron v233 checkpoint artifact",
        spectron_checkpoint_v233["artifact"],
        "spectron_translation_checkpoint_20260828_v233",
    )
    check(
        "Spectron v233 checkpoint parent",
        spectron_checkpoint_v233["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v232",
    )
    check(
        "Spectron v233 checkpoint database hash",
        spectron_checkpoint_v233["database"]["sha256"],
        "21fa935e68dd605c0549656df3a3b832d0c91e080b7d703b2042132ba078ddd6",
    )
    check(
        "Spectron v233 checkpoint default sub count",
        spectron_checkpoint_v233["database"]["default_sub_function_count"],
        1068,
    )
    check(
        "Spectron v233 checkpoint target-only count",
        spectron_checkpoint_v233["target_only_callback_labels"]["verified_name_count"],
        3,
    )
    check(
        "Spectron v234 player-hurt artifact",
        spectron_tclient_playerhurt_anchor["artifact"],
        "spectron_tclient_playerhurt_property_manual_translation_anchor_20260828",
    )
    check(
        "Spectron v234 player-hurt network",
        spectron_tclient_playerhurt_anchor["network_contacted"],
        False,
    )
    check(
        "Spectron v234 player-hurt anchor count",
        spectron_tclient_playerhurt_anchor["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron v234 player-hurt boundary recovery count",
        spectron_tclient_playerhurt_anchor["summary"]["boundary_recovery_count"],
        1,
    )
    check(
        "Spectron v234 player-hurt high confidence",
        spectron_tclient_playerhurt_anchor["summary"]["high_confidence_count"],
        1,
    )
    playerhurt = spectron_tclient_playerhurt_anchor["anchors"][0]
    check(
        "Spectron v234 player-hurt source",
        playerhurt["original_ea"],
        "0x1ed158",
    )
    check(
        "Spectron v234 player-hurt target",
        playerhurt["spectron_ea"],
        "0x1f1b08",
    )
    check(
        "Spectron v234 player-hurt target boundary",
        playerhurt["spectron_function_end"],
        "0x1f1b94",
    )
    check(
        "Spectron v234 player-hurt table record",
        playerhurt["target_script_table_record"],
        "0x398010",
    )
    check(
        "Spectron v234 player-hurt alias",
        playerhurt["proposed_name"],
        "v18_TClient_script_tclient_setplayerhurt",
    )
    check(
        "Spectron v234 checkpoint artifact",
        spectron_checkpoint_v234["artifact"],
        "spectron_translation_checkpoint_20260828_v234",
    )
    check(
        "Spectron v234 checkpoint parent",
        spectron_checkpoint_v234["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v233",
    )
    check(
        "Spectron v234 checkpoint database hash",
        spectron_checkpoint_v234["database"]["sha256"],
        "c7dda722fbab84a403ed8ba21351af98dc01e181c640c5048c126b2ff4f669b2",
    )
    check(
        "Spectron v234 checkpoint function count",
        spectron_checkpoint_v234["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v234 checkpoint default sub count",
        spectron_checkpoint_v234["database"]["default_sub_function_count"],
        1068,
    )
    check(
        "Spectron v234 checkpoint player-hurt count",
        spectron_checkpoint_v234["tclient_playerhurt_property_anchor"]["verified_name_count"],
        1,
    )
    check(
        "Spectron v235 GSFunctions property artifact",
        spectron_gsfunctions_property_anchors["artifact"],
        "spectron_gsfunctions_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v235 GSFunctions property network",
        spectron_gsfunctions_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v235 GSFunctions property anchor count",
        spectron_gsfunctions_property_anchors["summary"]["anchor_count"],
        12,
    )
    check(
        "Spectron v235 GSFunctions property high confidence",
        spectron_gsfunctions_property_anchors["summary"]["high_confidence_count"],
        12,
    )
    check(
        "Spectron v235 GSFunctions property target default count",
        spectron_gsfunctions_property_anchors["summary"]["target_default_name_count"],
        12,
    )
    check(
        "Spectron v235 GSFunctions property normalized shape count",
        spectron_gsfunctions_property_anchors["summary"]["normalized_shape_exact_count"],
        12,
    )
    check(
        "Spectron v235 GSFunctions property full metric count",
        spectron_gsfunctions_property_anchors["summary"]["full_metric_exact_count"],
        3,
    )
    check(
        "Spectron v235 GSFunctions property layout count",
        spectron_gsfunctions_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v235 GSFunctions property register-detail count",
        spectron_gsfunctions_property_anchors["summary"]["register_detail_difference_count"],
        9,
    )
    property_rows = {
        row["original_name"]: row
        for row in spectron_gsfunctions_property_anchors["anchors"]
    }
    check(
        "Spectron v235 carries-bush target",
        property_rows["GSFunctionsClient_get_carriesbush"]["spectron_ea"],
        "0x159414",
    )
    check(
        "Spectron v235 mouse-y target",
        property_rows["GSFunctionsClient_get_mousescreeny"]["spectron_ea"],
        "0x15a000",
    )
    check(
        "Spectron v235 client-height target",
        property_rows["GuiControl_setClientHeight"]["spectron_ea"],
        "0x1b6ccc",
    )
    check(
        "Spectron v235 animation target",
        property_rows["GuiControl_getIsInAnimation"]["spectron_ea"],
        "0x1b6e44",
    )
    check(
        "Spectron v235 checkpoint artifact",
        spectron_checkpoint_v235["artifact"],
        "spectron_translation_checkpoint_20260828_v235",
    )
    check(
        "Spectron v235 checkpoint parent",
        spectron_checkpoint_v235["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v234",
    )
    check(
        "Spectron v235 checkpoint database hash",
        spectron_checkpoint_v235["database"]["sha256"],
        "b58d447613b039f930e5ecd179a56a0e5ad19958715445f0663272dc830e0719",
    )
    check(
        "Spectron v235 checkpoint function count",
        spectron_checkpoint_v235["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v235 checkpoint default sub count",
        spectron_checkpoint_v235["database"]["default_sub_function_count"],
        1056,
    )
    check(
        "Spectron v235 checkpoint property count",
        spectron_checkpoint_v235["gsfunctions_property_anchors"]["verified_name_count"],
        12,
    )
    check(
        "Spectron v236 time-files-input artifact",
        spectron_time_files_input_anchors["artifact"],
        "spectron_time_files_input_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v236 time-files-input network",
        spectron_time_files_input_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v236 time-files-input anchor count",
        spectron_time_files_input_anchors["summary"]["anchor_count"],
        22,
    )
    check(
        "Spectron v236 time-files-input high confidence",
        spectron_time_files_input_anchors["summary"]["high_confidence_count"],
        22,
    )
    check(
        "Spectron v236 time-files-input target default count",
        spectron_time_files_input_anchors["summary"]["target_default_name_count"],
        22,
    )
    check(
        "Spectron v236 time-files-input normalized shape count",
        spectron_time_files_input_anchors["summary"]["normalized_shape_exact_count"],
        21,
    )
    check(
        "Spectron v236 time-files-input full metric count",
        spectron_time_files_input_anchors["summary"]["full_metric_exact_count"],
        17,
    )
    check(
        "Spectron v236 time-files-input layout count",
        spectron_time_files_input_anchors["summary"]["layout_change_count"],
        1,
    )
    check(
        "Spectron v236 time-files-input register-detail count",
        spectron_time_files_input_anchors["summary"]["register_detail_difference_count"],
        5,
    )
    check(
        "Spectron v236 time-files-input expanded body count",
        spectron_time_files_input_anchors["summary"]["expanded_body_count"],
        1,
    )
    check(
        "Spectron v236 time-files-input additional registration count",
        spectron_time_files_input_anchors["summary"]["additional_registration_count"],
        1,
    )
    time_files_rows = {
        row["original_name"]: row
        for row in spectron_time_files_input_anchors["anchors"]
    }
    check(
        "Spectron v236 identification target",
        time_files_rows["TIdentification_script_getOSID"]["spectron_ea"],
        "0xed694",
    )
    check(
        "Spectron v236 set-file-mod-time target",
        time_files_rows["TFileScripting_script_setFileModTime"]["spectron_ea"],
        "0xfeac0",
    )
    check(
        "Spectron v236 hardware-keyboard target",
        time_files_rows["TInput_getHardwareKeyboardEnabled"]["spectron_ea"],
        "0x16c4c8",
    )
    check(
        "Spectron v236 checkpoint artifact",
        spectron_checkpoint_v236["artifact"],
        "spectron_translation_checkpoint_20260828_v236",
    )
    check(
        "Spectron v236 checkpoint parent",
        spectron_checkpoint_v236["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v235",
    )
    check(
        "Spectron v236 checkpoint database hash",
        spectron_checkpoint_v236["database"]["sha256"],
        "04b1c4438c1d9473f949a1e27d8cf60b1d1199fddac80440a23429c8e5b1f44a",
    )
    check(
        "Spectron v236 checkpoint function count",
        spectron_checkpoint_v236["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v236 checkpoint default sub count",
        spectron_checkpoint_v236["database"]["default_sub_function_count"],
        1034,
    )
    check(
        "Spectron v236 checkpoint anchor count",
        spectron_checkpoint_v236["time_files_input_anchors"]["verified_name_count"],
        22,
    )
    check(
        "Spectron v237 level-object artifact",
        spectron_level_object_property_anchors["artifact"],
        "spectron_level_object_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v237 level-object network",
        spectron_level_object_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v237 level-object anchor count",
        spectron_level_object_property_anchors["summary"]["anchor_count"],
        7,
    )
    check(
        "Spectron v237 level-object high confidence",
        spectron_level_object_property_anchors["summary"]["high_confidence_count"],
        7,
    )
    check(
        "Spectron v237 level-object target default count",
        spectron_level_object_property_anchors["summary"]["target_default_name_count"],
        7,
    )
    check(
        "Spectron v237 level-object normalized shape count",
        spectron_level_object_property_anchors["summary"]["normalized_shape_exact_count"],
        7,
    )
    check(
        "Spectron v237 level-object full metric count",
        spectron_level_object_property_anchors["summary"]["full_metric_exact_count"],
        7,
    )
    check(
        "Spectron v237 level-object layout count",
        spectron_level_object_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v237 level-object boundary recovery count",
        spectron_level_object_property_anchors["summary"]["boundary_recovery_count"],
        1,
    )
    level_object_rows = {
        row["original_name"]: row
        for row in spectron_level_object_property_anchors["anchors"]
    }
    check(
        "Spectron v237 level-object z target",
        level_object_rows["TLevelObject_getZ"]["spectron_ea"],
        "0x16d460",
    )
    check(
        "Spectron v237 level-object z boundary",
        level_object_rows["TLevelObject_getZ"]["spectron_function_end"],
        "0x16d480",
    )
    check(
        "Spectron v237 level-object z metric exact",
        level_object_rows["TLevelObject_getZ"]["full_metric_equal"],
        True,
    )
    check(
        "Spectron v237 checkpoint artifact",
        spectron_checkpoint_v237["artifact"],
        "spectron_translation_checkpoint_20260828_v237",
    )
    check(
        "Spectron v237 checkpoint parent",
        spectron_checkpoint_v237["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v236",
    )
    check(
        "Spectron v237 checkpoint database hash",
        spectron_checkpoint_v237["database"]["sha256"],
        "5229c4d4d67261076bd57c46c8331426ac775afdac6a578f409764b68e5ef872",
    )
    check(
        "Spectron v237 checkpoint function count",
        spectron_checkpoint_v237["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v237 checkpoint default sub count",
        spectron_checkpoint_v237["database"]["default_sub_function_count"],
        1028,
    )
    check(
        "Spectron v237 checkpoint anchor count",
        spectron_checkpoint_v237["level_object_property_anchors"]["verified_name_count"],
        7,
    )
    check(
        "Spectron v238 Gani property artifact",
        spectron_gani_property_anchors["artifact"],
        "spectron_gani_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v238 Gani property network",
        spectron_gani_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v238 Gani property anchor count",
        spectron_gani_property_anchors["summary"]["anchor_count"],
        8,
    )
    check(
        "Spectron v238 Gani property high confidence",
        spectron_gani_property_anchors["summary"]["high_confidence_count"],
        8,
    )
    check(
        "Spectron v238 Gani property target default count",
        spectron_gani_property_anchors["summary"]["target_default_name_count"],
        8,
    )
    check(
        "Spectron v238 Gani property normalized shape count",
        spectron_gani_property_anchors["summary"]["normalized_shape_exact_count"],
        6,
    )
    check(
        "Spectron v238 Gani property full metric count",
        spectron_gani_property_anchors["summary"]["full_metric_exact_count"],
        5,
    )
    check(
        "Spectron v238 Gani property layout count",
        spectron_gani_property_anchors["summary"]["layout_change_count"],
        2,
    )
    check(
        "Spectron v238 Gani property register-detail count",
        spectron_gani_property_anchors["summary"]["register_detail_difference_count"],
        3,
    )
    check(
        "Spectron v238 Gani duplicate registration count",
        spectron_gani_property_anchors["summary"]["duplicate_registration_count"],
        1,
    )
    gani_rows = {
        row["original_name"]: row
        for row in spectron_gani_property_anchors["anchors"]
    }
    check(
        "Spectron v238 Gani body target",
        gani_rows["TGaniParam_getStringField376"]["spectron_ea"],
        "0x160cc0",
    )
    check(
        "Spectron v238 Gani enable setter target",
        gani_rows["TGaniObject_setEnableMovieReposition"]["spectron_ea"],
        "0x160550",
    )
    check(
        "Spectron v238 Gani duplicate body registration",
        gani_rows["TGaniParam_getStringField376"]["additional_registrations"][0]["script_name"],
        "bodyimg",
    )
    check(
        "Spectron v238 checkpoint artifact",
        spectron_checkpoint_v238["artifact"],
        "spectron_translation_checkpoint_20260828_v238",
    )
    check(
        "Spectron v238 checkpoint parent",
        spectron_checkpoint_v238["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v237",
    )
    check(
        "Spectron v238 checkpoint database hash",
        spectron_checkpoint_v238["database"]["sha256"],
        "b9e8068236409064bb27bde0f3f564398cc3ed7c664bc46af6eb5c5ce801f6a3",
    )
    check(
        "Spectron v238 checkpoint function count",
        spectron_checkpoint_v238["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v238 checkpoint default sub count",
        spectron_checkpoint_v238["database"]["default_sub_function_count"],
        1020,
    )
    check(
        "Spectron v238 checkpoint anchor count",
        spectron_checkpoint_v238["gani_property_anchors"]["verified_name_count"],
        8,
    )
    check(
        "Spectron v239 Options property artifact",
        spectron_options_property_anchors["artifact"],
        "spectron_options_property_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v239 Options property network",
        spectron_options_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v239 Options property anchor count",
        spectron_options_property_anchors["summary"]["anchor_count"],
        30,
    )
    check(
        "Spectron v239 Options property high confidence",
        spectron_options_property_anchors["summary"]["high_confidence_count"],
        30,
    )
    check(
        "Spectron v239 Options property target default count",
        spectron_options_property_anchors["summary"]["target_default_name_count"],
        30,
    )
    check(
        "Spectron v239 Options property normalized shape count",
        spectron_options_property_anchors["summary"]["normalized_shape_exact_count"],
        30,
    )
    check(
        "Spectron v239 Options property full metric count",
        spectron_options_property_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron v239 Options property layout count",
        spectron_options_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v239 Options property register-detail count",
        spectron_options_property_anchors["summary"]["register_detail_difference_count"],
        30,
    )
    check(
        "Spectron v239 Options property getter count",
        spectron_options_property_anchors["summary"]["getter_count"],
        17,
    )
    check(
        "Spectron v239 Options property setter count",
        spectron_options_property_anchors["summary"]["setter_count"],
        13,
    )
    check(
        "Spectron v239 Options preexisting target aliases",
        spectron_options_property_anchors["summary"]["preexisting_target_alias_count"],
        2,
    )
    options_rows = {
        row["original_name"]: row
        for row in spectron_options_property_anchors["anchors"]
    }
    check(
        "Spectron v239 Options cookie getter target",
        options_rows["TOptions_get_graalplugincookie"]["spectron_ea"],
        "0x16df10",
    )
    check(
        "Spectron v239 Options screenshot setter target",
        options_rows["TOptions_set_pref__video__screenshotformat"]["spectron_ea"],
        "0x16de54",
    )
    check(
        "Spectron v239 checkpoint artifact",
        spectron_checkpoint_v239["artifact"],
        "spectron_translation_checkpoint_20260828_v239",
    )
    check(
        "Spectron v239 checkpoint parent",
        spectron_checkpoint_v239["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v238",
    )
    check(
        "Spectron v239 checkpoint database hash",
        spectron_checkpoint_v239["database"]["sha256"],
        "4b83ebdffa26611933a959770f39e1d43b1ff64d796d7d28c2c04c3aec4ff021",
    )
    check(
        "Spectron v239 checkpoint function count",
        spectron_checkpoint_v239["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v239 checkpoint default sub count",
        spectron_checkpoint_v239["database"]["default_sub_function_count"],
        990,
    )
    check(
        "Spectron v239 checkpoint anchor count",
        spectron_checkpoint_v239["options_property_anchors"]["verified_name_count"],
        30,
    )
    check(
        "Spectron v240 particle-emitter property artifact",
        spectron_particle_emitter_property_anchors["artifact"],
        "spectron_particle_emitter_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v240 particle-emitter property network",
        spectron_particle_emitter_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v240 particle-emitter property anchor count",
        spectron_particle_emitter_property_anchors["summary"]["anchor_count"],
        42,
    )
    check(
        "Spectron v240 particle-emitter property high confidence",
        spectron_particle_emitter_property_anchors["summary"]["high_confidence_count"],
        42,
    )
    check(
        "Spectron v240 particle-emitter property target default count",
        spectron_particle_emitter_property_anchors["summary"]["target_default_name_count"],
        42,
    )
    check(
        "Spectron v240 particle-emitter property normalized shape count",
        spectron_particle_emitter_property_anchors["summary"]["normalized_shape_exact_count"],
        42,
    )
    check(
        "Spectron v240 particle-emitter property full metric count",
        spectron_particle_emitter_property_anchors["summary"]["full_metric_exact_count"],
        42,
    )
    check(
        "Spectron v240 particle-emitter property layout count",
        spectron_particle_emitter_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v240 particle-emitter property register-detail count",
        spectron_particle_emitter_property_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    check(
        "Spectron v240 particle-emitter property getter count",
        spectron_particle_emitter_property_anchors["summary"]["getter_count"],
        26,
    )
    check(
        "Spectron v240 particle-emitter property setter count",
        spectron_particle_emitter_property_anchors["summary"]["setter_count"],
        16,
    )
    check(
        "Spectron v240 particle-emitter preexisting target aliases",
        spectron_particle_emitter_property_anchors["summary"]["preexisting_target_alias_count"],
        9,
    )
    particle_rows = {
        row["original_name"]: row
        for row in spectron_particle_emitter_property_anchors["anchors"]
    }
    check(
        "Spectron v240 particle-emitter attach getter target",
        particle_rows["TParticleEmitter_get_attachposition"]["spectron_ea"],
        "0x242028",
    )
    check(
        "Spectron v240 particle-emitter particle getter target",
        particle_rows["TParticleEmitter_get_particle"]["spectron_ea"],
        "0x2422bc",
    )
    check(
        "Spectron v240 checkpoint artifact",
        spectron_checkpoint_v240["artifact"],
        "spectron_translation_checkpoint_20260828_v240",
    )
    check(
        "Spectron v240 checkpoint parent",
        spectron_checkpoint_v240["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v239",
    )
    check(
        "Spectron v240 checkpoint database hash",
        spectron_checkpoint_v240["database"]["sha256"],
        "32225a918d1ac903ae68f624937fe4d4296afe75fec63448ff6aa60b96c6cd72",
    )
    check(
        "Spectron v240 checkpoint function count",
        spectron_checkpoint_v240["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v240 checkpoint default sub count",
        spectron_checkpoint_v240["database"]["default_sub_function_count"],
        948,
    )
    check(
        "Spectron v240 checkpoint anchor count",
        spectron_checkpoint_v240["particle_emitter_property_anchors"]["verified_name_count"],
        42,
    )
    check(
        "Spectron v241 particle-emitter script artifact",
        spectron_particle_emitter_script_anchors["artifact"],
        "spectron_particle_emitter_script_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v241 particle-emitter script network",
        spectron_particle_emitter_script_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v241 particle-emitter script anchor count",
        spectron_particle_emitter_script_anchors["summary"]["anchor_count"],
        3,
    )
    check(
        "Spectron v241 particle-emitter script high confidence",
        spectron_particle_emitter_script_anchors["summary"]["high_confidence_count"],
        3,
    )
    check(
        "Spectron v241 particle-emitter script target default count",
        spectron_particle_emitter_script_anchors["summary"]["target_default_name_count"],
        3,
    )
    check(
        "Spectron v241 particle-emitter script normalized shape count",
        spectron_particle_emitter_script_anchors["summary"]["normalized_shape_exact_count"],
        3,
    )
    check(
        "Spectron v241 particle-emitter script full metric count",
        spectron_particle_emitter_script_anchors["summary"]["full_metric_exact_count"],
        3,
    )
    check(
        "Spectron v241 particle-emitter script layout count",
        spectron_particle_emitter_script_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v241 particle-emitter script register-detail count",
        spectron_particle_emitter_script_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    particle_script_rows = {
        row["original_name"]: row
        for row in spectron_particle_emitter_script_anchors["anchors"]
    }
    check(
        "Spectron v241 addglobalmodifier target",
        particle_script_rows["TParticleEmitter_script_addglobalmodifier"]["spectron_ea"],
        "0x2432b4",
    )
    check(
        "Spectron v241 addemitmodifier target",
        particle_script_rows["TParticleEmitter_script_addemitmodifier"]["spectron_ea"],
        "0x24348c",
    )
    check(
        "Spectron v241 checkpoint artifact",
        spectron_checkpoint_v241["artifact"],
        "spectron_translation_checkpoint_20260828_v241",
    )
    check(
        "Spectron v241 checkpoint parent",
        spectron_checkpoint_v241["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v240",
    )
    check(
        "Spectron v241 checkpoint database hash",
        spectron_checkpoint_v241["database"]["sha256"],
        "c154d03a1b28e31a06faa87876d1108c7acb971c884e4ae984cbe273573ba09e",
    )
    check(
        "Spectron v241 checkpoint function count",
        spectron_checkpoint_v241["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v241 checkpoint default sub count",
        spectron_checkpoint_v241["database"]["default_sub_function_count"],
        945,
    )
    check(
        "Spectron v241 checkpoint anchor count",
        spectron_checkpoint_v241["particle_emitter_script_anchors"]["verified_name_count"],
        3,
    )
    check(
        "Spectron v242 world-object property artifact",
        spectron_world_object_property_anchors["artifact"],
        "spectron_world_object_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v242 world-object property network",
        spectron_world_object_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v242 world-object property anchor count",
        spectron_world_object_property_anchors["summary"]["anchor_count"],
        22,
    )
    check(
        "Spectron v242 world-object property high confidence",
        spectron_world_object_property_anchors["summary"]["high_confidence_count"],
        22,
    )
    check(
        "Spectron v242 world-object property target default count",
        spectron_world_object_property_anchors["summary"]["target_default_name_count"],
        22,
    )
    check(
        "Spectron v242 world-object property normalized shape count",
        spectron_world_object_property_anchors["summary"]["normalized_shape_exact_count"],
        22,
    )
    check(
        "Spectron v242 world-object property full metric count",
        spectron_world_object_property_anchors["summary"]["full_metric_exact_count"],
        8,
    )
    check(
        "Spectron v242 world-object property layout count",
        spectron_world_object_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v242 world-object property register-detail count",
        spectron_world_object_property_anchors["summary"]["register_detail_difference_count"],
        14,
    )
    check(
        "Spectron v242 world-object property getter count",
        spectron_world_object_property_anchors["summary"]["getter_count"],
        19,
    )
    check(
        "Spectron v242 world-object property setter count",
        spectron_world_object_property_anchors["summary"]["setter_count"],
        3,
    )
    world_object_rows = {
        row["original_name"]: row
        for row in spectron_world_object_property_anchors["anchors"]
    }
    check(
        "Spectron v242 projectile X target",
        world_object_rows["TProjectile_getX"]["spectron_ea"],
        "0x1a3860",
    )
    check(
        "Spectron v242 level-link Y target",
        world_object_rows["TServerLevelLink_getY"]["spectron_ea"],
        "0x1a4578",
    )
    check(
        "Spectron v242 checkpoint artifact",
        spectron_checkpoint_v242["artifact"],
        "spectron_translation_checkpoint_20260828_v242",
    )
    check(
        "Spectron v242 checkpoint parent",
        spectron_checkpoint_v242["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v241",
    )
    check(
        "Spectron v242 checkpoint database hash",
        spectron_checkpoint_v242["database"]["sha256"],
        "6d8eb4e0dcacddce087564e3f14a7b355472cebac32f6854c007e98c740f5f44",
    )
    check(
        "Spectron v242 checkpoint function count",
        spectron_checkpoint_v242["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v242 checkpoint default sub count",
        spectron_checkpoint_v242["database"]["default_sub_function_count"],
        923,
    )
    check(
        "Spectron v242 checkpoint anchor count",
        spectron_checkpoint_v242["world_object_property_anchors"]["verified_name_count"],
        22,
    )
    check(
        "Spectron v243 player-translation property artifact",
        spectron_player_translation_property_anchors["artifact"],
        "spectron_player_translation_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v243 player-translation property network",
        spectron_player_translation_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v243 player-translation property anchor count",
        spectron_player_translation_property_anchors["summary"]["anchor_count"],
        9,
    )
    check(
        "Spectron v243 player-translation property high confidence",
        spectron_player_translation_property_anchors["summary"]["high_confidence_count"],
        9,
    )
    check(
        "Spectron v243 player-translation property target default count",
        spectron_player_translation_property_anchors["summary"]["target_default_name_count"],
        9,
    )
    check(
        "Spectron v243 player-translation property normalized shape count",
        spectron_player_translation_property_anchors["summary"]["normalized_shape_exact_count"],
        9,
    )
    check(
        "Spectron v243 player-translation property full metric count",
        spectron_player_translation_property_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron v243 player-translation property layout count",
        spectron_player_translation_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v243 player-translation property register-detail count",
        spectron_player_translation_property_anchors["summary"]["register_detail_difference_count"],
        9,
    )
    check(
        "Spectron v243 player-translation property getter count",
        spectron_player_translation_property_anchors["summary"]["getter_count"],
        6,
    )
    check(
        "Spectron v243 player-translation property setter count",
        spectron_player_translation_property_anchors["summary"]["setter_count"],
        3,
    )
    player_translation_rows = {
        row["original_name"]: row
        for row in spectron_player_translation_property_anchors["anchors"]
    }
    check(
        "Spectron v243 selected-list players target",
        player_translation_rows["TPlayer_get_selectedlistplayers"]["spectron_ea"],
        "0x170280",
    )
    check(
        "Spectron v243 language target",
        player_translation_rows["TTranslations_get_pref__graal__language"]["spectron_ea"],
        "0x195bf4",
    )
    check(
        "Spectron v243 checkpoint artifact",
        spectron_checkpoint_v243["artifact"],
        "spectron_translation_checkpoint_20260828_v243",
    )
    check(
        "Spectron v243 checkpoint parent",
        spectron_checkpoint_v243["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v242",
    )
    check(
        "Spectron v243 checkpoint database hash",
        spectron_checkpoint_v243["database"]["sha256"],
        "11d1275fbfca6b7500f430742de9e84f933d53462967e88fa61255ebad3e8e38",
    )
    check(
        "Spectron v243 checkpoint function count",
        spectron_checkpoint_v243["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v243 checkpoint default sub count",
        spectron_checkpoint_v243["database"]["default_sub_function_count"],
        914,
    )
    check(
        "Spectron v243 checkpoint anchor count",
        spectron_checkpoint_v243["player_translation_property_anchors"]["verified_name_count"],
        9,
    )
    check(
        "Spectron v244 server-NPC property artifact",
        spectron_server_npc_property_anchors["artifact"],
        "spectron_server_npc_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v244 server-NPC property network",
        spectron_server_npc_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v244 server-NPC property anchor count",
        spectron_server_npc_property_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron v244 server-NPC property high confidence",
        spectron_server_npc_property_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron v244 server-NPC property target default count",
        spectron_server_npc_property_anchors["summary"]["target_default_name_count"],
        6,
    )
    check(
        "Spectron v244 server-NPC property normalized shape count",
        spectron_server_npc_property_anchors["summary"]["normalized_shape_exact_count"],
        6,
    )
    check(
        "Spectron v244 server-NPC property full metric count",
        spectron_server_npc_property_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron v244 server-NPC property layout count",
        spectron_server_npc_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v244 server-NPC property register-detail count",
        spectron_server_npc_property_anchors["summary"]["register_detail_difference_count"],
        4,
    )
    check(
        "Spectron v244 server-NPC property getter count",
        spectron_server_npc_property_anchors["summary"]["getter_count"],
        3,
    )
    check(
        "Spectron v244 server-NPC property setter count",
        spectron_server_npc_property_anchors["summary"]["setter_count"],
        3,
    )
    server_npc_rows = {
        row["original_name"]: row
        for row in spectron_server_npc_property_anchors["anchors"]
    }
    check(
        "Spectron v244 horse-image getter target",
        server_npc_rows["TServerNPC_getHorseImg"]["spectron_ea"],
        "0x185060",
    )
    check(
        "Spectron v244 NPC Y setter target",
        server_npc_rows["TServerNPC_setY"]["spectron_ea"],
        "0x18b2e0",
    )
    check(
        "Spectron v244 checkpoint artifact",
        spectron_checkpoint_v244["artifact"],
        "spectron_translation_checkpoint_20260828_v244",
    )
    check(
        "Spectron v244 checkpoint parent",
        spectron_checkpoint_v244["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v243",
    )
    check(
        "Spectron v244 checkpoint database hash",
        spectron_checkpoint_v244["database"]["sha256"],
        "10ea7f378ae0fafa155d45da163a116477240c01970e4e61b1e7dba1efd8b942",
    )
    check(
        "Spectron v244 checkpoint function count",
        spectron_checkpoint_v244["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v244 checkpoint default sub count",
        spectron_checkpoint_v244["database"]["default_sub_function_count"],
        908,
    )
    check(
        "Spectron v244 checkpoint anchor count",
        spectron_checkpoint_v244["server_npc_property_anchors"]["verified_name_count"],
        6,
    )
    check(
        "Spectron v245 server-NPC script artifact",
        spectron_server_npc_script_anchors["artifact"],
        "spectron_server_npc_script_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v245 server-NPC script network",
        spectron_server_npc_script_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v245 server-NPC script anchor count",
        spectron_server_npc_script_anchors["summary"]["anchor_count"],
        7,
    )
    check(
        "Spectron v245 server-NPC script high confidence",
        spectron_server_npc_script_anchors["summary"]["high_confidence_count"],
        7,
    )
    check(
        "Spectron v245 server-NPC script target default count",
        spectron_server_npc_script_anchors["summary"]["target_default_name_count"],
        7,
    )
    check(
        "Spectron v245 server-NPC script normalized shape count",
        spectron_server_npc_script_anchors["summary"]["normalized_shape_exact_count"],
        7,
    )
    check(
        "Spectron v245 server-NPC script full metric count",
        spectron_server_npc_script_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron v245 server-NPC script layout count",
        spectron_server_npc_script_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v245 server-NPC script register-detail count",
        spectron_server_npc_script_anchors["summary"]["register_detail_difference_count"],
        7,
    )
    server_npc_script_rows = {
        row["original_name"]: row
        for row in spectron_server_npc_script_anchors["anchors"]
    }
    check(
        "Spectron v245 can-be-carried target",
        server_npc_script_rows["TServerNPC_script_canBeCarried"]["spectron_ea"],
        "0x184f48",
    )
    check(
        "Spectron v245 time-everywhere target",
        server_npc_script_rows["TServerNPC_script_timeEverywhere"]["spectron_ea"],
        "0x185010",
    )
    check(
        "Spectron v245 checkpoint artifact",
        spectron_checkpoint_v245["artifact"],
        "spectron_translation_checkpoint_20260828_v245",
    )
    check(
        "Spectron v245 checkpoint parent",
        spectron_checkpoint_v245["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v244",
    )
    check(
        "Spectron v245 checkpoint database hash",
        spectron_checkpoint_v245["database"]["sha256"],
        "108d94cfb65b8e35d121e75d766b27c9490b82e501787eb0738a355c167f4a13",
    )
    check(
        "Spectron v245 checkpoint function count",
        spectron_checkpoint_v245["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v245 checkpoint default sub count",
        spectron_checkpoint_v245["database"]["default_sub_function_count"],
        901,
    )
    check(
        "Spectron v245 checkpoint anchor count",
        spectron_checkpoint_v245["server_npc_script_anchors"]["verified_name_count"],
        7,
    )
    check(
        "Spectron v246 server-NPC showimg artifact",
        spectron_server_npc_showimg_anchors["artifact"],
        "spectron_server_npc_showimg_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v246 server-NPC showimg network",
        spectron_server_npc_showimg_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v246 server-NPC showimg anchor count",
        spectron_server_npc_showimg_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron v246 server-NPC showimg high confidence",
        spectron_server_npc_showimg_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron v246 server-NPC showimg target default count",
        spectron_server_npc_showimg_anchors["summary"]["target_default_name_count"],
        2,
    )
    check(
        "Spectron v246 server-NPC showimg normalized shape count",
        spectron_server_npc_showimg_anchors["summary"]["normalized_shape_exact_count"],
        0,
    )
    check(
        "Spectron v246 server-NPC showimg full metric count",
        spectron_server_npc_showimg_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron v246 server-NPC showimg layout count",
        spectron_server_npc_showimg_anchors["summary"]["layout_change_count"],
        2,
    )
    check(
        "Spectron v246 server-NPC showimg register-detail count",
        spectron_server_npc_showimg_anchors["summary"]["register_detail_difference_count"],
        2,
    )
    showimg_rows = {
        row["original_name"]: row
        for row in spectron_server_npc_showimg_anchors["anchors"]
    }
    check(
        "Spectron v246 showimg target",
        showimg_rows["TServerNPC_script_showImg"]["spectron_ea"],
        "0x1875a0",
    )
    check(
        "Spectron v246 showimg2 target",
        showimg_rows["TServerNPC_script_showImg2"]["spectron_ea"],
        "0x18742c",
    )
    check(
        "Spectron v246 checkpoint artifact",
        spectron_checkpoint_v246["artifact"],
        "spectron_translation_checkpoint_20260828_v246",
    )
    check(
        "Spectron v246 checkpoint parent",
        spectron_checkpoint_v246["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v245",
    )
    check(
        "Spectron v246 checkpoint database hash",
        spectron_checkpoint_v246["database"]["sha256"],
        "a8f616f41af51ec0076cbb37e3e9393910894674036e9e732a015ef59d64e515",
    )
    check(
        "Spectron v246 checkpoint function count",
        spectron_checkpoint_v246["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v246 checkpoint default sub count",
        spectron_checkpoint_v246["database"]["default_sub_function_count"],
        899,
    )
    check(
        "Spectron v246 checkpoint anchor count",
        spectron_checkpoint_v246["server_npc_showimg_anchors"]["verified_name_count"],
        2,
    )
    check(
        "Spectron v247 tiles-layer property artifact",
        spectron_tiles_layer_property_anchors["artifact"],
        "spectron_tiles_layer_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v247 tiles-layer property network",
        spectron_tiles_layer_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v247 tiles-layer property anchor count",
        spectron_tiles_layer_property_anchors["summary"]["anchor_count"],
        17,
    )
    check(
        "Spectron v247 tiles-layer property high confidence",
        spectron_tiles_layer_property_anchors["summary"]["high_confidence_count"],
        17,
    )
    check(
        "Spectron v247 tiles-layer property target default count",
        spectron_tiles_layer_property_anchors["summary"]["target_default_name_count"],
        17,
    )
    check(
        "Spectron v247 tiles-layer property normalized shape count",
        spectron_tiles_layer_property_anchors["summary"]["normalized_shape_exact_count"],
        17,
    )
    check(
        "Spectron v247 tiles-layer property full metric count",
        spectron_tiles_layer_property_anchors["summary"]["full_metric_exact_count"],
        17,
    )
    check(
        "Spectron v247 tiles-layer property layout count",
        spectron_tiles_layer_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v247 tiles-layer property register-detail count",
        spectron_tiles_layer_property_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    check(
        "Spectron v247 tiles-layer property getter count",
        spectron_tiles_layer_property_anchors["summary"]["getter_count"],
        9,
    )
    check(
        "Spectron v247 tiles-layer property setter count",
        spectron_tiles_layer_property_anchors["summary"]["setter_count"],
        8,
    )
    tiles_layer_rows = {
        row["original_name"]: row
        for row in spectron_tiles_layer_property_anchors["anchors"]
    }
    check(
        "Spectron v247 tiles-layer offset setter target",
        tiles_layer_rows["TTilesLayer_setOffset"]["spectron_ea"],
        "0x1a4870",
    )
    check(
        "Spectron v247 tiles-layer Z setter target",
        tiles_layer_rows["TTilesLayer_setZ"]["spectron_ea"],
        "0x1a45f0",
    )
    check(
        "Spectron v247 checkpoint artifact",
        spectron_checkpoint_v247["artifact"],
        "spectron_translation_checkpoint_20260828_v247",
    )
    check(
        "Spectron v247 checkpoint parent",
        spectron_checkpoint_v247["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v246",
    )
    check(
        "Spectron v247 checkpoint database hash",
        spectron_checkpoint_v247["database"]["sha256"],
        "3e0c053b6dc847f21a437e4e77883481a37e5ecc128b3e47971ecd72ed050b4d",
    )
    check(
        "Spectron v247 checkpoint function count",
        spectron_checkpoint_v247["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v247 checkpoint default sub count",
        spectron_checkpoint_v247["database"]["default_sub_function_count"],
        882,
    )
    check(
        "Spectron v247 checkpoint anchor count",
        spectron_checkpoint_v247["tiles_layer_property_anchors"]["verified_name_count"],
        17,
    )
    check(
        "Spectron v248 player property artifact",
        spectron_player_property_anchors["artifact"],
        "spectron_player_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v248 player property network",
        spectron_player_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v248 player property anchor count",
        spectron_player_property_anchors["summary"]["anchor_count"],
        30,
    )
    check(
        "Spectron v248 player property unique target count",
        spectron_player_property_anchors["summary"]["unique_target_count"],
        27,
    )
    check(
        "Spectron v248 player property high confidence",
        spectron_player_property_anchors["summary"]["high_confidence_count"],
        30,
    )
    check(
        "Spectron v248 player property target default count",
        spectron_player_property_anchors["summary"]["target_default_name_count"],
        30,
    )
    check(
        "Spectron v248 player property normalized shape count",
        spectron_player_property_anchors["summary"]["normalized_shape_exact_count"],
        30,
    )
    check(
        "Spectron v248 player property full metric count",
        spectron_player_property_anchors["summary"]["full_metric_exact_count"],
        7,
    )
    check(
        "Spectron v248 player property layout count",
        spectron_player_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v248 player property register-detail count",
        spectron_player_property_anchors["summary"]["register_detail_difference_count"],
        23,
    )
    check(
        "Spectron v248 player property getter count",
        spectron_player_property_anchors["summary"]["getter_count"],
        26,
    )
    check(
        "Spectron v248 player property setter count",
        spectron_player_property_anchors["summary"]["setter_count"],
        4,
    )
    player_property_rows = spectron_player_property_anchors["anchors"]
    check(
        "Spectron v248 alliedguilds setter target",
        next(
            row["spectron_ea"]
            for row in player_property_rows
            if row["script_name"] == "alliedguilds" and row["property_role"] == "setter"
        ),
        "0x1705c4",
    )
    check(
        "Spectron v248 shieldimg shared getter target",
        next(
            row["spectron_ea"]
            for row in player_property_rows
            if row["script_name"] == "shieldimg"
        ),
        "0x1704b4",
    )
    check(
        "Spectron v248 swordimg shared getter target",
        next(
            row["spectron_ea"]
            for row in player_property_rows
            if row["script_name"] == "swordimg"
        ),
        "0x170484",
    )
    check(
        "Spectron v248 checkpoint artifact",
        spectron_checkpoint_v248["artifact"],
        "spectron_translation_checkpoint_20260828_v248",
    )
    check(
        "Spectron v248 checkpoint parent",
        spectron_checkpoint_v248["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v247",
    )
    check(
        "Spectron v248 checkpoint database hash",
        spectron_checkpoint_v248["database"]["sha256"],
        "780a8ac4584699546ef14a692bd520f13389f5c3918f45b37e33256718028165",
    )
    check(
        "Spectron v248 checkpoint function count",
        spectron_checkpoint_v248["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v248 checkpoint default sub count",
        spectron_checkpoint_v248["database"]["default_sub_function_count"],
        855,
    )
    check(
        "Spectron v248 checkpoint anchor count",
        spectron_checkpoint_v248["player_property_anchors"]["verified_name_count"],
        30,
    )
    check(
        "Spectron v249 Gani residual artifact",
        spectron_gani_property_residual_anchors["artifact"],
        "spectron_gani_property_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v249 Gani residual network",
        spectron_gani_property_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v249 Gani residual anchor count",
        spectron_gani_property_residual_anchors["summary"]["anchor_count"],
        29,
    )
    check(
        "Spectron v249 Gani residual registration row count",
        spectron_gani_property_residual_anchors["summary"]["registration_row_count"],
        30,
    )
    check(
        "Spectron v249 Gani residual unique target count",
        spectron_gani_property_residual_anchors["summary"]["unique_target_count"],
        29,
    )
    check(
        "Spectron v249 Gani residual high confidence",
        spectron_gani_property_residual_anchors["summary"]["high_confidence_count"],
        29,
    )
    check(
        "Spectron v249 Gani residual target default count",
        spectron_gani_property_residual_anchors["summary"]["target_default_name_count"],
        29,
    )
    check(
        "Spectron v249 Gani residual normalized shape count",
        spectron_gani_property_residual_anchors["summary"]["normalized_shape_exact_count"],
        26,
    )
    check(
        "Spectron v249 Gani residual full metric count",
        spectron_gani_property_residual_anchors["summary"]["full_metric_exact_count"],
        8,
    )
    check(
        "Spectron v249 Gani residual layout count",
        spectron_gani_property_residual_anchors["summary"]["layout_change_count"],
        3,
    )
    check(
        "Spectron v249 Gani residual register-detail count",
        spectron_gani_property_residual_anchors["summary"]["register_detail_difference_count"],
        21,
    )
    check(
        "Spectron v249 Gani residual getter count",
        spectron_gani_property_residual_anchors["summary"]["getter_count"],
        17,
    )
    check(
        "Spectron v249 Gani residual setter count",
        spectron_gani_property_residual_anchors["summary"]["setter_count"],
        12,
    )
    check(
        "Spectron v249 Gani residual duplicate count",
        spectron_gani_property_residual_anchors["summary"]["duplicate_registration_count"],
        1,
    )
    gani_residual_rows = spectron_gani_property_residual_anchors["anchors"]
    check(
        "Spectron v249 Gani ani target",
        next(row["spectron_ea"] for row in gani_residual_rows if row["script_name"] == "ani"),
        "0x160560",
    )
    check(
        "Spectron v249 Gani head target",
        next(row["spectron_ea"] for row in gani_residual_rows if row["script_name"] == "head"),
        "0x160c90",
    )
    check(
        "Spectron v249 Gani zoom setter target",
        next(
            row["spectron_ea"]
            for row in gani_residual_rows
            if row["script_name"] == "zoom" and row["property_role"] == "setter"
        ),
        "0x161530",
    )
    check(
        "Spectron v249 checkpoint artifact",
        spectron_checkpoint_v249["artifact"],
        "spectron_translation_checkpoint_20260828_v249",
    )
    check(
        "Spectron v249 checkpoint parent",
        spectron_checkpoint_v249["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v248",
    )
    check(
        "Spectron v249 checkpoint database hash",
        spectron_checkpoint_v249["database"]["sha256"],
        "50377973defadbbf25181fdad93a1fcc4a06480f20bcdbd180dd9a63dc27defa",
    )
    check(
        "Spectron v249 checkpoint function count",
        spectron_checkpoint_v249["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v249 checkpoint default sub count",
        spectron_checkpoint_v249["database"]["default_sub_function_count"],
        826,
    )
    check(
        "Spectron v249 checkpoint anchor count",
        spectron_checkpoint_v249["gani_property_residual_anchors"]["verified_name_count"],
        29,
    )
    check(
        "Spectron v250 drawing-panel property artifact",
        spectron_drawing_panel_property_residual_anchors["artifact"],
        "spectron_drawing_panel_property_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v250 drawing-panel property network",
        spectron_drawing_panel_property_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v250 drawing-panel property anchor count",
        spectron_drawing_panel_property_residual_anchors["summary"]["anchor_count"],
        10,
    )
    check(
        "Spectron v250 drawing-panel registration row count",
        spectron_drawing_panel_property_residual_anchors["summary"]["registration_row_count"],
        12,
    )
    check(
        "Spectron v250 drawing-panel unique target count",
        spectron_drawing_panel_property_residual_anchors["summary"]["unique_target_count"],
        10,
    )
    check(
        "Spectron v250 drawing-panel high confidence",
        spectron_drawing_panel_property_residual_anchors["summary"]["high_confidence_count"],
        10,
    )
    check(
        "Spectron v250 drawing-panel target default count",
        spectron_drawing_panel_property_residual_anchors["summary"]["target_default_name_count"],
        10,
    )
    check(
        "Spectron v250 drawing-panel normalized shape count",
        spectron_drawing_panel_property_residual_anchors["summary"]["normalized_shape_exact_count"],
        10,
    )
    check(
        "Spectron v250 drawing-panel full metric count",
        spectron_drawing_panel_property_residual_anchors["summary"]["full_metric_exact_count"],
        8,
    )
    check(
        "Spectron v250 drawing-panel layout count",
        spectron_drawing_panel_property_residual_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v250 drawing-panel register-detail count",
        spectron_drawing_panel_property_residual_anchors["summary"]["register_detail_difference_count"],
        2,
    )
    check(
        "Spectron v250 drawing-panel getter count",
        spectron_drawing_panel_property_residual_anchors["summary"]["getter_count"],
        8,
    )
    check(
        "Spectron v250 drawing-panel setter count",
        spectron_drawing_panel_property_residual_anchors["summary"]["setter_count"],
        1,
    )
    check(
        "Spectron v250 drawing-panel callback count",
        spectron_drawing_panel_property_residual_anchors["summary"]["callback_count"],
        1,
    )
    check(
        "Spectron v250 drawing-panel duplicate count",
        spectron_drawing_panel_property_residual_anchors["summary"]["duplicate_registration_count"],
        2,
    )
    drawing_panel_residual_rows = spectron_drawing_panel_property_residual_anchors["anchors"]
    check(
        "Spectron v250 drawing-panel profile setter target",
        next(
            row["spectron_ea"]
            for row in drawing_panel_residual_rows
            if row["script_name"] == "profile"
        ),
        "0x11ce58",
    )
    check(
        "Spectron v250 drawing-panel stretched target",
        next(
            row["spectron_ea"]
            for row in drawing_panel_residual_rows
            if row["script_name"] == "drawimagestretched"
        ),
        "0x11ad8c",
    )
    check(
        "Spectron v250 checkpoint artifact",
        spectron_checkpoint_v250["artifact"],
        "spectron_translation_checkpoint_20260828_v250",
    )
    check(
        "Spectron v250 checkpoint parent",
        spectron_checkpoint_v250["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v249",
    )
    check(
        "Spectron v250 checkpoint database hash",
        spectron_checkpoint_v250["database"]["sha256"],
        "d9fa44a190b1b5014dd9e56651fd416c0e1923cba4e2cd8e361314a9ba7a046f",
    )
    check(
        "Spectron v250 checkpoint function count",
        spectron_checkpoint_v250["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v250 checkpoint default sub count",
        spectron_checkpoint_v250["database"]["default_sub_function_count"],
        816,
    )
    check(
        "Spectron v250 checkpoint anchor count",
        spectron_checkpoint_v250["drawing_panel_property_residual_anchors"]["verified_name_count"],
        10,
    )
    check(
        "Spectron v251 TPlayer findweapon artifact",
        spectron_tplayer_findweapon_anchors["artifact"],
        "spectron_tplayer_findweapon_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v251 TPlayer findweapon network",
        spectron_tplayer_findweapon_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v251 TPlayer findweapon anchor count",
        spectron_tplayer_findweapon_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron v251 TPlayer findweapon registration row count",
        spectron_tplayer_findweapon_anchors["summary"]["registration_row_count"],
        2,
    )
    check(
        "Spectron v251 TPlayer findweapon unique target count",
        spectron_tplayer_findweapon_anchors["summary"]["unique_target_count"],
        2,
    )
    check(
        "Spectron v251 TPlayer findweapon high confidence",
        spectron_tplayer_findweapon_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron v251 TPlayer findweapon target default count",
        spectron_tplayer_findweapon_anchors["summary"]["target_default_name_count"],
        2,
    )
    check(
        "Spectron v251 TPlayer findweapon normalized shape count",
        spectron_tplayer_findweapon_anchors["summary"]["normalized_shape_exact_count"],
        0,
    )
    check(
        "Spectron v251 TPlayer findweapon full metric count",
        spectron_tplayer_findweapon_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron v251 TPlayer findweapon layout count",
        spectron_tplayer_findweapon_anchors["summary"]["layout_change_count"],
        2,
    )
    check(
        "Spectron v251 TPlayer findweapon register-detail count",
        spectron_tplayer_findweapon_anchors["summary"]["register_detail_difference_count"],
        2,
    )
    check(
        "Spectron v251 TPlayer findweapon callback count",
        spectron_tplayer_findweapon_anchors["summary"]["callback_count"],
        2,
    )
    findweapon_rows = spectron_tplayer_findweapon_anchors["anchors"]
    check(
        "Spectron v251 property findweapon target",
        next(
            row["spectron_ea"]
            for row in findweapon_rows
            if row["original_name"] == "TPlayerProperties_script_findweapon"
        ),
        "0x1705f0",
    )
    check(
        "Spectron v251 static findweapon target",
        next(
            row["spectron_ea"]
            for row in findweapon_rows
            if row["original_name"] == "TPlayer_script_findweapon"
        ),
        "0x171728",
    )
    check(
        "Spectron v251 checkpoint artifact",
        spectron_checkpoint_v251["artifact"],
        "spectron_translation_checkpoint_20260828_v251",
    )
    check(
        "Spectron v251 checkpoint parent",
        spectron_checkpoint_v251["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v250",
    )
    check(
        "Spectron v251 checkpoint database hash",
        spectron_checkpoint_v251["database"]["sha256"],
        "7ab7b98f01f2a4e5241187e1f5864006a7b8b21f6fa163e61fc3c76081a65e9c",
    )
    check(
        "Spectron v251 checkpoint function count",
        spectron_checkpoint_v251["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v251 checkpoint default sub count",
        spectron_checkpoint_v251["database"]["default_sub_function_count"],
        814,
    )
    check(
        "Spectron v251 checkpoint anchor count",
        spectron_checkpoint_v251["tplayer_findweapon_anchors"]["verified_name_count"],
        2,
    )
    check(
        "Spectron v252 TGUIAnimation property artifact",
        spectron_tgui_animation_property_residual_anchors["artifact"],
        "spectron_tgui_animation_property_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v252 TGUIAnimation property network",
        spectron_tgui_animation_property_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v252 TGUIAnimation property anchor count",
        spectron_tgui_animation_property_residual_anchors["summary"]["anchor_count"],
        17,
    )
    check(
        "Spectron v252 TGUIAnimation property registration row count",
        spectron_tgui_animation_property_residual_anchors["summary"]["registration_row_count"],
        17,
    )
    check(
        "Spectron v252 TGUIAnimation property unique target count",
        spectron_tgui_animation_property_residual_anchors["summary"]["unique_target_count"],
        17,
    )
    check(
        "Spectron v252 TGUIAnimation property high confidence",
        spectron_tgui_animation_property_residual_anchors["summary"]["high_confidence_count"],
        17,
    )
    check(
        "Spectron v252 TGUIAnimation property target default count",
        spectron_tgui_animation_property_residual_anchors["summary"]["target_default_name_count"],
        17,
    )
    check(
        "Spectron v252 TGUIAnimation property normalized shape count",
        spectron_tgui_animation_property_residual_anchors["summary"]["normalized_shape_exact_count"],
        17,
    )
    check(
        "Spectron v252 TGUIAnimation property full metric count",
        spectron_tgui_animation_property_residual_anchors["summary"]["full_metric_exact_count"],
        17,
    )
    check(
        "Spectron v252 TGUIAnimation property layout count",
        spectron_tgui_animation_property_residual_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v252 TGUIAnimation property register-detail count",
        spectron_tgui_animation_property_residual_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    check(
        "Spectron v252 TGUIAnimation property getter count",
        spectron_tgui_animation_property_residual_anchors["summary"]["getter_count"],
        10,
    )
    check(
        "Spectron v252 TGUIAnimation property setter count",
        spectron_tgui_animation_property_residual_anchors["summary"]["setter_count"],
        7,
    )
    tgui_animation_rows = spectron_tgui_animation_property_residual_anchors["anchors"]
    check(
        "Spectron v252 currenttime target",
        next(
            row["spectron_ea"]
            for row in tgui_animation_rows
            if row["original_name"] == "TGUIAnimation_get_currenttime"
        ),
        "0x1ce298",
    )
    check(
        "Spectron v252 bounds setter target",
        next(
            row["spectron_ea"]
            for row in tgui_animation_rows
            if row["original_name"] == "TGUIAnimation_set_bounds"
        ),
        "0x1ceb50",
    )
    check(
        "Spectron v252 transition getter target",
        next(
            row["spectron_ea"]
            for row in tgui_animation_rows
            if row["original_name"] == "TGUIAnimation_get_transition"
        ),
        "0x1ce69c",
    )
    check(
        "Spectron v252 checkpoint artifact",
        spectron_checkpoint_v252["artifact"],
        "spectron_translation_checkpoint_20260828_v252",
    )
    check(
        "Spectron v252 checkpoint parent",
        spectron_checkpoint_v252["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v251",
    )
    check(
        "Spectron v252 checkpoint database hash",
        spectron_checkpoint_v252["database"]["sha256"],
        "90a0d433ed61969714d1c853823693ce4286e2d785e159535e7f68e06548af4b",
    )
    check(
        "Spectron v252 checkpoint function count",
        spectron_checkpoint_v252["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v252 checkpoint default sub count",
        spectron_checkpoint_v252["database"]["default_sub_function_count"],
        797,
    )
    check(
        "Spectron v252 checkpoint anchor count",
        spectron_checkpoint_v252["tgui_animation_property_residual_anchors"]["verified_name_count"],
        17,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property artifact",
        spectron_gui_bitmap_property_anchors["artifact"],
        "spectron_gui_bitmap_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v253 GuiBitmapCtrl property network",
        spectron_gui_bitmap_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property anchor count",
        spectron_gui_bitmap_property_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property registration row count",
        spectron_gui_bitmap_property_anchors["summary"]["registration_row_count"],
        6,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property unique target count",
        spectron_gui_bitmap_property_anchors["summary"]["unique_target_count"],
        5,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property high confidence",
        spectron_gui_bitmap_property_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property target default count",
        spectron_gui_bitmap_property_anchors["summary"]["target_default_name_count"],
        5,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property normalized shape count",
        spectron_gui_bitmap_property_anchors["summary"]["normalized_shape_exact_count"],
        5,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property full metric count",
        spectron_gui_bitmap_property_anchors["summary"]["full_metric_exact_count"],
        5,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property layout count",
        spectron_gui_bitmap_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property register-detail count",
        spectron_gui_bitmap_property_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property getter count",
        spectron_gui_bitmap_property_anchors["summary"]["getter_count"],
        4,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property setter count",
        spectron_gui_bitmap_property_anchors["summary"]["setter_count"],
        1,
    )
    check(
        "Spectron v253 GuiBitmapCtrl property duplicate count",
        spectron_gui_bitmap_property_anchors["summary"]["duplicate_registration_count"],
        1,
    )
    gui_bitmap_rows = spectron_gui_bitmap_property_anchors["anchors"]
    check(
        "Spectron v253 bitmap getter target",
        next(
            row["spectron_ea"]
            for row in gui_bitmap_rows
            if row["original_name"] == "GuiBitmapCtrl_get_bitmap"
        ),
        "0x1b0bd4",
    )
    check(
        "Spectron v253 fullbitmap setter target",
        next(
            row["spectron_ea"]
            for row in gui_bitmap_rows
            if row["original_name"] == "GuiBitmapCtrl_set_fullbitmap"
        ),
        "0x1b0b60",
    )
    check(
        "Spectron v253 tile getter target",
        next(
            row["spectron_ea"]
            for row in gui_bitmap_rows
            if row["original_name"] == "GuiBitmapCtrl_get_tile"
        ),
        "0x1b0b68",
    )
    check(
        "Spectron v253 checkpoint artifact",
        spectron_checkpoint_v253["artifact"],
        "spectron_translation_checkpoint_20260828_v253",
    )
    check(
        "Spectron v253 checkpoint parent",
        spectron_checkpoint_v253["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v252",
    )
    check(
        "Spectron v253 checkpoint database hash",
        spectron_checkpoint_v253["database"]["sha256"],
        "924bca24389cf9c6f8d07ade1f6a7b31726c8bc7991f7fdbacf6e94967a5028c",
    )
    check(
        "Spectron v253 checkpoint function count",
        spectron_checkpoint_v253["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v253 checkpoint default sub count",
        spectron_checkpoint_v253["database"]["default_sub_function_count"],
        792,
    )
    check(
        "Spectron v253 checkpoint anchor count",
        spectron_checkpoint_v253["gui_bitmap_property_anchors"]["verified_name_count"],
        5,
    )
    check(
        "Spectron v254 bitmap-button property artifact",
        spectron_gui_bitmap_button_property_anchors["artifact"],
        "spectron_gui_bitmap_button_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v254 bitmap-button property network",
        spectron_gui_bitmap_button_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v254 bitmap-button property anchor count",
        spectron_gui_bitmap_button_property_anchors["summary"]["anchor_count"],
        11,
    )
    check(
        "Spectron v254 bitmap-button property registration row count",
        spectron_gui_bitmap_button_property_anchors["summary"]["registration_row_count"],
        11,
    )
    check(
        "Spectron v254 bitmap-button property unique target count",
        spectron_gui_bitmap_button_property_anchors["summary"]["unique_target_count"],
        11,
    )
    check(
        "Spectron v254 bitmap-button property high confidence",
        spectron_gui_bitmap_button_property_anchors["summary"]["high_confidence_count"],
        11,
    )
    check(
        "Spectron v254 bitmap-button property target default count",
        spectron_gui_bitmap_button_property_anchors["summary"]["target_default_name_count"],
        11,
    )
    check(
        "Spectron v254 bitmap-button property normalized shape count",
        spectron_gui_bitmap_button_property_anchors["summary"]["normalized_shape_exact_count"],
        11,
    )
    check(
        "Spectron v254 bitmap-button property full metric count",
        spectron_gui_bitmap_button_property_anchors["summary"]["full_metric_exact_count"],
        9,
    )
    check(
        "Spectron v254 bitmap-button property layout count",
        spectron_gui_bitmap_button_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v254 bitmap-button property register-detail count",
        spectron_gui_bitmap_button_property_anchors["summary"]["register_detail_difference_count"],
        2,
    )
    check(
        "Spectron v254 bitmap-button property getter count",
        spectron_gui_bitmap_button_property_anchors["summary"]["getter_count"],
        6,
    )
    check(
        "Spectron v254 bitmap-button property setter count",
        spectron_gui_bitmap_button_property_anchors["summary"]["setter_count"],
        5,
    )
    bitmap_button_rows = spectron_gui_bitmap_button_property_anchors["anchors"]
    check(
        "Spectron v254 mouseover bitmap target",
        next(
            row["spectron_ea"]
            for row in bitmap_button_rows
            if row["original_name"] == "GuiBitmapButtonCtrl_get_mouseoverbitmap"
        ),
        "0x1b00dc",
    )
    check(
        "Spectron v254 button type setter target",
        next(
            row["spectron_ea"]
            for row in bitmap_button_rows
            if row["original_name"] == "GuiButtonBaseCtrl_set_buttontype"
        ),
        "0x1b1478",
    )
    check(
        "Spectron v254 group number setter target",
        next(
            row["spectron_ea"]
            for row in bitmap_button_rows
            if row["original_name"] == "GuiButtonBaseCtrl_set_groupnum"
        ),
        "0x1b1430",
    )
    check(
        "Spectron v254 checkpoint artifact",
        spectron_checkpoint_v254["artifact"],
        "spectron_translation_checkpoint_20260828_v254",
    )
    check(
        "Spectron v254 checkpoint parent",
        spectron_checkpoint_v254["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v253",
    )
    check(
        "Spectron v254 checkpoint database hash",
        spectron_checkpoint_v254["database"]["sha256"],
        "078918adcdeadc3fa6a894d07e0f9b1929dacaeb2043de3f9952ed8e2f9289e8",
    )
    check(
        "Spectron v254 checkpoint function count",
        spectron_checkpoint_v254["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v254 checkpoint default sub count",
        spectron_checkpoint_v254["database"]["default_sub_function_count"],
        781,
    )
    check(
        "Spectron v254 checkpoint anchor count",
        spectron_checkpoint_v254["gui_bitmap_button_property_anchors"]["verified_name_count"],
        11,
    )
    check(
        "Spectron v255 GuiControl property-tail artifact",
        spectron_guicontrol_property_tail_anchors["artifact"],
        "spectron_guicontrol_property_tail_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v255 GuiControl property-tail network",
        spectron_guicontrol_property_tail_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v255 GuiControl property-tail anchor count",
        spectron_guicontrol_property_tail_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron v255 GuiControl property-tail registration row count",
        spectron_guicontrol_property_tail_anchors["summary"]["registration_row_count"],
        4,
    )
    check(
        "Spectron v255 GuiControl property-tail unique target count",
        spectron_guicontrol_property_tail_anchors["summary"]["unique_target_count"],
        4,
    )
    check(
        "Spectron v255 GuiControl property-tail high confidence",
        spectron_guicontrol_property_tail_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron v255 GuiControl property-tail target default count",
        spectron_guicontrol_property_tail_anchors["summary"]["target_default_name_count"],
        4,
    )
    check(
        "Spectron v255 GuiControl property-tail normalized shape count",
        spectron_guicontrol_property_tail_anchors["summary"]["normalized_shape_exact_count"],
        4,
    )
    check(
        "Spectron v255 GuiControl property-tail full metric count",
        spectron_guicontrol_property_tail_anchors["summary"]["full_metric_exact_count"],
        4,
    )
    check(
        "Spectron v255 GuiControl property-tail layout count",
        spectron_guicontrol_property_tail_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v255 GuiControl property-tail register-detail count",
        spectron_guicontrol_property_tail_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    check(
        "Spectron v255 GuiControl property-tail getter count",
        spectron_guicontrol_property_tail_anchors["summary"]["getter_count"],
        1,
    )
    check(
        "Spectron v255 GuiControl property-tail setter count",
        spectron_guicontrol_property_tail_anchors["summary"]["setter_count"],
        3,
    )
    guicontrol_property_tail_rows = spectron_guicontrol_property_tail_anchors["anchors"]
    check(
        "Spectron v255 GuiControl cursor target",
        next(
            row["spectron_ea"]
            for row in guicontrol_property_tail_rows
            if row["original_name"] == "GuiControl_getCursor"
        ),
        "0x1becbc",
    )
    check(
        "Spectron v255 GuiControl flickering target",
        next(
            row["spectron_ea"]
            for row in guicontrol_property_tail_rows
            if row["original_name"] == "GuiControl_setFlickering"
        ),
        "0x1bbc10",
    )
    check(
        "Spectron v255 GuiControl animation target",
        next(
            row["spectron_ea"]
            for row in guicontrol_property_tail_rows
            if row["original_name"] == "GuiControl_setIsInAnimation"
        ),
        "0x1bc254",
    )
    check(
        "Spectron v255 GuiControl in-out animation target",
        next(
            row["spectron_ea"]
            for row in guicontrol_property_tail_rows
            if row["original_name"] == "GuiControl_setIsInOutAnimation"
        ),
        "0x1bc384",
    )
    check(
        "Spectron v255 checkpoint artifact",
        spectron_checkpoint_v255["artifact"],
        "spectron_translation_checkpoint_20260828_v255",
    )
    check(
        "Spectron v255 checkpoint parent",
        spectron_checkpoint_v255["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v254",
    )
    check(
        "Spectron v255 checkpoint database hash",
        spectron_checkpoint_v255["database"]["sha256"],
        "41201714ed45c2e165f0199268d1863fb6d7895f8067678c6614fc786c5254b6",
    )
    check(
        "Spectron v255 checkpoint function count",
        spectron_checkpoint_v255["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v255 checkpoint default sub count",
        spectron_checkpoint_v255["database"]["default_sub_function_count"],
        777,
    )
    check(
        "Spectron v255 checkpoint anchor count",
        spectron_checkpoint_v255["guicontrol_property_tail_anchors"]["verified_name_count"],
        4,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering artifact",
        spectron_guigraalctrl_isrendering_anchors["artifact"],
        "spectron_guigraalctrl_isrendering_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering network",
        spectron_guigraalctrl_isrendering_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering anchor count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering registration row count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["registration_row_count"],
        2,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering unique target count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["unique_target_count"],
        2,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering high confidence",
        spectron_guigraalctrl_isrendering_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering target default count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["target_default_name_count"],
        2,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering normalized shape count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["normalized_shape_exact_count"],
        2,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering full metric count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering layout count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering register-detail count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering getter count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["getter_count"],
        1,
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering setter count",
        spectron_guigraalctrl_isrendering_anchors["summary"]["setter_count"],
        1,
    )
    guigraalctrl_isrendering_rows = spectron_guigraalctrl_isrendering_anchors["anchors"]
    check(
        "Spectron v256 GuiGraalCtrl isrendering getter target",
        next(
            row["spectron_ea"]
            for row in guigraalctrl_isrendering_rows
            if row["original_name"] == "GuiGraalCtrl_get_isrendering"
        ),
        "0x1bf7ac",
    )
    check(
        "Spectron v256 GuiGraalCtrl isrendering setter target",
        next(
            row["spectron_ea"]
            for row in guigraalctrl_isrendering_rows
            if row["original_name"] == "GuiGraalCtrl_set_isrendering"
        ),
        "0x1bf7b4",
    )
    check(
        "Spectron v256 checkpoint artifact",
        spectron_checkpoint_v256["artifact"],
        "spectron_translation_checkpoint_20260828_v256",
    )
    check(
        "Spectron v256 checkpoint parent",
        spectron_checkpoint_v256["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v255",
    )
    check(
        "Spectron v256 checkpoint database hash",
        spectron_checkpoint_v256["database"]["sha256"],
        "51cc802c6c5ae38aa70bf09119f3caef12fe4e6907403d9a54211e79e110731c",
    )
    check(
        "Spectron v256 checkpoint function count",
        spectron_checkpoint_v256["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v256 checkpoint default sub count",
        spectron_checkpoint_v256["database"]["default_sub_function_count"],
        775,
    )
    check(
        "Spectron v256 checkpoint anchor count",
        spectron_checkpoint_v256["guigraalctrl_isrendering_anchors"]["verified_name_count"],
        2,
    )
    check(
        "Spectron v257 GuiScrollCtrl property artifact",
        spectron_guiscrollctrl_property_anchors["artifact"],
        "spectron_guiscrollctrl_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v257 GuiScrollCtrl property network",
        spectron_guiscrollctrl_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v257 GuiScrollCtrl property anchor count",
        spectron_guiscrollctrl_property_anchors["summary"]["anchor_count"],
        11,
    )
    check(
        "Spectron v257 GuiScrollCtrl property registration row count",
        spectron_guiscrollctrl_property_anchors["summary"]["registration_row_count"],
        11,
    )
    check(
        "Spectron v257 GuiScrollCtrl property unique target count",
        spectron_guiscrollctrl_property_anchors["summary"]["unique_target_count"],
        11,
    )
    check(
        "Spectron v257 GuiScrollCtrl property high confidence",
        spectron_guiscrollctrl_property_anchors["summary"]["high_confidence_count"],
        11,
    )
    check(
        "Spectron v257 GuiScrollCtrl property target default count",
        spectron_guiscrollctrl_property_anchors["summary"]["target_default_name_count"],
        11,
    )
    check(
        "Spectron v257 GuiScrollCtrl property normalized shape count",
        spectron_guiscrollctrl_property_anchors["summary"]["normalized_shape_exact_count"],
        11,
    )
    check(
        "Spectron v257 GuiScrollCtrl property full metric count",
        spectron_guiscrollctrl_property_anchors["summary"]["full_metric_exact_count"],
        9,
    )
    check(
        "Spectron v257 GuiScrollCtrl property layout count",
        spectron_guiscrollctrl_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v257 GuiScrollCtrl property register-detail count",
        spectron_guiscrollctrl_property_anchors["summary"]["register_detail_difference_count"],
        2,
    )
    check(
        "Spectron v257 GuiScrollCtrl property getter count",
        spectron_guiscrollctrl_property_anchors["summary"]["getter_count"],
        8,
    )
    check(
        "Spectron v257 GuiScrollCtrl property setter count",
        spectron_guiscrollctrl_property_anchors["summary"]["setter_count"],
        3,
    )
    guiscrollctrl_property_rows = spectron_guiscrollctrl_property_anchors["anchors"]
    check(
        "Spectron v257 GuiScrollCtrl childmargin target",
        next(
            row["spectron_ea"]
            for row in guiscrollctrl_property_rows
            if row["original_name"] == "GuiScrollCtrl_get_childmargin"
        ),
        "0x1c4b08",
    )
    check(
        "Spectron v257 GuiScrollCtrl scrollbar target",
        next(
            row["spectron_ea"]
            for row in guiscrollctrl_property_rows
            if row["original_name"] == "GuiScrollCtrl_get_hscrollbar"
        ),
        "0x1c4ab8",
    )
    check(
        "Spectron v257 GuiScrollCtrl scrollpos target",
        next(
            row["spectron_ea"]
            for row in guiscrollctrl_property_rows
            if row["original_name"] == "GuiScrollCtrl_get_scrollpos"
        ),
        "0x1c4b2c",
    )
    check(
        "Spectron v257 GuiScrollCtrl vscrollbar target",
        next(
            row["spectron_ea"]
            for row in guiscrollctrl_property_rows
            if row["original_name"] == "GuiScrollCtrl_get_vscrollbar"
        ),
        "0x1c4a78",
    )
    check(
        "Spectron v257 checkpoint artifact",
        spectron_checkpoint_v257["artifact"],
        "spectron_translation_checkpoint_20260828_v257",
    )
    check(
        "Spectron v257 checkpoint parent",
        spectron_checkpoint_v257["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v256",
    )
    check(
        "Spectron v257 checkpoint database hash",
        spectron_checkpoint_v257["database"]["sha256"],
        "91201c29da6a4798a7f1918c2f11fa848cb66848615079beaaf29d04b022d82e",
    )
    check(
        "Spectron v257 checkpoint function count",
        spectron_checkpoint_v257["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v257 checkpoint default sub count",
        spectron_checkpoint_v257["database"]["default_sub_function_count"],
        764,
    )
    check(
        "Spectron v257 checkpoint anchor count",
        spectron_checkpoint_v257["guiscrollctrl_property_anchors"]["verified_name_count"],
        11,
    )
    check(
        "Spectron v258 GuiStretchCtrl property artifact",
        spectron_guistretchctrl_property_anchors["artifact"],
        "spectron_guistretchctrl_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v258 GuiStretchCtrl property network",
        spectron_guistretchctrl_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v258 GuiStretchCtrl property anchor count",
        spectron_guistretchctrl_property_anchors["summary"]["anchor_count"],
        7,
    )
    check(
        "Spectron v258 GuiStretchCtrl property registration row count",
        spectron_guistretchctrl_property_anchors["summary"]["registration_row_count"],
        7,
    )
    check(
        "Spectron v258 GuiStretchCtrl property unique target count",
        spectron_guistretchctrl_property_anchors["summary"]["unique_target_count"],
        7,
    )
    check(
        "Spectron v258 GuiStretchCtrl property high confidence",
        spectron_guistretchctrl_property_anchors["summary"]["high_confidence_count"],
        7,
    )
    check(
        "Spectron v258 GuiStretchCtrl property target default count",
        spectron_guistretchctrl_property_anchors["summary"]["target_default_name_count"],
        7,
    )
    check(
        "Spectron v258 GuiStretchCtrl property normalized shape count",
        spectron_guistretchctrl_property_anchors["summary"]["normalized_shape_exact_count"],
        7,
    )
    check(
        "Spectron v258 GuiStretchCtrl property full metric count",
        spectron_guistretchctrl_property_anchors["summary"]["full_metric_exact_count"],
        7,
    )
    check(
        "Spectron v258 GuiStretchCtrl property layout count",
        spectron_guistretchctrl_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v258 GuiStretchCtrl property register-detail count",
        spectron_guistretchctrl_property_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    check(
        "Spectron v258 GuiStretchCtrl property getter count",
        spectron_guistretchctrl_property_anchors["summary"]["getter_count"],
        5,
    )
    check(
        "Spectron v258 GuiStretchCtrl property setter count",
        spectron_guistretchctrl_property_anchors["summary"]["setter_count"],
        2,
    )
    guistretchctrl_property_rows = spectron_guistretchctrl_property_anchors["anchors"]
    check(
        "Spectron v258 GuiStretchCtrl clientextent target",
        next(
            row["spectron_ea"]
            for row in guistretchctrl_property_rows
            if row["original_name"] == "GuiStretchCtrl_get_clientextent"
        ),
        "0x1c9d08",
    )
    check(
        "Spectron v258 GuiTextCtrl maxchars target",
        next(
            row["spectron_ea"]
            for row in guistretchctrl_property_rows
            if row["original_name"] == "GuiTextCtrl_get_maxchars"
        ),
        "0x1ca6d8",
    )
    check(
        "Spectron v258 GuiTextCtrl text setter target",
        next(
            row["spectron_ea"]
            for row in guistretchctrl_property_rows
            if row["original_name"] == "GuiTextCtrl_set_text"
        ),
        "0x1ca710",
    )
    check(
        "Spectron v258 checkpoint artifact",
        spectron_checkpoint_v258["artifact"],
        "spectron_translation_checkpoint_20260828_v258",
    )
    check(
        "Spectron v258 checkpoint parent",
        spectron_checkpoint_v258["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v257",
    )
    check(
        "Spectron v258 checkpoint database hash",
        spectron_checkpoint_v258["database"]["sha256"],
        "7e7aa1628bd8f9123540346c06455d7b2e1aca803092f4ba3466cd4974f2bbd8",
    )
    check(
        "Spectron v258 checkpoint function count",
        spectron_checkpoint_v258["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v258 checkpoint default sub count",
        spectron_checkpoint_v258["database"]["default_sub_function_count"],
        757,
    )
    check(
        "Spectron v258 checkpoint anchor count",
        spectron_checkpoint_v258["guistretchctrl_property_anchors"]["verified_name_count"],
        7,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property artifact",
        spectron_guitexteditctrl_property_anchors["artifact"],
        "spectron_guitexteditctrl_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v259 GuiTextEditCtrl property network",
        spectron_guitexteditctrl_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property anchor count",
        spectron_guitexteditctrl_property_anchors["summary"]["anchor_count"],
        9,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property registration row count",
        spectron_guitexteditctrl_property_anchors["summary"]["registration_row_count"],
        9,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property unique target count",
        spectron_guitexteditctrl_property_anchors["summary"]["unique_target_count"],
        9,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property high confidence",
        spectron_guitexteditctrl_property_anchors["summary"]["high_confidence_count"],
        9,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property target default count",
        spectron_guitexteditctrl_property_anchors["summary"]["target_default_name_count"],
        9,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property normalized shape count",
        spectron_guitexteditctrl_property_anchors["summary"]["normalized_shape_exact_count"],
        9,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property full metric count",
        spectron_guitexteditctrl_property_anchors["summary"]["full_metric_exact_count"],
        9,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property layout count",
        spectron_guitexteditctrl_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property register-detail count",
        spectron_guitexteditctrl_property_anchors["summary"]["register_detail_difference_count"],
        0,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property getter count",
        spectron_guitexteditctrl_property_anchors["summary"]["getter_count"],
        6,
    )
    check(
        "Spectron v259 GuiTextEditCtrl property setter count",
        spectron_guitexteditctrl_property_anchors["summary"]["setter_count"],
        3,
    )
    guitexteditctrl_property_rows = spectron_guitexteditctrl_property_anchors["anchors"]
    check(
        "Spectron v259 GuiTextEditCtrl deniedsound target",
        next(
            row["spectron_ea"]
            for row in guitexteditctrl_property_rows
            if row["original_name"] == "GuiTextEditCtrl_get_deniedsound"
        ),
        "0x1cb4fc",
    )
    check(
        "Spectron v259 GuiTextEditCtrl inputtype target",
        next(
            row["spectron_ea"]
            for row in guitexteditctrl_property_rows
            if row["original_name"] == "GuiTextEditCtrl_get_inputtype"
        ),
        "0x1cb95c",
    )
    check(
        "Spectron v259 GuiTextEditCtrl tabcomplete target",
        next(
            row["spectron_ea"]
            for row in guitexteditctrl_property_rows
            if row["original_name"] == "GuiTextEditCtrl_set_tabcomplete"
        ),
        "0x1cb498",
    )
    check(
        "Spectron v259 checkpoint artifact",
        spectron_checkpoint_v259["artifact"],
        "spectron_translation_checkpoint_20260828_v259",
    )
    check(
        "Spectron v259 checkpoint parent",
        spectron_checkpoint_v259["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v258",
    )
    check(
        "Spectron v259 checkpoint database hash",
        spectron_checkpoint_v259["database"]["sha256"],
        "9b5a46e16dbf912a7e67583b8f626f52878bcbb30225e3674793d3b8ef5114d9",
    )
    check(
        "Spectron v259 checkpoint function count",
        spectron_checkpoint_v259["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v259 checkpoint default sub count",
        spectron_checkpoint_v259["database"]["default_sub_function_count"],
        748,
    )
    check(
        "Spectron v259 checkpoint anchor count",
        spectron_checkpoint_v259["guitexteditctrl_property_anchors"]["verified_name_count"],
        9,
    )
    check(
        "Spectron v260 TGraalVar property artifact",
        spectron_tgraalvar_property_residual_anchors["artifact"],
        "spectron_tgraalvar_property_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v260 TGraalVar property network",
        spectron_tgraalvar_property_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v260 TGraalVar property anchor count",
        spectron_tgraalvar_property_residual_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron v260 TGraalVar property registration row count",
        spectron_tgraalvar_property_residual_anchors["summary"]["registration_row_count"],
        4,
    )
    check(
        "Spectron v260 TGraalVar property unique target count",
        spectron_tgraalvar_property_residual_anchors["summary"]["unique_target_count"],
        4,
    )
    check(
        "Spectron v260 TGraalVar property high confidence",
        spectron_tgraalvar_property_residual_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron v260 TGraalVar property target default count",
        spectron_tgraalvar_property_residual_anchors["summary"]["target_default_name_count"],
        4,
    )
    check(
        "Spectron v260 TGraalVar property normalized shape count",
        spectron_tgraalvar_property_residual_anchors["summary"]["normalized_shape_exact_count"],
        2,
    )
    check(
        "Spectron v260 TGraalVar property full metric count",
        spectron_tgraalvar_property_residual_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron v260 TGraalVar property layout count",
        spectron_tgraalvar_property_residual_anchors["summary"]["layout_change_count"],
        2,
    )
    check(
        "Spectron v260 TGraalVar property register-detail count",
        spectron_tgraalvar_property_residual_anchors["summary"]["register_detail_difference_count"],
        2,
    )
    check(
        "Spectron v260 TGraalVar property getter count",
        spectron_tgraalvar_property_residual_anchors["summary"]["getter_count"],
        2,
    )
    check(
        "Spectron v260 TGraalVar property setter count",
        spectron_tgraalvar_property_residual_anchors["summary"]["setter_count"],
        2,
    )
    tgraalvar_property_rows = spectron_tgraalvar_property_residual_anchors["anchors"]
    check(
        "Spectron v260 TGraalVar name setter target",
        next(
            row["spectron_ea"]
            for row in tgraalvar_property_rows
            if row["original_name"] == "TGraalVar_set_name"
        ),
        "0x21376c",
    )
    check(
        "Spectron v260 TGraalVar joinedclasses target",
        next(
            row["spectron_ea"]
            for row in tgraalvar_property_rows
            if row["original_name"] == "TGraalVar_get_joinedclasses"
        ),
        "0x21675c",
    )
    check(
        "Spectron v260 checkpoint artifact",
        spectron_checkpoint_v260["artifact"],
        "spectron_translation_checkpoint_20260828_v260",
    )
    check(
        "Spectron v260 checkpoint parent",
        spectron_checkpoint_v260["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v259",
    )
    check(
        "Spectron v260 checkpoint database hash",
        spectron_checkpoint_v260["database"]["sha256"],
        "a8d0c87f225ba9cd5490e7616ea05d983d48c80b8ef07ec7a8da2b91e675e944",
    )
    check(
        "Spectron v260 checkpoint function count",
        spectron_checkpoint_v260["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v260 checkpoint default sub count",
        spectron_checkpoint_v260["database"]["default_sub_function_count"],
        744,
    )
    check(
        "Spectron v260 checkpoint anchor count",
        spectron_checkpoint_v260["tgraalvar_property_residual_anchors"]["verified_name_count"],
        4,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer artifact",
        spectron_tbodypanel_bodycacheperplayer_anchor["artifact"],
        "spectron_tbodypanel_bodycacheperplayer_manual_translation_anchor_20260828",
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer network",
        spectron_tbodypanel_bodycacheperplayer_anchor["network_contacted"],
        False,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer anchor count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer registration row count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["registration_row_count"],
        1,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer unique target count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["unique_target_count"],
        1,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer high confidence",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer target default count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer normalized shape count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["normalized_shape_exact_count"],
        1,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer full metric count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer layout count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer register-detail count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["register_detail_difference_count"],
        1,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer getter count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["getter_count"],
        1,
    )
    check(
        "Spectron v261 TBodyPanel bodycacheperplayer setter count",
        spectron_tbodypanel_bodycacheperplayer_anchor["summary"]["setter_count"],
        0,
    )
    check(
        "Spectron v261 bodycacheperplayer target",
        spectron_tbodypanel_bodycacheperplayer_anchor["anchors"][0]["spectron_ea"],
        "0x245e0c",
    )
    check(
        "Spectron v261 checkpoint artifact",
        spectron_checkpoint_v261["artifact"],
        "spectron_translation_checkpoint_20260828_v261",
    )
    check(
        "Spectron v261 checkpoint parent",
        spectron_checkpoint_v261["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v260",
    )
    check(
        "Spectron v261 checkpoint database hash",
        spectron_checkpoint_v261["database"]["sha256"],
        "d2f88d291451b82578968bff85c7018fdba2d2c0a18ec256ac7b3368d73e77de",
    )
    check(
        "Spectron v261 checkpoint function count",
        spectron_checkpoint_v261["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v261 checkpoint default sub count",
        spectron_checkpoint_v261["database"]["default_sub_function_count"],
        743,
    )
    check(
        "Spectron v261 checkpoint anchor count",
        spectron_checkpoint_v261["tbodypanel_bodycacheperplayer_anchor"]["verified_name_count"],
        1,
    )
    check(
        "Spectron v262 residual property artifact",
        spectron_residual_property_anchors["artifact"],
        "spectron_residual_property_manual_translation_anchors_20260828",
    )
    check(
        "Spectron v262 residual property network",
        spectron_residual_property_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron v262 residual property anchor count",
        spectron_residual_property_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron v262 residual property registration row count",
        spectron_residual_property_anchors["summary"]["registration_row_count"],
        6,
    )
    check(
        "Spectron v262 residual property unique target count",
        spectron_residual_property_anchors["summary"]["unique_target_count"],
        6,
    )
    check(
        "Spectron v262 residual property high confidence",
        spectron_residual_property_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron v262 residual property target default count",
        spectron_residual_property_anchors["summary"]["target_default_name_count"],
        6,
    )
    check(
        "Spectron v262 residual property normalized shape count",
        spectron_residual_property_anchors["summary"]["normalized_shape_exact_count"],
        6,
    )
    check(
        "Spectron v262 residual property full metric count",
        spectron_residual_property_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron v262 residual property layout count",
        spectron_residual_property_anchors["summary"]["layout_change_count"],
        0,
    )
    check(
        "Spectron v262 residual property register-detail count",
        spectron_residual_property_anchors["summary"]["register_detail_difference_count"],
        4,
    )
    check(
        "Spectron v262 residual property getter count",
        spectron_residual_property_anchors["summary"]["getter_count"],
        3,
    )
    check(
        "Spectron v262 residual property setter count",
        spectron_residual_property_anchors["summary"]["setter_count"],
        3,
    )
    residual_property_rows = spectron_residual_property_anchors["anchors"]
    check(
        "Spectron v262 stylesection getter target",
        next(
            row["spectron_ea"]
            for row in residual_property_rows
            if row["original_name"] == "GuiButtonCtrl_get_stylesection"
        ),
        "0x1b21a8",
    )
    check(
        "Spectron v262 script-log getter target",
        next(
            row["spectron_ea"]
            for row in residual_property_rows
            if row["original_name"] == "TScriptProperty_get_scriptlogwritetoreadonly"
        ),
        "0x22cba0",
    )
    check(
        "Spectron v262 waterheight setter target",
        next(
            row["spectron_ea"]
            for row in residual_property_rows
            if row["original_name"] == "TTiles_set_waterheight"
        ),
        "0x238ec0",
    )
    check(
        "Spectron v262 checkpoint artifact",
        spectron_checkpoint_v262["artifact"],
        "spectron_translation_checkpoint_20260828_v262",
    )
    check(
        "Spectron v262 checkpoint parent",
        spectron_checkpoint_v262["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v261",
    )
    check(
        "Spectron v262 checkpoint database hash",
        spectron_checkpoint_v262["database"]["sha256"],
        "6ec4091d8781101661216a2b99f6414cc3f5a07c556185eb40de2e203351d67e",
    )
    check(
        "Spectron v262 checkpoint function count",
        spectron_checkpoint_v262["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v262 checkpoint default sub count",
        spectron_checkpoint_v262["database"]["default_sub_function_count"],
        737,
    )
    check(
        "Spectron v262 checkpoint anchor count",
        spectron_checkpoint_v262["residual_property_anchors"]["verified_name_count"],
        6,
    )
    check(
        "Spectron GUI and Android anchor artifact",
        spectron_gui_android_anchors["artifact"],
        "spectron_gui_android_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GUI and Android anchor network",
        spectron_gui_android_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GUI and Android anchor count",
        spectron_gui_android_anchors["summary"]["anchor_count"],
        3,
    )
    check(
        "Spectron GUI and Android unique target count",
        spectron_gui_android_anchors["summary"]["unique_target_count"],
        3,
    )
    check(
        "Spectron GUI and Android high-confidence count",
        spectron_gui_android_anchors["summary"]["high_confidence_count"],
        3,
    )
    check(
        "Spectron GUI and Android target default count",
        spectron_gui_android_anchors["summary"]["target_default_name_count"],
        3,
    )
    check(
        "Spectron GUI and Android normalized exact count",
        spectron_gui_android_anchors["summary"]["normalized_shape_exact_count"],
        0,
    )
    check(
        "Spectron GUI and Android full metric exact count",
        spectron_gui_android_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron GUI and Android layout change count",
        spectron_gui_android_anchors["summary"]["layout_change_count"],
        3,
    )
    check(
        "Spectron GUI and Android register-detail count",
        spectron_gui_android_anchors["summary"]["register_detail_difference_count"],
        3,
    )
    gui_android_rows = spectron_gui_android_anchors["anchors"]
    check(
        "Spectron popdialog target",
        next(
            row["spectron_ea"]
            for row in gui_android_rows
            if row["original_name"] == "GuiCanvas_script_popdialog"
        ),
        "0x1b5cf8",
    )
    check(
        "Spectron TGraalVar trigger target",
        next(
            row["spectron_ea"]
            for row in gui_android_rows
            if row["original_name"] == "TGraalVar_script_trigger"
        ),
        "0x216a64",
    )
    check(
        "Spectron Facebook graph target",
        next(
            row["spectron_ea"]
            for row in gui_android_rows
            if row["original_name"] == "MainAndroid_script_requestnewfacebookgraph2"
        ),
        "0x253544",
    )
    check(
        "Spectron v263 corrected checkpoint artifact",
        spectron_checkpoint_v263_corrected["artifact"],
        "spectron_translation_checkpoint_20260828_v263_corrected",
    )
    check(
        "Spectron v263 corrected checkpoint parent",
        spectron_checkpoint_v263_corrected["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v262",
    )
    check(
        "Spectron v263 corrected checkpoint database hash",
        spectron_checkpoint_v263_corrected["database"]["sha256"],
        "be53b6e48e2156630ce3ae418fe0da388fd11405ef093dad80d93e0cc06df1b0",
    )
    check(
        "Spectron v263 corrected checkpoint function count",
        spectron_checkpoint_v263_corrected["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v263 corrected checkpoint default sub count",
        spectron_checkpoint_v263_corrected["database"]["default_sub_function_count"],
        734,
    )
    check(
        "Spectron v263 corrected checkpoint anchor count",
        spectron_checkpoint_v263_corrected["gui_android_anchors"]["verified_name_count"],
        3,
    )
    check(
        "Spectron Android bridge target-only artifact",
        spectron_android_bridge_target_only_labels["artifact"],
        "spectron_android_bridge_target_only_labels_20260828",
    )
    check(
        "Spectron Android bridge target-only network",
        spectron_android_bridge_target_only_labels["network_contacted"],
        False,
    )
    check(
        "Spectron Android bridge target-only label count",
        spectron_android_bridge_target_only_labels["summary"]["label_count"],
        22,
    )
    check(
        "Spectron Android bridge target-only high-confidence count",
        spectron_android_bridge_target_only_labels["summary"]["high_confidence_count"],
        22,
    )
    check(
        "Spectron Android bridge target-only default count",
        spectron_android_bridge_target_only_labels["summary"]["target_default_name_count"],
        22,
    )
    check(
        "Spectron Android bridge target-only source counterpart count",
        spectron_android_bridge_target_only_labels["summary"]["source_counterpart_count"],
        0,
    )
    android_bridge_rows = {
        row["target_ea"]: row
        for row in spectron_android_bridge_target_only_labels["labels"]
    }
    check(
        "Spectron Android bridge GetIntentData target",
        android_bridge_rows["0x24b4ec"]["proposed_name"],
        "spectron_deeplink_getdeeplinkdata",
    )
    check(
        "Spectron Android bridge Java static string target",
        android_bridge_rows["0x24fee4"]["proposed_name"],
        "spectron_androidgetjavastaticstring",
    )
    check(
        "Spectron Android bridge system property target",
        android_bridge_rows["0x2531ec"]["proposed_name"],
        "spectron_androidsystempropertyget",
    )
    check(
        "Spectron v264 corrected checkpoint artifact",
        spectron_checkpoint_v264_corrected["artifact"],
        "spectron_translation_checkpoint_20260828_v264_corrected",
    )
    check(
        "Spectron v264 corrected checkpoint parent",
        spectron_checkpoint_v264_corrected["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v263_corrected",
    )
    check(
        "Spectron v264 corrected checkpoint database hash",
        spectron_checkpoint_v264_corrected["database"]["sha256"],
        "5719066e789659c5414a832423c2f8bb0691b8fa61c8ee354ed3a9e17fbf4a69",
    )
    check(
        "Spectron v264 corrected checkpoint function count",
        spectron_checkpoint_v264_corrected["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v264 corrected checkpoint default sub count",
        spectron_checkpoint_v264_corrected["database"]["default_sub_function_count"],
        712,
    )
    check(
        "Spectron v264 corrected checkpoint target-only count",
        spectron_checkpoint_v264_corrected["android_bridge_target_only_labels"]["verified_name_count"],
        22,
    )
    check(
        "Spectron Android legacy anchor artifact",
        spectron_android_legacy_anchors["artifact"],
        "spectron_android_legacy_manual_translation_anchors_20260828",
    )
    check(
        "Spectron Android legacy anchor network",
        spectron_android_legacy_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron Android legacy anchor count",
        spectron_android_legacy_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron Android legacy unique target count",
        spectron_android_legacy_anchors["summary"]["unique_target_count"],
        4,
    )
    check(
        "Spectron Android legacy high-confidence count",
        spectron_android_legacy_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron Android legacy target default count",
        spectron_android_legacy_anchors["summary"]["target_default_name_count"],
        3,
    )
    check(
        "Spectron Android legacy normalized exact count",
        spectron_android_legacy_anchors["summary"]["normalized_shape_exact_count"],
        0,
    )
    check(
        "Spectron Android legacy full metric exact count",
        spectron_android_legacy_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    check(
        "Spectron Android legacy layout change count",
        spectron_android_legacy_anchors["summary"]["layout_change_count"],
        4,
    )
    check(
        "Spectron Android legacy register-detail count",
        spectron_android_legacy_anchors["summary"]["register_detail_difference_count"],
        4,
    )
    android_legacy_rows = {
        row["original_name"]: row for row in spectron_android_legacy_anchors["anchors"]
    }
    check(
        "Spectron TapJoy secret target",
        android_legacy_rows["MainAndroid_script_settapjoysecret"]["spectron_ea"],
        "0x24a240",
    )
    check(
        "Spectron TapJoy application ID target",
        android_legacy_rows["MainAndroid_script_settapjoyapplicationid"]["spectron_ea"],
        "0x24a254",
    )
    check(
        "Spectron TapJoy connector target",
        android_legacy_rows["JNI_connectToTapJoyService"]["spectron_ea"],
        "0x24c7e4",
    )
    check(
        "Spectron Android ID target",
        android_legacy_rows["androidGetID_void"]["spectron_ea"],
        "0x2502f4",
    )
    check(
        "Spectron v265 checkpoint artifact",
        spectron_checkpoint_v265["artifact"],
        "spectron_translation_checkpoint_20260828_v265",
    )
    check(
        "Spectron v265 checkpoint parent",
        spectron_checkpoint_v265["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v264_corrected",
    )
    check(
        "Spectron v265 checkpoint database hash",
        spectron_checkpoint_v265["database"]["sha256"],
        "89eafac9cb7b6cba867fa6e39c0fd6e6814a0b45b586e5d75238b2502e566e61",
    )
    check(
        "Spectron v265 checkpoint function count",
        spectron_checkpoint_v265["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v265 checkpoint default sub count",
        spectron_checkpoint_v265["database"]["default_sub_function_count"],
        709,
    )
    check(
        "Spectron v265 checkpoint anchor count",
        spectron_checkpoint_v265["android_legacy_anchors"]["verified_name_count"],
        4,
    )
    check(
        "Spectron Android security target-only artifact",
        spectron_android_security_target_only_labels["artifact"],
        "spectron_android_security_target_only_labels_20260828",
    )
    check(
        "Spectron Android security target-only network",
        spectron_android_security_target_only_labels["network_contacted"],
        False,
    )
    check(
        "Spectron Android security target-only label count",
        spectron_android_security_target_only_labels["summary"]["label_count"],
        5,
    )
    check(
        "Spectron Android security target-only high-confidence count",
        spectron_android_security_target_only_labels["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron Android security target-only default count",
        spectron_android_security_target_only_labels["summary"]["target_default_name_count"],
        5,
    )
    check(
        "Spectron Android security target-only source counterpart count",
        spectron_android_security_target_only_labels["summary"]["source_counterpart_count"],
        0,
    )
    android_security_rows = {
        row["target_ea"]: row
        for row in spectron_android_security_target_only_labels["labels"]
    }
    check(
        "Spectron getandroidabi target-only label",
        android_security_rows["0x24a1d8"]["proposed_name"],
        "spectron_getandroidabi",
    )
    check(
        "Spectron Frida sleep-loop target-only label",
        android_security_rows["0x24a2ac"]["proposed_name"],
        "spectron_frida_detection_sleep_loop",
    )
    check(
        "Spectron v266 checkpoint artifact",
        spectron_checkpoint_v266["artifact"],
        "spectron_translation_checkpoint_20260828_v266",
    )
    check(
        "Spectron v266 checkpoint parent",
        spectron_checkpoint_v266["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v265",
    )
    check(
        "Spectron v266 checkpoint database hash",
        spectron_checkpoint_v266["database"]["sha256"],
        "1d9a96fb4db2f9ee1d6353ca2ea94deb30ae5e03085c2bf8ca1286a89f99616f",
    )
    check(
        "Spectron v266 checkpoint function count",
        spectron_checkpoint_v266["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v266 checkpoint default sub count",
        spectron_checkpoint_v266["database"]["default_sub_function_count"],
        704,
    )
    check(
        "Spectron v266 checkpoint label count",
        spectron_checkpoint_v266["android_security_target_only_labels"]["verified_name_count"],
        5,
    )
    check(
        "Spectron corrected Android security artifact",
        spectron_android_security_target_only_labels_corrected["artifact"],
        "spectron_android_security_target_only_labels_corrected_20260828",
    )
    check(
        "Spectron corrected Android security network",
        spectron_android_security_target_only_labels_corrected["network_contacted"],
        False,
    )
    check(
        "Spectron corrected Android security label count",
        spectron_android_security_target_only_labels_corrected["summary"]["label_count"],
        6,
    )
    check(
        "Spectron corrected Android security high-confidence count",
        spectron_android_security_target_only_labels_corrected["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron corrected Android security default count",
        spectron_android_security_target_only_labels_corrected["summary"]["target_default_name_count"],
        6,
    )
    corrected_security_rows = {
        row["target_ea"]: row
        for row in spectron_android_security_target_only_labels_corrected["labels"]
    }
    check(
        "Spectron corrected class-exists target",
        corrected_security_rows["0x250090"]["proposed_name"],
        "spectron_android_getjavaclassexists",
    )
    check(
        "Spectron corrected static-function-exists target",
        corrected_security_rows["0x2500ec"]["proposed_name"],
        "spectron_android_getstaticjavafuncexists",
    )
    check(
        "Spectron v267 checkpoint artifact",
        spectron_checkpoint_v267["artifact"],
        "spectron_translation_checkpoint_20260828_v267",
    )
    check(
        "Spectron v267 checkpoint parent",
        spectron_checkpoint_v267["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v266",
    )
    check(
        "Spectron v267 checkpoint database hash",
        spectron_checkpoint_v267["database"]["sha256"],
        "a2c29b06f0fed5b7631586051e28b246a28882c057bfe808ff7db32516a20a5f",
    )
    check(
        "Spectron v267 checkpoint function count",
        spectron_checkpoint_v267["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v267 checkpoint default sub count",
        spectron_checkpoint_v267["database"]["default_sub_function_count"],
        703,
    )
    check(
        "Spectron v267 checkpoint label count",
        spectron_checkpoint_v267["android_security_target_only_labels_corrected"]["verified_name_count"],
        6,
    )
    check(
        "Spectron package identity artifact",
        spectron_android_package_identity_labels["artifact"],
        "spectron_android_package_identity_labels_20260828",
    )
    check(
        "Spectron package identity network",
        spectron_android_package_identity_labels["network_contacted"],
        False,
    )
    check(
        "Spectron package identity label count",
        spectron_android_package_identity_labels["summary"]["label_count"],
        1,
    )
    check(
        "Spectron package identity target",
        spectron_android_package_identity_labels["labels"][0]["target_ea"],
        "0x24a9ec",
    )
    check(
        "Spectron package identity label",
        spectron_android_package_identity_labels["labels"][0]["proposed_name"],
        "spectron_quattro_android_getsignature",
    )
    check(
        "Spectron v268 checkpoint artifact",
        spectron_checkpoint_v268["artifact"],
        "spectron_translation_checkpoint_20260828_v268",
    )
    check(
        "Spectron v268 checkpoint parent",
        spectron_checkpoint_v268["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v267",
    )
    check(
        "Spectron v268 checkpoint database hash",
        spectron_checkpoint_v268["database"]["sha256"],
        "00d08f743e7e01ac77b6eb8ccec266db89be0c8cc2382ebd542e23f2d80a4077",
    )
    check(
        "Spectron v268 checkpoint function count",
        spectron_checkpoint_v268["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v268 checkpoint default sub count",
        spectron_checkpoint_v268["database"]["default_sub_function_count"],
        702,
    )
    check(
        "Spectron v268 checkpoint label count",
        spectron_checkpoint_v268["android_package_identity_labels"]["verified_name_count"],
        1,
    )
    check(
        "Spectron TGraalVar script-runtime artifact",
        spectron_tgraalvar_script_runtime_anchors["artifact"],
        "spectron_tgraalvar_script_runtime_manual_translation_anchors_20260828",
    )
    check(
        "Spectron TGraalVar script-runtime network",
        spectron_tgraalvar_script_runtime_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron TGraalVar script-runtime total",
        spectron_tgraalvar_script_runtime_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron TGraalVar script-runtime high confidence",
        spectron_tgraalvar_script_runtime_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron TGraalVar script-runtime semantic overlap",
        spectron_tgraalvar_script_runtime_anchors["summary"]["already_in_semantic_map"],
        0,
    )
    check(
        "Spectron TGraalVar script-runtime exact count",
        spectron_tgraalvar_script_runtime_anchors["summary"]["exact_shape_anchor_count"],
        4,
    )
    check(
        "Spectron TGraalVar script-runtime layout count",
        spectron_tgraalvar_script_runtime_anchors["summary"]["layout_change_anchor_count"],
        1,
    )
    check(
        "Spectron TGraalVar script-runtime default count",
        spectron_tgraalvar_script_runtime_anchors["summary"]["target_default_name_count"],
        5,
    )
    script_runtime_rows = {
        row["spectron_ea"]: row
        for row in spectron_tgraalvar_script_runtime_anchors["anchors"]
    }
    check(
        "Spectron TGraalVar clearvars target",
        script_runtime_rows["0x21362c"]["proposed_name"],
        "v18_TGraalVar_script_clearvars",
    )
    check(
        "Spectron TGraalVar addnamedstring match kind",
        script_runtime_rows["0x2138b0"]["match_kind"],
        "manual-tgraalvar-script-runtime-layout-anchor",
    )
    check(
        "Spectron TGraalVar script-runtime exact rows",
        sum(row["exact_metric_match"] for row in script_runtime_rows.values()),
        4,
    )
    check(
        "Spectron TGraalVar target-only artifact",
        spectron_tgraalvar_target_only_labels["artifact"],
        "spectron_tgraalvar_target_only_labels_20260828",
    )
    check(
        "Spectron TGraalVar target-only network",
        spectron_tgraalvar_target_only_labels["network_contacted"],
        False,
    )
    check(
        "Spectron TGraalVar target-only total",
        spectron_tgraalvar_target_only_labels["summary"]["label_count"],
        1,
    )
    check(
        "Spectron TGraalVar target-only default count",
        spectron_tgraalvar_target_only_labels["summary"]["target_default_name_count"],
        1,
    )
    target_only_row = spectron_tgraalvar_target_only_labels["labels"][0]
    check(
        "Spectron TGraalVar target-only address",
        target_only_row["target_ea"],
        "0x218870",
    )
    check(
        "Spectron TGraalVar target-only decoded name",
        target_only_row["script_name"],
        "loadvarsfromarray",
    )
    check(
        "Spectron TGraalVar target-only label",
        target_only_row["proposed_name"],
        "spectron_TGraalVar_script_loadvarsfromarray_TGraalVar",
    )
    check(
        "Spectron v269 checkpoint artifact",
        spectron_checkpoint_v269["artifact"],
        "spectron_translation_checkpoint_20260828_v269",
    )
    check(
        "Spectron v269 checkpoint parent",
        spectron_checkpoint_v269["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v268",
    )
    check(
        "Spectron v269 checkpoint database hash",
        spectron_checkpoint_v269["database"]["sha256"],
        "26b5b1d498d924771172b33c68bb551e373e408ef1054d65b5ba386bec6e0eaf",
    )
    check(
        "Spectron v269 checkpoint function count",
        spectron_checkpoint_v269["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v269 checkpoint default sub count",
        spectron_checkpoint_v269["database"]["default_sub_function_count"],
        696,
    )
    check(
        "Spectron v269 checkpoint script-runtime count",
        spectron_checkpoint_v269["tgraalvar_script_runtime_anchors"]["verified_name_count"],
        5,
    )
    check(
        "Spectron v269 checkpoint target-only count",
        spectron_checkpoint_v269["tgraalvar_target_only_labels"]["verified_name_count"],
        1,
    )
    check(
        "Spectron script-table surface artifact",
        spectron_script_table_surface_anchors["artifact"],
        "spectron_script_table_surface_manual_translation_anchors_20260828",
    )
    check(
        "Spectron script-table surface network",
        spectron_script_table_surface_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron script-table surface anchor count",
        spectron_script_table_surface_anchors["summary"]["anchor_count"],
        17,
    )
    check(
        "Spectron script-table surface unique target count",
        spectron_script_table_surface_anchors["summary"]["unique_target_count"],
        17,
    )
    check(
        "Spectron script-table surface high-confidence count",
        spectron_script_table_surface_anchors["summary"]["high_confidence_count"],
        17,
    )
    check(
        "Spectron script-table surface target default count",
        spectron_script_table_surface_anchors["summary"]["target_default_name_count"],
        16,
    )
    check(
        "Spectron script-table surface normalized exact count",
        spectron_script_table_surface_anchors["summary"]["normalized_shape_exact_count"],
        15,
    )
    check(
        "Spectron script-table surface full metric exact count",
        spectron_script_table_surface_anchors["summary"]["full_metric_exact_count"],
        12,
    )
    check(
        "Spectron script-table surface layout change count",
        spectron_script_table_surface_anchors["summary"]["layout_change_count"],
        2,
    )
    check(
        "Spectron script-table surface correction count",
        spectron_script_table_surface_anchors["summary"]["correction_count"],
        1,
    )
    script_table_surface_rows = {
        row["spectron_ea"]: row
        for row in spectron_script_table_surface_anchors["anchors"]
    }
    check(
        "Spectron script-table pushdialog target",
        script_table_surface_rows["0x1b5cf8"]["proposed_name"],
        "v18_GuiCanvas_script_pushdialog",
    )
    check(
        "Spectron script-table pushdialog correction",
        script_table_surface_rows["0x1b5cf8"]["corrected_from"],
        "v18_GuiCanvas_script_popdialog",
    )
    check(
        "Spectron script-table popdialog target",
        script_table_surface_rows["0x1b58c4"]["proposed_name"],
        "v18_GuiCanvas_script_popdialog",
    )
    check(
        "Spectron script-table objecttype target",
        script_table_surface_rows["0x2141e4"]["proposed_name"],
        "v18_TGraalVar_script_objecttype",
    )
    check(
        "Spectron script-table gettileset target",
        script_table_surface_rows["0x238edc"]["proposed_name"],
        "v18_TTiles_script_gettileset",
    )
    check(
        "Spectron v270 checkpoint artifact",
        spectron_checkpoint_v270["artifact"],
        "spectron_translation_checkpoint_20260828_v270",
    )
    check(
        "Spectron v270 checkpoint parent",
        spectron_checkpoint_v270["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v269",
    )
    check(
        "Spectron v270 checkpoint database hash",
        spectron_checkpoint_v270["database"]["sha256"],
        "cc36148be4302e46bcc0a30bee43e4dd873ff7b25b93a6b49f74db7cfbfbb789",
    )
    check(
        "Spectron v270 checkpoint function count",
        spectron_checkpoint_v270["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v270 checkpoint default sub count",
        spectron_checkpoint_v270["database"]["default_sub_function_count"],
        680,
    )
    check(
        "Spectron v270 checkpoint script-table count",
        spectron_checkpoint_v270["script_table_surface_anchors"]["verified_name_count"],
        17,
    )
    check(
        "Spectron runtime callback residual artifact",
        spectron_runtime_callback_residual_anchors["artifact"],
        "spectron_runtime_callback_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron runtime callback residual network",
        spectron_runtime_callback_residual_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron runtime callback residual anchor count",
        spectron_runtime_callback_residual_anchors["summary"]["anchor_count"],
        9,
    )
    check(
        "Spectron runtime callback residual unique target count",
        spectron_runtime_callback_residual_anchors["summary"]["unique_target_count"],
        9,
    )
    check(
        "Spectron runtime callback residual high-confidence count",
        spectron_runtime_callback_residual_anchors["summary"]["high_confidence_count"],
        9,
    )
    check(
        "Spectron runtime callback residual exact count",
        spectron_runtime_callback_residual_anchors["summary"]["exact_metric_match_count"],
        9,
    )
    check(
        "Spectron runtime callback residual default count",
        spectron_runtime_callback_residual_anchors["summary"]["target_default_name_count"],
        8,
    )
    check(
        "Spectron runtime callback residual TStream count",
        spectron_runtime_callback_residual_anchors["summary"]["tstream_count"],
        4,
    )
    check(
        "Spectron runtime callback residual zlib count",
        spectron_runtime_callback_residual_anchors["summary"]["zlib_count"],
        2,
    )
    check(
        "Spectron runtime callback residual YAJL count",
        spectron_runtime_callback_residual_anchors["summary"]["yajl_count"],
        3,
    )
    runtime_callback_rows = {
        row["spectron_ea"]: row
        for row in spectron_runtime_callback_residual_anchors["anchors"]
    }
    check(
        "Spectron runtime callback TStream tell target",
        runtime_callback_rows["0xf19cc"]["proposed_name"],
        "v18_TStream_zipTellFile",
    )
    check(
        "Spectron runtime callback zlib calloc target",
        runtime_callback_rows["0x296ff0"]["proposed_name"],
        "v18_zlib_zcalloc",
    )
    check(
        "Spectron runtime callback YAJL malloc target",
        runtime_callback_rows["0x2bcd20"]["proposed_name"],
        "v18_yajl_internal_malloc",
    )
    check(
        "Spectron TPlayer Quattro property artifact",
        spectron_tplayer_quattro_zoom_property_labels["artifact"],
        "spectron_tplayer_quattro_zoom_property_target_only_labels_20260828",
    )
    check(
        "Spectron TPlayer Quattro property network",
        spectron_tplayer_quattro_zoom_property_labels["network_contacted"],
        False,
    )
    check(
        "Spectron TPlayer Quattro property label count",
        spectron_tplayer_quattro_zoom_property_labels["summary"]["label_count"],
        2,
    )
    check(
        "Spectron TPlayer Quattro property high-confidence count",
        spectron_tplayer_quattro_zoom_property_labels["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron TPlayer Quattro property default count",
        spectron_tplayer_quattro_zoom_property_labels["summary"]["target_default_name_count"],
        2,
    )
    check(
        "Spectron TPlayer Quattro property source counterpart count",
        spectron_tplayer_quattro_zoom_property_labels["summary"]["source_counterpart_count"],
        0,
    )
    check(
        "Spectron TPlayer Quattro property getter count",
        spectron_tplayer_quattro_zoom_property_labels["summary"]["getter_count"],
        1,
    )
    check(
        "Spectron TPlayer Quattro property setter count",
        spectron_tplayer_quattro_zoom_property_labels["summary"]["setter_count"],
        1,
    )
    quattro_rows = {
        row["target_ea"]: row
        for row in spectron_tplayer_quattro_zoom_property_labels["labels"]
    }
    check(
        "Spectron TPlayer Quattro getter target",
        quattro_rows["0x170334"]["proposed_name"],
        "spectron_TPlayer_get_useQuattroZoomFactorCulling",
    )
    check(
        "Spectron TPlayer Quattro setter target",
        quattro_rows["0x170344"]["proposed_name"],
        "spectron_TPlayer_set_useQuattroZoomFactorCulling",
    )
    check(
        "Spectron v271 checkpoint artifact",
        spectron_checkpoint_v271["artifact"],
        "spectron_translation_checkpoint_20260828_v271",
    )
    check(
        "Spectron v271 checkpoint parent",
        spectron_checkpoint_v271["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v270",
    )
    check(
        "Spectron v271 checkpoint database hash",
        spectron_checkpoint_v271["database"]["sha256"],
        "9ce571f635b79dfc95faf97b80242e52003620367c5edf30ee5c3fb028616e14",
    )
    check(
        "Spectron v271 checkpoint function count",
        spectron_checkpoint_v271["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v271 checkpoint default sub count",
        spectron_checkpoint_v271["database"]["default_sub_function_count"],
        670,
    )
    check(
        "Spectron v271 checkpoint runtime count",
        spectron_checkpoint_v271["runtime_callback_residual_anchors"]["verified_name_count"],
        9,
    )
    check(
        "Spectron v271 checkpoint property count",
        spectron_checkpoint_v271["tplayer_quattro_zoom_property_labels"]["verified_name_count"],
        2,
    )
    check(
        "Spectron zlib inflate_fast artifact",
        spectron_zlib_inflate_fast_anchor["artifact"],
        "spectron_zlib_inflate_fast_manual_translation_anchor_20260828",
    )
    check(
        "Spectron zlib inflate_fast network",
        spectron_zlib_inflate_fast_anchor["network_contacted"],
        False,
    )
    check(
        "Spectron zlib inflate_fast anchor count",
        spectron_zlib_inflate_fast_anchor["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron zlib inflate_fast high-confidence count",
        spectron_zlib_inflate_fast_anchor["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron zlib inflate_fast target default count",
        spectron_zlib_inflate_fast_anchor["summary"]["target_default_name_count"],
        1,
    )
    check(
        "Spectron zlib inflate_fast normalized count",
        spectron_zlib_inflate_fast_anchor["summary"]["normalized_shape_exact_count"],
        1,
    )
    zlib_inflate_fast_rows = {
        row["spectron_ea"]: row
        for row in spectron_zlib_inflate_fast_anchor["anchors"]
    }
    check(
        "Spectron zlib inflate_fast target",
        zlib_inflate_fast_rows["0x297764"]["proposed_name"],
        "v18_zlib_inflate_fast",
    )
    check(
        "Spectron zlib inflate_fast source current name",
        zlib_inflate_fast_rows["0x297764"]["original_current_name"],
        "sub_28A2F4",
    )
    check(
        "Spectron zlib inflate_fast target current name",
        zlib_inflate_fast_rows["0x297764"]["spectron_current_name"],
        "sub_297764",
    )
    check(
        "Spectron v272 checkpoint artifact",
        spectron_checkpoint_v272["artifact"],
        "spectron_translation_checkpoint_20260828_v272",
    )
    check(
        "Spectron v272 checkpoint parent",
        spectron_checkpoint_v272["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v271",
    )
    check(
        "Spectron v272 checkpoint database hash",
        spectron_checkpoint_v272["database"]["sha256"],
        "976eb158d621ac25c65c79ab0939de80e5965a7e45b1bf9f322dddcd6125763c",
    )
    check(
        "Spectron v272 checkpoint function count",
        spectron_checkpoint_v272["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v272 checkpoint default sub count",
        spectron_checkpoint_v272["database"]["default_sub_function_count"],
        669,
    )
    check(
        "Spectron v272 checkpoint zlib count",
        spectron_checkpoint_v272["zlib_inflate_fast_anchor"]["verified_name_count"],
        1,
    )
    check(
        "Spectron libjpeg I/O artifact",
        spectron_jpeg_io_anchors["artifact"],
        "spectron_jpeg_io_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg I/O network",
        spectron_jpeg_io_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg I/O anchor count",
        spectron_jpeg_io_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron libjpeg I/O unique target count",
        spectron_jpeg_io_anchors["summary"]["unique_target_count"],
        6,
    )
    check(
        "Spectron libjpeg I/O high-confidence count",
        spectron_jpeg_io_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron libjpeg I/O normalized count",
        spectron_jpeg_io_anchors["summary"]["normalized_shape_exact_count"],
        6,
    )
    check(
        "Spectron libjpeg I/O exact count",
        spectron_jpeg_io_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron libjpeg I/O destination count",
        spectron_jpeg_io_anchors["summary"]["destination_callback_count"],
        3,
    )
    check(
        "Spectron libjpeg I/O source count",
        spectron_jpeg_io_anchors["summary"]["source_callback_count"],
        3,
    )
    jpeg_io_rows = {
        row["spectron_ea"]: row for row in spectron_jpeg_io_anchors["anchors"]
    }
    jpeg_io_expected = {
        "0x298e64": "v18_jpeg_init_destination",
        "0x298ea0": "v18_jpeg_empty_output_buffer",
        "0x298f14": "v18_jpeg_term_destination",
        "0x29902c": "v18_jpeg_init_source",
        "0x29903c": "v18_jpeg_fill_input_buffer",
        "0x2990f8": "v18_jpeg_skip_input_data",
    }
    for target_ea, expected_name in jpeg_io_expected.items():
        check(
            "Spectron libjpeg I/O target " + target_ea,
            jpeg_io_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v273 checkpoint artifact",
        spectron_checkpoint_v273["artifact"],
        "spectron_translation_checkpoint_20260828_v273",
    )
    check(
        "Spectron v273 checkpoint parent",
        spectron_checkpoint_v273["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v272",
    )
    check(
        "Spectron v273 checkpoint database hash",
        spectron_checkpoint_v273["database"]["sha256"],
        "054b633f56a9aaee6d99048666c209831563a6e32046adab17ea48224d46807f",
    )
    check(
        "Spectron v273 checkpoint function count",
        spectron_checkpoint_v273["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v273 checkpoint default sub count",
        spectron_checkpoint_v273["database"]["default_sub_function_count"],
        663,
    )
    check(
        "Spectron v273 checkpoint libjpeg count",
        spectron_checkpoint_v273["jpeg_io_anchors"]["verified_name_count"],
        6,
    )
    check(
        "Spectron libjpeg jdinput controller artifact",
        spectron_jdinput_controller_anchors["artifact"],
        "spectron_jpeg_input_controller_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdinput controller network",
        spectron_jdinput_controller_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdinput controller anchor count",
        spectron_jdinput_controller_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron libjpeg jdinput controller unique target count",
        spectron_jdinput_controller_anchors["summary"]["unique_target_count"],
        4,
    )
    check(
        "Spectron libjpeg jdinput controller high-confidence count",
        spectron_jdinput_controller_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron libjpeg jdinput controller normalized count",
        spectron_jdinput_controller_anchors["summary"]["normalized_shape_exact_count"],
        4,
    )
    check(
        "Spectron libjpeg jdinput controller exact count",
        spectron_jdinput_controller_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    jdinput_rows = {
        row["spectron_ea"]: row
        for row in spectron_jdinput_controller_anchors["anchors"]
    }
    jdinput_expected = {
        "0x2992b4": "v18_jpeg_finish_input_pass",
        "0x2992c8": "v18_jpeg_reset_input_controller",
        "0x299320": "v18_jpeg_start_input_pass",
        "0x2997e8": "v18_jpeg_consume_markers",
    }
    for target_ea, expected_name in jdinput_expected.items():
        check(
            "Spectron libjpeg jdinput controller target " + target_ea,
            jdinput_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v274 checkpoint artifact",
        spectron_checkpoint_v274["artifact"],
        "spectron_translation_checkpoint_20260828_v274",
    )
    check(
        "Spectron v274 checkpoint parent",
        spectron_checkpoint_v274["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v273",
    )
    check(
        "Spectron v274 checkpoint database hash",
        spectron_checkpoint_v274["database"]["sha256"],
        "0f9298e5426fde565eaa76b46e31c8241dcc640f0ea27937d3ccd4d31230bc13",
    )
    check(
        "Spectron v274 checkpoint function count",
        spectron_checkpoint_v274["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v274 checkpoint default sub count",
        spectron_checkpoint_v274["database"]["default_sub_function_count"],
        659,
    )
    check(
        "Spectron v274 checkpoint jdinput count",
        spectron_checkpoint_v274["jdinput_controller_anchors"]["verified_name_count"],
        4,
    )
    check(
        "Spectron libjpeg jdmarker artifact",
        spectron_jdmarker_anchors["artifact"],
        "spectron_jpeg_marker_reader_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdmarker network",
        spectron_jdmarker_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdmarker anchor count",
        spectron_jdmarker_anchors["summary"]["anchor_count"],
        9,
    )
    check(
        "Spectron libjpeg jdmarker unique target count",
        spectron_jdmarker_anchors["summary"]["unique_target_count"],
        9,
    )
    check(
        "Spectron libjpeg jdmarker high-confidence count",
        spectron_jdmarker_anchors["summary"]["high_confidence_count"],
        9,
    )
    check(
        "Spectron libjpeg jdmarker normalized count",
        spectron_jdmarker_anchors["summary"]["normalized_shape_exact_count"],
        9,
    )
    check(
        "Spectron libjpeg jdmarker exact count",
        spectron_jdmarker_anchors["summary"]["full_metric_exact_count"],
        8,
    )
    jdmarker_rows = {
        row["spectron_ea"]: row
        for row in spectron_jdmarker_anchors["anchors"]
    }
    jdmarker_expected = {
        "0x29a028": "v18_jpeg_get_sof",
        "0x29a46c": "v18_jpeg_examine_app0",
        "0x29a75c": "v18_jpeg_skip_variable",
        "0x29a870": "v18_jpeg_reset_marker_reader",
        "0x29a894": "v18_jpeg_get_dht",
        "0x29ac74": "v18_jpeg_save_marker",
        "0x29afac": "v18_jpeg_get_interesting_appn",
        "0x29b20c": "v18_jpeg_read_markers",
        "0x29bf90": "v18_jpeg_read_restart_marker",
    }
    for target_ea, expected_name in jdmarker_expected.items():
        check(
            "Spectron libjpeg jdmarker target " + target_ea,
            jdmarker_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v275 checkpoint artifact",
        spectron_checkpoint_v275["artifact"],
        "spectron_translation_checkpoint_20260828_v275",
    )
    check(
        "Spectron v275 checkpoint parent",
        spectron_checkpoint_v275["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v274",
    )
    check(
        "Spectron v275 checkpoint database hash",
        spectron_checkpoint_v275["database"]["sha256"],
        "d16670d36212d270fc1ac476aae6ab5cb540ed4d209c50a8981edf2804dff9ee",
    )
    check(
        "Spectron v275 checkpoint function count",
        spectron_checkpoint_v275["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v275 checkpoint default sub count",
        spectron_checkpoint_v275["database"]["default_sub_function_count"],
        650,
    )
    check(
        "Spectron v275 checkpoint jdmarker count",
        spectron_checkpoint_v275["jdmarker_anchors"]["verified_name_count"],
        9,
    )
    check(
        "Spectron libjpeg jdmaster/jdmerge artifact",
        spectron_jdmaster_jdmerge_anchors["artifact"],
        "spectron_jpeg_master_merge_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdmaster/jdmerge network",
        spectron_jdmaster_jdmerge_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdmaster/jdmerge anchor count",
        spectron_jdmaster_jdmerge_anchors["summary"]["anchor_count"],
        7,
    )
    check(
        "Spectron libjpeg jdmaster/jdmerge unique target count",
        spectron_jdmaster_jdmerge_anchors["summary"]["unique_target_count"],
        7,
    )
    check(
        "Spectron libjpeg jdmaster/jdmerge high-confidence count",
        spectron_jdmaster_jdmerge_anchors["summary"]["high_confidence_count"],
        7,
    )
    check(
        "Spectron libjpeg jdmaster/jdmerge normalized count",
        spectron_jdmaster_jdmerge_anchors["summary"]["normalized_shape_exact_count"],
        7,
    )
    check(
        "Spectron libjpeg jdmaster/jdmerge exact count",
        spectron_jdmaster_jdmerge_anchors["summary"]["full_metric_exact_count"],
        7,
    )
    jdmaster_jdmerge_rows = {
        row["spectron_ea"]: row
        for row in spectron_jdmaster_jdmerge_anchors["anchors"]
    }
    jdmaster_jdmerge_expected = {
        "0x29c720": "v18_jpeg_prepare_for_output_pass",
        "0x29c8e8": "v18_jpeg_finish_output_pass",
        "0x29d350": "v18_jpeg_start_pass_merged_upsample",
        "0x29d364": "v18_jpeg_merged_1v_upsample",
        "0x29d3b4": "v18_jpeg_h2v1_merged_upsample",
        "0x29d504": "v18_jpeg_h2v2_merged_upsample",
        "0x29d704": "v18_jpeg_merged_2v_upsample",
    }
    for target_ea, expected_name in jdmaster_jdmerge_expected.items():
        check(
            "Spectron libjpeg jdmaster/jdmerge target " + target_ea,
            jdmaster_jdmerge_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v276 checkpoint artifact",
        spectron_checkpoint_v276["artifact"],
        "spectron_translation_checkpoint_20260828_v276",
    )
    check(
        "Spectron v276 checkpoint parent",
        spectron_checkpoint_v276["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v275",
    )
    check(
        "Spectron v276 checkpoint database hash",
        spectron_checkpoint_v276["database"]["sha256"],
        "787cdf2e8483cd7845dd29f6a488d1d746f10cfb38c43024623555bc4491f0eb",
    )
    check(
        "Spectron v276 checkpoint function count",
        spectron_checkpoint_v276["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v276 checkpoint default sub count",
        spectron_checkpoint_v276["database"]["default_sub_function_count"],
        643,
    )
    check(
        "Spectron v276 checkpoint output-pipeline count",
        spectron_checkpoint_v276["jdmaster_jdmerge_anchors"]["verified_name_count"],
        7,
    )
    check(
        "Spectron libjpeg jdphuff artifact",
        spectron_jdphuff_anchors["artifact"],
        "spectron_jpeg_progressive_huffman_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdphuff network",
        spectron_jdphuff_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdphuff anchor count",
        spectron_jdphuff_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron libjpeg jdphuff unique target count",
        spectron_jdphuff_anchors["summary"]["unique_target_count"],
        5,
    )
    check(
        "Spectron libjpeg jdphuff high-confidence count",
        spectron_jdphuff_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron libjpeg jdphuff normalized count",
        spectron_jdphuff_anchors["summary"]["normalized_shape_exact_count"],
        5,
    )
    check(
        "Spectron libjpeg jdphuff exact count",
        spectron_jdphuff_anchors["summary"]["full_metric_exact_count"],
        1,
    )
    jdphuff_rows = {
        row["spectron_ea"]: row for row in spectron_jdphuff_anchors["anchors"]
    }
    jdphuff_expected = {
        "0x29d9a8": "v18_jpeg_start_pass_phuff_decoder",
        "0x29ddcc": "v18_jpeg_decode_mcu_AC_refine",
        "0x29e2ac": "v18_jpeg_decode_mcu_AC_first",
        "0x29e5c4": "v18_jpeg_decode_mcu_DC_refine",
        "0x29e768": "v18_jpeg_decode_mcu_DC_first",
    }
    for target_ea, expected_name in jdphuff_expected.items():
        check(
            "Spectron libjpeg jdphuff target " + target_ea,
            jdphuff_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v277 checkpoint artifact",
        spectron_checkpoint_v277["artifact"],
        "spectron_translation_checkpoint_20260828_v277",
    )
    check(
        "Spectron v277 checkpoint parent",
        spectron_checkpoint_v277["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v276",
    )
    check(
        "Spectron v277 checkpoint database hash",
        spectron_checkpoint_v277["database"]["sha256"],
        "633510a1e4fe2f112bf4e5ce73532d894bedda0d67a519a5eceec66078e2318c",
    )
    check(
        "Spectron v277 checkpoint function count",
        spectron_checkpoint_v277["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v277 checkpoint default sub count",
        spectron_checkpoint_v277["database"]["default_sub_function_count"],
        638,
    )
    check(
        "Spectron v277 checkpoint jdphuff count",
        spectron_checkpoint_v277["jdphuff_anchors"]["verified_name_count"],
        5,
    )
    check(
        "Spectron libjpeg jdpostct artifact",
        spectron_jdpostct_anchors["artifact"],
        "spectron_jpeg_postprocessing_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdpostct network",
        spectron_jdpostct_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdpostct anchor count",
        spectron_jdpostct_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron libjpeg jdpostct unique target count",
        spectron_jdpostct_anchors["summary"]["unique_target_count"],
        4,
    )
    check(
        "Spectron libjpeg jdpostct high-confidence count",
        spectron_jdpostct_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron libjpeg jdpostct normalized count",
        spectron_jdpostct_anchors["summary"]["normalized_shape_exact_count"],
        4,
    )
    check(
        "Spectron libjpeg jdpostct exact count",
        spectron_jdpostct_anchors["summary"]["full_metric_exact_count"],
        3,
    )
    jdpostct_rows = {
        row["spectron_ea"]: row for row in spectron_jdpostct_anchors["anchors"]
    }
    jdpostct_expected = {
        "0x29eb68": "v18_jpeg_start_pass_dpost",
        "0x29ec80": "v18_jpeg_post_process_1pass",
        "0x29ed10": "v18_jpeg_post_process_prepass",
        "0x29ee10": "v18_jpeg_post_process_2pass",
    }
    for target_ea, expected_name in jdpostct_expected.items():
        check(
            "Spectron libjpeg jdpostct target " + target_ea,
            jdpostct_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v278 checkpoint artifact",
        spectron_checkpoint_v278["artifact"],
        "spectron_translation_checkpoint_20260828_v278",
    )
    check(
        "Spectron v278 checkpoint parent",
        spectron_checkpoint_v278["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v277",
    )
    check(
        "Spectron v278 checkpoint database hash",
        spectron_checkpoint_v278["database"]["sha256"],
        "190b42912a47a71415585174e3b78f5cd74a8f97872e3293db5aef2fab7f7228",
    )
    check(
        "Spectron v278 checkpoint function count",
        spectron_checkpoint_v278["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v278 checkpoint default sub count",
        spectron_checkpoint_v278["database"]["default_sub_function_count"],
        634,
    )
    check(
        "Spectron v278 checkpoint jdpostct count",
        spectron_checkpoint_v278["jdpostct_anchors"]["verified_name_count"],
        4,
    )
    check(
        "Spectron libjpeg jdsample artifact",
        spectron_jdsample_anchors["artifact"],
        "spectron_jpeg_upsampler_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdsample network",
        spectron_jdsample_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdsample anchor count",
        spectron_jdsample_anchors["summary"]["anchor_count"],
        9,
    )
    check(
        "Spectron libjpeg jdsample unique target count",
        spectron_jdsample_anchors["summary"]["unique_target_count"],
        9,
    )
    check(
        "Spectron libjpeg jdsample high-confidence count",
        spectron_jdsample_anchors["summary"]["high_confidence_count"],
        9,
    )
    check(
        "Spectron libjpeg jdsample normalized count",
        spectron_jdsample_anchors["summary"]["normalized_shape_exact_count"],
        9,
    )
    check(
        "Spectron libjpeg jdsample exact count",
        spectron_jdsample_anchors["summary"]["full_metric_exact_count"],
        9,
    )
    jdsample_rows = {
        row["spectron_ea"]: row for row in spectron_jdsample_anchors["anchors"]
    }
    jdsample_expected = {
        "0x29efdc": "v18_jpeg_start_pass_upsample",
        "0x29eff4": "v18_jpeg_sep_upsample",
        "0x29f158": "v18_jpeg_fullsize_upsample",
        "0x29f160": "v18_jpeg_noop_upsample",
        "0x29f168": "v18_jpeg_h2v1_upsample",
        "0x29f3dc": "v18_jpeg_h2v1_fancy_upsample",
        "0x29f690": "v18_jpeg_h1v2_fancy_upsample",
        "0x29f7d0": "v18_jpeg_int_upsample",
        "0x29f9d8": "v18_jpeg_h2v2_upsample",
    }
    for target_ea, expected_name in jdsample_expected.items():
        check(
            "Spectron libjpeg jdsample target " + target_ea,
            jdsample_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v279 checkpoint artifact",
        spectron_checkpoint_v279["artifact"],
        "spectron_translation_checkpoint_20260828_v279",
    )
    check(
        "Spectron v279 checkpoint parent",
        spectron_checkpoint_v279["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v278",
    )
    check(
        "Spectron v279 checkpoint database hash",
        spectron_checkpoint_v279["database"]["sha256"],
        "131bdd75a02324441e0cd819feacd5ee46958ba7b7d3263eada9fc8601fc5b59",
    )
    check(
        "Spectron v279 checkpoint function count",
        spectron_checkpoint_v279["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v279 checkpoint default sub count",
        spectron_checkpoint_v279["database"]["default_sub_function_count"],
        625,
    )
    check(
        "Spectron v279 checkpoint jdsample count",
        spectron_checkpoint_v279["jdsample_anchors"]["verified_name_count"],
        9,
    )
    check(
        "Spectron libjpeg jerror artifact",
        spectron_jerror_anchors["artifact"],
        "spectron_jpeg_error_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jerror network",
        spectron_jerror_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jerror anchor count",
        spectron_jerror_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron libjpeg jerror unique target count",
        spectron_jerror_anchors["summary"]["unique_target_count"],
        5,
    )
    check(
        "Spectron libjpeg jerror high-confidence count",
        spectron_jerror_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron libjpeg jerror normalized count",
        spectron_jerror_anchors["summary"]["normalized_shape_exact_count"],
        5,
    )
    check(
        "Spectron libjpeg jerror exact count",
        spectron_jerror_anchors["summary"]["full_metric_exact_count"],
        4,
    )
    jerror_rows = {
        row["spectron_ea"]: row for row in spectron_jerror_anchors["anchors"]
    }
    jerror_expected = {
        "0x29ff1c": "v18_jpeg_emit_message",
        "0x29ff94": "v18_jpeg_reset_error_mgr",
        "0x29ffa4": "v18_jpeg_format_message",
        "0x2a008c": "v18_jpeg_output_message",
        "0x2a00d4": "v18_jpeg_error_exit",
    }
    for target_ea, expected_name in jerror_expected.items():
        check(
            "Spectron libjpeg jerror target " + target_ea,
            jerror_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v280 checkpoint artifact",
        spectron_checkpoint_v280["artifact"],
        "spectron_translation_checkpoint_20260828_v280",
    )
    check(
        "Spectron v280 checkpoint parent",
        spectron_checkpoint_v280["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v279",
    )
    check(
        "Spectron v280 checkpoint database hash",
        spectron_checkpoint_v280["database"]["sha256"],
        "b87e3bc5ecf33c2df89d57987b7bdf80255efc3289eed8dfe976d67e24d1ff13",
    )
    check(
        "Spectron v280 checkpoint function count",
        spectron_checkpoint_v280["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v280 checkpoint default sub count",
        spectron_checkpoint_v280["database"]["default_sub_function_count"],
        620,
    )
    check(
        "Spectron v280 checkpoint jerror count",
        spectron_checkpoint_v280["jerror_anchors"]["verified_name_count"],
        5,
    )
    check(
        "Spectron libjpeg jmemmgr artifact",
        spectron_jmemmgr_anchors["artifact"],
        "spectron_jpeg_memory_manager_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jmemmgr network",
        spectron_jmemmgr_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jmemmgr anchor count",
        spectron_jmemmgr_anchors["summary"]["anchor_count"],
        11,
    )
    check(
        "Spectron libjpeg jmemmgr unique target count",
        spectron_jmemmgr_anchors["summary"]["unique_target_count"],
        11,
    )
    check(
        "Spectron libjpeg jmemmgr high-confidence count",
        spectron_jmemmgr_anchors["summary"]["high_confidence_count"],
        11,
    )
    check(
        "Spectron libjpeg jmemmgr normalized count",
        spectron_jmemmgr_anchors["summary"]["normalized_shape_exact_count"],
        9,
    )
    check(
        "Spectron libjpeg jmemmgr exact count",
        spectron_jmemmgr_anchors["summary"]["full_metric_exact_count"],
        6,
    )
    check(
        "Spectron libjpeg jmemmgr layout difference count",
        spectron_jmemmgr_anchors["summary"]["layout_difference_count"],
        2,
    )
    jmemmgr_rows = {
        row["spectron_ea"]: row for row in spectron_jmemmgr_anchors["anchors"]
    }
    jmemmgr_expected = {
        "0x2a0168": "v18_jpeg_alloc_small",
        "0x2a0368": "v18_jpeg_alloc_large",
        "0x2a04c8": "v18_jpeg_alloc_sarray",
        "0x2a05d8": "v18_jpeg_alloc_barray",
        "0x2a0970": "v18_jpeg_realize_virt_arrays",
        "0x2a0d20": "v18_jpeg_request_virt_sarray",
        "0x2a0f3c": "v18_jpeg_request_virt_barray",
        "0x2a1158": "v18_jpeg_access_virt_barray",
        "0x2a12c0": "v18_jpeg_access_virt_sarray",
        "0x2a1640": "v18_jpeg_free_pool",
        "0x2a19a4": "v18_jpeg_self_destruct",
    }
    for target_ea, expected_name in jmemmgr_expected.items():
        check(
            "Spectron libjpeg jmemmgr target " + target_ea,
            jmemmgr_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v281 checkpoint artifact",
        spectron_checkpoint_v281["artifact"],
        "spectron_translation_checkpoint_20260828_v281",
    )
    check(
        "Spectron v281 checkpoint parent",
        spectron_checkpoint_v281["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v280",
    )
    check(
        "Spectron v281 checkpoint database hash",
        spectron_checkpoint_v281["database"]["sha256"],
        "6b59348c18a8346c3d915a2d536616dfa5aba43ed4605a7bcf0e09f252f8db13",
    )
    check(
        "Spectron v281 checkpoint function count",
        spectron_checkpoint_v281["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v281 checkpoint default sub count",
        spectron_checkpoint_v281["database"]["default_sub_function_count"],
        609,
    )
    check(
        "Spectron v281 checkpoint jmemmgr count",
        spectron_checkpoint_v281["jmemmgr_anchors"]["verified_name_count"],
        11,
    )
    check(
        "Spectron libjpeg jquant1 artifact",
        spectron_jquant1_anchors["artifact"],
        "spectron_jpeg_one_pass_quantizer_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jquant1 network",
        spectron_jquant1_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jquant1 anchor count",
        spectron_jquant1_anchors["summary"]["anchor_count"],
        8,
    )
    check(
        "Spectron libjpeg jquant1 unique target count",
        spectron_jquant1_anchors["summary"]["unique_target_count"],
        8,
    )
    check(
        "Spectron libjpeg jquant1 high-confidence count",
        spectron_jquant1_anchors["summary"]["high_confidence_count"],
        8,
    )
    check(
        "Spectron libjpeg jquant1 normalized count",
        spectron_jquant1_anchors["summary"]["normalized_shape_exact_count"],
        8,
    )
    check(
        "Spectron libjpeg jquant1 exact count",
        spectron_jquant1_anchors["summary"]["full_metric_exact_count"],
        7,
    )
    jquant1_rows = {
        row["spectron_ea"]: row for row in spectron_jquant1_anchors["anchors"]
    }
    jquant1_expected = {
        "0x2a23b4": "v18_jpeg_color_quantize",
        "0x2a2440": "v18_jpeg_color_quantize3",
        "0x2a24c0": "v18_jpeg_quantize3_ord_dither",
        "0x2a25a8": "v18_jpeg_finish_pass_1_quant",
        "0x2a25ac": "v18_jpeg_new_color_map_1_quant",
        "0x2a25d4": "v18_jpeg_quantize_fs_dither",
        "0x2a27b4": "v18_jpeg_quantize_ord_dither",
        "0x2a28cc": "v18_jpeg_start_pass_1_quant",
    }
    for target_ea, expected_name in jquant1_expected.items():
        check(
            "Spectron libjpeg jquant1 target " + target_ea,
            jquant1_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v282 checkpoint artifact",
        spectron_checkpoint_v282["artifact"],
        "spectron_translation_checkpoint_20260828_v282",
    )
    check(
        "Spectron v282 checkpoint parent",
        spectron_checkpoint_v282["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v281",
    )
    check(
        "Spectron v282 checkpoint database hash",
        spectron_checkpoint_v282["database"]["sha256"],
        "97e6e0fe4b2cac011692a6ed945fbabf89f4c5d66eb8a2ccc635f8c1f914308c",
    )
    check(
        "Spectron v282 checkpoint function count",
        spectron_checkpoint_v282["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v282 checkpoint default sub count",
        spectron_checkpoint_v282["database"]["default_sub_function_count"],
        602,
    )
    check(
        "Spectron v282 checkpoint jquant1 count",
        spectron_checkpoint_v282["jquant1_anchors"]["verified_name_count"],
        8,
    )
    check(
        "Spectron libjpeg jquant2 artifact",
        spectron_jquant2_anchors["artifact"],
        "spectron_jpeg_two_pass_quantizer_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jquant2 network",
        spectron_jquant2_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jquant2 anchor count",
        spectron_jquant2_anchors["summary"]["anchor_count"],
        9,
    )
    check(
        "Spectron libjpeg jquant2 unique target count",
        spectron_jquant2_anchors["summary"]["unique_target_count"],
        9,
    )
    check(
        "Spectron libjpeg jquant2 high-confidence count",
        spectron_jquant2_anchors["summary"]["high_confidence_count"],
        9,
    )
    check(
        "Spectron libjpeg jquant2 normalized count",
        spectron_jquant2_anchors["summary"]["normalized_shape_exact_count"],
        9,
    )
    check(
        "Spectron libjpeg jquant2 exact count",
        spectron_jquant2_anchors["summary"]["full_metric_exact_count"],
        8,
    )
    jquant2_rows = {
        row["spectron_ea"]: row for row in spectron_jquant2_anchors["anchors"]
    }
    jquant2_expected = {
        "0x2a36e0": "v18_jpeg_prescan_quantize",
        "0x2a3764": "v18_jpeg_finish_pass2",
        "0x2a3768": "v18_jpeg_new_color_map_2_quant",
        "0x2a3778": "v18_jpeg_start_pass_2_quant",
        "0x2a3a90": "v18_jpeg_update_box",
        "0x2a3ed4": "v18_jpeg_fill_inverse_cmap",
        "0x2a4350": "v18_jpeg_pass2_no_dither",
        "0x2a4454": "v18_jpeg_pass2_fs_dither",
        "0x2a47f8": "v18_jpeg_finish_pass1",
    }
    for target_ea, expected_name in jquant2_expected.items():
        check(
            "Spectron libjpeg jquant2 target " + target_ea,
            jquant2_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v283 checkpoint artifact",
        spectron_checkpoint_v283["artifact"],
        "spectron_translation_checkpoint_20260828_v283",
    )
    check(
        "Spectron v283 checkpoint parent",
        spectron_checkpoint_v283["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v282",
    )
    check(
        "Spectron v283 checkpoint database hash",
        spectron_checkpoint_v283["database"]["sha256"],
        "8ae1bb3865ffccb93966589947ff232624ea926fe0e04cfd67989d435d13f167",
    )
    check(
        "Spectron v283 checkpoint function count",
        spectron_checkpoint_v283["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v283 checkpoint default sub count",
        spectron_checkpoint_v283["database"]["default_sub_function_count"],
        594,
    )
    check(
        "Spectron v283 checkpoint jquant2 count",
        spectron_checkpoint_v283["jquant2_anchors"]["verified_name_count"],
        9,
    )
    check(
        "Spectron libjpeg jdcoefct artifact",
        spectron_jdcoefct_anchors["artifact"],
        "spectron_jpeg_coefficient_controller_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdcoefct network",
        spectron_jdcoefct_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdcoefct anchor count",
        spectron_jdcoefct_anchors["summary"]["anchor_count"],
        7,
    )
    check(
        "Spectron libjpeg jdcoefct unique target count",
        spectron_jdcoefct_anchors["summary"]["unique_target_count"],
        7,
    )
    check(
        "Spectron libjpeg jdcoefct high-confidence count",
        spectron_jdcoefct_anchors["summary"]["high_confidence_count"],
        7,
    )
    check(
        "Spectron libjpeg jdcoefct normalized count",
        spectron_jdcoefct_anchors["summary"]["normalized_shape_exact_count"],
        7,
    )
    check(
        "Spectron libjpeg jdcoefct exact count",
        spectron_jdcoefct_anchors["summary"]["full_metric_exact_count"],
        6,
    )
    jdcoefct_rows = {
        row["spectron_ea"]: row for row in spectron_jdcoefct_anchors["anchors"]
    }
    jdcoefct_expected = {
        "0x2a9b2c": "v18_jpeg_dummy_consume_data",
        "0x2a9b34": "v18_jpeg_consume_data",
        "0x2a9e38": "v18_jpeg_start_output_pass",
        "0x2a9ff0": "v18_jpeg_decompress_smooth_data",
        "0x2aa768": "v18_jpeg_decompress_data",
        "0x2aa980": "v18_jpeg_coef_start_input_pass",
        "0x2aa9e0": "v18_jpeg_decompress_onepass",
    }
    for target_ea, expected_name in jdcoefct_expected.items():
        check(
            "Spectron libjpeg jdcoefct target " + target_ea,
            jdcoefct_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v284 checkpoint artifact",
        spectron_checkpoint_v284["artifact"],
        "spectron_translation_checkpoint_20260828_v284",
    )
    check(
        "Spectron v284 checkpoint parent",
        spectron_checkpoint_v284["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v283",
    )
    check(
        "Spectron v284 checkpoint database hash",
        spectron_checkpoint_v284["database"]["sha256"],
        "75ec25ac82f7724c4332611be2e8bfdea2dc1453f825b0bd0e845e53cfed8bf7",
    )
    check(
        "Spectron v284 checkpoint function count",
        spectron_checkpoint_v284["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v284 checkpoint default sub count",
        spectron_checkpoint_v284["database"]["default_sub_function_count"],
        587,
    )
    check(
        "Spectron v284 checkpoint jdcoefct count",
        spectron_checkpoint_v284["jdcoefct_anchors"]["verified_name_count"],
        7,
    )
    check(
        "Spectron libjpeg jdcolor artifact",
        spectron_jdcolor_anchors["artifact"],
        "spectron_jpeg_color_deconverter_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdcolor network",
        spectron_jdcolor_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdcolor anchor count",
        spectron_jdcolor_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron libjpeg jdcolor unique target count",
        spectron_jdcolor_anchors["summary"]["unique_target_count"],
        6,
    )
    check(
        "Spectron libjpeg jdcolor high-confidence count",
        spectron_jdcolor_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron libjpeg jdcolor normalized count",
        spectron_jdcolor_anchors["summary"]["normalized_shape_exact_count"],
        6,
    )
    check(
        "Spectron libjpeg jdcolor exact count",
        spectron_jdcolor_anchors["summary"]["full_metric_exact_count"],
        6,
    )
    jdcolor_rows = {
        row["spectron_ea"]: row for row in spectron_jdcolor_anchors["anchors"]
    }
    jdcolor_expected = {
        "0x2aaed8": "v18_jpeg_ycc_rgb_convert",
        "0x2aaf98": "v18_jpeg_null_convert",
        "0x2ab014": "v18_jpeg_gray_rgb_convert",
        "0x2ab358": "v18_jpeg_ycck_cmyk_convert",
        "0x2ab438": "v18_jpeg_start_pass_dcolor",
        "0x2ab43c": "v18_jpeg_grayscale_convert",
    }
    for target_ea, expected_name in jdcolor_expected.items():
        check(
            "Spectron libjpeg jdcolor target " + target_ea,
            jdcolor_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v285 checkpoint artifact",
        spectron_checkpoint_v285["artifact"],
        "spectron_translation_checkpoint_20260828_v285",
    )
    check(
        "Spectron v285 checkpoint parent",
        spectron_checkpoint_v285["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v284",
    )
    check(
        "Spectron v285 checkpoint database hash",
        spectron_checkpoint_v285["database"]["sha256"],
        "9808e39ad80e9bb122ae35656c2eb48d23097bfcdd31e3b67db568d6bc13cd1d",
    )
    check(
        "Spectron v285 checkpoint function count",
        spectron_checkpoint_v285["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v285 checkpoint default sub count",
        spectron_checkpoint_v285["database"]["default_sub_function_count"],
        582,
    )
    check(
        "Spectron v285 checkpoint jdcolor count",
        spectron_checkpoint_v285["jdcolor_anchors"]["verified_name_count"],
        6,
    )
    check(
        "Spectron libjpeg jddctmgr artifact",
        spectron_jddctmgr_anchors["artifact"],
        "spectron_jpeg_inverse_dct_manager_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jddctmgr network",
        spectron_jddctmgr_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jddctmgr anchor count",
        spectron_jddctmgr_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron libjpeg jddctmgr unique target count",
        spectron_jddctmgr_anchors["summary"]["unique_target_count"],
        1,
    )
    check(
        "Spectron libjpeg jddctmgr high-confidence count",
        spectron_jddctmgr_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron libjpeg jddctmgr normalized count",
        spectron_jddctmgr_anchors["summary"]["normalized_shape_exact_count"],
        1,
    )
    check(
        "Spectron libjpeg jddctmgr exact count",
        spectron_jddctmgr_anchors["summary"]["full_metric_exact_count"],
        0,
    )
    jddctmgr_rows = {
        row["spectron_ea"]: row for row in spectron_jddctmgr_anchors["anchors"]
    }
    check(
        "Spectron libjpeg jddctmgr target 0x2ab87c",
        jddctmgr_rows["0x2ab87c"]["proposed_name"],
        "v18_jpeg_idct_start_pass",
    )
    check(
        "Spectron v286 checkpoint artifact",
        spectron_checkpoint_v286["artifact"],
        "spectron_translation_checkpoint_20260828_v286",
    )
    check(
        "Spectron v286 checkpoint parent",
        spectron_checkpoint_v286["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v285",
    )
    check(
        "Spectron v286 checkpoint database hash",
        spectron_checkpoint_v286["database"]["sha256"],
        "87624a85eae15f9520bfcbf1b356121aa7af6b97db66997a66bcea5baadadae9",
    )
    check(
        "Spectron v286 checkpoint function count",
        spectron_checkpoint_v286["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v286 checkpoint default sub count",
        spectron_checkpoint_v286["database"]["default_sub_function_count"],
        581,
    )
    check(
        "Spectron v286 checkpoint jddctmgr count",
        spectron_checkpoint_v286["jddctmgr_anchors"]["verified_name_count"],
        1,
    )
    check(
        "Spectron libjpeg jdhuff artifact",
        spectron_jdhuff_anchors["artifact"],
        "spectron_jpeg_baseline_huffman_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdhuff network",
        spectron_jdhuff_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdhuff anchor count",
        spectron_jdhuff_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron libjpeg jdhuff unique target count",
        spectron_jdhuff_anchors["summary"]["unique_target_count"],
        2,
    )
    check(
        "Spectron libjpeg jdhuff high-confidence count",
        spectron_jdhuff_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron libjpeg jdhuff normalized count",
        spectron_jdhuff_anchors["summary"]["normalized_shape_exact_count"],
        1,
    )
    check(
        "Spectron libjpeg jdhuff exact count",
        spectron_jdhuff_anchors["summary"]["full_metric_exact_count"],
        1,
    )
    check(
        "Spectron libjpeg jdhuff relocation count",
        spectron_jdhuff_anchors["summary"]["relocation_shape_difference_count"],
        1,
    )
    jdhuff_rows = {
        row["spectron_ea"]: row for row in spectron_jdhuff_anchors["anchors"]
    }
    jdhuff_expected = {
        "0x2ac740": "v18_jpeg_start_pass_huff_decoder",
        "0x2acba4": "v18_jpeg_decode_mcu",
    }
    for target_ea, expected_name in jdhuff_expected.items():
        check(
            "Spectron libjpeg jdhuff target " + target_ea,
            jdhuff_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron jdhuff decode metric exception",
        jdhuff_rows["0x2acba4"]["metric_differences"],
        [
            "opcode_shape_hash",
            "register_shape_hash",
            "shape_hash",
            "register_detail_hash",
        ],
    )
    check(
        "Spectron v287 checkpoint artifact",
        spectron_checkpoint_v287["artifact"],
        "spectron_translation_checkpoint_20260828_v287",
    )
    check(
        "Spectron v287 checkpoint parent",
        spectron_checkpoint_v287["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v286",
    )
    check(
        "Spectron v287 checkpoint database hash",
        spectron_checkpoint_v287["database"]["sha256"],
        "5af0d676931b984f0eac35dfa49ff13f66b11f5b3a8c023f19a9d03fc26b844e",
    )
    check(
        "Spectron v287 checkpoint function count",
        spectron_checkpoint_v287["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v287 checkpoint default sub count",
        spectron_checkpoint_v287["database"]["default_sub_function_count"],
        579,
    )
    check(
        "Spectron v287 checkpoint jdhuff count",
        spectron_checkpoint_v287["jdhuff_anchors"]["verified_name_count"],
        2,
    )
    check(
        "Spectron libjpeg jdmainct artifact",
        spectron_jdmainct_anchors["artifact"],
        "spectron_jpeg_main_controller_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jdmainct network",
        spectron_jdmainct_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jdmainct anchor count",
        spectron_jdmainct_anchors["summary"]["anchor_count"],
        4,
    )
    check(
        "Spectron libjpeg jdmainct unique target count",
        spectron_jdmainct_anchors["summary"]["unique_target_count"],
        4,
    )
    check(
        "Spectron libjpeg jdmainct high-confidence count",
        spectron_jdmainct_anchors["summary"]["high_confidence_count"],
        4,
    )
    check(
        "Spectron libjpeg jdmainct normalized count",
        spectron_jdmainct_anchors["summary"]["normalized_shape_exact_count"],
        4,
    )
    check(
        "Spectron libjpeg jdmainct exact count",
        spectron_jdmainct_anchors["summary"]["full_metric_exact_count"],
        3,
    )
    jdmainct_rows = {
        row["spectron_ea"]: row for row in spectron_jdmainct_anchors["anchors"]
    }
    jdmainct_expected = {
        "0x2ad108": "v18_jpeg_process_data_simple_main",
        "0x2ad1b0": "v18_jpeg_process_data_context_main",
        "0x2ad530": "v18_jpeg_process_data_crank_post",
        "0x2ad568": "v18_jpeg_start_pass_main",
    }
    for target_ea, expected_name in jdmainct_expected.items():
        check(
            "Spectron libjpeg jdmainct target " + target_ea,
            jdmainct_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v288 checkpoint artifact",
        spectron_checkpoint_v288["artifact"],
        "spectron_translation_checkpoint_20260828_v288",
    )
    check(
        "Spectron v288 checkpoint parent",
        spectron_checkpoint_v288["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v287",
    )
    check(
        "Spectron v288 checkpoint database hash",
        spectron_checkpoint_v288["database"]["sha256"],
        "99d386649d7356bf021dfd87e8e153b29e24a52f14b83504d5b7b28956c68065",
    )
    check(
        "Spectron v288 checkpoint function count",
        spectron_checkpoint_v288["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v288 checkpoint default sub count",
        spectron_checkpoint_v288["database"]["default_sub_function_count"],
        575,
    )
    check(
        "Spectron v288 checkpoint jdmainct count",
        spectron_checkpoint_v288["jdmainct_anchors"]["verified_name_count"],
        4,
    )
    check(
        "Spectron libjpeg jccolor artifact",
        spectron_jccolor_anchors["artifact"],
        "spectron_jpeg_compressor_color_converter_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jccolor network",
        spectron_jccolor_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jccolor anchor count",
        spectron_jccolor_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron libjpeg jccolor unique target count",
        spectron_jccolor_anchors["summary"]["unique_target_count"],
        6,
    )
    check(
        "Spectron libjpeg jccolor high-confidence count",
        spectron_jccolor_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron libjpeg jccolor normalized count",
        spectron_jccolor_anchors["summary"]["normalized_shape_exact_count"],
        6,
    )
    check(
        "Spectron libjpeg jccolor exact count",
        spectron_jccolor_anchors["summary"]["full_metric_exact_count"],
        6,
    )
    jccolor_rows = {
        row["spectron_ea"]: row for row in spectron_jccolor_anchors["anchors"]
    }
    jccolor_expected = {
        "0x2aff7c": "v18_jpeg_rgb_ycc_start",
        "0x2b0040": "v18_jpeg_rgb_ycc_convert",
        "0x2b0114": "v18_jpeg_rgb_gray_convert",
        "0x2b018c": "v18_jpeg_cmyk_ycck_convert",
        "0x2b0290": "v18_jpeg_c_grayscale_convert",
        "0x2b02dc": "v18_jpeg_c_null_convert",
    }
    for target_ea, expected_name in jccolor_expected.items():
        check(
            "Spectron libjpeg jccolor target " + target_ea,
            jccolor_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron v289 checkpoint artifact",
        spectron_checkpoint_v289["artifact"],
        "spectron_translation_checkpoint_20260828_v289",
    )
    check(
        "Spectron v289 checkpoint parent",
        spectron_checkpoint_v289["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v288",
    )
    check(
        "Spectron v289 checkpoint database hash",
        spectron_checkpoint_v289["database"]["sha256"],
        "15b16bb239ebe1e4eccc22629d68a31a8275feff61be37b2a408e19db20ea9bb",
    )
    check(
        "Spectron v289 checkpoint function count",
        spectron_checkpoint_v289["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v289 checkpoint default sub count",
        spectron_checkpoint_v289["database"]["default_sub_function_count"],
        569,
    )
    check(
        "Spectron v289 checkpoint jccolor count",
        spectron_checkpoint_v289["jccolor_anchors"]["verified_name_count"],
        6,
    )
    check(
        "Spectron libjpeg jccoefct artifact",
        spectron_jccoefct_anchors["artifact"],
        "spectron_jpeg_compressor_coefficient_controller_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jccoefct network",
        spectron_jccoefct_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jccoefct anchor count",
        spectron_jccoefct_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron libjpeg jccoefct unique target count",
        spectron_jccoefct_anchors["summary"]["unique_target_count"],
        5,
    )
    check(
        "Spectron libjpeg jccoefct high-confidence count",
        spectron_jccoefct_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron libjpeg jccoefct normalized count",
        spectron_jccoefct_anchors["summary"]["normalized_shape_exact_count"],
        5,
    )
    check(
        "Spectron libjpeg jccoefct exact count",
        spectron_jccoefct_anchors["summary"]["full_metric_exact_count"],
        4,
    )
    jccoefct_rows = {
        row["spectron_ea"]: row for row in spectron_jccoefct_anchors["anchors"]
    }
    jccoefct_expected = {
        "0x2aefc0": "v18_jpeg_start_iMCU_row",
        "0x2af024": "v18_jpeg_compress_output",
        "0x2af2b0": "v18_jpeg_compress_data",
        "0x2af804": "v18_jpeg_start_pass_coef",
        "0x2af93c": "v18_jpeg_compress_first_pass",
    }
    for target_ea, expected_name in jccoefct_expected.items():
        check(
            "Spectron libjpeg jccoefct target " + target_ea,
            jccoefct_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron jccoefct start-pass metric exception",
        jccoefct_rows["0x2af804"]["metric_differences"],
        ["register_detail_hash"],
    )
    check(
        "Spectron v290 checkpoint artifact",
        spectron_checkpoint_v290["artifact"],
        "spectron_translation_checkpoint_20260828_v290",
    )
    check(
        "Spectron v290 checkpoint parent",
        spectron_checkpoint_v290["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v289",
    )
    check(
        "Spectron v290 checkpoint database hash",
        spectron_checkpoint_v290["database"]["sha256"],
        "5a74d5d6915311fedf66eb33f1c7a6901baad8ad47653ae1c445698eccbf37e7",
    )
    check(
        "Spectron v290 checkpoint function count",
        spectron_checkpoint_v290["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v290 checkpoint default sub count",
        spectron_checkpoint_v290["database"]["default_sub_function_count"],
        564,
    )
    check(
        "Spectron v290 checkpoint jccoefct count",
        spectron_checkpoint_v290["jccoefct_anchors"]["verified_name_count"],
        5,
    )
    check(
        "Spectron libjpeg jcdctmgr artifact",
        spectron_jcdctmgr_anchors["artifact"],
        "spectron_jpeg_forward_dct_manager_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jcdctmgr network",
        spectron_jcdctmgr_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jcdctmgr anchor count",
        spectron_jcdctmgr_anchors["summary"]["anchor_count"],
        3,
    )
    check(
        "Spectron libjpeg jcdctmgr unique target count",
        spectron_jcdctmgr_anchors["summary"]["unique_target_count"],
        3,
    )
    check(
        "Spectron libjpeg jcdctmgr high-confidence count",
        spectron_jcdctmgr_anchors["summary"]["high_confidence_count"],
        3,
    )
    check(
        "Spectron libjpeg jcdctmgr normalized count",
        spectron_jcdctmgr_anchors["summary"]["normalized_shape_exact_count"],
        3,
    )
    check(
        "Spectron libjpeg jcdctmgr exact count",
        spectron_jcdctmgr_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    jcdctmgr_rows = {
        row["spectron_ea"]: row for row in spectron_jcdctmgr_anchors["anchors"]
    }
    jcdctmgr_expected = {
        "0x2b0660": "v18_jpeg_start_pass_fdctmgr",
        "0x2b0aa8": "v18_jpeg_forward_DCT",
        "0x2b0c10": "v18_jpeg_forward_DCT_float",
    }
    for target_ea, expected_name in jcdctmgr_expected.items():
        check(
            "Spectron libjpeg jcdctmgr target " + target_ea,
            jcdctmgr_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron jcdctmgr start-pass metric exception",
        jcdctmgr_rows["0x2b0660"]["metric_differences"],
        ["register_detail_hash"],
    )
    check(
        "Spectron v291 checkpoint artifact",
        spectron_checkpoint_v291["artifact"],
        "spectron_translation_checkpoint_20260828_v291",
    )
    check(
        "Spectron v291 checkpoint parent",
        spectron_checkpoint_v291["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v290",
    )
    check(
        "Spectron v291 checkpoint database hash",
        spectron_checkpoint_v291["database"]["sha256"],
        "9933c9b80f7962b4e3666ad5f6eee22b42487e8027d2691fb9e36abd6d1e76a4",
    )
    check(
        "Spectron v291 checkpoint function count",
        spectron_checkpoint_v291["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v291 checkpoint default sub count",
        spectron_checkpoint_v291["database"]["default_sub_function_count"],
        561,
    )
    check(
        "Spectron v291 checkpoint jcdctmgr count",
        spectron_checkpoint_v291["jcdctmgr_anchors"]["verified_name_count"],
        3,
    )
    check(
        "Spectron libjpeg jchuff artifact",
        spectron_jchuff_anchors["artifact"],
        "spectron_jpeg_huffman_encoder_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jchuff network",
        spectron_jchuff_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jchuff anchor count",
        spectron_jchuff_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron libjpeg jchuff unique target count",
        spectron_jchuff_anchors["summary"]["unique_target_count"],
        5,
    )
    check(
        "Spectron libjpeg jchuff high-confidence count",
        spectron_jchuff_anchors["summary"]["high_confidence_count"],
        5,
    )
    check(
        "Spectron libjpeg jchuff normalized count",
        spectron_jchuff_anchors["summary"]["normalized_shape_exact_count"],
        5,
    )
    check(
        "Spectron libjpeg jchuff exact count",
        spectron_jchuff_anchors["summary"]["full_metric_exact_count"],
        2,
    )
    jchuff_rows = {
        row["spectron_ea"]: row for row in spectron_jchuff_anchors["anchors"]
    }
    jchuff_expected = {
        "0x2b1160": "v18_jpeg_encode_mcu_gather",
        "0x2b13a0": "v18_jpeg_finish_pass_huff",
        "0x2b1520": "v18_jpeg_encode_mcu_huff",
        "0x2b2338": "v18_jpeg_start_pass_huff",
        "0x2b2914": "v18_jpeg_finish_pass_gather",
    }
    for target_ea, expected_name in jchuff_expected.items():
        check(
            "Spectron libjpeg jchuff target " + target_ea,
            jchuff_rows[target_ea]["proposed_name"],
            expected_name,
        )
    for target_ea in ("0x2b1160", "0x2b1520", "0x2b2338"):
        check(
            "Spectron jchuff register-detail exception " + target_ea,
            jchuff_rows[target_ea]["metric_differences"],
            ["register_detail_hash"],
        )
    check(
        "Spectron v292 checkpoint artifact",
        spectron_checkpoint_v292["artifact"],
        "spectron_translation_checkpoint_20260828_v292",
    )
    check(
        "Spectron v292 checkpoint parent",
        spectron_checkpoint_v292["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v291",
    )
    check(
        "Spectron v292 checkpoint database hash",
        spectron_checkpoint_v292["database"]["sha256"],
        "4ad75f4e344be7e0d168d3674b0bd93b743d5148448ec7a2b50f559fb48f7c09",
    )
    check(
        "Spectron v292 checkpoint function count",
        spectron_checkpoint_v292["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v292 checkpoint default sub count",
        spectron_checkpoint_v292["database"]["default_sub_function_count"],
        556,
    )
    check(
        "Spectron v292 checkpoint jchuff count",
        spectron_checkpoint_v292["jchuff_anchors"]["verified_name_count"],
        5,
    )
    check(
        "Spectron libjpeg jcmainct and jcmaster artifact",
        spectron_jcmainct_jcmaster_anchors["artifact"],
        "spectron_jpeg_main_master_controller_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jcmainct and jcmaster network",
        spectron_jcmainct_jcmaster_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jcmainct and jcmaster anchor count",
        spectron_jcmainct_jcmaster_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron libjpeg jcmainct and jcmaster unique target count",
        spectron_jcmainct_jcmaster_anchors["summary"]["unique_target_count"],
        6,
    )
    check(
        "Spectron libjpeg jcmainct and jcmaster high-confidence count",
        spectron_jcmainct_jcmaster_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron libjpeg jcmainct and jcmaster normalized count",
        spectron_jcmainct_jcmaster_anchors["summary"]["normalized_shape_exact_count"],
        6,
    )
    check(
        "Spectron libjpeg jcmainct and jcmaster exact count",
        spectron_jcmainct_jcmaster_anchors["summary"]["full_metric_exact_count"],
        5,
    )
    jcmainct_jcmaster_rows = {
        row["spectron_ea"]: row
        for row in spectron_jcmainct_jcmaster_anchors["anchors"]
    }
    jcmainct_jcmaster_expected = {
        "0x2b2aac": "v18_jpeg_c_process_data_simple_main",
        "0x2b2bcc": "v18_jpeg_c_start_pass_main",
        "0x2b2d08": "v18_jpeg_initial_setup",
        "0x2b36a4": "v18_jpeg_pass_startup",
        "0x2b36e0": "v18_jpeg_finish_pass_master",
        "0x2b3794": "v18_jpeg_prepare_for_pass",
    }
    for target_ea, expected_name in jcmainct_jcmaster_expected.items():
        check(
            "Spectron libjpeg jcmainct and jcmaster target " + target_ea,
            jcmainct_jcmaster_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron jcmainct process-data metric differences",
        jcmainct_jcmaster_rows["0x2b2aac"]["metric_differences"],
        [],
    )
    check(
        "Spectron jcmainct start-pass metric exception",
        jcmainct_jcmaster_rows["0x2b2bcc"]["metric_differences"],
        ["register_detail_hash"],
    )
    check(
        "Spectron v293 checkpoint artifact",
        spectron_checkpoint_v293["artifact"],
        "spectron_translation_checkpoint_20260828_v293",
    )
    check(
        "Spectron v293 checkpoint parent",
        spectron_checkpoint_v293["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v292",
    )
    check(
        "Spectron v293 checkpoint database hash",
        spectron_checkpoint_v293["database"]["sha256"],
        "98aca07125910b711ab08522d8513d60d75dbf253c627a73f025a7d2a7213590",
    )
    check(
        "Spectron v293 checkpoint function count",
        spectron_checkpoint_v293["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v293 checkpoint default sub count",
        spectron_checkpoint_v293["database"]["default_sub_function_count"],
        550,
    )
    check(
        "Spectron v293 checkpoint controller count",
        spectron_checkpoint_v293["jpeg_main_master_controller_anchors"][
            "verified_name_count"
        ],
        6,
    )
    check(
        "Spectron libjpeg jcphuff encoder artifact",
        spectron_jcphuff_encoder_anchors["artifact"],
        "spectron_jpeg_progressive_huffman_encoder_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jcphuff encoder network",
        spectron_jcphuff_encoder_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jcphuff encoder anchor count",
        spectron_jcphuff_encoder_anchors["summary"]["anchor_count"],
        8,
    )
    check(
        "Spectron libjpeg jcphuff encoder unique target count",
        spectron_jcphuff_encoder_anchors["summary"]["unique_target_count"],
        8,
    )
    check(
        "Spectron libjpeg jcphuff encoder high-confidence count",
        spectron_jcphuff_encoder_anchors["summary"]["high_confidence_count"],
        8,
    )
    check(
        "Spectron libjpeg jcphuff encoder normalized count",
        spectron_jcphuff_encoder_anchors["summary"]["normalized_shape_exact_count"],
        8,
    )
    check(
        "Spectron libjpeg jcphuff encoder exact count",
        spectron_jcphuff_encoder_anchors["summary"]["full_metric_exact_count"],
        5,
    )
    jcphuff_encoder_rows = {
        row["spectron_ea"]: row
        for row in spectron_jcphuff_encoder_anchors["anchors"]
    }
    jcphuff_encoder_expected = {
        "0x2b486c": "v18_jpeg_start_pass_phuff",
        "0x2b4a4c": "v18_jpeg_emit_eobrun",
        "0x2b50f0": "v18_jpeg_encode_mcu_AC_refine",
        "0x2b5d5c": "v18_jpeg_finish_pass_phuff",
        "0x2b5f14": "v18_jpeg_finish_pass_gather_phuff",
        "0x2b6214": "v18_jpeg_encode_mcu_DC_refine",
        "0x2b669c": "v18_jpeg_encode_mcu_DC_first",
        "0x2b6f50": "v18_jpeg_encode_mcu_AC_first",
    }
    for target_ea, expected_name in jcphuff_encoder_expected.items():
        check(
            "Spectron libjpeg jcphuff encoder target " + target_ea,
            jcphuff_encoder_rows[target_ea]["proposed_name"],
            expected_name,
        )
    check(
        "Spectron jcphuff encoder reopen count",
        spectron_checkpoint_v294["jpeg_progressive_huffman_encoder_anchors"][
            "verified_name_count"
        ],
        8,
    )
    check(
        "Spectron v294 checkpoint artifact",
        spectron_checkpoint_v294["artifact"],
        "spectron_translation_checkpoint_20260828_v294",
    )
    check(
        "Spectron v294 checkpoint parent",
        spectron_checkpoint_v294["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v293",
    )
    check(
        "Spectron v294 checkpoint database hash",
        spectron_checkpoint_v294["database"]["sha256"],
        "3c01779252a8df94532b47f36c0e2b366d339338db950124f900be6036ae8efd",
    )
    check(
        "Spectron v294 checkpoint function count",
        spectron_checkpoint_v294["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v294 checkpoint default sub count",
        spectron_checkpoint_v294["database"]["default_sub_function_count"],
        542,
    )
    check(
        "Spectron libjpeg jcprepct and jcsample artifact",
        spectron_jcprepct_jcsample_anchors["artifact"],
        "spectron_jpeg_preprocessing_downsampling_manual_translation_anchors_20260828",
    )
    check(
        "Spectron libjpeg jcprepct and jcsample network",
        spectron_jcprepct_jcsample_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron libjpeg jcprepct and jcsample anchor count",
        spectron_jcprepct_jcsample_anchors["summary"]["anchor_count"],
        10,
    )
    check(
        "Spectron libjpeg jcprepct and jcsample unique target count",
        spectron_jcprepct_jcsample_anchors["summary"]["unique_target_count"],
        10,
    )
    check(
        "Spectron libjpeg jcprepct and jcsample high-confidence count",
        spectron_jcprepct_jcsample_anchors["summary"]["high_confidence_count"],
        10,
    )
    check(
        "Spectron libjpeg jcprepct and jcsample normalized count",
        spectron_jcprepct_jcsample_anchors["summary"]["normalized_shape_exact_count"],
        10,
    )
    check(
        "Spectron libjpeg jcprepct and jcsample exact count",
        spectron_jcprepct_jcsample_anchors["summary"]["full_metric_exact_count"],
        10,
    )
    jcprepct_jcsample_rows = {
        row["spectron_ea"]: row
        for row in spectron_jcprepct_jcsample_anchors["anchors"]
    }
    jcprepct_jcsample_expected = {
        "0x2b7928": "v18_jpeg_start_pass_prep",
        "0x2b7980": "v18_jpeg_pre_process_context",
        "0x2b7c14": "v18_jpeg_pre_process_data",
        "0x2b82b0": "v18_jpeg_sep_downsample",
        "0x2b8354": "v18_jpeg_int_downsample",
        "0x2b8764": "v18_jpeg_h2v1_downsample",
        "0x2b8914": "v18_jpeg_h2v2_downsample",
        "0x2b8ae0": "v18_jpeg_h2v2_smooth_downsample",
        "0x2b8e98": "v18_jpeg_fullsize_smooth_downsample",
        "0x2b9140": "v18_jpeg_fullsize_downsample",
    }
    for target_ea, expected_name in jcprepct_jcsample_expected.items():
        check(
            "Spectron libjpeg jcprepct and jcsample target " + target_ea,
            jcprepct_jcsample_rows[target_ea]["proposed_name"],
            expected_name,
        )
        check(
            "Spectron libjpeg jcprepct and jcsample metrics " + target_ea,
            jcprepct_jcsample_rows[target_ea]["metric_differences"],
            [],
        )
    check(
        "Spectron v295 checkpoint artifact",
        spectron_checkpoint_v295["artifact"],
        "spectron_translation_checkpoint_20260828_v295",
    )
    check(
        "Spectron v295 checkpoint parent",
        spectron_checkpoint_v295["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v294",
    )
    check(
        "Spectron v295 checkpoint database hash",
        spectron_checkpoint_v295["database"]["sha256"],
        "a9c756cdd96084cf9dd6fd5ce2c885acd4ea0fffafb6b1c626fafab239c5d284",
    )
    check(
        "Spectron v295 checkpoint function count",
        spectron_checkpoint_v295["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v295 checkpoint default sub count",
        spectron_checkpoint_v295["database"]["default_sub_function_count"],
        532,
    )
    check(
        "Spectron v295 checkpoint prep and downsample count",
        spectron_checkpoint_v295["jpeg_preprocessing_downsampling_anchors"][
            "verified_name_count"
        ],
        10,
    )
    check(
        "Spectron GIF LZW line-decoder artifact",
        spectron_gif_lzw_line_decoder_anchors["artifact"],
        "spectron_gif_lzw_line_decoder_manual_translation_anchors_20260828",
    )
    check(
        "Spectron GIF LZW line-decoder network",
        spectron_gif_lzw_line_decoder_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron GIF LZW line-decoder anchor count",
        spectron_gif_lzw_line_decoder_anchors["summary"]["anchor_count"],
        1,
    )
    check(
        "Spectron GIF LZW line-decoder high-confidence count",
        spectron_gif_lzw_line_decoder_anchors["summary"]["high_confidence_count"],
        1,
    )
    check(
        "Spectron GIF LZW line-decoder normalized count",
        spectron_gif_lzw_line_decoder_anchors["summary"]["normalized_shape_exact_count"],
        1,
    )
    check(
        "Spectron GIF LZW line-decoder target",
        spectron_gif_lzw_line_decoder_anchors["anchors"][0]["proposed_name"],
        "v18_DGifDecompressLine",
    )
    check(
        "Spectron GIF LZW line-decoder metric difference",
        spectron_gif_lzw_line_decoder_anchors["anchors"][0]["metric_differences"],
        ["register_detail_hash"],
    )
    check(
        "Spectron v296 checkpoint artifact",
        spectron_checkpoint_v296["artifact"],
        "spectron_translation_checkpoint_20260828_v296",
    )
    check(
        "Spectron v296 checkpoint parent",
        spectron_checkpoint_v296["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v295",
    )
    check(
        "Spectron v296 checkpoint parent path",
        spectron_checkpoint_v296["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v295.json",
    )
    check(
        "Spectron v296 checkpoint database hash",
        spectron_checkpoint_v296["database"]["sha256"],
        "12f5465bef23235773b87f7c68339eca35246663316adfc7ae5baf11795b474e",
    )
    check(
        "Spectron v296 checkpoint function count",
        spectron_checkpoint_v296["database"]["function_count"],
        11696,
    )
    check(
        "Spectron v296 checkpoint default sub count",
        spectron_checkpoint_v296["database"]["default_sub_function_count"],
        531,
    )
    check(
        "Spectron v296 checkpoint GIF LZW line-decoder count",
        spectron_checkpoint_v296["gif_lzw_line_decoder_anchors"][
            "verified_name_count"
        ],
        1,
    )
    check(
        "Spectron FDCT literal-pool repair artifact",
        spectron_fdct_literal_pool_repair["artifact"],
        "spectron_fdct_literal_pool_boundary_repair_20260828",
    )
    check(
        "Spectron FDCT literal-pool repair network",
        spectron_fdct_literal_pool_repair["network_contacted"],
        False,
    )
    check(
        "Spectron FDCT literal-pool repair pool count",
        spectron_fdct_literal_pool_repair["summary"]["pool_count"],
        1,
    )
    check(
        "Spectron FDCT literal-pool repair removed function count",
        spectron_fdct_literal_pool_repair["summary"][
            "phantom_function_count_removed"
        ],
        1,
    )
    check(
        "Spectron FDCT literal-pool repair data item count",
        spectron_fdct_literal_pool_repair["summary"]["data_item_count_created"],
        4,
    )
    check(
        "Spectron FDCT literal-pool repair byte preservation",
        spectron_fdct_literal_pool_repair["summary"]["bytes_changed"],
        False,
    )
    check(
        "Spectron FDCT literal-pool repair reopen failures",
        spectron_fdct_literal_pool_repair["summary"]["reopen_failure_count"],
        0,
    )
    check(
        "Spectron FDCT literal-pool repair start",
        spectron_fdct_literal_pool_repair["pool"]["target_start"],
        "0x2b9870",
    )
    check(
        "Spectron FDCT literal-pool repair real neighbor",
        spectron_fdct_literal_pool_repair["pool"]["real_function_after_pool"][
            "name"
        ],
        "v18_jpeg_fdct_ifast_int",
    )
    check(
        "Spectron v297 checkpoint artifact",
        spectron_checkpoint_v297["artifact"],
        "spectron_translation_checkpoint_20260828_v297",
    )
    check(
        "Spectron v297 checkpoint parent",
        spectron_checkpoint_v297["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v296",
    )
    check(
        "Spectron v297 checkpoint parent path",
        spectron_checkpoint_v297["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v296.json",
    )
    check(
        "Spectron v297 checkpoint database hash",
        spectron_checkpoint_v297["database"]["sha256"],
        "c4f0175e2839ed6143413d67e1cfef35daf973bcdbb26181ad1879c355f6b3c1",
    )
    check(
        "Spectron v297 checkpoint function count",
        spectron_checkpoint_v297["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v297 checkpoint default sub count",
        spectron_checkpoint_v297["database"]["default_sub_function_count"],
        530,
    )
    check(
        "Spectron v297 checkpoint repair pool count",
        spectron_checkpoint_v297["fdct_literal_pool_boundary_repair"][
            "pool_count"
        ],
        1,
    )
    check(
        "Spectron v297 checkpoint repair reopen failures",
        spectron_checkpoint_v297["fdct_literal_pool_boundary_repair"][
            "reopen_failure_count"
        ],
        0,
    )
    check(
        "Spectron FreeType base cleanup artifact",
        spectron_freetype_base_cleanup_anchors["artifact"],
        "spectron_freetype_base_cleanup_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType base cleanup network",
        spectron_freetype_base_cleanup_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType base cleanup anchor count",
        spectron_freetype_base_cleanup_anchors["summary"]["anchor_count"],
        2,
    )
    check(
        "Spectron FreeType base cleanup high-confidence count",
        spectron_freetype_base_cleanup_anchors["summary"]["high_confidence_count"],
        2,
    )
    check(
        "Spectron FreeType base cleanup normalized count",
        spectron_freetype_base_cleanup_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        2,
    )
    freetype_cleanup_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_base_cleanup_anchors["anchors"]
    }
    check(
        "Spectron FreeType destroy_size target",
        freetype_cleanup_rows["0x25e304"]["proposed_name"],
        "v18_destroy_size",
    )
    check(
        "Spectron FreeType destroy_face target",
        freetype_cleanup_rows["0x260300"]["proposed_name"],
        "v18_destroy_face",
    )
    check(
        "Spectron FreeType destroy_size metrics",
        freetype_cleanup_rows["0x25e304"]["metric_differences"],
        [],
    )
    check(
        "Spectron FreeType destroy_face metrics",
        freetype_cleanup_rows["0x260300"]["metric_differences"],
        ["register_detail_hash"],
    )
    check(
        "Spectron v298 checkpoint artifact",
        spectron_checkpoint_v298["artifact"],
        "spectron_translation_checkpoint_20260828_v298",
    )
    check(
        "Spectron v298 checkpoint parent",
        spectron_checkpoint_v298["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v297",
    )
    check(
        "Spectron v298 checkpoint parent path",
        spectron_checkpoint_v298["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v297.json",
    )
    check(
        "Spectron v298 checkpoint database hash",
        spectron_checkpoint_v298["database"]["sha256"],
        "1de475653381e7ddf9b17cfadf43d816a29babfdb40b87bbf1f7825e0866c26d",
    )
    check(
        "Spectron v298 checkpoint function count",
        spectron_checkpoint_v298["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v298 checkpoint default sub count",
        spectron_checkpoint_v298["database"]["default_sub_function_count"],
        528,
    )
    check(
        "Spectron v298 checkpoint FreeType cleanup count",
        spectron_checkpoint_v298["freetype_base_cleanup_anchors"][
            "verified_name_count"
        ],
        2,
    )
    check(
        "Spectron FreeType SFNT service artifact",
        spectron_freetype_sfnt_service_anchors["artifact"],
        "spectron_freetype_sfnt_service_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType SFNT service network",
        spectron_freetype_sfnt_service_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType SFNT service anchor count",
        spectron_freetype_sfnt_service_anchors["summary"]["anchor_count"],
        5,
    )
    check(
        "Spectron FreeType SFNT service high-confidence count",
        spectron_freetype_sfnt_service_anchors["summary"][
            "high_confidence_count"
        ],
        5,
    )
    check(
        "Spectron FreeType SFNT service normalized count",
        spectron_freetype_sfnt_service_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        5,
    )
    check(
        "Spectron FreeType SFNT service full-match count",
        spectron_freetype_sfnt_service_anchors["summary"][
            "full_metric_exact_count"
        ],
        4,
    )
    freetype_sfnt_service_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_sfnt_service_anchors["anchors"]
    }
    check(
        "Spectron FreeType tt_get_cmap_info target",
        freetype_sfnt_service_rows["0x262008"]["proposed_name"],
        "v18_tt_get_cmap_info",
    )
    check(
        "Spectron FreeType sfnt_get_ps_name target",
        freetype_sfnt_service_rows["0x264e24"]["proposed_name"],
        "v18_sfnt_get_ps_name",
    )
    check(
        "Spectron FreeType tt_face_load_any target",
        freetype_sfnt_service_rows["0x263aac"]["proposed_name"],
        "v18_tt_face_load_any",
    )
    check(
        "Spectron FreeType get_sfnt_table metrics",
        freetype_sfnt_service_rows["0x2621f0"]["metric_differences"],
        ["register_detail_hash"],
    )
    check(
        "Spectron v299 checkpoint artifact",
        spectron_checkpoint_v299["artifact"],
        "spectron_translation_checkpoint_20260828_v299",
    )
    check(
        "Spectron v299 checkpoint parent",
        spectron_checkpoint_v299["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v298",
    )
    check(
        "Spectron v299 checkpoint parent path",
        spectron_checkpoint_v299["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v298.json",
    )
    check(
        "Spectron v299 checkpoint database hash",
        spectron_checkpoint_v299["database"]["sha256"],
        "f6bcdeba610fbe47ba182477ccc74b5cbff727b17f9b0013395beb3902228367",
    )
    check(
        "Spectron v299 checkpoint function count",
        spectron_checkpoint_v299["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v299 checkpoint default sub count",
        spectron_checkpoint_v299["database"]["default_sub_function_count"],
        523,
    )
    check(
        "Spectron v299 checkpoint SFNT service count",
        spectron_checkpoint_v299["freetype_sfnt_service_anchors"][
            "verified_name_count"
        ],
        5,
    )
    check(
        "Spectron FreeType SFNT interface artifact",
        spectron_freetype_sfnt_interface_anchors["artifact"],
        "spectron_freetype_sfnt_interface_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType SFNT interface network",
        spectron_freetype_sfnt_interface_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType SFNT interface anchor count",
        spectron_freetype_sfnt_interface_anchors["summary"]["anchor_count"],
        21,
    )
    check(
        "Spectron FreeType SFNT interface high-confidence count",
        spectron_freetype_sfnt_interface_anchors["summary"][
            "high_confidence_count"
        ],
        21,
    )
    check(
        "Spectron FreeType SFNT interface normalized count",
        spectron_freetype_sfnt_interface_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        21,
    )
    check(
        "Spectron FreeType SFNT interface full-match count",
        spectron_freetype_sfnt_interface_anchors["summary"][
            "full_metric_exact_count"
        ],
        13,
    )
    check(
        "Spectron FreeType SFNT interface slot count",
        spectron_freetype_sfnt_interface_anchors["summary"][
            "interface_slot_count"
        ],
        19,
    )
    check(
        "Spectron FreeType SFNT interface name-helper count",
        spectron_freetype_sfnt_interface_anchors["summary"]["name_helper_count"],
        2,
    )
    freetype_sfnt_interface_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_sfnt_interface_anchors["anchors"]
    }
    freetype_sfnt_interface_expected = {
        "0x263a58": ("v18_tt_face_goto_table", "sfnt_interface.goto_table", []),
        "0x264b74": ("v18_sfnt_init_face", "sfnt_interface.init_face", ["register_detail_hash"]),
        "0x267d50": ("v18_sfnt_load_face", "sfnt_interface.load_face", ["register_detail_hash"]),
        "0x2646c4": ("v18_sfnt_done_face", "sfnt_interface.done_face", []),
        "0x265674": ("v18_tt_face_load_head", "sfnt_interface.load_head", ["register_detail_hash"]),
        "0x264194": ("v18_tt_face_load_hhea", "sfnt_interface.load_hhea", []),
        "0x265608": ("v18_tt_face_load_cmap", "sfnt_interface.load_cmap", []),
        "0x2653d4": ("v18_tt_face_load_maxp", "sfnt_interface.load_maxp", []),
        "0x263fec": ("v18_tt_face_load_os2", "sfnt_interface.load_os2", ["register_detail_hash"]),
        "0x263f84": ("v18_tt_face_load_post", "sfnt_interface.load_post", ["register_detail_hash"]),
        "0x263dd0": ("v18_tt_face_load_name", "sfnt_interface.load_name", ["register_detail_hash"]),
        "0x263430": ("v18_tt_face_free_name", "sfnt_interface.free_name", []),
        "0x2644a0": ("v18_tt_face_load_kern", "sfnt_interface.load_kern", []),
        "0x264364": ("v18_tt_face_load_gasp", "sfnt_interface.load_gasp", []),
        "0x263d6c": ("v18_tt_face_load_pclt", "sfnt_interface.load_pclt", ["register_detail_hash"]),
        "0x262028": ("v18_tt_face_get_kerning", "sfnt_interface.get_kerning", []),
        "0x265098": ("v18_tt_face_load_font_dir", "sfnt_interface.load_font_dir", ["register_detail_hash"]),
        "0x263cec": ("v18_tt_face_load_hmtx", "sfnt_interface.load_hmtx", []),
        "0x263b48": ("v18_tt_face_get_metrics", "sfnt_interface.get_metrics", []),
        "0x2634d0": ("v18_tt_name_entry_ascii_from_other", "sfnt_load_face name conversion helper", []),
        "0x263840": ("v18_tt_name_entry_ascii_from_utf16", "sfnt_load_face name conversion helper", []),
    }
    check(
        "Spectron FreeType SFNT interface target set",
        set(freetype_sfnt_interface_rows),
        set(freetype_sfnt_interface_expected),
    )
    for target_ea, (expected_name, expected_slot, expected_differences) in freetype_sfnt_interface_expected.items():
        row = freetype_sfnt_interface_rows[target_ea]
        check(
            "Spectron FreeType SFNT interface name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType SFNT interface role " + target_ea,
            row["interface_slot"],
            expected_slot,
        )
        check(
            "Spectron FreeType SFNT interface metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
    check(
        "Spectron v300 checkpoint artifact",
        spectron_checkpoint_v300["artifact"],
        "spectron_translation_checkpoint_20260828_v300",
    )
    check(
        "Spectron v300 checkpoint parent",
        spectron_checkpoint_v300["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v299",
    )
    check(
        "Spectron v300 checkpoint parent path",
        spectron_checkpoint_v300["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v299.json",
    )
    check(
        "Spectron v300 checkpoint database hash",
        spectron_checkpoint_v300["database"]["sha256"],
        "d05ecd64d3430bfa54cb34120ab750a46f0d8a5dbad54180afd0da18b8e312b5",
    )
    check(
        "Spectron v300 checkpoint function count",
        spectron_checkpoint_v300["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v300 checkpoint default sub count",
        spectron_checkpoint_v300["database"]["default_sub_function_count"],
        502,
    )
    check(
        "Spectron v300 checkpoint SFNT interface count",
        spectron_checkpoint_v300["freetype_sfnt_interface_anchors"][
            "verified_name_count"
        ],
        21,
    )
    check(
        "Spectron FreeType smooth artifact",
        spectron_freetype_smooth_anchors["artifact"],
        "spectron_freetype_smooth_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType smooth network",
        spectron_freetype_smooth_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType smooth anchor count",
        spectron_freetype_smooth_anchors["summary"]["anchor_count"],
        12,
    )
    check(
        "Spectron FreeType smooth high-confidence count",
        spectron_freetype_smooth_anchors["summary"]["high_confidence_count"],
        12,
    )
    check(
        "Spectron FreeType smooth normalized count",
        spectron_freetype_smooth_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        12,
    )
    check(
        "Spectron FreeType smooth full-match count",
        spectron_freetype_smooth_anchors["summary"]["full_metric_exact_count"],
        10,
    )
    check(
        "Spectron FreeType smooth callback-table count",
        spectron_freetype_smooth_anchors["summary"][
            "callback_table_anchor_count"
        ],
        11,
    )
    check(
        "Spectron FreeType smooth cmap-builder count",
        spectron_freetype_smooth_anchors["summary"][
            "cmap_builder_anchor_count"
        ],
        1,
    )
    freetype_smooth_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_smooth_anchors["anchors"]
    }
    freetype_smooth_expected = {
        "0x268a64": (
            "v18_ft_smooth_init",
            "smooth renderer module initializer",
            [],
        ),
        "0x268a9c": (
            "v18_ft_smooth_set_mode",
            "smooth renderer mode callback",
            [],
        ),
        "0x268ac4": (
            "v18_gray_raster_done",
            "gray raster destructor",
            [],
        ),
        "0x268bdc": (
            "v18_gray_raster_new",
            "gray raster constructor",
            [],
        ),
        "0x268c24": (
            "v18_ft_smooth_get_cbox",
            "smooth renderer control-box callback",
            [],
        ),
        "0x268c4c": (
            "v18_ft_smooth_render_lcd_v",
            "vertical LCD smooth renderer callback",
            [],
        ),
        "0x268f00": (
            "v18_gray_raster_reset",
            "gray raster pool reset callback",
            [],
        ),
        "0x268f5c": (
            "v18_ft_smooth_transform",
            "smooth renderer transform callback",
            [],
        ),
        "0x269ce8": (
            "v18_gray_raster_render",
            "gray raster render callback",
            ["register_detail_hash"],
        ),
        "0x269ee8": (
            "v18_ft_smooth_render",
            "normal smooth renderer callback",
            [],
        ),
        "0x26a128": (
            "v18_ft_smooth_render_lcd",
            "horizontal LCD smooth renderer callback",
            [],
        ),
        "0x264828": (
            "v18_tt_face_build_cmaps",
            "TrueType cmap builder",
            ["register_detail_hash"],
        ),
    }
    check(
        "Spectron FreeType smooth target set",
        set(freetype_smooth_rows),
        set(freetype_smooth_expected),
    )
    for target_ea, (expected_name, expected_role, expected_differences) in freetype_smooth_expected.items():
        row = freetype_smooth_rows[target_ea]
        check(
            "Spectron FreeType smooth name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType smooth role " + target_ea,
            row["source_role"],
            expected_role,
        )
        check(
            "Spectron FreeType smooth metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType smooth normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
    check(
        "Spectron v301 checkpoint artifact",
        spectron_checkpoint_v301["artifact"],
        "spectron_translation_checkpoint_20260828_v301",
    )
    check(
        "Spectron v301 checkpoint parent",
        spectron_checkpoint_v301["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v300",
    )
    check(
        "Spectron v301 checkpoint parent path",
        spectron_checkpoint_v301["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v300.json",
    )
    check(
        "Spectron v301 checkpoint database hash",
        spectron_checkpoint_v301["database"]["sha256"],
        "385ff0bf22b942386ac6857321529201857ac190668dca6c7e673107be8350ca",
    )
    check(
        "Spectron v301 checkpoint function count",
        spectron_checkpoint_v301["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v301 checkpoint default sub count",
        spectron_checkpoint_v301["database"]["default_sub_function_count"],
        490,
    )
    check(
        "Spectron v301 checkpoint FreeType smooth count",
        spectron_checkpoint_v301["freetype_smooth_anchors"][
            "verified_name_count"
        ],
        12,
    )
    check(
        "Spectron FreeType gray internal artifact",
        spectron_freetype_gray_internal_anchors["artifact"],
        "spectron_freetype_gray_internal_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType gray internal network",
        spectron_freetype_gray_internal_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType gray internal anchor count",
        spectron_freetype_gray_internal_anchors["summary"]["anchor_count"],
        9,
    )
    check(
        "Spectron FreeType gray internal high-confidence count",
        spectron_freetype_gray_internal_anchors["summary"][
            "high_confidence_count"
        ],
        9,
    )
    check(
        "Spectron FreeType gray internal normalized count",
        spectron_freetype_gray_internal_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        9,
    )
    check(
        "Spectron FreeType gray internal full-match count",
        spectron_freetype_gray_internal_anchors["summary"][
            "full_metric_exact_count"
        ],
        7,
    )
    freetype_gray_internal_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_gray_internal_anchors["anchors"]
    }
    freetype_gray_internal_expected = {
        "0x268ad0": (
            "v18_gray_render_span",
            "gray raster span callback",
            ["register_detail_hash"],
        ),
        "0x268fd4": (
            "v18_gray_convert_glyph_inner",
            "gray glyph conversion inner helper",
            ["register_detail_hash"],
        ),
        "0x269118": (
            "v18_gray_move_to",
            "gray outline move callback",
            [],
        ),
        "0x2692b4": (
            "v18_gray_convert_glyph",
            "gray glyph conversion helper",
            [],
        ),
        "0x26a3e8": (
            "v18_gray_render_scanline",
            "gray scanline renderer",
            [],
        ),
        "0x26a92c": (
            "v18_gray_render_line",
            "gray line renderer",
            [],
        ),
        "0x26b12c": (
            "v18_gray_render_cubic",
            "gray cubic Bézier renderer",
            [],
        ),
        "0x26b4bc": (
            "v18_gray_render_conic",
            "gray conic Bézier renderer",
            [],
        ),
        "0x26b75c": (
            "v18_gray_line_to",
            "gray outline line callback",
            [],
        ),
    }
    check(
        "Spectron FreeType gray internal target set",
        set(freetype_gray_internal_rows),
        set(freetype_gray_internal_expected),
    )
    for target_ea, (expected_name, expected_role, expected_differences) in freetype_gray_internal_expected.items():
        row = freetype_gray_internal_rows[target_ea]
        check(
            "Spectron FreeType gray internal name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType gray internal role " + target_ea,
            row["source_role"],
            expected_role,
        )
        check(
            "Spectron FreeType gray internal metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType gray internal normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
    check(
        "Spectron v302 checkpoint artifact",
        spectron_checkpoint_v302["artifact"],
        "spectron_translation_checkpoint_20260828_v302",
    )
    check(
        "Spectron v302 checkpoint parent",
        spectron_checkpoint_v302["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v301",
    )
    check(
        "Spectron v302 checkpoint parent path",
        spectron_checkpoint_v302["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v301.json",
    )
    check(
        "Spectron v302 checkpoint database hash",
        spectron_checkpoint_v302["database"]["sha256"],
        "71ab01a1215b46848c4ae511fbd065432be83d357d80a2f17a1efa045d814ab5",
    )
    check(
        "Spectron v302 checkpoint function count",
        spectron_checkpoint_v302["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v302 checkpoint default sub count",
        spectron_checkpoint_v302["database"]["default_sub_function_count"],
        481,
    )
    check(
        "Spectron v302 checkpoint FreeType gray internal count",
        spectron_checkpoint_v302["freetype_gray_internal_anchors"][
            "verified_name_count"
        ],
        9,
    )
    check(
        "Spectron FreeType TrueType interpreter artifact",
        spectron_freetype_tt_interpreter_anchors["artifact"],
        "spectron_freetype_tt_interpreter_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType TrueType interpreter network",
        spectron_freetype_tt_interpreter_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType TrueType interpreter anchor count",
        spectron_freetype_tt_interpreter_anchors["summary"]["anchor_count"],
        19,
    )
    check(
        "Spectron FreeType TrueType interpreter high-confidence count",
        spectron_freetype_tt_interpreter_anchors["summary"][
            "high_confidence_count"
        ],
        19,
    )
    check(
        "Spectron FreeType TrueType interpreter normalized count",
        spectron_freetype_tt_interpreter_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        19,
    )
    check(
        "Spectron FreeType TrueType interpreter full-match count",
        spectron_freetype_tt_interpreter_anchors["summary"][
            "full_metric_exact_count"
        ],
        19,
    )
    freetype_tt_interpreter_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_tt_interpreter_anchors["anchors"]
    }
    freetype_tt_interpreter_expected = {
        "0x26b790": (
            "0x25e320",
            "v18_tt_get_kerning",
            "TrueType kerning driver wrapper",
        ),
        "0x26b7cc": (
            "0x25e35c",
            "v18_tt_face_get_location",
            "TrueType loca-table glyph location helper",
        ),
        "0x26b954": (
            "0x25e4e4",
            "v18_tt_size_init",
            "TrueType size object initializer",
        ),
        "0x26b974": (
            "0x25e504",
            "v18_TT_MulFix14",
            "14-bit fixed-point multiplication helper",
        ),
        "0x26b9f0": (
            "0x25e580",
            "v18_Direct_Move_X",
            "current-coordinate x movement helper",
        ),
        "0x26ba20": (
            "0x25e5b0",
            "v18_Direct_Move_Y",
            "current-coordinate y movement helper",
        ),
        "0x26ba54": (
            "0x25e5e4",
            "v18_Direct_Move_Orig_X",
            "original-coordinate x movement helper",
        ),
        "0x26ba6c": (
            "0x25e5fc",
            "v18_Direct_Move_Orig_Y",
            "original-coordinate y movement helper",
        ),
        "0x26ba88": (
            "0x25e618",
            "v18_Round_None",
            "no-op TrueType rounding mode",
        ),
        "0x26bab0": (
            "0x25e640",
            "v18_TT_DotFix14",
            "14-bit fixed-point vector dot product",
        ),
        "0x26bb3c": (
            "0x25e6cc",
            "v18_Project_x",
            "x-axis projection helper",
        ),
        "0x26bb44": (
            "0x25e6d4",
            "v18_Project_y",
            "y-axis projection helper",
        ),
        "0x26bb4c": (
            "0x25e6dc",
            "v18_Ins_NPUSHW",
            "TrueType NPUSHW opcode handler",
        ),
        "0x26bbe0": (
            "0x25e770",
            "v18_Ins_PUSHW",
            "TrueType PUSHW opcode handler",
        ),
        "0x26bc68": (
            "0x25e7f8",
            "v18_Ins_GC",
            "TrueType GC opcode handler",
        ),
        "0x26bd00": (
            "0x25e890",
            "v18_Ins_SCFS",
            "TrueType SCFS opcode handler",
        ),
        "0x26bdc0": (
            "0x25e950",
            "v18_Ins_GETINFO",
            "TrueType GETINFO opcode handler",
        ),
        "0x26be18": (
            "0x25e9a8",
            "v18_Ins_MD",
            "TrueType MD opcode handler",
        ),
        "0x26c240": (
            "0x25edd0",
            "v18_Ins_IUP",
            "TrueType IUP opcode handler",
        ),
    }
    check(
        "Spectron FreeType TrueType interpreter target set",
        set(freetype_tt_interpreter_rows),
        set(freetype_tt_interpreter_expected),
    )
    for target_ea, (source_ea, expected_name, expected_role) in freetype_tt_interpreter_expected.items():
        row = freetype_tt_interpreter_rows[target_ea]
        check(
            "Spectron FreeType TrueType interpreter source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType TrueType interpreter name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType TrueType interpreter role " + target_ea,
            row["source_role"],
            expected_role,
        )
        check(
            "Spectron FreeType TrueType interpreter metrics " + target_ea,
            row["metric_differences"],
            [],
        )
        check(
            "Spectron FreeType TrueType interpreter normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType TrueType interpreter full metrics " + target_ea,
            row["full_metric_equal"],
            True,
        )
    check(
        "Spectron v303 checkpoint artifact",
        spectron_checkpoint_v303["artifact"],
        "spectron_translation_checkpoint_20260828_v303",
    )
    check(
        "Spectron v303 checkpoint parent",
        spectron_checkpoint_v303["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v302",
    )
    check(
        "Spectron v303 checkpoint parent path",
        spectron_checkpoint_v303["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v302.json",
    )
    check(
        "Spectron v303 checkpoint database hash",
        spectron_checkpoint_v303["database"]["sha256"],
        "36ebf8b934351b45aea6ba5664c93f0d7b66b8b7a3d7ed49980e030226d6c47c",
    )
    check(
        "Spectron v303 checkpoint function count",
        spectron_checkpoint_v303["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v303 checkpoint default sub count",
        spectron_checkpoint_v303["database"]["default_sub_function_count"],
        462,
    )
    check(
        "Spectron v303 checkpoint TrueType interpreter count",
        spectron_checkpoint_v303["freetype_tt_interpreter_anchors"][
            "verified_name_count"
        ],
        19,
    )
    check(
        "Spectron FreeType TrueType runtime artifact",
        spectron_freetype_tt_runtime_anchors["artifact"],
        "spectron_freetype_tt_runtime_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType TrueType runtime network",
        spectron_freetype_tt_runtime_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType TrueType runtime anchor count",
        spectron_freetype_tt_runtime_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron FreeType TrueType runtime high-confidence count",
        spectron_freetype_tt_runtime_anchors["summary"]["high_confidence_count"],
        6,
    )
    check(
        "Spectron FreeType TrueType runtime normalized count",
        spectron_freetype_tt_runtime_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        6,
    )
    check(
        "Spectron FreeType TrueType runtime full-match count",
        spectron_freetype_tt_runtime_anchors["summary"]["full_metric_exact_count"],
        5,
    )
    freetype_tt_runtime_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_tt_runtime_anchors["anchors"]
    }
    freetype_tt_runtime_expected = {
        "0x26c0f4": (
            "0x25ec84",
            "v18_Direct_Move_Orig",
            "original-coordinate direct movement helper",
            [],
            True,
        ),
        "0x26c184": (
            "0x25ed14",
            "v18_Direct_Move",
            "current-coordinate direct movement helper",
            [],
            True,
        ),
        "0x26c964": (
            "0x25f4f4",
            "v18_tt_slot_init",
            "TrueType slot initializer",
            [],
            True,
        ),
        "0x26c970": (
            "0x25f500",
            "v18_tt_face_done",
            "TrueType face teardown",
            [],
            True,
        ),
        "0x26cab8": (
            "0x25f648",
            "v18_tt_face_init",
            "TrueType face initializer",
            ["register_detail_hash"],
            False,
        ),
        "0x26d1fc": (
            "0x25fd8c",
            "v18_Current_Ratio",
            "TrueType interpreter scaling-ratio helper",
            [],
            True,
        ),
    }
    check(
        "Spectron FreeType TrueType runtime target set",
        set(freetype_tt_runtime_rows),
        set(freetype_tt_runtime_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_role,
        expected_differences,
        expected_full_match,
    ) in freetype_tt_runtime_expected.items():
        row = freetype_tt_runtime_rows[target_ea]
        check(
            "Spectron FreeType TrueType runtime source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType TrueType runtime name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType TrueType runtime role " + target_ea,
            row["source_role"],
            expected_role,
        )
        check(
            "Spectron FreeType TrueType runtime metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType TrueType runtime normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType TrueType runtime full metrics " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron v304 checkpoint artifact",
        spectron_checkpoint_v304["artifact"],
        "spectron_translation_checkpoint_20260828_v304",
    )
    check(
        "Spectron v304 checkpoint parent",
        spectron_checkpoint_v304["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v303",
    )
    check(
        "Spectron v304 checkpoint parent path",
        spectron_checkpoint_v304["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v303.json",
    )
    check(
        "Spectron v304 checkpoint database hash",
        spectron_checkpoint_v304["database"]["sha256"],
        "8c2e1b1591fbb80bb3d874c3dfa4708d6e7d4bfc503748a70c519f07202494c4",
    )
    check(
        "Spectron v304 checkpoint function count",
        spectron_checkpoint_v304["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v304 checkpoint default sub count",
        spectron_checkpoint_v304["database"]["default_sub_function_count"],
        456,
    )
    check(
        "Spectron v304 checkpoint TrueType runtime count",
        spectron_checkpoint_v304["freetype_tt_runtime_anchors"][
            "verified_name_count"
        ],
        6,
    )
    check(
        "Spectron FreeType TrueType rounding artifact",
        spectron_freetype_tt_rounding_anchors["artifact"],
        "spectron_freetype_tt_rounding_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType TrueType rounding network",
        spectron_freetype_tt_rounding_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType TrueType rounding anchor count",
        spectron_freetype_tt_rounding_anchors["summary"]["anchor_count"],
        8,
    )
    check(
        "Spectron FreeType TrueType rounding high-confidence count",
        spectron_freetype_tt_rounding_anchors["summary"]["high_confidence_count"],
        8,
    )
    check(
        "Spectron FreeType TrueType rounding normalized count",
        spectron_freetype_tt_rounding_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        8,
    )
    check(
        "Spectron FreeType TrueType rounding full-match count",
        spectron_freetype_tt_rounding_anchors["summary"]["full_metric_exact_count"],
        7,
    )
    freetype_tt_rounding_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_tt_rounding_anchors["anchors"]
    }
    freetype_tt_rounding_expected = {
        "0x26d2a8": (
            "0x25fe38",
            "v18_Round_To_Grid",
            "TrueType grid-rounding callback",
            [],
            True,
        ),
        "0x26d2ec": (
            "0x25fe7c",
            "v18_Round_To_Half_Grid",
            "TrueType half-grid rounding callback",
            [],
            True,
        ),
        "0x26d328": (
            "0x25feb8",
            "v18_Round_Down_To_Grid",
            "TrueType downward grid-rounding callback",
            [],
            True,
        ),
        "0x26d364": (
            "0x25fef4",
            "v18_Round_Up_To_Grid",
            "TrueType upward grid-rounding callback",
            [],
            True,
        ),
        "0x26d3a8": (
            "0x25ff38",
            "v18_Round_To_Double_Grid",
            "TrueType double-grid rounding callback",
            [],
            True,
        ),
        "0x26d3ec": (
            "0x25ff7c",
            "v18_Round_Super",
            "TrueType super-rounding callback",
            [],
            True,
        ),
        "0x26d458": (
            "0x25ffe8",
            "v18_Round_Super_45",
            "TrueType precise super-rounding callback",
            [],
            True,
        ),
        "0x26d4c0": (
            "0x260050",
            "v18_Compute_Funcs",
            "TrueType interpreter callback selector",
            ["register_detail_hash"],
            False,
        ),
    }
    check(
        "Spectron FreeType TrueType rounding target set",
        set(freetype_tt_rounding_rows),
        set(freetype_tt_rounding_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_role,
        expected_differences,
        expected_full_match,
    ) in freetype_tt_rounding_expected.items():
        row = freetype_tt_rounding_rows[target_ea]
        check(
            "Spectron FreeType TrueType rounding source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType TrueType rounding name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType TrueType rounding role " + target_ea,
            row["source_role"],
            expected_role,
        )
        check(
            "Spectron FreeType TrueType rounding metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType TrueType rounding normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType TrueType rounding full metrics " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron v305 checkpoint artifact",
        spectron_checkpoint_v305["artifact"],
        "spectron_translation_checkpoint_20260828_v305",
    )
    check(
        "Spectron v305 checkpoint parent",
        spectron_checkpoint_v305["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v304",
    )
    check(
        "Spectron v305 checkpoint parent path",
        spectron_checkpoint_v305["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v304.json",
    )
    check(
        "Spectron v305 checkpoint database hash",
        spectron_checkpoint_v305["database"]["sha256"],
        "28920bb7cd08c4b94bc16b82bd3a4770e9873b55af3ff2269bec87755876c931",
    )
    check(
        "Spectron v305 checkpoint function count",
        spectron_checkpoint_v305["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v305 checkpoint default sub count",
        spectron_checkpoint_v305["database"]["default_sub_function_count"],
        448,
    )
    check(
        "Spectron v305 checkpoint TrueType rounding count",
        spectron_checkpoint_v305["freetype_tt_rounding_anchors"][
            "verified_name_count"
        ],
        8,
    )
    check(
        "Spectron FreeType TrueType opcode-state artifact",
        spectron_freetype_tt_opcode_state_anchors["artifact"],
        "spectron_freetype_tt_opcode_state_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType TrueType opcode-state network",
        spectron_freetype_tt_opcode_state_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType TrueType opcode-state anchor count",
        spectron_freetype_tt_opcode_state_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron FreeType TrueType opcode-state high-confidence count",
        spectron_freetype_tt_opcode_state_anchors["summary"][
            "high_confidence_count"
        ],
        6,
    )
    check(
        "Spectron FreeType TrueType opcode-state normalized count",
        spectron_freetype_tt_opcode_state_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        6,
    )
    check(
        "Spectron FreeType TrueType opcode-state full-match count",
        spectron_freetype_tt_opcode_state_anchors["summary"][
            "full_metric_exact_count"
        ],
        6,
    )
    freetype_tt_opcode_state_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_tt_opcode_state_anchors["anchors"]
    }
    freetype_tt_opcode_state_expected = {
        "0x26d714": (
            "0x2602a4",
            "v18_Ins_SZP0",
            "TrueType SZP0 zone-pointer opcode handler",
            [],
            True,
        ),
        "0x26d76c": (
            "0x2602fc",
            "v18_Ins_SZP1",
            "TrueType SZP1 zone-pointer opcode handler",
            [],
            True,
        ),
        "0x26d7c4": (
            "0x260354",
            "v18_Ins_SZP2",
            "TrueType SZP2 zone-pointer opcode handler",
            [],
            True,
        ),
        "0x26d81c": (
            "0x2603ac",
            "v18_Ins_SZPS",
            "TrueType SZPS zone-pointer opcode handler",
            [],
            True,
        ),
        "0x26d8d8": (
            "0x260468",
            "v18_Ins_ALIGNRP",
            "TrueType AlignRP opcode handler",
            [],
            True,
        ),
        "0x26da00": (
            "0x260590",
            "v18_Ins_UTP",
            "TrueType UTP opcode handler",
            [],
            True,
        ),
    }
    check(
        "Spectron FreeType TrueType opcode-state target set",
        set(freetype_tt_opcode_state_rows),
        set(freetype_tt_opcode_state_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_role,
        expected_differences,
        expected_full_match,
    ) in freetype_tt_opcode_state_expected.items():
        row = freetype_tt_opcode_state_rows[target_ea]
        check(
            "Spectron FreeType TrueType opcode-state source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType TrueType opcode-state name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType TrueType opcode-state role " + target_ea,
            row["source_role"],
            expected_role,
        )
        check(
            "Spectron FreeType TrueType opcode-state metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType TrueType opcode-state normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType TrueType opcode-state full metrics " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron v306 checkpoint artifact",
        spectron_checkpoint_v306["artifact"],
        "spectron_translation_checkpoint_20260828_v306",
    )
    check(
        "Spectron v306 checkpoint parent",
        spectron_checkpoint_v306["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v305",
    )
    check(
        "Spectron v306 checkpoint parent path",
        spectron_checkpoint_v306["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v305.json",
    )
    check(
        "Spectron v306 checkpoint database hash",
        spectron_checkpoint_v306["database"]["sha256"],
        "4a4eb58f2245daf73e262e87c447370e9e8da96329e5a0ab19ca8e2740ad91df",
    )
    check(
        "Spectron v306 checkpoint function count",
        spectron_checkpoint_v306["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v306 checkpoint default sub count",
        spectron_checkpoint_v306["database"]["default_sub_function_count"],
        442,
    )
    check(
        "Spectron v306 checkpoint TrueType opcode-state count",
        spectron_checkpoint_v306["freetype_tt_opcode_state_anchors"][
            "verified_name_count"
        ],
        6,
    )
    check(
        "Spectron FreeType TrueType opcode-core artifact",
        spectron_freetype_tt_opcode_core_anchors["artifact"],
        "spectron_freetype_tt_opcode_core_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType TrueType opcode-core network",
        spectron_freetype_tt_opcode_core_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType TrueType opcode-core anchor count",
        spectron_freetype_tt_opcode_core_anchors["summary"]["anchor_count"],
        6,
    )
    check(
        "Spectron FreeType TrueType opcode-core high-confidence count",
        spectron_freetype_tt_opcode_core_anchors["summary"][
            "high_confidence_count"
        ],
        6,
    )
    check(
        "Spectron FreeType TrueType opcode-core normalized count",
        spectron_freetype_tt_opcode_core_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        6,
    )
    check(
        "Spectron FreeType TrueType opcode-core full-match count",
        spectron_freetype_tt_opcode_core_anchors["summary"][
            "full_metric_exact_count"
        ],
        6,
    )
    freetype_tt_opcode_core_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_tt_opcode_core_anchors["anchors"]
    }
    freetype_tt_opcode_core_expected = {
        "0x26dad0": (
            "0x260660",
            "v18_Ins_MDRP",
            "TrueType MDRP direct-relative-point opcode handler",
            [],
            True,
        ),
        "0x26dd50": (
            "0x2608e0",
            "v18_Ins_MIRP",
            "TrueType MIRP indirect-relative-point opcode handler",
            [],
            True,
        ),
        "0x26e034": (
            "0x260bc4",
            "v18_Normalize",
            "TrueType unit-vector normalization helper",
            [],
            True,
        ),
        "0x26e1ec": (
            "0x260d7c",
            "v18_Ins_MINDEX",
            "TrueType MINDEX stack-reordering opcode handler",
            [],
            True,
        ),
        "0x26e270": (
            "0x260e00",
            "v18_TT_Done_Context",
            "TrueType execution-context destructor",
            [],
            True,
        ),
        "0x26e2fc": (
            "0x260e8c",
            "v18_Ins_IP",
            "TrueType IP interpolate-point opcode handler",
            [],
            True,
        ),
    }
    check(
        "Spectron FreeType TrueType opcode-core target set",
        set(freetype_tt_opcode_core_rows),
        set(freetype_tt_opcode_core_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_role,
        expected_differences,
        expected_full_match,
    ) in freetype_tt_opcode_core_expected.items():
        row = freetype_tt_opcode_core_rows[target_ea]
        check(
            "Spectron FreeType TrueType opcode-core source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType TrueType opcode-core name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType TrueType opcode-core role " + target_ea,
            row["source_role"],
            expected_role,
        )
        check(
            "Spectron FreeType TrueType opcode-core metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType TrueType opcode-core normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType TrueType opcode-core full metrics " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron v307 checkpoint artifact",
        spectron_checkpoint_v307["artifact"],
        "spectron_translation_checkpoint_20260828_v307",
    )
    check(
        "Spectron v307 checkpoint parent",
        spectron_checkpoint_v307["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v306",
    )
    check(
        "Spectron v307 checkpoint parent path",
        spectron_checkpoint_v307["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v306.json",
    )
    check(
        "Spectron v307 checkpoint database hash",
        spectron_checkpoint_v307["database"]["sha256"],
        "2f9136831860bd73c73b966212134aea033a819d9f96520f6a0d887158f36b9c",
    )
    check(
        "Spectron v307 checkpoint function count",
        spectron_checkpoint_v307["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v307 checkpoint default sub count",
        spectron_checkpoint_v307["database"]["default_sub_function_count"],
        436,
    )
    check(
        "Spectron v307 checkpoint TrueType opcode-core count",
        spectron_checkpoint_v307["freetype_tt_opcode_core_anchors"][
            "verified_name_count"
        ],
        6,
    )
    check(
        "Spectron FreeType TrueType runtime-tail artifact",
        spectron_freetype_tt_runtime_tail_anchors["artifact"],
        "spectron_freetype_tt_runtime_tail_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType TrueType runtime-tail network",
        spectron_freetype_tt_runtime_tail_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType TrueType runtime-tail anchor count",
        spectron_freetype_tt_runtime_tail_anchors["summary"]["anchor_count"],
        11,
    )
    check(
        "Spectron FreeType TrueType runtime-tail high-confidence count",
        spectron_freetype_tt_runtime_tail_anchors["summary"][
            "high_confidence_count"
        ],
        11,
    )
    check(
        "Spectron FreeType TrueType runtime-tail normalized count",
        spectron_freetype_tt_runtime_tail_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        11,
    )
    check(
        "Spectron FreeType TrueType runtime-tail full-match count",
        spectron_freetype_tt_runtime_tail_anchors["summary"][
            "full_metric_exact_count"
        ],
        9,
    )
    check(
        "Spectron FreeType TrueType runtime-tail register-detail count",
        spectron_freetype_tt_runtime_tail_anchors["summary"][
            "register_detail_only_difference_count"
        ],
        2,
    )
    freetype_tt_runtime_tail_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_tt_runtime_tail_anchors["anchors"]
    }
    freetype_tt_runtime_tail_expected = {
        "0x26ea94": (
            "0x261624",
            "v18_Ins_ENDF",
            "TrueType ENDF function-definition return opcode handler",
            [],
            True,
        ),
        "0x26eb50": (
            "0x2616e0",
            "v18_tt_size_done",
            "TrueType size-object destructor",
            [],
            True,
        ),
        "0x26ec88": (
            "0x261818",
            "v18_Dual_Project",
            "TrueType dual-vector projection callback",
            [],
            True,
        ),
        "0x26ed14": (
            "0x2618a4",
            "v18_Ins_FDEF",
            "TrueType FDEF function-definition opcode handler",
            ["register_detail_hash"],
            False,
        ),
        "0x26ee44": (
            "0x2619d4",
            "v18_Ins_IDEF",
            "TrueType IDEF instruction-definition opcode handler",
            ["register_detail_hash"],
            False,
        ),
        "0x26f1fc": (
            "0x261d8c",
            "v18_Ins_DELTAP",
            "TrueType DELTAP point-adjustment opcode handler",
            [],
            True,
        ),
        "0x26f434": (
            "0x261fc4",
            "v18_Ins_DELTAC",
            "TrueType DELTAC control-value adjustment opcode handler",
            [],
            True,
        ),
        "0x26f664": (
            "0x2621f4",
            "v18_TT_Load_Context",
            "TrueType execution-context loader",
            [],
            True,
        ),
        "0x26fa58": (
            "0x2625e8",
            "v18_Ins_SHC",
            "TrueType SHC contour-shift opcode handler",
            [],
            True,
        ),
        "0x26fcd4": (
            "0x262864",
            "v18_Ins_SHP",
            "TrueType SHP point-shift opcode handler",
            [],
            True,
        ),
        "0x26fee4": (
            "0x262a74",
            "v18_Ins_ISECT",
            "TrueType ISECT intersection-point opcode handler",
            [],
            True,
        ),
    }
    check(
        "Spectron FreeType TrueType runtime-tail target set",
        set(freetype_tt_runtime_tail_rows),
        set(freetype_tt_runtime_tail_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_role,
        expected_differences,
        expected_full_match,
    ) in freetype_tt_runtime_tail_expected.items():
        row = freetype_tt_runtime_tail_rows[target_ea]
        check(
            "Spectron FreeType TrueType runtime-tail source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType TrueType runtime-tail name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType TrueType runtime-tail role " + target_ea,
            row["source_role"],
            expected_role,
        )
        check(
            "Spectron FreeType TrueType runtime-tail metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType TrueType runtime-tail normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType TrueType runtime-tail full metrics " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron FreeType TrueType projection correction artifact",
        spectron_freetype_tt_projection_correction["artifact"],
        "spectron_freetype_tt_projection_name_correction_20260828",
    )
    check(
        "Spectron FreeType TrueType projection correction network",
        spectron_freetype_tt_projection_correction["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType TrueType projection correction count",
        spectron_freetype_tt_projection_correction["summary"]["correction_count"],
        1,
    )
    projection_correction = spectron_freetype_tt_projection_correction[
        "corrections"
    ][0]
    check(
        "Spectron FreeType TrueType projection correction target",
        projection_correction["target_ea"],
        "0x26bab0",
    )
    check(
        "Spectron FreeType TrueType projection correction old name",
        projection_correction["current_name"],
        "v18_TT_DotFix14",
    )
    check(
        "Spectron FreeType TrueType projection correction new name",
        projection_correction["restored_name"],
        "v18_Project",
    )
    check(
        "Spectron FreeType TrueType projection correction source",
        projection_correction["source_ea"],
        "0x25e640",
    )
    check(
        "Spectron FreeType TrueType projection correction metrics",
        projection_correction["metric_differences"],
        [],
    )
    check(
        "Spectron v308 checkpoint artifact",
        spectron_checkpoint_v308["artifact"],
        "spectron_translation_checkpoint_20260828_v308",
    )
    check(
        "Spectron v308 checkpoint parent",
        spectron_checkpoint_v308["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v307",
    )
    check(
        "Spectron v308 checkpoint parent path",
        spectron_checkpoint_v308["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v307.json",
    )
    check(
        "Spectron v308 checkpoint database hash",
        spectron_checkpoint_v308["database"]["sha256"],
        "2ac5e911c27e2cc07642c7b8433d54b708a536062114b4b2bea3609524c3bab8",
    )
    check(
        "Spectron v308 checkpoint database close-reopen",
        spectron_checkpoint_v308["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v308 checkpoint function count",
        spectron_checkpoint_v308["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v308 checkpoint default sub count",
        spectron_checkpoint_v308["database"]["default_sub_function_count"],
        425,
    )
    check(
        "Spectron v308 checkpoint TrueType runtime-tail count",
        spectron_checkpoint_v308["freetype_tt_runtime_tail_anchors"][
            "verified_name_count"
        ],
        11,
    )
    check(
        "Spectron v308 checkpoint projection correction count",
        spectron_checkpoint_v308["freetype_tt_projection_name_correction"][
            "verified_name_count"
        ],
        1,
    )
    check(
        "Spectron FreeType TrueType glyph-loader artifact",
        spectron_freetype_tt_glyph_loader_anchors["artifact"],
        "spectron_freetype_tt_glyph_loader_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType TrueType glyph-loader network",
        spectron_freetype_tt_glyph_loader_anchors["network_contacted"],
        False,
    )
    check(
        "Spectron FreeType TrueType glyph-loader count",
        spectron_freetype_tt_glyph_loader_anchors["summary"]["anchor_count"],
        7,
    )
    check(
        "Spectron FreeType TrueType glyph-loader high confidence",
        spectron_freetype_tt_glyph_loader_anchors["summary"][
            "high_confidence_count"
        ],
        7,
    )
    check(
        "Spectron FreeType TrueType glyph-loader normalized count",
        spectron_freetype_tt_glyph_loader_anchors["summary"][
            "normalized_shape_exact_count"
        ],
        7,
    )
    check(
        "Spectron FreeType TrueType glyph-loader full metric count",
        spectron_freetype_tt_glyph_loader_anchors["summary"][
            "full_metric_exact_count"
        ],
        6,
    )
    glyph_loader_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_tt_glyph_loader_anchors["anchors"]
    }
    glyph_loader_expected = {
        "0x270224": ("0x262db4", "v18_load_truetype_glyph", [], True),
        "0x27118c": (
            "0x263d1c",
            "v18_TT_Load_Glyph",
            ["register_detail_hash"],
            False,
        ),
        "0x2723e8": ("0x264f78", "v18_tt_glyph_load", [], True),
        "0x27243c": ("0x264fcc", "v18_Ins_SxVTL", [], True),
        "0x27268c": ("0x26521c", "v18_Ins_CALL", [], True),
        "0x2727e0": ("0x265370", "v18_Ins_LOOPCALL", [], True),
        "0x272944": ("0x2654d4", "v18_Ins_UNKNOWN", [], True),
    }
    check(
        "Spectron FreeType TrueType glyph-loader target set",
        set(glyph_loader_rows),
        set(glyph_loader_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_differences,
        expected_full_match,
    ) in glyph_loader_expected.items():
        row = glyph_loader_rows[target_ea]
        check(
            "Spectron FreeType TrueType glyph-loader source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType TrueType glyph-loader name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType TrueType glyph-loader metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType TrueType glyph-loader normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType TrueType glyph-loader full metrics " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron v309 checkpoint artifact",
        spectron_checkpoint_v309["artifact"],
        "spectron_translation_checkpoint_20260828_v309",
    )
    check(
        "Spectron v309 checkpoint parent",
        spectron_checkpoint_v309["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v308",
    )
    check(
        "Spectron v309 checkpoint parent path",
        spectron_checkpoint_v309["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v308.json",
    )
    check(
        "Spectron v309 checkpoint database hash",
        spectron_checkpoint_v309["database"]["sha256"],
        "73e94e4ea548857972a5a0222c24860c4ed6123e0fda9cba61bd3e090c4bd824",
    )
    check(
        "Spectron v309 checkpoint database close-reopen",
        spectron_checkpoint_v309["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v309 checkpoint function count",
        spectron_checkpoint_v309["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v309 checkpoint default sub count",
        spectron_checkpoint_v309["database"]["default_sub_function_count"],
        418,
    )
    check(
        "Spectron v309 checkpoint glyph-loader count",
        spectron_checkpoint_v309["freetype_tt_glyph_loader_anchors"][
            "verified_name_count"
        ],
        7,
    )
    check(
        "Spectron FreeType autofit artifact",
        spectron_freetype_autofit_anchors["artifact"],
        "spectron_freetype_autofit_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType autofit network",
        spectron_freetype_autofit_anchors["network_contacted"],
        False,
    )
    autofit_summary = spectron_freetype_autofit_anchors["summary"]
    check("Spectron FreeType autofit anchor count", autofit_summary["anchor_count"], 8)
    check(
        "Spectron FreeType autofit callback count",
        autofit_summary["callback_anchor_count"],
        7,
    )
    check(
        "Spectron FreeType autofit segment-analysis count",
        autofit_summary["segment_analysis_anchor_count"],
        1,
    )
    check(
        "Spectron FreeType autofit high-confidence count",
        autofit_summary["high_confidence_count"],
        8,
    )
    check(
        "Spectron FreeType autofit normalized count",
        autofit_summary["normalized_shape_exact_count"],
        8,
    )
    check(
        "Spectron FreeType autofit full metric count",
        autofit_summary["full_metric_exact_count"],
        8,
    )
    check(
        "Spectron FreeType autofit source default count",
        autofit_summary["source_default_name_count"],
        8,
    )
    check(
        "Spectron FreeType autofit target default count",
        autofit_summary["target_default_name_count"],
        8,
    )
    autofit_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_autofit_anchors["anchors"]
    }
    autofit_expected = {
        "0x27533c": (
            "0x267ecc",
            "v18_tt_driver_init",
            "tt_driver_init",
            "src/truetype/ttobjs.c",
        ),
        "0x275360": (
            "0x267ef0",
            "v18_af_dummy_hints_init",
            "af_dummy_hints_init",
            "src/autofit/afdummy.c",
        ),
        "0x275378": (
            "0x267f08",
            "v18_af_dummy_hints_apply",
            "af_dummy_hints_apply",
            "src/autofit/afdummy.c",
        ),
        "0x275380": (
            "0x267f10",
            "v18_af_latin_hints_init",
            "af_latin_hints_init",
            "src/autofit/aflatin.c",
        ),
        "0x275400": (
            "0x267f90",
            "v18_af_latin2_hints_init",
            "af_latin2_hints_init",
            "src/autofit/aflatin2.c",
        ),
        "0x275480": (
            "0x268010",
            "v18_af_cjk_metrics_scale",
            "af_cjk_metrics_scale",
            "src/autofit/afcjk.c",
        ),
        "0x2754c0": (
            "0x268050",
            "v18_af_cjk_hints_init",
            "af_cjk_hints_init",
            "src/autofit/afcjk.c",
        ),
        "0x275530": (
            "0x2680c0",
            "v18_af_latin2_hints_compute_segments",
            "af_latin2_hints_compute_segments",
            "src/autofit/aflatin2.c",
        ),
    }
    check(
        "Spectron FreeType autofit target set",
        set(autofit_rows),
        set(autofit_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_source_name,
        expected_source_file,
    ) in autofit_expected.items():
        row = autofit_rows[target_ea]
        check(
            "Spectron FreeType autofit source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType autofit name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType autofit source name " + target_ea,
            row["source_name"],
            expected_source_name,
        )
        check(
            "Spectron FreeType autofit source file " + target_ea,
            row["source_file"],
            expected_source_file,
        )
        check(
            "Spectron FreeType autofit metrics " + target_ea,
            row["metric_differences"],
            [],
        )
        check(
            "Spectron FreeType autofit normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType autofit full metrics " + target_ea,
            row["full_metric_equal"],
            True,
        )
    check(
        "Spectron FreeType autofit verified name count",
        spectron_checkpoint_v310["freetype_autofit_anchors"]["verified_name_count"],
        8,
    )
    check(
        "Spectron FreeType autofit reopen failures",
        spectron_checkpoint_v310["freetype_autofit_anchors"]["reopen_failure_count"],
        0,
    )
    check(
        "Spectron v310 checkpoint artifact",
        spectron_checkpoint_v310["artifact"],
        "spectron_translation_checkpoint_20260828_v310",
    )
    check(
        "Spectron v310 checkpoint parent",
        spectron_checkpoint_v310["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v309",
    )
    check(
        "Spectron v310 checkpoint parent path",
        spectron_checkpoint_v310["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v309.json",
    )
    check(
        "Spectron v310 checkpoint database hash",
        spectron_checkpoint_v310["database"]["sha256"],
        "b2b94918d6b9cd30c6fe90c34e8db95cf9fde200e6074b11f9db86476244c33b",
    )
    check(
        "Spectron v310 checkpoint database close-reopen",
        spectron_checkpoint_v310["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v310 checkpoint function count",
        spectron_checkpoint_v310["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v310 checkpoint default sub count",
        spectron_checkpoint_v310["database"]["default_sub_function_count"],
        410,
    )
    check(
        "Spectron FreeType autofit follow-up artifact",
        spectron_freetype_autofit_followup_anchors["artifact"],
        "spectron_freetype_autofit_followup_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType autofit follow-up network",
        spectron_freetype_autofit_followup_anchors["network_contacted"],
        False,
    )
    followup_summary = spectron_freetype_autofit_followup_anchors["summary"]
    check(
        "Spectron FreeType autofit follow-up anchor count",
        followup_summary["anchor_count"],
        7,
    )
    check(
        "Spectron FreeType autofit follow-up high-confidence count",
        followup_summary["high_confidence_count"],
        7,
    )
    check(
        "Spectron FreeType autofit follow-up normalized count",
        followup_summary["normalized_shape_exact_count"],
        7,
    )
    check(
        "Spectron FreeType autofit follow-up full metric count",
        followup_summary["full_metric_exact_count"],
        6,
    )
    check(
        "Spectron FreeType autofit follow-up register-detail count",
        followup_summary["register_detail_only_count"],
        1,
    )
    check(
        "Spectron FreeType autofit follow-up source default count",
        followup_summary["source_default_name_count"],
        7,
    )
    check(
        "Spectron FreeType autofit follow-up target default count",
        followup_summary["target_default_name_count"],
        7,
    )
    followup_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_autofit_followup_anchors["anchors"]
    }
    followup_expected = {
        "0x275a78": (
            "0x268608",
            "v18_af_latin2_hints_link_segments",
            "af_latin2_hints_link_segments",
            "src/autofit/aflatin2.c",
            [],
            True,
        ),
        "0x275d6c": (
            "0x2688fc",
            "v18_af_latin2_hints_compute_edges",
            "af_latin2_hints_compute_edges",
            "src/autofit/aflatin2.c",
            [],
            True,
        ),
        "0x2762c8": (
            "0x268e58",
            "v18_af_glyph_hints_done",
            "af_glyph_hints_done",
            "src/autofit/afhints.c",
            ["register_detail_hash"],
            False,
        ),
        "0x2763b4": (
            "0x268f44",
            "v18_af_loader_load_g",
            "af_loader_load_g",
            "src/autofit/afloader.c",
            [],
            True,
        ),
        "0x276b44": (
            "0x2696d4",
            "v18_af_glyph_hints_reload",
            "af_glyph_hints_reload",
            "src/autofit/afhints.c",
            [],
            True,
        ),
        "0x277064": (
            "0x269bf4",
            "v18_af_latin2_metrics_scale",
            "af_latin2_metrics_scale",
            "src/autofit/aflatin2.c",
            [],
            True,
        ),
        "0x27738c": (
            "0x269f1c",
            "v18_af_latin_metrics_scale",
            "af_latin_metrics_scale",
            "src/autofit/aflatin.c",
            [],
            True,
        ),
    }
    check(
        "Spectron FreeType autofit follow-up target set",
        set(followup_rows),
        set(followup_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_source_name,
        expected_source_file,
        expected_differences,
        expected_full_match,
    ) in followup_expected.items():
        row = followup_rows[target_ea]
        check(
            "Spectron FreeType autofit follow-up source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType autofit follow-up name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType autofit follow-up source name " + target_ea,
            row["source_name"],
            expected_source_name,
        )
        check(
            "Spectron FreeType autofit follow-up source file " + target_ea,
            row["source_file"],
            expected_source_file,
        )
        check(
            "Spectron FreeType autofit follow-up metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType autofit follow-up normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType autofit follow-up full metrics " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron FreeType autofit follow-up verified name count",
        spectron_checkpoint_v311["freetype_autofit_followup_anchors"][
            "verified_name_count"
        ],
        7,
    )
    check(
        "Spectron FreeType autofit follow-up reopen failures",
        spectron_checkpoint_v311["freetype_autofit_followup_anchors"][
            "reopen_failure_count"
        ],
        0,
    )
    check(
        "Spectron v311 checkpoint artifact",
        spectron_checkpoint_v311["artifact"],
        "spectron_translation_checkpoint_20260828_v311",
    )
    check(
        "Spectron v311 checkpoint parent",
        spectron_checkpoint_v311["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v310",
    )
    check(
        "Spectron v311 checkpoint parent path",
        spectron_checkpoint_v311["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v310.json",
    )
    check(
        "Spectron v311 checkpoint database hash",
        spectron_checkpoint_v311["database"]["sha256"],
        "ce20ddf7e3d8835cb79f6889c9291445a0472480169f07cfadc6c6d6e1e6a6df",
    )
    check(
        "Spectron v311 checkpoint database close-reopen",
        spectron_checkpoint_v311["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v311 checkpoint function count",
        spectron_checkpoint_v311["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v311 checkpoint default sub count",
        spectron_checkpoint_v311["database"]["default_sub_function_count"],
        403,
    )
    check(
        "Spectron FreeType autofit metrics artifact",
        spectron_freetype_autofit_metrics_anchors["artifact"],
        "spectron_freetype_autofit_metrics_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType autofit metrics network",
        spectron_freetype_autofit_metrics_anchors["network_contacted"],
        False,
    )
    metrics_summary = spectron_freetype_autofit_metrics_anchors["summary"]
    check(
        "Spectron FreeType autofit metrics anchor count",
        metrics_summary["anchor_count"],
        13,
    )
    check(
        "Spectron FreeType autofit metrics target set size",
        metrics_summary["unique_target_count"],
        13,
    )
    check(
        "Spectron FreeType autofit metrics correction count",
        metrics_summary["correction_count"],
        2,
    )
    check(
        "Spectron FreeType autofit metrics new-label count",
        metrics_summary["new_label_count"],
        11,
    )
    check(
        "Spectron FreeType autofit metrics high-confidence count",
        metrics_summary["high_confidence_count"],
        13,
    )
    check(
        "Spectron FreeType autofit metrics normalized count",
        metrics_summary["normalized_shape_exact_count"],
        13,
    )
    check(
        "Spectron FreeType autofit metrics full metric count",
        metrics_summary["full_metric_exact_count"],
        11,
    )
    check(
        "Spectron FreeType autofit metrics register-detail count",
        metrics_summary["register_detail_only_count"],
        2,
    )
    check(
        "Spectron FreeType autofit metrics source default count",
        metrics_summary["source_default_name_count"],
        13,
    )
    check(
        "Spectron FreeType autofit metrics target default count",
        metrics_summary["target_default_name_count"],
        13,
    )
    metrics_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_autofit_metrics_anchors["anchors"]
    }
    metrics_expected = {
        "0x275a78": (
            "0x268608",
            "v18_af_cjk_hints_link_segments",
            "af_cjk_hints_link_segments",
            "src/autofit/afcjk.c",
            [],
            True,
            True,
            "v18_af_latin2_hints_link_segments",
        ),
        "0x275d6c": (
            "0x2688fc",
            "v18_af_cjk_hints_compute_edges",
            "af_cjk_hints_compute_edges",
            "src/autofit/afcjk.c",
            [],
            True,
            True,
            "v18_af_latin2_hints_compute_edges",
        ),
        "0x277840": (
            "0x26a3d0",
            "v18_af_latin_hints_compute_segments",
            "af_latin_hints_compute_segments",
            "src/autofit/aflatin.c",
            [],
            True,
            False,
            None,
        ),
        "0x277d74": (
            "0x26a904",
            "v18_af_latin_metrics_init_widths",
            "af_latin_metrics_init_widths",
            "src/autofit/aflatin.c",
            [],
            True,
            False,
            None,
        ),
        "0x27823c": (
            "0x26adcc",
            "v18_af_cjk_metrics_init",
            "af_cjk_metrics_init",
            "src/autofit/afcjk.c",
            [],
            True,
            False,
            None,
        ),
        "0x2782a4": (
            "0x26ae34",
            "v18_af_hint_normal_stem",
            "af_hint_normal_stem",
            "src/autofit/afcjk.c",
            [],
            True,
            False,
            None,
        ),
        "0x278608": (
            "0x26b198",
            "v18_af_latin2_metrics_init_widths",
            "af_latin2_metrics_init_widths",
            "src/autofit/aflatin2.c",
            [],
            True,
            False,
            None,
        ),
        "0x278ad0": (
            "0x26b660",
            "v18_af_latin2_metrics_init",
            "af_latin2_metrics_init",
            "src/autofit/aflatin2.c",
            ["register_detail_hash"],
            False,
            False,
            None,
        ),
        "0x278fbc": (
            "0x26bb4c",
            "v18_af_latin_metrics_init",
            "af_latin_metrics_init",
            "src/autofit/aflatin.c",
            ["register_detail_hash"],
            False,
            False,
            None,
        ),
        "0x2794b0": (
            "0x26c040",
            "v18_af_latin2_hints_compute_edges",
            "af_latin2_hints_compute_edges",
            "src/autofit/aflatin2.c",
            [],
            True,
            False,
            None,
        ),
        "0x279a8c": (
            "0x26c61c",
            "v18_af_latin_hints_compute_edges",
            "af_latin_hints_compute_edges",
            "src/autofit/aflatin.c",
            [],
            True,
            False,
            None,
        ),
        "0x279fd8": (
            "0x26cb68",
            "v18_af_glyph_hints_align_edge_points",
            "af_glyph_hints_align_edge_points",
            "src/autofit/afhints.c",
            [],
            True,
            False,
            None,
        ),
        "0x27a668": (
            "0x26d1f8",
            "v18_af_cjk_hints_apply",
            "af_cjk_hints_apply",
            "src/autofit/afcjk.c",
            [],
            True,
            False,
            None,
        ),
    }
    check(
        "Spectron FreeType autofit metrics target set",
        set(metrics_rows),
        set(metrics_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_source_name,
        expected_source_file,
        expected_differences,
        expected_full_match,
        expected_correction,
        expected_previous_name,
    ) in metrics_expected.items():
        row = metrics_rows[target_ea]
        check(
            "Spectron FreeType autofit metrics source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType autofit metrics name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType autofit metrics source name " + target_ea,
            row["source_name"],
            expected_source_name,
        )
        check(
            "Spectron FreeType autofit metrics source file " + target_ea,
            row["source_file"],
            expected_source_file,
        )
        check(
            "Spectron FreeType autofit metrics differences " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType autofit metrics normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType autofit metrics full match " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
        check(
            "Spectron FreeType autofit metrics correction " + target_ea,
            row.get("correction", False),
            expected_correction,
        )
        if expected_previous_name is not None:
            check(
                "Spectron FreeType autofit metrics previous name " + target_ea,
                row.get("previous_v311_name"),
                expected_previous_name,
            )
    check(
        "Spectron FreeType autofit metrics verified name count",
        spectron_checkpoint_v312["freetype_autofit_metrics_anchors"][
            "verified_name_count"
        ],
        13,
    )
    check(
        "Spectron FreeType autofit metrics reopen failures",
        spectron_checkpoint_v312["freetype_autofit_metrics_anchors"][
            "reopen_failure_count"
        ],
        0,
    )
    check(
        "Spectron v312 checkpoint artifact",
        spectron_checkpoint_v312["artifact"],
        "spectron_translation_checkpoint_20260828_v312",
    )
    check(
        "Spectron v312 checkpoint parent",
        spectron_checkpoint_v312["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v311",
    )
    check(
        "Spectron v312 checkpoint parent path",
        spectron_checkpoint_v312["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v311.json",
    )
    check(
        "Spectron v312 checkpoint database hash",
        spectron_checkpoint_v312["database"]["sha256"],
        "a0ab5988b005eed29537dfb65f53e0b511fb6b7e6d9985bf5cb39e2414e06402",
    )
    check(
        "Spectron v312 checkpoint database close-reopen",
        spectron_checkpoint_v312["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v312 checkpoint function count",
        spectron_checkpoint_v312["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v312 checkpoint default sub count",
        spectron_checkpoint_v312["database"]["default_sub_function_count"],
        392,
    )
    check(
        "Spectron bzip2 helpers artifact",
        spectron_bzip2_helpers_anchors["artifact"],
        "spectron_bzip2_helpers_manual_translation_anchors_20260828",
    )
    check(
        "Spectron bzip2 helpers network",
        spectron_bzip2_helpers_anchors["network_contacted"],
        False,
    )
    bzip2_summary = spectron_bzip2_helpers_anchors["summary"]
    check("Spectron bzip2 helpers anchor count", bzip2_summary["anchor_count"], 3)
    check(
        "Spectron bzip2 helpers target set size",
        bzip2_summary["unique_target_count"],
        3,
    )
    check(
        "Spectron bzip2 helpers high-confidence count",
        bzip2_summary["high_confidence_count"],
        3,
    )
    check(
        "Spectron bzip2 helpers normalized count",
        bzip2_summary["normalized_shape_exact_count"],
        3,
    )
    check(
        "Spectron bzip2 helpers full metric count",
        bzip2_summary["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron bzip2 helpers register-detail count",
        bzip2_summary["register_detail_only_count"],
        1,
    )
    check(
        "Spectron bzip2 helpers source default count",
        bzip2_summary["source_default_name_count"],
        3,
    )
    check(
        "Spectron bzip2 helpers target default count",
        bzip2_summary["target_default_name_count"],
        3,
    )
    bzip2_rows = {
        row["spectron_ea"]: row
        for row in spectron_bzip2_helpers_anchors["anchors"]
    }
    bzip2_expected = {
        "0x2807c0": (
            "0x273350",
            "v18_bzip2_default_bzfree",
            "default_bzfree",
            [],
            True,
        ),
        "0x2807d0": (
            "0x273360",
            "v18_bzip2_default_bzalloc",
            "default_bzalloc",
            [],
            True,
        ),
        "0x2807dc": (
            "0x27336c",
            "v18_bzip2_handle_compress",
            "handle_compress",
            ["register_detail_hash"],
            False,
        ),
    }
    check(
        "Spectron bzip2 helpers target set",
        set(bzip2_rows),
        set(bzip2_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_source_name,
        expected_differences,
        expected_full_match,
    ) in bzip2_expected.items():
        row = bzip2_rows[target_ea]
        check(
            "Spectron bzip2 helpers source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron bzip2 helpers name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron bzip2 helpers source name " + target_ea,
            row["source_name"],
            expected_source_name,
        )
        check(
            "Spectron bzip2 helpers metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron bzip2 helpers normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron bzip2 helpers full match " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron bzip2 helpers verified name count",
        spectron_checkpoint_v313["bzip2_helpers_anchors"][
            "verified_name_count"
        ],
        3,
    )
    check(
        "Spectron bzip2 helpers reopen failures",
        spectron_checkpoint_v313["bzip2_helpers_anchors"][
            "reopen_failure_count"
        ],
        0,
    )
    check(
        "Spectron v313 checkpoint artifact",
        spectron_checkpoint_v313["artifact"],
        "spectron_translation_checkpoint_20260828_v313",
    )
    check(
        "Spectron v313 checkpoint parent",
        spectron_checkpoint_v313["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v312",
    )
    check(
        "Spectron v313 checkpoint parent path",
        spectron_checkpoint_v313["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v312.json",
    )
    check(
        "Spectron v313 checkpoint database hash",
        spectron_checkpoint_v313["database"]["sha256"],
        "45f965884bffdc73e981d88d2965fac94f453640a29aa4d44acc7aca6b9e46e5",
    )
    check(
        "Spectron v313 checkpoint database close-reopen",
        spectron_checkpoint_v313["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v313 checkpoint function count",
        spectron_checkpoint_v313["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v313 checkpoint default sub count",
        spectron_checkpoint_v313["database"]["default_sub_function_count"],
        389,
    )
    check(
        "Spectron FreeType apply artifact",
        spectron_freetype_apply_anchors["artifact"],
        "spectron_freetype_apply_manual_translation_anchors_20260828",
    )
    check(
        "Spectron FreeType apply network",
        spectron_freetype_apply_anchors["network_contacted"],
        False,
    )
    freetype_apply_summary = spectron_freetype_apply_anchors["summary"]
    check(
        "Spectron FreeType apply anchor count",
        freetype_apply_summary["anchor_count"],
        2,
    )
    check(
        "Spectron FreeType apply target set size",
        freetype_apply_summary["unique_target_count"],
        2,
    )
    check(
        "Spectron FreeType apply high-confidence count",
        freetype_apply_summary["high_confidence_count"],
        2,
    )
    check(
        "Spectron FreeType apply normalized count",
        freetype_apply_summary["normalized_shape_exact_count"],
        2,
    )
    check(
        "Spectron FreeType apply full metric count",
        freetype_apply_summary["full_metric_exact_count"],
        2,
    )
    check(
        "Spectron FreeType apply register-detail count",
        freetype_apply_summary["register_detail_only_count"],
        0,
    )
    check(
        "Spectron FreeType apply source default count",
        freetype_apply_summary["source_default_name_count"],
        2,
    )
    check(
        "Spectron FreeType apply target default count",
        freetype_apply_summary["target_default_name_count"],
        2,
    )
    freetype_apply_rows = {
        row["spectron_ea"]: row
        for row in spectron_freetype_apply_anchors["anchors"]
    }
    freetype_apply_expected = {
        "0x27b3cc": (
            "0x26df5c",
            "v18_af_latin2_hints_apply",
            "af_latin2_hints_apply",
            "src/autofit/aflatin2.c",
            [],
            True,
        ),
        "0x27cc90": (
            "0x26f820",
            "v18_af_latin_hints_apply",
            "af_latin_hints_apply",
            "src/autofit/aflatin.c",
            [],
            True,
        ),
    }
    check(
        "Spectron FreeType apply target set",
        set(freetype_apply_rows),
        set(freetype_apply_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_source_name,
        expected_source_file,
        expected_differences,
        expected_full_match,
    ) in freetype_apply_expected.items():
        row = freetype_apply_rows[target_ea]
        check(
            "Spectron FreeType apply source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron FreeType apply name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron FreeType apply source name " + target_ea,
            row["source_name"],
            expected_source_name,
        )
        check(
            "Spectron FreeType apply source file " + target_ea,
            row["source_file"],
            expected_source_file,
        )
        check(
            "Spectron FreeType apply metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron FreeType apply normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron FreeType apply full match " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron FreeType apply verified name count",
        spectron_checkpoint_v314["freetype_apply_anchors"][
            "verified_name_count"
        ],
        2,
    )
    check(
        "Spectron FreeType apply reopen failures",
        spectron_checkpoint_v314["freetype_apply_anchors"][
            "reopen_failure_count"
        ],
        0,
    )
    check(
        "Spectron v314 checkpoint artifact",
        spectron_checkpoint_v314["artifact"],
        "spectron_translation_checkpoint_20260828_v314",
    )
    check(
        "Spectron v314 checkpoint parent",
        spectron_checkpoint_v314["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v313",
    )
    check(
        "Spectron v314 checkpoint parent path",
        spectron_checkpoint_v314["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v313.json",
    )
    check(
        "Spectron v314 checkpoint database hash",
        spectron_checkpoint_v314["database"]["sha256"],
        "338d9a62d76c6c2178acbd2a8ea50d811ff2959f25745e1aa5bdebea369bf279",
    )
    check(
        "Spectron v314 checkpoint database close-reopen",
        spectron_checkpoint_v314["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v314 checkpoint function count",
        spectron_checkpoint_v314["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v314 checkpoint default sub count",
        spectron_checkpoint_v314["database"]["default_sub_function_count"],
        387,
    )
    check(
        "Spectron jcmarker artifact",
        spectron_jcmarker_anchors["artifact"],
        "spectron_jpeg_marker_writer_manual_translation_anchors_20260828",
    )
    check(
        "Spectron jcmarker network",
        spectron_jcmarker_anchors["network_contacted"],
        False,
    )
    jcmarker_summary = spectron_jcmarker_anchors["summary"]
    check("Spectron jcmarker anchor count", jcmarker_summary["anchor_count"], 9)
    check(
        "Spectron jcmarker target set size",
        jcmarker_summary["unique_target_count"],
        9,
    )
    check(
        "Spectron jcmarker high-confidence count",
        jcmarker_summary["high_confidence_count"],
        9,
    )
    check(
        "Spectron jcmarker normalized count",
        jcmarker_summary["normalized_shape_exact_count"],
        9,
    )
    check(
        "Spectron jcmarker full metric count",
        jcmarker_summary["full_metric_exact_count"],
        7,
    )
    check(
        "Spectron jcmarker register-detail count",
        jcmarker_summary["register_detail_only_count"],
        2,
    )
    check(
        "Spectron jcmarker source default count",
        jcmarker_summary["source_default_name_count"],
        9,
    )
    check(
        "Spectron jcmarker target default count",
        jcmarker_summary["target_default_name_count"],
        9,
    )
    check(
        "Spectron jcmarker method count",
        jcmarker_summary["marker_method_count"],
        7,
    )
    check(
        "Spectron jcmarker internal emitter count",
        jcmarker_summary["internal_emitter_count"],
        2,
    )
    check(
        "Spectron jcmarker writer body count",
        jcmarker_summary["writer_body_count"],
        5,
    )
    jcmarker_rows = {
        row["spectron_ea"]: row
        for row in spectron_jcmarker_anchors["anchors"]
    }
    jcmarker_expected = {
        "0x2a5b30": (
            "0x2986c0",
            "v18_jpeg_write_marker_byte",
            "write_marker_byte",
            [],
            True,
        ),
        "0x2a5b9c": (
            "0x29872c",
            "v18_jpeg_write_file_trailer",
            "write_file_trailer",
            [],
            True,
        ),
        "0x2a5c60": (
            "0x2987f0",
            "v18_jpeg_write_marker_header",
            "write_marker_header",
            [],
            True,
        ),
        "0x2a5e10": (
            "0x2989a0",
            "v18_jpeg_emit_dht",
            "emit_dht",
            [],
            True,
        ),
        "0x2a6300": (
            "0x298e90",
            "v18_jpeg_write_file_header",
            "write_file_header",
            [],
            True,
        ),
        "0x2a6f38": (
            "0x299ac8",
            "v18_jpeg_emit_dqt",
            "emit_dqt",
            [],
            True,
        ),
        "0x2a72c4": (
            "0x299e54",
            "v18_jpeg_write_frame_header",
            "write_frame_header",
            ["register_detail_hash"],
            False,
        ),
        "0x2a7748": (
            "0x29a2d8",
            "v18_jpeg_write_tables_only",
            "write_tables_only",
            ["register_detail_hash"],
            False,
        ),
        "0x2a7eb8": (
            "0x29aa48",
            "v18_jpeg_write_scan_header",
            "write_scan_header",
            [],
            True,
        ),
    }
    check(
        "Spectron jcmarker target set",
        set(jcmarker_rows),
        set(jcmarker_expected),
    )
    for target_ea, (
        source_ea,
        expected_name,
        expected_source_name,
        expected_differences,
        expected_full_match,
    ) in jcmarker_expected.items():
        row = jcmarker_rows[target_ea]
        check(
            "Spectron jcmarker source " + target_ea,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron jcmarker name " + target_ea,
            row["proposed_name"],
            expected_name,
        )
        check(
            "Spectron jcmarker source name " + target_ea,
            row["source_name"],
            expected_source_name,
        )
        check(
            "Spectron jcmarker source file " + target_ea,
            row["source_file"],
            "jcmarker.c",
        )
        check(
            "Spectron jcmarker metrics " + target_ea,
            row["metric_differences"],
            expected_differences,
        )
        check(
            "Spectron jcmarker normalized " + target_ea,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron jcmarker full match " + target_ea,
            row["full_metric_equal"],
            expected_full_match,
        )
    check(
        "Spectron jcmarker verified name count",
        spectron_checkpoint_v315["jcmarker_anchors"]["verified_name_count"],
        9,
    )
    check(
        "Spectron jcmarker reopen failures",
        spectron_checkpoint_v315["jcmarker_anchors"]["reopen_failure_count"],
        0,
    )
    check(
        "Spectron v315 checkpoint artifact",
        spectron_checkpoint_v315["artifact"],
        "spectron_translation_checkpoint_20260828_v315",
    )
    check(
        "Spectron v315 checkpoint parent",
        spectron_checkpoint_v315["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v314",
    )
    check(
        "Spectron v315 checkpoint parent path",
        spectron_checkpoint_v315["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v314.json",
    )
    check(
        "Spectron v315 checkpoint database hash",
        spectron_checkpoint_v315["database"]["sha256"],
        "c0c270a006c67f5f7ee2bb5f097c6fa2639ebaaba859cfa6070b2ebfcb1dabe6",
    )
    check(
        "Spectron v315 checkpoint database close-reopen",
        spectron_checkpoint_v315["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v315 checkpoint function count",
        spectron_checkpoint_v315["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v315 checkpoint default sub count",
        spectron_checkpoint_v315["database"]["default_sub_function_count"],
        378,
    )
    check(
        "Spectron tt_size_reset artifact",
        spectron_freetype_tt_size_reset_anchor["artifact"],
        "spectron_freetype_tt_size_reset_manual_translation_anchor_20260828",
    )
    check(
        "Spectron tt_size_reset network",
        spectron_freetype_tt_size_reset_anchor["network_contacted"],
        False,
    )
    tt_size_reset_summary = spectron_freetype_tt_size_reset_anchor["summary"]
    check("Spectron tt_size_reset anchor count", tt_size_reset_summary["anchor_count"], 1)
    check(
        "Spectron tt_size_reset target set size",
        tt_size_reset_summary["unique_target_count"],
        1,
    )
    check(
        "Spectron tt_size_reset high-confidence count",
        tt_size_reset_summary["high_confidence_count"],
        1,
    )
    check(
        "Spectron tt_size_reset normalized count",
        tt_size_reset_summary["normalized_shape_exact_count"],
        1,
    )
    check(
        "Spectron tt_size_reset full metric count",
        tt_size_reset_summary["full_metric_exact_count"],
        1,
    )
    check(
        "Spectron tt_size_reset register-detail count",
        tt_size_reset_summary["register_detail_only_count"],
        0,
    )
    check(
        "Spectron tt_size_reset source default count",
        tt_size_reset_summary["source_default_name_count"],
        1,
    )
    check(
        "Spectron tt_size_reset target default count",
        tt_size_reset_summary["target_default_name_count"],
        1,
    )
    check(
        "Spectron tt_size_reset role count",
        tt_size_reset_summary["tt_size_reset_count"],
        1,
    )
    tt_size_reset_row = spectron_freetype_tt_size_reset_anchor["anchors"][0]
    check("Spectron tt_size_reset source", tt_size_reset_row["original_ea"], "0x25eaf8")
    check("Spectron tt_size_reset target", tt_size_reset_row["spectron_ea"], "0x26bf68")
    check(
        "Spectron tt_size_reset name",
        tt_size_reset_row["proposed_name"],
        "v18_tt_size_reset",
    )
    check(
        "Spectron tt_size_reset source role",
        tt_size_reset_row["source_name"],
        "tt_size_reset",
    )
    check(
        "Spectron tt_size_reset source file",
        tt_size_reset_row["source_file"],
        "src/truetype/ttobjs.c",
    )
    check(
        "Spectron tt_size_reset metrics",
        tt_size_reset_row["metric_differences"],
        [],
    )
    check(
        "Spectron tt_size_reset normalized",
        tt_size_reset_row["normalized_shape_equal"],
        True,
    )
    check(
        "Spectron tt_size_reset full match",
        tt_size_reset_row["full_metric_equal"],
        True,
    )
    check(
        "Spectron tt_size_reset source slot",
        spectron_freetype_tt_size_reset_anchor["context"]["source_size_reset_slot"],
        "0x36d3e0",
    )
    check(
        "Spectron tt_size_reset target slot",
        spectron_freetype_tt_size_reset_anchor["context"]["target_size_reset_slot"],
        "0x3801b0",
    )
    check(
        "Spectron tt_size_reset verified name count",
        spectron_checkpoint_v316["tt_size_reset_anchor"]["verified_name_count"],
        1,
    )
    check(
        "Spectron tt_size_reset reopen failures",
        spectron_checkpoint_v316["tt_size_reset_anchor"]["reopen_failure_count"],
        0,
    )
    check(
        "Spectron v316 checkpoint artifact",
        spectron_checkpoint_v316["artifact"],
        "spectron_translation_checkpoint_20260828_v316",
    )
    check(
        "Spectron v316 checkpoint parent",
        spectron_checkpoint_v316["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v315",
    )
    check(
        "Spectron v316 checkpoint parent path",
        spectron_checkpoint_v316["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v315.json",
    )
    check(
        "Spectron v316 checkpoint database hash",
        spectron_checkpoint_v316["database"]["sha256"],
        "ba52348b6c87fc441fe94c3c70fc96efd4a5e6be4a1c72ee1f3efc5269b42b5b",
    )
    check(
        "Spectron v316 checkpoint database close-reopen",
        spectron_checkpoint_v316["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v316 checkpoint function count",
        spectron_checkpoint_v316["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v316 checkpoint default sub count",
        spectron_checkpoint_v316["database"]["default_sub_function_count"],
        377,
    )
    check(
        "Spectron JPEG/GPC residual artifact",
        spectron_jpeg_gpc_residual_anchors["artifact"],
        "spectron_jpeg_gpc_residual_manual_translation_anchors_20260828",
    )
    check(
        "Spectron JPEG/GPC residual network",
        spectron_jpeg_gpc_residual_anchors["network_contacted"],
        False,
    )
    jpeg_gpc_summary = spectron_jpeg_gpc_residual_anchors["summary"]
    check("Spectron JPEG/GPC residual anchor count", jpeg_gpc_summary["anchor_count"], 4)
    check(
        "Spectron JPEG/GPC residual target set size",
        jpeg_gpc_summary["unique_target_count"],
        4,
    )
    check(
        "Spectron JPEG/GPC residual high-confidence count",
        jpeg_gpc_summary["high_confidence_count"],
        4,
    )
    check(
        "Spectron JPEG/GPC residual normalized count",
        jpeg_gpc_summary["normalized_shape_exact_count"],
        4,
    )
    check(
        "Spectron JPEG/GPC residual full metric count",
        jpeg_gpc_summary["full_metric_exact_count"],
        3,
    )
    check(
        "Spectron JPEG/GPC residual register-detail count",
        jpeg_gpc_summary["register_detail_only_count"],
        1,
    )
    check(
        "Spectron JPEG/GPC residual source default count",
        jpeg_gpc_summary["source_default_name_count"],
        4,
    )
    check(
        "Spectron JPEG/GPC residual target default count",
        jpeg_gpc_summary["target_default_name_count"],
        4,
    )
    check(
        "Spectron JPEG/GPC residual JPEG count",
        jpeg_gpc_summary["jpeg_marker_reader_count"],
        1,
    )
    check(
        "Spectron JPEG/GPC residual scanbeam count",
        jpeg_gpc_summary["gpc_scanbeam_tree_count"],
        2,
    )
    check(
        "Spectron JPEG/GPC residual allocation diagnostic count",
        jpeg_gpc_summary["gpc_allocation_diagnostic_count"],
        1,
    )
    jpeg_gpc_expected = [
        ("0xe0454", "0xdfae4", "v18_jpeg_examine_app14", []),
        ("0x152200", "0x155028", "v18_gpc_free_sbtree", []),
        ("0x152898", "0x1556c0", "v18_gpc_build_sbt", []),
        (
            "0xe01a0",
            "0xdf830",
            "v18_gpc_tristrip_node_malloc_failure",
            ["register_detail_hash"],
        ),
    ]
    jpeg_gpc_rows = spectron_jpeg_gpc_residual_anchors["anchors"]
    check(
        "Spectron JPEG/GPC residual row count",
        len(jpeg_gpc_rows),
        len(jpeg_gpc_expected),
    )
    for index, (source_ea, target_ea, proposed_name, differences) in enumerate(
        jpeg_gpc_expected
    ):
        row = jpeg_gpc_rows[index]
        check(
            "Spectron JPEG/GPC residual source %d" % index,
            row["original_ea"],
            source_ea,
        )
        check(
            "Spectron JPEG/GPC residual target %d" % index,
            row["spectron_ea"],
            target_ea,
        )
        check(
            "Spectron JPEG/GPC residual name %d" % index,
            row["proposed_name"],
            proposed_name,
        )
        check(
            "Spectron JPEG/GPC residual normalized %d" % index,
            row["normalized_shape_equal"],
            True,
        )
        check(
            "Spectron JPEG/GPC residual metric differences %d" % index,
            row["metric_differences"],
            differences,
        )
    check(
        "Spectron JPEG/GPC residual GPC displacement",
        spectron_jpeg_gpc_residual_anchors["context"]["gpc_address_displacement"],
        "0x2e28",
    )
    check(
        "Spectron v317 checkpoint artifact",
        spectron_checkpoint_v317["artifact"],
        "spectron_translation_checkpoint_20260828_v317",
    )
    check(
        "Spectron v317 checkpoint parent",
        spectron_checkpoint_v317["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v316",
    )
    check(
        "Spectron v317 checkpoint parent path",
        spectron_checkpoint_v317["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v316.json",
    )
    check(
        "Spectron v317 checkpoint database hash",
        spectron_checkpoint_v317["database"]["sha256"],
        "0d39dce494c293094f370237decece95f27b176d3e7f477be8f50b7ed402575c",
    )
    check(
        "Spectron v317 checkpoint database close-reopen",
        spectron_checkpoint_v317["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v317 checkpoint function count",
        spectron_checkpoint_v317["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v317 checkpoint default sub count",
        spectron_checkpoint_v317["database"]["default_sub_function_count"],
        373,
    )
    check(
        "Spectron v317 anchor count",
        spectron_checkpoint_v317["jpeg_gpc_residual_anchors"]["anchor_count"],
        4,
    )
    check(
        "Spectron v317 verified name count",
        spectron_checkpoint_v317["jpeg_gpc_residual_anchors"]["verified_name_count"],
        4,
    )
    check(
        "Spectron v317 reopen failures",
        spectron_checkpoint_v317["jpeg_gpc_residual_anchors"]["reopen_failure_count"],
        0,
    )
    check(
        "Spectron residual target-only artifact",
        spectron_residual_target_only_labels["artifact"],
        "spectron_residual_target_only_labels_20260828",
    )
    check(
        "Spectron residual target-only network",
        spectron_residual_target_only_labels["network_contacted"],
        False,
    )
    residual_label_summary = spectron_residual_target_only_labels["summary"]
    check("Spectron residual target-only label count", residual_label_summary["label_count"], 373)
    check(
        "Spectron residual target-only high-confidence count",
        residual_label_summary["high_confidence_count"],
        373,
    )
    check(
        "Spectron residual target-only default count",
        residual_label_summary["target_default_name_count"],
        373,
    )
    check(
        "Spectron residual target-only startup count",
        residual_label_summary["startup_array_count"],
        230,
    )
    check(
        "Spectron residual target-only fini count",
        residual_label_summary["fini_array_entry_count"],
        117,
    )
    check(
        "Spectron residual target-only init count",
        residual_label_summary["init_array_entry_count"],
        113,
    )
    check(
        "Spectron residual target-only TString count",
        residual_label_summary["tstring_clear_wrapper_count"],
        99,
    )
    check(
        "Spectron residual target-only CanTfaz6bZ count",
        residual_label_summary["can_tfaz6bz_clear_wrapper_count"],
        35,
    )
    check(
        "Spectron residual target-only vuuHgangcF count",
        residual_label_summary["vuu_hgangcf_destructor_thunk_count"],
        6,
    )
    check(
        "Spectron residual target-only G0gxgajWBw count",
        residual_label_summary["g0gxgajwbw_destructor_thunk_count"],
        2,
    )
    check(
        "Spectron residual target-only resolver count",
        residual_label_summary["aarch64_plt_resolver_count"],
        1,
    )
    residual_labels = spectron_residual_target_only_labels["labels"]
    check(
        "Spectron residual target-only unique targets",
        len({label["target_ea"] for label in residual_labels}),
        373,
    )
    check(
        "Spectron residual target-only all target-only",
        residual_label_summary["target_only_count"],
        373,
    )
    residual_label_samples = {
        "0xd1500": "spectron_aarch64_plt_resolver",
        "0xdfb64": "spectron_fini_array_entry_0xdfb64",
        "0xe0480": "spectron_init_array_entry_0xe0480",
        "0xe431c": "spectron_tstring_clear_wrapper_0xe431c",
        "0x18f7d4": "spectron_can_tfaz6bz_clear_wrapper_0x18f7d4",
        "0xe36fc": "spectron_vuu_hgangcf_destructor_thunk_0xe36fc",
        "0x216058": "spectron_g0gxgajwbw_destructor_thunk_0x216058",
    }
    residual_labels_by_ea = {label["target_ea"]: label for label in residual_labels}
    for target_ea, proposed_name in residual_label_samples.items():
        check(
            "Spectron residual target-only sample " + target_ea,
            residual_labels_by_ea[target_ea]["proposed_name"],
            proposed_name,
        )
    check(
        "Spectron v318 checkpoint artifact",
        spectron_checkpoint_v318["artifact"],
        "spectron_translation_checkpoint_20260828_v318",
    )
    check(
        "Spectron v318 checkpoint parent",
        spectron_checkpoint_v318["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v317",
    )
    check(
        "Spectron v318 checkpoint parent path",
        spectron_checkpoint_v318["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v317.json",
    )
    check(
        "Spectron v318 checkpoint database hash",
        spectron_checkpoint_v318["database"]["sha256"],
        "006016f0d13a7a52e24fd18e3ec50443c69525cccfaad834b2b00d9b6d7fd58b",
    )
    check(
        "Spectron v318 checkpoint database close-reopen",
        spectron_checkpoint_v318["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v318 checkpoint function count",
        spectron_checkpoint_v318["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v318 checkpoint default sub count",
        spectron_checkpoint_v318["database"]["default_sub_function_count"],
        0,
    )
    check(
        "Spectron v318 label count",
        spectron_checkpoint_v318["residual_target_only_labels"]["anchor_count"],
        373,
    )
    check(
        "Spectron v318 verified label count",
        spectron_checkpoint_v318["residual_target_only_labels"]["verified_name_count"],
        373,
    )
    check(
        "Spectron v318 reopen failures",
        spectron_checkpoint_v318["residual_target_only_labels"]["reopen_failure_count"],
        0,
    )
    coverage_v318_origins = spectron_name_coverage_v318["name_origins"]
    coverage_v319_origins = spectron_name_coverage_v319["name_origins"]
    check(
        "Spectron v318 name audit artifact",
        spectron_name_coverage_v318["artifact"],
        "spectron_name_coverage_audit",
    )
    check(
        "Spectron v318 name audit input hash",
        spectron_name_coverage_v318["input_sha256"],
        "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    check(
        "Spectron v318 name audit function count",
        spectron_name_coverage_v318["function_count"],
        11695,
    )
    check(
        "Spectron v318 name audit default count",
        spectron_name_coverage_v318["default_name_count"],
        9,
    )
    check(
        "Spectron v318 name audit origin counts",
        coverage_v318_origins,
        {
            "ida_default": 9,
            "ida_named_or_other": 4053,
            "target_jni_export": 7,
            "target_named_export": 1001,
            "target_only_descriptive": 408,
            "translated_v18_alias": 6217,
        },
    )
    check(
        "Spectron v319 name audit function count",
        spectron_name_coverage_v319["function_count"],
        11695,
    )
    check(
        "Spectron v319 name audit default count",
        spectron_name_coverage_v319["default_name_count"],
        0,
    )
    check(
        "Spectron v319 name audit origin counts",
        coverage_v319_origins,
        {
            "ida_named_or_other": 4053,
            "target_jni_export": 7,
            "target_named_export": 1001,
            "target_only_descriptive": 417,
            "translated_v18_alias": 6217,
        },
    )
    check(
        "Spectron nullsub label artifact",
        spectron_nullsub_labels["artifact"],
        "spectron_nullsub_target_only_labels_20260828",
    )
    check(
        "Spectron nullsub label network marker",
        spectron_nullsub_labels["network_contacted"],
        False,
    )
    check(
        "Spectron nullsub label count",
        spectron_nullsub_labels["summary"]["label_count"],
        9,
    )
    check(
        "Spectron nullsub label high-confidence count",
        spectron_nullsub_labels["summary"]["high_confidence_count"],
        9,
    )
    check(
        "Spectron nullsub target-only count",
        spectron_nullsub_labels["summary"]["target_only_count"],
        9,
    )
    nullsub_labels_by_ea = {
        label["target_ea"]: label for label in spectron_nullsub_labels["labels"]
    }
    check(
        "Spectron nullsub label unique target count",
        len(nullsub_labels_by_ea),
        9,
    )
    for target_ea, label in nullsub_labels_by_ea.items():
        check(
            "Spectron nullsub label name " + target_ea,
            label["proposed_name"],
            "spectron_nullsub_stub_" + target_ea,
        )
        check(
            "Spectron nullsub label body " + target_ea,
            label["target_metrics"],
            {
                "bytes_hex": "c0035fd6",
                "first_instruction": "RET",
                "size": 4,
                "xrefs_to": label["target_metrics"]["xrefs_to"],
            },
        )
    check(
        "Spectron v319 checkpoint artifact",
        spectron_checkpoint_v319["artifact"],
        "spectron_translation_checkpoint_20260828_v319",
    )
    check(
        "Spectron v319 checkpoint parent",
        spectron_checkpoint_v319["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v318",
    )
    check(
        "Spectron v319 checkpoint parent path",
        spectron_checkpoint_v319["parent_checkpoint"]["path"],
        "artifacts/spectron_translation_checkpoint_20260828_v318.json",
    )
    check(
        "Spectron v319 checkpoint database hash",
        spectron_checkpoint_v319["database"]["sha256"],
        "ca68997409b58ee6342a5288319c4d3b834fde1a7d526aa62db962c46164defd",
    )
    check(
        "Spectron v319 checkpoint database close-reopen",
        spectron_checkpoint_v319["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v319 checkpoint function count",
        spectron_checkpoint_v319["database"]["function_count"],
        11695,
    )
    check(
        "Spectron v319 checkpoint default sub count",
        spectron_checkpoint_v319["database"]["default_sub_function_count"],
        0,
    )
    check(
        "Spectron v319 nullsub label count",
        spectron_checkpoint_v319["nullsub_target_only_labels"]["anchor_count"],
        9,
    )
    check(
        "Spectron v319 nullsub verified count",
        spectron_checkpoint_v319["nullsub_target_only_labels"]["verified_name_count"],
        9,
    )
    check(
        "Spectron v319 nullsub reopen failures",
        spectron_checkpoint_v319["nullsub_target_only_labels"]["reopen_failure_count"],
        0,
    )
    coverage_v320_origins = spectron_name_coverage_v320["name_origins"]
    check(
        "Spectron v320 dynamic application artifact",
        spectron_dynamic_function_application["artifact"],
        "spectron_dynamic_function_application",
    )
    check(
        "Spectron v320 dynamic application network",
        spectron_dynamic_function_application["network_contacted"],
        False,
    )
    check(
        "Spectron v320 dynamic application mode",
        spectron_dynamic_function_application["apply"],
        True,
    )
    check(
        "Spectron v320 dynamic application rows",
        spectron_dynamic_function_application["row_count"],
        12,
    )
    check(
        "Spectron v320 dynamic application materialized",
        spectron_dynamic_function_application["materialized_count"],
        12,
    )
    check(
        "Spectron v320 dynamic application failures",
        spectron_dynamic_function_application["failure_count"],
        0,
    )
    check(
        "Spectron v320 dynamic application saved",
        spectron_dynamic_function_application["saved"],
        True,
    )
    check(
        "Spectron v320 dynamic boundary artifact",
        spectron_dynamic_boundaries["artifact"],
        "spectron_dynamic_symbol_boundary_audit",
    )
    check(
        "Spectron v320 dynamic boundary network",
        spectron_dynamic_boundaries["network_contacted"],
        False,
    )
    check(
        "Spectron v320 dynamic boundary input hash",
        spectron_dynamic_boundaries["input_sha256"],
        "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    check(
        "Spectron v320 dynamic boundary defined functions",
        spectron_dynamic_boundaries["defined_function_symbol_count"],
        5782,
    )
    check(
        "Spectron v320 dynamic boundary exact starts",
        spectron_dynamic_boundaries["ida_exact_start_count"],
        5782,
    )
    check(
        "Spectron v320 dynamic boundary missing starts",
        spectron_dynamic_boundaries["ida_missing_exact_start_count"],
        0,
    )
    check(
        "Spectron v320 dynamic boundary row count",
        len(spectron_dynamic_boundaries["rows"]),
        5782,
    )
    check(
        "Spectron v320 dynamic symbol coverage artifact",
        spectron_dynamic_symbol_coverage["artifact"],
        "spectron_dynamic_symbol_coverage_audit_20260828",
    )
    check(
        "Spectron v320 dynamic symbol coverage network",
        spectron_dynamic_symbol_coverage["network_contacted"],
        False,
    )
    check(
        "Spectron v320 dynamic symbol coverage input hash",
        spectron_dynamic_symbol_coverage["input_sha256"],
        "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    dynamic_symbol_coverage_summary = spectron_dynamic_symbol_coverage["summary"]
    check(
        "Spectron v320 dynamic symbol coverage named rows",
        dynamic_symbol_coverage_summary["named_dynamic_symbol_count"],
        6770,
    )
    check(
        "Spectron v320 dynamic symbol coverage defined rows",
        dynamic_symbol_coverage_summary["defined_named_symbol_count"],
        6600,
    )
    check(
        "Spectron v320 dynamic symbol coverage locations",
        dynamic_symbol_coverage_summary["location_counts"],
        {
            "ida_data_item": 482,
            "ida_function_exact": 5782,
            "ida_noncode_item": 336,
            "undefined_or_zero_value": 170,
        },
    )
    check(
        "Spectron v320 dynamic symbol coverage name matches",
        dynamic_symbol_coverage_summary["name_match_counts"],
        {
            "item_name_match": 1901,
            "item_name_mismatch": 4869,
            "value_name_match": 1901,
            "value_name_mismatch": 4869,
        },
    )
    check(
        "Spectron v320 dynamic symbol coverage statuses",
        dynamic_symbol_coverage_summary["status_counts"],
        {
            "exact_retained_dynamic_name": 1901,
            "linker_boundary_alias_mismatch": 7,
            "other_retained_target_name": 151,
            "source_backed_v18_alias": 4541,
            "undefined_import_with_plt_stub": 169,
            "undefined_no_target_address": 1,
        },
    )
    check(
        "Spectron v320 name audit input hash",
        spectron_name_coverage_v320["input_sha256"],
        "f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219",
    )
    check(
        "Spectron v320 name audit function count",
        spectron_name_coverage_v320["function_count"],
        11707,
    )
    check(
        "Spectron v320 name audit default count",
        spectron_name_coverage_v320["default_name_count"],
        0,
    )
    check(
        "Spectron v320 name audit origin counts",
        coverage_v320_origins,
        {
            "ida_named_or_other": 4053,
            "target_jni_export": 7,
            "target_named_export": 1013,
            "target_only_descriptive": 417,
            "translated_v18_alias": 6217,
        },
    )
    check(
        "Spectron v320 symbol inventory artifact",
        spectron_symbol_inventory_v320["artifact"],
        "spectron_symbol_translation_inventory_20260828",
    )
    check(
        "Spectron v320 symbol inventory network",
        spectron_symbol_inventory_v320["network_contacted"],
        False,
    )
    inventory_v320_summary = spectron_symbol_inventory_v320["summary"]
    check(
        "Spectron v320 symbol inventory named rows",
        inventory_v320_summary["named_dynamic_symbol_count"],
        6770,
    )
    check(
        "Spectron v320 symbol inventory defined named rows",
        inventory_v320_summary["defined_named_symbol_count"],
        6600,
    )
    check(
        "Spectron v320 symbol inventory defined functions",
        inventory_v320_summary["section_defined_function_count"],
        5782,
    )
    check(
        "Spectron v320 symbol inventory matched rows",
        inventory_v320_summary["ida_function_match_count"],
        5782,
    )
    check(
        "Spectron v320 symbol inventory status counts",
        inventory_v320_summary["translation_status_counts"],
        {
            "ida_named_or_other": 74,
            "no_ida_function_at_symbol_value": 988,
            "retained_target_name": 1167,
            "source_backed_v18_alias": 4541,
        },
    )
    check(
        "Spectron v320 checkpoint artifact",
        spectron_checkpoint_v320["artifact"],
        "spectron_translation_checkpoint_20260828_v320",
    )
    check(
        "Spectron v320 checkpoint parent",
        spectron_checkpoint_v320["parent_checkpoint"]["artifact"],
        "spectron_translation_checkpoint_20260828_v319",
    )
    check(
        "Spectron v320 checkpoint database hash",
        spectron_checkpoint_v320["database"]["sha256"],
        "17015ba3140200199269ca94675e043e1e87cbefcdfa473680062a55ac96a0d6",
    )
    check(
        "Spectron v320 checkpoint database close-reopen",
        spectron_checkpoint_v320["database"]["close_reopen_verified"],
        True,
    )
    check(
        "Spectron v320 checkpoint function count",
        spectron_checkpoint_v320["database"]["function_count"],
        11707,
    )
    check(
        "Spectron v320 checkpoint default names",
        spectron_checkpoint_v320["database"]["default_name_count"],
        0,
    )
    check(
        "Spectron v320 checkpoint materialized boundaries",
        spectron_checkpoint_v320["dynamic_function_boundary_repair"]["materialized_count"],
        12,
    )
    check(
        "Spectron v320 checkpoint exact starts",
        spectron_checkpoint_v320["dynamic_function_boundary_repair"]["ida_exact_start_count"],
        5782,
    )
    check(
        "Spectron v320 checkpoint missing starts",
        spectron_checkpoint_v320["dynamic_function_boundary_repair"]["ida_missing_exact_start_count"],
        0,
    )
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
        spectron_symbol_audit,
        spectron_connector_endpoints,
        spectron_loopback_patch_audit,
        spectron_arm64_loopback_loading,
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
        spectron_connection_helper_anchors,
        spectron_client_state_helper_anchors,
        spectron_connection_state_anchors,
        spectron_http_request_anchors,
        spectron_socket_state_anchors,
        spectron_socket_behavior,
        spectron_http_request_state_anchors,
        spectron_npc_helper_anchors,
        spectron_html_atom_anchors,
        spectron_html_page_anchors,
        spectron_gui_text_list_anchors,
        spectron_gui_text_list_entry_anchors,
        spectron_encryption_graalvar_anchors,
        spectron_compact_residual_anchors,
        spectron_t2d_matrix_manager_anchors,
        spectron_mrandom_anchors,
        spectron_tstringlist_residual_anchors,
        spectron_server_object_lifecycle_anchors,
        spectron_gui_ml_text_residual_anchors,
        spectron_gui_drawing_showimg_property_anchors,
        spectron_gui_browser_property_anchors,
        spectron_gui_context_menu_property_anchors,
        spectron_gui_array_popup_residual_anchors,
        spectron_gui_popup_rows_anchor,
        spectron_gui_progress_getter_anchor,
        spectron_gui_text_list_selection_script_anchors,
        spectron_mrandom_property_residual_anchors,
        spectron_gui_drawing_panel_script_anchors,
        spectron_tclient_script_property_anchors,
        spectron_file_cache_property_anchors,
        spectron_tclient_handler_anchors,
        spectron_target_only_labels,
        spectron_tclient_playerhurt_anchor,
        spectron_gsfunctions_property_anchors,
        spectron_time_files_input_anchors,
        spectron_level_object_property_anchors,
        spectron_gani_property_anchors,
        spectron_options_property_anchors,
        spectron_particle_emitter_property_anchors,
        spectron_particle_emitter_script_anchors,
        spectron_world_object_property_anchors,
        spectron_player_translation_property_anchors,
        spectron_server_npc_property_anchors,
        spectron_server_npc_script_anchors,
        spectron_server_npc_showimg_anchors,
        spectron_tiles_layer_property_anchors,
        spectron_player_property_anchors,
        spectron_gani_property_residual_anchors,
        spectron_drawing_panel_property_residual_anchors,
        spectron_tplayer_findweapon_anchors,
        spectron_tgui_animation_property_residual_anchors,
        spectron_gui_bitmap_property_anchors,
        spectron_gui_bitmap_button_property_anchors,
        spectron_guicontrol_property_tail_anchors,
        spectron_guigraalctrl_isrendering_anchors,
        spectron_guiscrollctrl_property_anchors,
        spectron_guistretchctrl_property_anchors,
        spectron_guitexteditctrl_property_anchors,
        spectron_tgraalvar_property_residual_anchors,
        spectron_tbodypanel_bodycacheperplayer_anchor,
        spectron_residual_property_anchors,
        spectron_player_helper_anchors,
        spectron_input_window_anchors,
        spectron_visual_helper_anchors,
        spectron_script_runtime_anchors,
        spectron_core_helper_anchors,
        spectron_render_gui_anchors,
        spectron_json_folder_anchors,
        spectron_resource_object_anchors,
        spectron_script_machine_anchors,
        spectron_script_space_anchors,
        spectron_script_execution_anchors,
        spectron_script_dispatch_anchors,
        spectron_script_scheduler_anchors,
        spectron_event_object_anchors,
        spectron_script_action_anchors,
        spectron_stack_entry_anchors,
        spectron_machine_helper_anchors,
        spectron_array_mutation_anchors,
        spectron_string_search_anchors,
        spectron_string_helper_anchors,
        spectron_variable_construction_anchors,
        spectron_script_object_anchors,
        spectron_script_state_anchors,
        spectron_execution_dispatch_anchors,
        spectron_tokenizer_anchors,
        spectron_script_executor_anchors,
        spectron_script_property_anchors,
        spectron_script_universe_anchors,
        spectron_static_json_tiles_anchors,
        spectron_tiles_update_anchors,
        spectron_particle_anchors,
        spectron_showimg_anchors,
        spectron_showimg_residual_anchors,
        spectron_server_object_scalar_anchors,
        spectron_compression_anchors,
        spectron_files_anchors,
        spectron_encryption_anchors,
        spectron_tlist_anchors,
        spectron_sounds_anchors,
        spectron_sounds_tail_anchors,
        spectron_hash_container_anchors,
        spectron_hash_lifecycle_anchors,
        spectron_tstring_anchors,
        spectron_tstring_clear_anchors,
        spectron_static_clear_anchors,
        spectron_static_callback_role_correction,
        spectron_http_request_receive_anchors,
        spectron_server_list_connection_anchors,
        spectron_server_list_state_anchors,
        spectron_http_request_cleanup_anchors,
        spectron_tsocket_residual_anchors,
        spectron_game_environment_anchors,
        spectron_client_environment_graphics_anchors,
        spectron_client_environment_static_clear_anchors,
        spectron_client_environment_restart_state_anchors,
        spectron_particle_emitter_anchors,
        spectron_particle_emitter_script_vars_anchors,
        spectron_resource_link_lists_anchors,
        spectron_clear_cur_anis_anchors,
        spectron_options_window_position_anchors,
        spectron_displayed_gif_anchors,
        spectron_gui_button_types_anchors,
        spectron_gui_alignment_tables_anchors,
        spectron_gui_stretch_modes_anchors,
        spectron_tgui_render_colors_anchors,
        spectron_thtml_definitions_defaults_anchors,
        spectron_tclient_static_strings_anchors,
        spectron_server_animation_anchors,
        spectron_player_lifecycle_anchors,
        spectron_player_emoticon_anchors,
        spectron_player_level_entry_anchors,
        spectron_player_side_level_anchors,
        spectron_player_map_position_anchors,
        spectron_player_link_traversal_anchors,
        spectron_player_weapon_state_anchors,
        spectron_player_visual_setter_anchors,
        spectron_player_movement_anchors,
        spectron_server_player_state_anchors,
        spectron_server_npc_state_anchors,
        spectron_npc_accessor_anchors,
        spectron_npc_destructor_anchors,
        spectron_server_level_property_anchors,
        spectron_server_level_interaction_anchors,
        spectron_server_level_lifecycle_anchors,
        spectron_server_level_side_helpers_anchors,
        spectron_server_level_storage_anchors,
        spectron_hidden_testnpc_anchors,
        spectron_level_map_lookup_anchors,
        spectron_gani_constructor_anchors,
        spectron_gani_helper_anchors,
        spectron_gani_runtime_anchors,
        spectron_gani_render_anchors,
        spectron_gani_frame_playback_anchors,
        spectron_gani_lifecycle_anchors,
        spectron_tplayer_core_anchors,
        spectron_resource_parser_anchors,
        spectron_static_utility_anchors,
        spectron_font_bitmap_anchors,
        spectron_mng_animation_anchors,
        spectron_script_machine_tail_anchors,
        spectron_script_stream_profile_anchors,
        spectron_ani_lexer_anchors,
        spectron_number_array_string_anchors,
        spectron_client_environment_clock_anchors,
        spectron_client_var_core_anchors,
        spectron_tstringlist_comma_anchors,
        spectron_tstringlist_extended_anchors,
        spectron_hash_family_anchors,
        spectron_options_anchors,
        spectron_texture_anchors,
        spectron_drawing_panel_texture_anchors,
        spectron_draw_texture_anchors,
        spectron_bitmap_array_holder_anchors,
        spectron_color_manager_anchors,
        spectron_font_runtime_anchors,
        spectron_window_input_anchors,
        spectron_drawing_panel_residual_anchors,
        spectron_image_html_anchors,
        spectron_panel_bitmap_anchors,
        spectron_gif_decoder_anchors,
        spectron_window_residual_anchors,
        spectron_sound_runtime_anchors,
        spectron_sound_java_d1_anchors,
        spectron_pixelbuffer_residual_anchors,
        spectron_pixelbuffer_bitmap_lifecycle_anchors,
        spectron_animation_palette_residual_anchors,
        spectron_panel_virtual_renderer_residual_anchors,
        spectron_dummy_panel_residual_anchors,
        spectron_screen_panel_renderer_residual_anchors,
        spectron_screen_panel_window_gles_residual_anchors,
        spectron_font_manager_font_residual_anchors,
        spectron_font_options_font_data_residual_anchors,
        spectron_gui_control_profile_accessor_anchors,
        spectron_gui_control_profile_destructor_anchors,
        spectron_guicontrol_property_residual_anchors,
        spectron_guicontrol_virtual_residual_anchors,
        spectron_guicontrol_event_sizing_residual_anchors,
        spectron_guicontrol_style_bounds_residual_anchors,
        spectron_guicontrol_event_dispatch_residual_anchors,
        spectron_guicontrol_initialization_residual_anchors,
        spectron_guicontrol_create_residual_anchors,
        spectron_tsocket_accessor_residual_anchors,
        spectron_tsocket_ssl_residual_anchors,
        spectron_tsocket_receive_residual_anchors,
        spectron_tsocket_lifecycle_residual_anchors,
        spectron_tsocket_host_residual_anchors,
        spectron_tsocket_properties_residual_anchors,
        spectron_socket_cache_residual_anchors,
        spectron_url_cache_residual_anchors,
        spectron_gui_android_anchors,
        spectron_android_bridge_target_only_labels,
        spectron_checkpoint_v263_corrected,
        spectron_checkpoint_v264_corrected,
        spectron_android_legacy_anchors,
        spectron_android_security_target_only_labels,
        spectron_checkpoint_v265,
        spectron_checkpoint_v266,
        spectron_android_security_target_only_labels_corrected,
        spectron_android_package_identity_labels,
        spectron_checkpoint_v267,
        spectron_checkpoint_v268,
        spectron_tgraalvar_script_runtime_anchors,
        spectron_tgraalvar_target_only_labels,
        spectron_checkpoint_v269,
        spectron_script_table_surface_anchors,
        spectron_checkpoint_v270,
        spectron_runtime_callback_residual_anchors,
        spectron_tplayer_quattro_zoom_property_labels,
        spectron_checkpoint_v271,
        spectron_zlib_inflate_fast_anchor,
        spectron_checkpoint_v272,
        spectron_jpeg_io_anchors,
        spectron_checkpoint_v273,
        spectron_jdinput_controller_anchors,
        spectron_checkpoint_v274,
        spectron_jdmarker_anchors,
        spectron_checkpoint_v275,
        spectron_jdmaster_jdmerge_anchors,
        spectron_checkpoint_v276,
        spectron_jdphuff_anchors,
        spectron_checkpoint_v277,
        spectron_jdpostct_anchors,
        spectron_checkpoint_v278,
        spectron_jdsample_anchors,
        spectron_checkpoint_v279,
        spectron_jerror_anchors,
        spectron_checkpoint_v280,
        spectron_jmemmgr_anchors,
        spectron_checkpoint_v281,
        spectron_jquant1_anchors,
        spectron_checkpoint_v282,
        spectron_jquant2_anchors,
        spectron_checkpoint_v283,
        spectron_jccolor_anchors,
        spectron_checkpoint_v289,
        spectron_jccoefct_anchors,
        spectron_checkpoint_v290,
        spectron_jcdctmgr_anchors,
        spectron_checkpoint_v291,
        spectron_jchuff_anchors,
        spectron_checkpoint_v292,
        spectron_jcphuff_encoder_anchors,
        spectron_jcmainct_jcmaster_anchors,
        spectron_checkpoint_v293,
        spectron_checkpoint_v294,
        spectron_jcprepct_jcsample_anchors,
        spectron_checkpoint_v295,
        spectron_gif_lzw_line_decoder_anchors,
        spectron_checkpoint_v296,
        spectron_fdct_literal_pool_repair,
        spectron_checkpoint_v297,
        spectron_freetype_base_cleanup_anchors,
        spectron_checkpoint_v298,
        spectron_freetype_sfnt_service_anchors,
        spectron_checkpoint_v299,
        spectron_freetype_sfnt_interface_anchors,
        spectron_checkpoint_v300,
        spectron_freetype_smooth_anchors,
        spectron_checkpoint_v301,
        spectron_freetype_gray_internal_anchors,
        spectron_checkpoint_v302,
        spectron_freetype_tt_interpreter_anchors,
        spectron_checkpoint_v303,
        spectron_freetype_tt_runtime_anchors,
        spectron_checkpoint_v304,
        spectron_freetype_tt_rounding_anchors,
        spectron_checkpoint_v305,
        spectron_freetype_tt_opcode_state_anchors,
        spectron_checkpoint_v306,
        spectron_freetype_tt_opcode_core_anchors,
        spectron_checkpoint_v307,
        spectron_freetype_tt_runtime_tail_anchors,
        spectron_freetype_tt_projection_correction,
        spectron_checkpoint_v308,
        spectron_freetype_tt_glyph_loader_anchors,
        spectron_checkpoint_v309,
        spectron_freetype_autofit_anchors,
        spectron_checkpoint_v310,
        spectron_freetype_autofit_followup_anchors,
        spectron_checkpoint_v311,
        spectron_freetype_autofit_metrics_anchors,
        spectron_checkpoint_v312,
        spectron_bzip2_helpers_anchors,
        spectron_checkpoint_v313,
        spectron_freetype_apply_anchors,
        spectron_checkpoint_v314,
        spectron_jcmarker_anchors,
        spectron_checkpoint_v315,
        spectron_freetype_tt_size_reset_anchor,
        spectron_checkpoint_v316,
        spectron_jpeg_gpc_residual_anchors,
        spectron_checkpoint_v317,
        spectron_residual_target_only_labels,
        spectron_checkpoint_v318,
        spectron_name_coverage_v318,
        spectron_name_coverage_v319,
        spectron_nullsub_labels,
        spectron_checkpoint_v319,
        spectron_name_coverage_v320,
        spectron_dynamic_function_application,
        spectron_dynamic_boundaries,
        spectron_dynamic_symbol_coverage,
        spectron_symbol_inventory_v320,
        spectron_checkpoint_v320,
    ):
        check("offline artifact marker", document.get("network_contacted"), False)

    print("research archive validation: ok (%d checks)" % len(checks))


if __name__ == "__main__":
    main()
