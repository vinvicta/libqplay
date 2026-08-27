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
    spectron_particle_emitter_anchors = load_json(
        "artifacts/spectron_particle_emitter_manual_translation_anchors_20260826.json"
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
    check("Spectron checkpoint database default sub count", spectron_checkpoint["database"]["default_sub_function_count"], 1240)
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
    check("Spectron checkpoint TString anchor count", spectron_checkpoint["tstring_anchors"]["verified_name_count"], 6)
    check("Spectron checkpoint TString clear anchor count", spectron_checkpoint["tstring_clear_anchors"]["verified_name_count"], 1)
    check("Spectron checkpoint static-clear anchor count", spectron_checkpoint["static_clear_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint HTTP response anchor count", spectron_checkpoint["http_request_receive_anchors"]["verified_name_count"], 2)
    check("Spectron checkpoint server-list connection anchor count", spectron_checkpoint["server_list_connection_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint server-list state anchor count", spectron_checkpoint["server_list_state_anchors"]["verified_name_count"], 4)
    check("Spectron checkpoint HTTP cleanup anchor count", spectron_checkpoint["http_request_cleanup_anchors"]["verified_name_count"], 5)
    check("Spectron checkpoint database hash", spectron_checkpoint["database"]["sha256"], "a01af52c52de0c5d203d15ee0eb839b6a30ff13094a08474668c71773a0f17a2")
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
        spectron_connection_helper_anchors,
        spectron_client_state_helper_anchors,
        spectron_connection_state_anchors,
        spectron_http_request_anchors,
        spectron_socket_state_anchors,
        spectron_socket_behavior,
        spectron_http_request_state_anchors,
        spectron_npc_helper_anchors,
        spectron_html_atom_anchors,
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
        spectron_hash_container_anchors,
        spectron_tstring_anchors,
        spectron_tstring_clear_anchors,
        spectron_static_clear_anchors,
        spectron_static_callback_role_correction,
        spectron_http_request_receive_anchors,
        spectron_server_list_connection_anchors,
        spectron_server_list_state_anchors,
        spectron_http_request_cleanup_anchors,
        spectron_particle_emitter_anchors,
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
    ):
        check("offline artifact marker", document.get("network_contacted"), False)

    print("research archive validation: ok (%d checks)" % len(checks))


if __name__ == "__main__":
    main()
