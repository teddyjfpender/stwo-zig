//! Literal RV64 test inventory, collected by the package inventory and checked
//! together with it. Focused roots retain their independent test-count floors.
test {
    _ = @import("stwo_riscv_rv64").modules.air_memory_native_frontier_wire_test;
    _ = @import("stwo_riscv_rv64").modules.tests_frequent_operations_test;
    _ = @import("stwo_riscv_rv64").modules.air_program_packed_control_test;
    _ = @import("stwo_riscv_rv64").modules.air_full_packed_frame_test;
    _ = @import("stwo_riscv_rv64").modules.air_full_tests_prepared_view_test;
    _ = @import("stwo_riscv_rv64").modules.air_providers_tests_compact_hash_source_test;
    _ = @import("stwo_riscv_rv64").modules.air_full_component;
    _ = @import("stwo_riscv_rv64").modules.air_full_frame;
    _ = @import("stwo_riscv_rv64").modules.air_full_tests_coset_evaluation_test;
    _ = @import("stwo_riscv_rv64").modules.air_full_tests_parallel_test;
    _ = @import("stwo_riscv_rv64").modules.air_geometry;
    _ = @import("stwo_riscv_rv64").modules.air_lane;
    _ = @import("stwo_riscv_rv64").modules.air_memory_permutation_point;
    _ = @import("stwo_riscv_rv64").modules.air_memory_graph_model;
    _ = @import("stwo_riscv_rv64").modules.air_memory_policy_air_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_policy_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_values_test;
    _ = @import("stwo_riscv_rv64").modules.air_program_tests_component_test;
    _ = @import("stwo_riscv_rv64").modules.air_program_tests_service_test;
    _ = @import("stwo_riscv_rv64").modules.air_program_tests_setup_test;
    _ = @import("stwo_riscv_rv64").modules.air_providers_tables;
    _ = @import("stwo_riscv_rv64").modules.air_range_provider;
    _ = @import("stwo_riscv_rv64").modules.air_tests_admission_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_byte_operations_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_byte_terms_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_degree_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_encoding_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_inflation_reuse_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_local_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_memory_factoring_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_relations_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_representation_model_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_state_cyclic_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_weighted_sink_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_packed_fields_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_secp_lane_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_packed_control_test;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_execution_test_root;
    _ = @import("stwo_riscv_rv64").modules.tests_access_census_test;
    _ = @import("stwo_riscv_rv64").modules.tests_compact_tape_test;
    _ = @import("stwo_riscv_rv64").modules.tests_tape_wire_test;
    _ = @import("rv64/tests/ethereum_contract_test.zig");
    _ = @import("stwo_riscv_rv64").modules.tests_execution_test;
    _ = @import("stwo_riscv_rv64").modules.tests_foundations_test;
    _ = @import("stwo_riscv_rv64").modules.tests_memory_commitment_test;
    _ = @import("stwo_riscv_rv64").modules.tests_service_session_test;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_air_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_coset_evaluation_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_execution_test_root_4bef1028;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_parallel_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_program_test_root;
    _ = @import("stwo_riscv_rv64").modules.air_memory_batch_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_cell_air_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_chunk_air_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_internal_relations;
    _ = @import("stwo_riscv_rv64").modules.air_memory_node_air_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_openings_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_private_trace_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_provider_interaction_test;
    _ = @import("stwo_riscv_rv64").modules.air_providers_tests_degree_metadata_test;
    _ = @import("stwo_riscv_rv64").modules.tests_boundary_capture_test;
    _ = @import("rv64/tests/ethereum_services_test.zig");
    _ = @import("stwo_riscv_rv64").modules.air_memory_graph_air_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_ownership_test;
    _ = @import("stwo_riscv_rv64").modules.air_memory_terminal_air_test;
}

test {
    _ = @import("stwo_riscv_rv64").modules.air_tests_state_canonical_test;
}

test {
    _ = @import("stwo_riscv_rv64").modules.air_tests_local_lanes_test;
}

test {
    _ = @import("stwo_riscv_rv64").modules.air_tests_mixed_lane_test;
}

test {
    _ = @import("stwo_riscv_rv64").modules.air_memory_native_frontier_test;
}

test {
    _ = @import("stwo_riscv_rv64").modules.air_memory_prepared_graph_test;
}

test {
    _ = @import("stwo_riscv_rv64").modules.air_delegations_tests_registry_test;
}

test {
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_merged_prefix_test;
}

test {
    _ = @import("stwo_riscv_rv64").modules.air_word16_shift_word_merged_test;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_arith256_mod;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_arith256_tests;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_bulk_memory_tests;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_curves_mod;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_curves_secp_tests;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_curves_tests;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_division_word16_product_packed_test;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_division_word16_product_source_test;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_division_word16_product_test;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_keccak_sponge_tests;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_sha256_mod;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_sha256_native;
    _ = @import("stwo_riscv_rv64").modules.air_delegations_sha256_tests;
    _ = @import("stwo_riscv_rv64").modules.air_memory_load_store_dword_tests;
    _ = @import("stwo_riscv_rv64").modules.air_memory_load_store_boundary_source;
    _ = @import("stwo_riscv_rv64").modules.air_native_output_pages;
    _ = @import("stwo_riscv_rv64").modules.air_providers_parallel_rows_test;
    _ = @import("stwo_riscv_rv64").modules.air_tests_packed_om_fields_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_cpu_rom_lookup_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_index_control_authority_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_interaction_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_packed_rows_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_source_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_binary_packed_rows_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_binary_source_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_binary_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_binary_zbb_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_shift_byte_packed_rows_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_shift_byte_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_shift_word_interaction_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_shift_word_packed_rows_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_shift_word_packed_table_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_shift_word_source_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_shift_word_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_u16_source_test;
    _ = @import("stwo_riscv_rv64").modules.candidate_isa_test;
    _ = @import("rv64/ethereum_contract.zig");
    _ = @import("rv64/ethereum_execution.zig");
    _ = @import("stwo_riscv_precompiles").modules.rv64_services_arith256;
    _ = @import("stwo_riscv_rv64").modules.ethereum_services_bulk_memory;
    _ = @import("stwo_riscv_rv64").modules.ethereum_services_candidate_curves;
    _ = @import("stwo_riscv_rv64").modules.ethereum_services_candidate_jumpdest;
    _ = @import("stwo_riscv_rv64").modules.ethereum_services_candidate_services;
    _ = @import("stwo_riscv_rv64").modules.ethereum_services_curves;
    _ = @import("stwo_riscv_rv64").modules.ethereum_services_keccak_sponge;
    _ = @import("stwo_riscv_precompiles").modules.rv64_services_secp256k1;
    _ = @import("stwo_riscv_precompiles").modules.rv64_services_sha256;
    _ = @import("stwo_riscv_rv64").modules.isa_audit;
    _ = @import("stwo_riscv_rv64").modules.ram_word_set;
    _ = @import("stwo_riscv_rv64").modules.tests_fast_execution_test;
    _ = @import("stwo_riscv_rv64").modules.tests_zbb_binary_test;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_alu_parallel_interaction_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_arith256_truth_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_curves_truth_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_index_control_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_keccak_sponge_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_ls_dword_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_rom_lookup_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_sha256_truth_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_simd_fields_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_alu_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_binary_source_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_bulk_memory_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_chips_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_division_product_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_shift_packed_table_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_shift_source_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_shift_test_root;
    _ = @import("stwo_riscv_testing").modules.cases_rv64_word16_shift_word_test_root;
}

comptime {
    _ = @import("stwo_riscv_testing").modules.cases_retained_typed_component_test_root;
}

comptime {
    _ = @import("stwo_riscv_testing").modules.cases_recursion_air_tests_universal_typed_component_test;
}

comptime {
    _ = @import("stwo_riscv_testing").modules.cases_recursion_air_tests_universal_typed_quotient_test;
}

comptime {
    _ = @import("stwo_riscv_recursion").modules.tests_fri_profile_frontier_test;
    _ = @import("stwo_riscv_testing").modules.cases_retained_fri_frontier_test_root;
}
