//! Literal RV64 test inventory, collected by the package inventory and checked
//! together with it. Focused roots retain their independent test-count floors.
test {
    _ = @import("rv64/air/memory/native_frontier_wire_test.zig");
    _ = @import("rv64/tests/frequent_operations_test.zig");
    _ = @import("rv64/air/program/packed_control_test.zig");
    _ = @import("rv64/air/full/packed_frame_test.zig");
    _ = @import("rv64/air/full/tests/prepared_view_test.zig");
    _ = @import("rv64/air/providers/tests/compact_hash_source_test.zig");
    _ = @import("rv64/air/full/component.zig");
    _ = @import("rv64/air/full/frame.zig");
    _ = @import("rv64/air/full/tests/coset_evaluation_test.zig");
    _ = @import("rv64/air/full/tests/parallel_test.zig");
    _ = @import("rv64/air/geometry.zig");
    _ = @import("rv64/air/lane.zig");
    _ = @import("rv64/air/memory/permutation_point.zig");
    _ = @import("rv64/air/memory/graph_model.zig");
    _ = @import("rv64/air/memory/policy_air_test.zig");
    _ = @import("rv64/air/memory/policy_test.zig");
    _ = @import("rv64/air/memory/values_test.zig");
    _ = @import("rv64/air/program/tests/component_test.zig");
    _ = @import("rv64/air/program/tests/service_test.zig");
    _ = @import("rv64/air/program/tests/setup_test.zig");
    _ = @import("rv64/air/providers/tables.zig");
    _ = @import("rv64/air/range/provider.zig");
    _ = @import("rv64/air/tests/admission_test.zig");
    _ = @import("rv64/air/tests/byte_operations_test.zig");
    _ = @import("rv64/air/tests/byte_terms_test.zig");
    _ = @import("rv64/air/tests/degree_test.zig");
    _ = @import("rv64/air/tests/encoding_test.zig");
    _ = @import("rv64/air/tests/inflation_reuse_test.zig");
    _ = @import("rv64/air/tests/local_test.zig");
    _ = @import("rv64/air/tests/memory_factoring_test.zig");
    _ = @import("rv64/air/tests/relations_test.zig");
    _ = @import("rv64/air/tests/representation_model_test.zig");
    _ = @import("rv64/air/tests/state_cyclic_test.zig");
    _ = @import("rv64/air/tests/weighted_sink_test.zig");
    _ = @import("rv64/air/tests/packed_fields_test.zig");
    _ = @import("rv64/air/tests/secp_lane_test.zig");
    _ = @import("rv64/air/tests/packed_control_test.zig");
    _ = @import("rv64/execution_test_root.zig");
    _ = @import("rv64/tests/access_census_test.zig");
    _ = @import("rv64/tests/compact_tape_test.zig");
    _ = @import("rv64/tests/tape_wire_test.zig");
    _ = @import("rv64/tests/ethereum_contract_test.zig");
    _ = @import("rv64/tests/execution_test.zig");
    _ = @import("rv64/tests/foundations_test.zig");
    _ = @import("rv64/tests/memory_commitment_test.zig");
    _ = @import("rv64/tests/service_session_test.zig");
    _ = @import("rv64_air_test_root.zig");
    _ = @import("rv64_coset_evaluation_test_root.zig");
    _ = @import("rv64_execution_test_root.zig");
    _ = @import("rv64_parallel_test_root.zig");
    _ = @import("rv64_program_test_root.zig");
    _ = @import("rv64/air/memory/batch_test.zig");
    _ = @import("rv64/air/memory/cell_air_test.zig");
    _ = @import("rv64/air/memory/chunk_air_test.zig");
    _ = @import("rv64/air/memory/internal_relations.zig");
    _ = @import("rv64/air/memory/node_air_test.zig");
    _ = @import("rv64/air/memory/openings_test.zig");
    _ = @import("rv64/air/memory/private_trace_test.zig");
    _ = @import("rv64/air/memory/provider_interaction_test.zig");
    _ = @import("rv64/air/providers/tests/degree_metadata_test.zig");
    _ = @import("rv64/tests/boundary_capture_test.zig");
    _ = @import("rv64/tests/ethereum_services_test.zig");
    _ = @import("rv64/air/memory/graph_air_test.zig");
    _ = @import("rv64/air/memory/ownership_test.zig");
    _ = @import("rv64/air/memory/terminal_air_test.zig");
}

test {
    _ = @import("rv64/air/tests/state_canonical_test.zig");
}

test {
    _ = @import("rv64/air/tests/local_lanes_test.zig");
}

test {
    _ = @import("rv64/air/tests/mixed_lane_test.zig");
}

test {
    _ = @import("rv64/air/memory/native_frontier_test.zig");
}

test {
    _ = @import("rv64/air/memory/prepared_graph_test.zig");
}

test {
    _ = @import("rv64/air/delegations/tests/registry_test.zig");
}

test {
    _ = @import("rv64/air/word16/alu_merged_prefix_test.zig");
}

test {
    _ = @import("rv64/air/word16/shift_word_merged_test.zig");
    _ = @import("rv64/air/delegations/arith256/mod.zig");
    _ = @import("rv64/air/delegations/arith256/tests.zig");
    _ = @import("rv64/air/delegations/bulk_memory/tests.zig");
    _ = @import("rv64/air/delegations/curves/mod.zig");
    _ = @import("rv64/air/delegations/curves/secp_tests.zig");
    _ = @import("rv64/air/delegations/curves/tests.zig");
    _ = @import("rv64/air/delegations/division/word16_product/packed_test.zig");
    _ = @import("rv64/air/delegations/division/word16_product/source_test.zig");
    _ = @import("rv64/air/delegations/division/word16_product/test.zig");
    _ = @import("rv64/air/delegations/keccak_sponge/tests.zig");
    _ = @import("rv64/air/delegations/sha256/mod.zig");
    _ = @import("rv64/air/delegations/sha256/native.zig");
    _ = @import("rv64/air/delegations/sha256/tests.zig");
    _ = @import("rv64/air/memory/load_store_dword/tests.zig");
    _ = @import("rv64/air/memory/load_store/boundary_source.zig");
    _ = @import("rv64/air/native_output_pages.zig");
    _ = @import("rv64/air/providers/parallel_rows_test.zig");
    _ = @import("rv64/air/tests/packed_om_fields_test.zig");
    _ = @import("rv64/air/word16_cpu/rom_lookup_test.zig");
    _ = @import("rv64/air/word16_index_control/authority_test.zig");
    _ = @import("rv64/air/word16/alu_interaction_test.zig");
    _ = @import("rv64/air/word16/alu_packed_rows_test.zig");
    _ = @import("rv64/air/word16/alu_source_test.zig");
    _ = @import("rv64/air/word16/alu_test.zig");
    _ = @import("rv64/air/word16/binary_packed_rows_test.zig");
    _ = @import("rv64/air/word16/binary_source_test.zig");
    _ = @import("rv64/air/word16/binary_test.zig");
    _ = @import("rv64/air/word16/binary_zbb_test.zig");
    _ = @import("rv64/air/word16/shift_byte_packed_rows_test.zig");
    _ = @import("rv64/air/word16/shift_byte_test.zig");
    _ = @import("rv64/air/word16/shift_word_interaction_test.zig");
    _ = @import("rv64/air/word16/shift_word_packed_rows_test.zig");
    _ = @import("rv64/air/word16/shift_word_packed_table_test.zig");
    _ = @import("rv64/air/word16/shift_word_source_test.zig");
    _ = @import("rv64/air/word16/shift_word_test.zig");
    _ = @import("rv64/air/word16/u16_source_test.zig");
    _ = @import("rv64/candidate_isa_test.zig");
    _ = @import("rv64/ethereum_contract.zig");
    _ = @import("rv64/ethereum_execution.zig");
    _ = @import("rv64/ethereum_services/arith256.zig");
    _ = @import("rv64/ethereum_services/bulk_memory.zig");
    _ = @import("rv64/ethereum_services/candidate_curves.zig");
    _ = @import("rv64/ethereum_services/candidate_jumpdest.zig");
    _ = @import("rv64/ethereum_services/candidate_services.zig");
    _ = @import("rv64/ethereum_services/curves.zig");
    _ = @import("rv64/ethereum_services/keccak_sponge.zig");
    _ = @import("rv64/ethereum_services/secp256k1.zig");
    _ = @import("rv64/ethereum_services/sha256.zig");
    _ = @import("rv64/isa_audit.zig");
    _ = @import("rv64/ram_word_set.zig");
    _ = @import("rv64/tests/fast_execution_test.zig");
    _ = @import("rv64/tests/zbb_binary_test.zig");
    _ = @import("rv64_alu_parallel_interaction_test_root.zig");
    _ = @import("rv64_arith256_truth_test_root.zig");
    _ = @import("rv64_curves_truth_test_root.zig");
    _ = @import("rv64_index_control_test_root.zig");
    _ = @import("rv64_keccak_sponge_test_root.zig");
    _ = @import("rv64_ls_dword_test_root.zig");
    _ = @import("rv64_rom_lookup_test_root.zig");
    _ = @import("rv64_sha256_truth_test_root.zig");
    _ = @import("rv64_simd_fields_test_root.zig");
    _ = @import("rv64_word16_alu_test_root.zig");
    _ = @import("rv64_word16_binary_source_test_root.zig");
    _ = @import("rv64_word16_bulk_memory_test_root.zig");
    _ = @import("rv64_word16_chips_test_root.zig");
    _ = @import("rv64_word16_division_product_test_root.zig");
    _ = @import("rv64_word16_shift_packed_table_test_root.zig");
    _ = @import("rv64_word16_shift_source_test_root.zig");
    _ = @import("rv64_word16_shift_test_root.zig");
    _ = @import("rv64_word16_shift_word_test_root.zig");
}

comptime {
    _ = @import("retained_typed_component_test_root.zig");
}

comptime {
    _ = @import("recursion/air/tests/universal_typed_component_test.zig");
}

comptime {
    _ = @import("recursion/air/tests/universal_typed_quotient_test.zig");
}

comptime {
    _ = @import("recursion/tests/fri_profile_frontier_test.zig");
    _ = @import("retained_fri_frontier_test_root.zig");
}
