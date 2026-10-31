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
    _ = @import("rv64/air/word16_v1/alu_merged_prefix_test.zig");
}
