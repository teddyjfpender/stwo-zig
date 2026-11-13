//! Canonical typed domain interfaces; test hooks are explicitly unstable.

pub const aggregation = struct {
    pub const hash = @import("primitives/aggregation/hash.zig");
};
pub const air = struct {
    pub const binary_node_128 = @import("air/binary_node_128.zig");
    pub const blake3_state_tree = @import("air/blake3_state_tree.zig");
    pub const boundary = @import("air/boundary.zig");
    pub const byte_tree_topology = @import("air/byte_tree_topology.zig");
    pub const hash_component = @import("air/hash_component.zig");
    pub const hash_component_prepared_support = @import("air/hash_component_prepared_support.zig");
    pub const hash_runtime_program = @import("air/hash_runtime_program.zig");
    pub const incremental_boundary_interaction = @import("air/incremental_boundary_interaction.zig");
    pub const incremental_bridge = @import("air/incremental_bridge.zig");
    pub const incremental_bridge_component = @import("air/incremental_bridge_component.zig");
    pub const interaction = @import("air/interaction.zig");
    pub const merkle_node = @import("air/merkle_node.zig");
    pub const merkle_typed_admission = @import("air/merkle_typed_admission.zig");
    pub const poseidon2 = @import("air/poseidon2.zig");
    pub const poseidon2_air = @import("air/poseidon2_air.zig");
    pub const poseidon2_call = @import("air/poseidon2_call.zig");
    pub const poseidon2_degree3_verifier = @import("air/poseidon2_degree3_verifier.zig");
    pub const poseidon2_layout = @import("air/poseidon2_layout.zig");
    pub const poseidon2_narrow_backend = @import("air/poseidon2_narrow_backend.zig");
    pub const poseidon2_narrow_component = @import("air/poseidon2_narrow_component.zig");
    pub const poseidon2_narrow_degree3 = @import("air/poseidon2_narrow_degree3.zig");
    pub const poseidon2_universal_component = @import("air/poseidon2_universal_component.zig");
    pub const poseidon2_universal_degree3 = @import("air/poseidon2_universal_degree3.zig");
    pub const poseidon2_universal_equations = @import("air/poseidon2_universal_equations.zig");
    pub const poseidon2_universal_identity = @import("air/poseidon2_universal_identity.zig");
    pub const poseidon2_universal_layout = @import("air/poseidon2_universal_layout.zig");
    pub const poseidon2_wide_equations = @import("air/poseidon2_wide_equations.zig");
    pub const poseidon2_wide_typed_admission = @import("air/poseidon2_wide_typed_admission.zig");
    pub const sparse_merkle = @import("air/sparse_merkle.zig");
    pub const trace = @import("air/trace.zig");
};
pub const common = struct {
    pub const poseidon2 = @import("primitives/common/poseidon2.zig");
};
pub const prover = struct {
    pub const authority = @import("prover/authority.zig");
    pub const poseidon_witness_work = @import("primitives/prover/poseidon_witness_work.zig");
    pub const provider_order_component = @import("prover/provider_order_component.zig");
    pub const standalone_component = @import("prover/standalone_component.zig");
};
pub const recursion = struct {
    pub const blake3_identity_digest = @import("primitives/recursion/blake3_identity_digest.zig");
    pub const poseidon2_channel = @import("primitives/recursion/poseidon2_channel.zig");
};
pub const testing = struct {
    pub const air = struct {
        pub const hash_component_reference_test_support = @import("air/hash_component_reference_test_support.zig");
    };
    pub const inventory_source = @embedFile("tests/root.zig");
    pub const proposals = struct {
        pub const materialization_frontier_cost_model = @import("typed/materialization_frontier_cost_model.zig");
        pub const materialization_frontier_manifest = @import("typed/materialization_frontier_manifest.zig");
        pub const materialization_frontier_projection = @import("typed/materialization_frontier_projection.zig");
        pub const poseidon_layout_benchmark_command = @import("typed/poseidon_layout_benchmark_command.zig");
        pub const typed_poseidon2_frontier_artifact = @import("typed/typed_poseidon2_frontier_artifact.zig");
    };
};
pub const typed = struct {
    pub const typed_poseidon2 = @import("typed/typed_poseidon2.zig");
    pub const typed_poseidon2_authority = @import("typed/typed_poseidon2_authority.zig");
    pub const typed_poseidon2_compact = @import("typed/typed_poseidon2_compact.zig");
    pub const typed_poseidon2_compat = @import("typed/typed_poseidon2_compat.zig");
    pub const typed_poseidon2_degree5_component = @import("typed/typed_poseidon2_degree5_component.zig");
    pub const typed_poseidon2_degree5_row_program = @import("typed/typed_poseidon2_degree5_row_program.zig");
    pub const typed_poseidon2_degree5_trace = @import("typed/typed_poseidon2_degree5_trace.zig");
    pub const typed_poseidon2_degree_bounded_candidate = @import("typed/typed_poseidon2_degree_bounded_candidate.zig");
    pub const typed_poseidon2_degree_bounded_component = @import("typed/typed_poseidon2_degree_bounded_component.zig");
    pub const typed_poseidon2_degree_bounded_residency = @import("typed/typed_poseidon2_degree_bounded_residency.zig");
    pub const typed_poseidon2_degree_bounded_trace = @import("typed/typed_poseidon2_degree_bounded_trace.zig");
    pub const typed_poseidon2_fixed_polynomials = @import("typed/typed_poseidon2_fixed_polynomials.zig");
    pub const typed_poseidon2_identity = @import("typed/typed_poseidon2_identity.zig");
    pub const typed_poseidon2_identity_codec = @import("typed/typed_poseidon2_identity_codec.zig");
    pub const typed_poseidon2_identity_golden = @import("typed/typed_poseidon2_identity_golden.zig");
    pub const typed_poseidon2_proof_authority = @import("typed/typed_poseidon2_proof_authority.zig");
    pub const typed_poseidon2_relations = @import("typed/typed_poseidon2_relations.zig");
    pub const typed_poseidon2_wide = @import("typed/typed_poseidon2_wide.zig");
    pub const typed_poseidon2_witness = @import("typed/typed_poseidon2_witness.zig");
};

test {
    _ = @import("tests/root.zig");
}
