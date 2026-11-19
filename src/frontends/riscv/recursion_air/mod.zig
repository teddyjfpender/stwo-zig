//! Canonical typed domain interfaces; test hooks are explicitly unstable.

pub const arithmetic_fusion_fixed_columns = @import("arithmetic/arithmetic_fusion_fixed_columns.zig");
pub const blake3 = struct {
    pub const direct_cohort_columns = @import("blake3/trace/blake3_direct_cohort_columns.zig");
    pub const direct_source_columns = @import("blake3/trace/blake3_direct_source_columns.zig");
    pub const draw_hash_layout = @import("blake3/transcript/blake3_draw_hash_layout.zig");
    pub const draw_witness = @import("blake3/transcript/blake3_draw_witness.zig");
    pub const fixture_roster = @import("blake3/trace/blake3_fixture_roster.zig");
    pub const frontier_capture = @import("blake3/openings/blake3_frontier_capture.zig");
    pub const lifted_leaf_plan = @import("blake3/openings/blake3_lifted_leaf_plan.zig");
    pub const merkle_group_witness = @import("blake3/openings/blake3_merkle_group_witness.zig");
    pub const merkle_path_witness = @import("blake3/openings/blake3_merkle_path_witness.zig");
    pub const native_recorder = @import("blake3/transcript/blake3_native_recorder.zig");
    pub const node_route = @import("blake3/openings/blake3_node_route.zig");
    pub const nonhash_emission = @import("blake3/trace/blake3_nonhash_emission.zig");
    pub const path_sharing_census = @import("blake3/openings/blake3_path_sharing_census.zig");
    pub const pcs_transcript = @import("blake3/transcript/blake3_pcs_transcript.zig");
    pub const query_witness = @import("blake3/openings/blake3_query_witness.zig");
    pub const recursive_column_rows = @import("blake3/trace/blake3_recursive_column_rows.zig");
    pub const root_sources = @import("blake3/openings/blake3_root_sources.zig");
    pub const scalar_payload_rows = @import("blake3/trace/blake3_scalar_payload_rows.zig");
    pub const shared_root_plan = @import("blake3/openings/blake3_shared_root_plan.zig");
    pub const transcript_plan = @import("blake3/transcript/blake3_transcript_plan.zig");
    pub const transcript_witness = @import("blake3/transcript/blake3_transcript_witness.zig");
    pub const two_level_frontier = @import("blake3/openings/blake3_two_level_frontier.zig");
    pub const upstream_source_columns = @import("blake3/trace/blake3_upstream_source_columns.zig");
};
pub const control = struct {
    pub const component = @import("composition/control_component.zig");
    pub const slice_witness = @import("composition/control_slice_witness.zig");
    pub const witness = @import("composition/control_witness.zig");
};
pub const detached = struct {
    pub const graph_input = @import("composition/detached_graph_input.zig");
    pub const parent_catalog = @import("composition/detached_parent_catalog.zig");
    pub const pcs_opening4 = @import("composition/detached_pcs_opening4.zig");
    pub const poseidon_graph = @import("composition/detached_poseidon_graph.zig");
};
pub const field_public_word = @import("statement/field_public_word.zig");
pub const field_statement_word = @import("statement/field_statement_word.zig");
pub const fixed_wire = @import("wire/fixed_wire.zig");
pub const fri = struct {
    pub const merkle_anchor = @import("fri/fri_merkle_anchor.zig");
    pub const merkle_anchor_relation = @import("fri/fri_merkle_anchor_relation.zig");
    pub const merkle_anchor_witness = @import("fri/fri_merkle_anchor_witness.zig");
    pub const merkle_leaf = @import("fri/fri_merkle_leaf.zig");
    pub const merkle_leaf_relation = @import("fri/fri_merkle_leaf_relation.zig");
    pub const merkle_leaf_witness = @import("fri/fri_merkle_leaf_witness.zig");
    pub const merkle_node = @import("fri/fri_merkle_node.zig");
    pub const merkle_node_relation = @import("fri/fri_merkle_node_relation.zig");
    pub const merkle_node_witness = @import("fri/fri_merkle_node_witness.zig");
    pub const verifier_control = @import("fri/fri_verifier_control.zig");
    pub const verifier_control_relation = @import("fri/fri_verifier_control_relation.zig");
    pub const verifier_control_witness = @import("fri/fri_verifier_control_witness.zig");
    pub const verifier_input = @import("fri/fri_verifier_input.zig");
    pub const verifier_input_relation = @import("fri/fri_verifier_input_relation.zig");
};
pub const interaction_generator = @import("composition/interaction_generator.zig");
pub const linear_ops_witness = @import("arithmetic/linear_ops_witness.zig");
pub const merkle = struct {
    pub const path = @import("openings/merkle_path.zig");
    pub const path_poseidon_bridge = @import("openings/merkle_path_poseidon_bridge.zig");
    pub const path_relation = @import("openings/merkle_path_relation.zig");
    pub const path_witness = @import("openings/merkle_path_witness.zig");
    pub const root = @import("openings/merkle_root.zig");
    pub const root_relation = @import("openings/merkle_root_relation.zig");
    pub const root_witness = @import("openings/merkle_root_witness.zig");
};
pub const pcs_deep_input = @import("openings/pcs_deep_input.zig");
pub const pcs_deep_input_relation = @import("openings/pcs_deep_input_relation.zig");
pub const pow = struct {
    pub const check = @import("transcript/pow_check.zig");
    pub const check_witness = @import("transcript/pow_check_witness.zig");
    pub const frame = @import("transcript/pow_frame.zig");
    pub const frame_relation = @import("transcript/pow_frame_relation.zig");
    pub const frame_witness = @import("transcript/pow_frame_witness.zig");
};
pub const prepared_interaction_generation = @import("composition/prepared_interaction_generation.zig");
pub const protocol = struct {
    pub const aggregation = struct {
        pub const types = @import("protocol/aggregation/types.zig");
    };
    pub const recursion = struct {
        pub const blake3_engine_protocol = @import("protocol/recursion/blake3_engine_protocol.zig");
        pub const engine_protocol = @import("protocol/recursion/engine_protocol.zig");
        pub const fixed_profile = @import("protocol/recursion/fixed_profile.zig");
        pub const fixed_wire = @import("protocol/recursion/fixed_wire.zig");
        pub const protocol = @import("protocol/recursion/protocol.zig");
        pub const protocol_statement_constants = @import("protocol/recursion/protocol_statement_constants.zig");
    };
};
pub const qm31 = struct {
    pub const inv_witness = @import("arithmetic/qm31_inv_witness.zig");
    pub const mul_full = @import("arithmetic/qm31_mul_full.zig");
    pub const mul_full_witness = @import("arithmetic/qm31_mul_full_witness.zig");
};
pub const query = struct {
    pub const bits = @import("openings/query_bits.zig");
    pub const bits_profile = @import("openings/query_bits_profile.zig");
    pub const bits_relation = @import("openings/query_bits_relation.zig");
    pub const bits_witness = @import("openings/query_bits_witness.zig");
    pub const mapping = @import("openings/query_mapping.zig");
    pub const mapping_relation = @import("openings/query_mapping_relation.zig");
    pub const mapping_witness = @import("openings/query_mapping_witness.zig");
};
pub const relation = struct {
    pub const challenge = @import("transcript/relation_challenge.zig");
    pub const challenge_witness = @import("transcript/relation_challenge_witness.zig");
};
pub const roster_composition_geometry = @import("composition/roster_composition_geometry.zig");
pub const segment_public_outer_air = @import("statement/segment_public_outer_air.zig");
pub const statement = struct {
    pub const clocks = @import("statement/statement_clocks.zig");
    pub const input = @import("statement/statement_input.zig");
    pub const input_relation = @import("statement/statement_input_relation.zig");
    pub const publication = @import("statement/statement_publication.zig");
    pub const semantics_input = @import("statement/statement_semantics_input.zig");
    pub const semantics_input_relation = @import("statement/statement_semantics_input_relation.zig");
};
pub const structural_sha256 = @import("wire/structural_sha256.zig");
pub const testing = struct {
    pub const assets = @import("assets.zig");
    pub const blake3 = struct {
        pub const hash_test_support = @import("blake3/trace/blake3_hash_test_support.zig");
        pub const main_column_test_support = @import("blake3/trace/blake3_main_column_test_support.zig");
    };
    pub const inventory_source = @embedFile("tests/root.zig");
    pub const test_support = @import("test_support.zig");
    pub const tests = struct {
        pub const blake3_rejection_fixture_test_support = @import("tests/blake3_rejection_fixture_test_support.zig");
        pub const qm31_mul_full_relation_test_support = @import("tests/qm31_mul_full_relation_test_support.zig");
        pub const vm_public_logup_control_test = @import("tests/vm_public_logup_control_test.zig");
    };
};
pub const trace_merkle = @import("openings/trace_merkle.zig");
pub const trace_merkle_relation = @import("openings/trace_merkle_relation.zig");
pub const trace_merkle_witness = @import("openings/trace_merkle_witness.zig");
pub const transcript = struct {
    pub const air = @import("transcript/transcript_air.zig");
    pub const air_witness = @import("transcript/transcript_air_witness.zig");
    pub const binding = @import("transcript/transcript_binding.zig");
    pub const binding_witness = @import("transcript/transcript_binding_witness.zig");
    pub const payload = @import("transcript/transcript_payload.zig");
    pub const payload_clocks = @import("transcript/transcript_payload_clocks.zig");
    pub const payload_relation = @import("transcript/transcript_payload_relation.zig");
    pub const payload_witness = @import("transcript/transcript_payload_witness.zig");
    pub const state = @import("transcript/transcript_state.zig");
    pub const state_witness = @import("transcript/transcript_state_witness.zig");
    pub const word = @import("transcript/transcript_word.zig");
    pub const word_witness = @import("transcript/transcript_word_witness.zig");
};
pub const universal_catalog = @import("composition/universal_catalog.zig");
pub const universal_catalog_entry = @import("composition/universal_catalog_entry.zig");
pub const verifier_component_parameters = @import("composition/verifier_component_parameters.zig");
pub const verifier_parameter_tags = @import("composition/verifier_parameter_tags.zig");
pub const verifier_randomness = @import("transcript/verifier_randomness.zig");
pub const verifier_randomness_relation = @import("transcript/verifier_randomness_relation.zig");
pub const verifier_randomness_witness = @import("transcript/verifier_randomness_witness.zig");
pub const verifier_schedule = @import("composition/verifier_schedule.zig");
pub const verifier_wire_claims = @import("wire/verifier_wire_claims.zig");
pub const verifier_wire_protocol = @import("wire/verifier_wire_protocol.zig");
pub const vm_air_composition_control = @import("composition/vm_air_composition_control.zig");
pub const vm_air_composition_input = @import("composition/vm_air_composition_input.zig");
pub const vm_air_composition_input_relation = @import("composition/vm_air_composition_input_relation.zig");
pub const vm_public_claim_hash = @import("statement/vm_public_claim_hash.zig");
pub const vm_public_claim_hash_authority = @import("statement/vm_public_claim_hash_authority.zig");
pub const vm_public_claim_input = @import("statement/vm_public_claim_input.zig");
pub const vm_public_claim_semantics_input = @import("statement/vm_public_claim_semantics_input.zig");
pub const vm_public_claim_semantics_input_witness = @import("statement/vm_public_claim_semantics_input_witness.zig");
pub const vm_public_io_hash = @import("statement/vm_public_io_hash.zig");
pub const vm_public_logup_control = @import("statement/vm_public_logup_control.zig");
pub const vm_public_logup_control_relation = @import("statement/vm_public_logup_control_relation.zig");
pub const vm_public_logup_control_v2 = @import("statement/variable_boundary_vm_public_logup.zig");
pub const vm_public_logup_control_witness = @import("statement/vm_public_logup_control_witness.zig");
pub const vm_public_logup_input = @import("statement/vm_public_logup_input.zig");
pub const vm_public_logup_input_witness = @import("statement/vm_public_logup_input_witness.zig");
pub const wire_interaction = @import("wire/wire_interaction.zig");

test {
    _ = @import("tests/root.zig");
}
