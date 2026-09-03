//! Fast, production-decoupled gate for recursion-local typed AIR.
//!
//! Shared VM-provider bridges intentionally live in `recursion_air_test_root`.
//! Keeping them out of this root prevents an opcode-registry edit from pulling
//! the complete runner/infra test closure into every recursion iteration.

test {
    _ = @import("air/lang/relation_test.zig");
    _ = @import("recursion/fri_profile_frontier_test.zig");
    _ = @import("recursion/transcript_program_test.zig");
    _ = @import("recursion/scheduled_channel.zig");
    _ = @import("recursion/segment_transcript_witness_test.zig");
    _ = @import("recursion/segment_leaf_authority_test.zig");
    _ = @import("recursion/vm_public_semantics_circuit_test.zig");
    _ = @import("recursion/span_statement_test.zig");
    _ = @import("recursion/vm_public_claim_test.zig");
    _ = @import("recursion/air/merkle_root_test.zig");
    _ = @import("recursion/air/fri_merkle_leaf_test.zig");
    _ = @import("recursion/air/fri_merkle_node_test.zig");
    _ = @import("recursion/air/fri_merkle_anchor_test.zig");
    _ = @import("recursion/air/fri_verifier_control_test.zig");
    _ = @import("recursion/air/fri_verifier_circuit_test.zig");
    _ = @import("recursion/air/pcs_deep_circuit_test.zig");
    _ = @import("recursion/air/verifier_arithmetic_lowering_test.zig");
    _ = @import("recursion/air/fri_verifier_input.zig");
    _ = @import("recursion/air/fri_verifier_input_test.zig");
    _ = @import("recursion/air/fri_verifier_lowering_test.zig");
    _ = @import("recursion/air/merkle_path_test.zig");
    _ = @import("recursion/air/framework_interaction.zig");
    _ = @import("recursion/air/pcs_deep_input_test.zig");
    _ = @import("recursion/air/pow_check_test.zig");
    _ = @import("recursion/air/pow_frame_test.zig");
    _ = @import("recursion/air/composition_circuit_test.zig");
    _ = @import("recursion/air/composition_graph_recorder.zig");
    _ = @import("recursion/air/universal_shared_provider_composition.zig");
    _ = @import("recursion/air/control_test.zig");
    _ = @import("recursion/air/control_component.zig");
    _ = @import("recursion/air/direct_constraint_program.zig");
    _ = @import("recursion/air/inventory_test.zig");
    _ = @import("recursion/air/linear_ops_adversarial_test.zig");
    _ = @import("recursion/air/linear_ops_test.zig");
    _ = @import("recursion/air/qm31_inv_adversarial_test.zig");
    _ = @import("recursion/air/qm31_inv_test.zig");
    _ = @import("recursion/air/qm31_mul_adversarial_test.zig");
    _ = @import("recursion/air/qm31_mul_full_adversarial_test.zig");
    _ = @import("recursion/air/qm31_mul_full_test.zig");
    _ = @import("recursion/air/qm31_mul_test.zig");
    _ = @import("recursion/air/query_bits_test.zig");
    _ = @import("recursion/air/query_bits_heterogeneous_v2_test.zig");
    _ = @import("recursion/air/pcs_input_arena_heterogeneous_v2_test.zig");
    _ = @import("recursion/air/fri_rows_profiles_heterogeneous_v2_test.zig");
    _ = @import("recursion/air/fri_rows_authority_heterogeneous_v2_test.zig");
    _ = @import("recursion/air/query_mapping_test.zig");
    _ = @import("recursion/air/query_mapping_witness_heterogeneous_v2_test.zig");
    _ = @import("recursion/air/relation_challenge_test.zig");
    _ = @import("recursion/air/temporal_packed_relation_challenge_v2.zig");
    _ = @import("recursion/air/relation_effect.zig");
    _ = @import("recursion/air/relation_interaction.zig");
    _ = @import("recursion/air/statement_input_test.zig");
    _ = @import("recursion/air/trace_merkle_test.zig");
    _ = @import("recursion/air/trace_merkle_witness_heterogeneous_v2_test.zig");
    _ = @import("recursion/air/transcript_air_test.zig");
    _ = @import("recursion/air/transcript_binding_test.zig");
    _ = @import("recursion/air/transcript_payload_test.zig");
    _ = @import("recursion/air/transcript_state_test.zig");
    _ = @import("recursion/air/transcript_word_test.zig");
    _ = @import("recursion/air/statement_semantics_input_test.zig");
    _ = @import("recursion/air/universal_challenges.zig");
    _ = @import("recursion/air/universal_manifest_test.zig");
    _ = @import("recursion/air/universal_typed_component_test.zig");
    _ = @import("recursion/air/universal_roster.zig");
    _ = @import("recursion/air/universal_roster_inventory_test.zig");
    _ = @import("recursion/air/verifier_schedule.zig");
    _ = @import("recursion/air/verifier_randomness_test.zig");
    _ = @import("recursion/air/control_slice_test.zig");
    _ = @import("recursion/air/control_slice_heterogeneous_v2_test.zig");
    _ = @import("recursion/air/vm_air_composition_input_test.zig");
    _ = @import("recursion/air/vm_public_claim_hash_test.zig");
    _ = @import("recursion/air/vm_public_claim_input_test.zig");
    _ = @import("recursion/air/vm_public_claim_semantics_input_test.zig");
    _ = @import("recursion/air/vm_public_io_hash_test.zig");
    _ = @import("recursion/air/vm_public_logup_input_test.zig");
}
