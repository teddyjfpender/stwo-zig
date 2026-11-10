//! Recursion protocol namespace.

pub const vm_composition_sample_geometry = @import("vm_composition_sample_geometry.zig");

pub const air = @import("air/mod.zig");
pub const detached_boundary_preparation_v1 = @import("detached_boundary_preparation.zig");
pub const detached_child_capture_v1 = @import("detached_child_capture.zig");
pub const detached_parent_statement_preparation_v1 = @import("detached_parent_statement_preparation.zig");
pub const detached_segment_recording_components_v1 = @import("detached_segment_recording_components.zig");
pub const detached_fri_core_v2 = @import("detached_fri_core.zig");
pub const detached_composition_preparation_v1 = @import("detached_composition_preparation.zig");
pub const detached_leaf_cohort_v2 = @import("detached_leaf_cohort.zig");
pub const detached_parent_preparation_v1 = @import("detached_parent_preparation.zig");

pub const segment_public_claim_hash_authority_v2 = @import("segment_public_claim_hash_authority.zig");
pub const binary_fri_outer_source = @import("binary_fri_outer_source.zig");
pub const binary_global_closure_outer_source = @import("binary_global_closure_outer_source.zig");
pub const captured_fri = @import("captured_fri.zig");
pub const compact_tuple_ledger_v1 = @import("compact_tuple_ledger.zig");
pub const engine = @import("engine.zig");
pub const verifier_tree = @import("verifier_tree.zig");
pub const fixed_profile = @import("fixed_profile.zig");
pub const fixed_wire = @import("fixed_wire.zig");
pub const fixed_wire_adapter = @import("fixed_wire_adapter.zig");
pub const fri_profile_frontier = @import("fri_profile_frontier.zig");
pub const leaf_profile = @import("leaf_profile.zig");
pub const pair_node = @import("pair_node.zig");
pub const poseidon2_channel = @import("poseidon2_channel.zig");
pub const proof_ingress = @import("ethereum_proof_ingress_compat.zig");
pub const protocol = @import("protocol.zig");
pub const recording_poseidon_channel_v4 =
    @import("recording_poseidon_channel.zig");
pub const recursion_air_composition_circuit_v3 = @import("recursion_air_composition_circuit_v3.zig");
/// Shared fixtures consumed by integration tests through the frontend owner.
pub const segment_leaf_authority = @import("segment_leaf_authority.zig");
pub const segment_leaf_authority_v2 = @import("segment_leaf_authority_v2.zig");
pub const segment_leaf_local_authority_v3 =
    @import("segment_leaf_local_authority.zig");
pub const segment_leaf_local_projection_v3 =
    @import("segment_leaf_local_projection.zig");
pub const segment_leaf_local_verified_link_v3 =
    @import("segment_leaf_local_verified_link.zig");
pub const segment_leaf_outer_air_v2 = @import("segment_leaf_outer_air.zig");
pub const segment_leaf_outer_authority_v2 = @import("segment_leaf_outer_authority.zig");
pub const segment_outer_cohort_v2 = @import("segment_outer_cohort.zig");
pub const segment_publication_input_provider_authority_v2 =
    @import("segment_publication_input_provider_authority.zig");
pub const segment_profile = @import("segment_profile.zig");
pub const segment_range_authority = @import("segment_range_authority.zig");
pub const segment_shared_poseidon_schedule_v2 = @import("segment_shared_poseidon_schedule.zig");
pub const segment_transcript_outer_source_v2 = @import("segment_transcript_outer_source_v2.zig");
pub const segment_public_native_sum_authority_v2 = @import("segment_public_native_sum_authority.zig");
pub const segment_statement_outer_source = @import("segment_statement_outer_source.zig");
pub const segment_statement_v2 = @import("segment_statement.zig");
pub const segment_transcript_witness = @import("segment_transcript_witness.zig");
pub const native_scheduled_channel = @import("native_scheduled_channel.zig");
pub const outer_parent_child_admission = @import("outer_parent_child_admission.zig");
pub const span_statement = @import("span_statement.zig");
pub const span_continuation_v1 = @import("span_continuation.zig");
pub const statement_semantics_circuit = @import("statement_semantics_circuit.zig");
pub const temporal_pair_node = @import("temporal_pair_node.zig");
pub const transcript_program = @import("transcript_program.zig");
pub const transcript_program_v2 = @import("transcript_program_v2.zig");
pub const transcript_shape = @import("transcript_shape.zig");
pub const vm_public_claim = @import("vm_public_claim.zig");
pub const vm_public_semantics_circuit = @import("vm_public_semantics_circuit.zig");
pub const vm_air_profile = @import("vm_air_profile.zig");
pub const vm_air_profile_v2 = @import("vm_air_profile_v2.zig");
pub const vm_air_composition_circuit = @import("vm_air_composition_circuit.zig");
pub const vm_air_composition_prepared_v2 =
    @import("vm_air_composition_prepared.zig");
pub const vm_leaf_context = @import("vm_leaf_context.zig");
pub const vm_leaf_context_v2 = @import("vm_leaf_context_v2.zig");

pub const vm_composition_preparation = @import("vm_composition_preparation.zig");

pub const detached_parent_verifier_components_v1 = @import("detached_parent_verifier_components.zig");
pub const detached_parent_components_v1 = @import("detached_parent_components.zig");
pub const detached_pcs_preparation_v1 = @import("detached_pcs_preparation.zig");
pub const detached_parent_prepared_v1 = @import("detached_parent_prepared.zig");
pub const detached_parent_protocol_v1 = @import("detached_parent_protocol.zig");

pub const artifact_limits = @import("artifact_limits.zig");
pub const detached_parent_verifier_v1 = @import("detached_parent_verifier.zig");

pub const detached_parent_command_v1 = @import("detached_parent_command.zig");

pub const detached_segment_admission_v1 = @import("detached_segment_admission.zig");
pub const segment_leaf_parameters_v2 = @import("segment_leaf_parameters.zig");
pub const detached_segment_definitions_v1 = @import("detached_segment_definitions.zig");
pub const detached_segment_verifier_components_v1 = @import("detached_segment_verifier_components.zig");

pub const segment_leaf_statement_contract_v2 = @import("segment_leaf_statement_contract.zig");
pub const detached_segment_public_inputs_v1 = @import("detached_segment_public_inputs.zig");

pub const detached_segment_authority_boundary_v1 = @import("detached_segment_authority_boundary.zig");
pub const detached_segment_protocol_v1 = @import("detached_segment_protocol.zig");
pub const detached_segment_verifier_v1 = @import("detached_segment_verifier.zig");
pub const detached_segment_command_v1 = @import("detached_segment_command.zig");

pub const pcs_transcript_program_v1 = @import("pcs_transcript_program.zig");
pub const transcript_frame_rows_v1 = @import("transcript_frame_rows.zig");

pub const detached_child_views_v1 = @import("detached_child_views.zig");
pub const detached_prefix_preparation_v1 = @import("detached_prefix_preparation.zig");
pub const detached_pcs_rows_v1 = @import("detached_pcs_rows.zig");

pub const detached_section_profile_v1 = @import("detached_section_profile.zig");
pub const detached_memory_profile_v1 = @import("detached_memory_profile.zig");
pub const detached_segment_protocol_fixture_v1 = @import("detached_segment_protocol_fixture.zig");
pub const detached_native_leaf_preparation_v2 = @import("detached_native_leaf_preparation.zig");
pub const detached_leaf_noncore_owner_v2 = @import("detached_leaf_noncore_owner.zig");
pub const detached_recording_verifier_v1 = @import("detached_recording_verifier.zig");

pub const transaction_storage_v2 = @import("transaction_storage.zig");

pub const leaf_interaction_generator_v2 = @import("leaf_interaction_generator.zig");

pub const binary_verified_publication = @import("binary_verified_publication.zig");
pub const segment_verified_publication_v2 = @import("segment_verified_publication.zig");
pub const segment_verified_artifact_v2 = @import("segment_verified_artifact.zig");
pub const segment_outer_transaction_v2 = @import("segment_outer_transaction.zig");
pub const engine_protocol = @import("engine_protocol.zig");
pub const canonical_proof_identity_v1 = @import("canonical_proof_identity.zig");
pub const segment_outer_wire_geometry_v2 = @import("segment_outer_wire_geometry.zig");

pub const vm_composition_base_geometry_v2 = @import("vm_composition_base_geometry.zig");
pub const vm_selected_lookup_compiler_v2 = @import("vm_selected_lookup_compiler.zig");
pub const vm_composition_graph_support_v2 = @import("vm_composition_graph_support.zig");
pub const vm_composition_graph_base_v2 = @import("vm_composition_graph_base.zig");
pub const vm_composition_transcript_aggregates_v2 = @import("vm_composition_transcript_aggregates.zig");
