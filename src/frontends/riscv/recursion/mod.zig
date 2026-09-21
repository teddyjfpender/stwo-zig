//! Recursion protocol namespace.

pub const air = @import("air/mod.zig");
pub const segment_public_claim_hash_authority_v2 = @import("segment_public_claim_hash_authority_v2.zig");
pub const arithmetic_circuit = @import("arithmetic_circuit.zig");
pub const binary_arithmetic_rows_heterogeneous_v2 =
    @import("binary_arithmetic_rows_heterogeneous_v2.zig");
pub const binary_fri_outer_bundle = @import("binary_fri_outer_bundle.zig");
pub const binary_composition_rows_heterogeneous_v2 =
    @import("binary_composition_rows_heterogeneous_v2.zig");
pub const binary_fri_outer_source = @import("binary_fri_outer_source.zig");
pub const binary_global_closure_outer_source = @import("binary_global_closure_outer_source.zig");
pub const binary_inactive_outer_source = @import("binary_inactive_outer_source.zig");
pub const binary_merkle_path_program_heterogeneous_v2 =
    @import("binary_merkle_path_program_heterogeneous_v2.zig");
pub const binary_node_program_descriptor_v1 =
    @import("binary_node_program_descriptor_v1.zig");
pub const binary_public_rows_program_heterogeneous_v2 =
    @import("binary_public_rows_program_heterogeneous_v2.zig");
pub const binary_poseidon_provider_program_heterogeneous_v2 =
    @import("binary_poseidon_provider_program_heterogeneous_v2.zig");
pub const binary_pair_nonfri_outer_bundle = @import("binary_pair_nonfri_outer_bundle.zig");
pub const binary_pair_authority = @import("binary_pair_authority.zig");
pub const binary_transcript_outer_source = @import("binary_transcript_outer_source.zig");
pub const canonical_empty_cohort_v3 = @import("canonical_empty_cohort_v3.zig");
pub const captured_fri = @import("captured_fri.zig");
pub const compact_tuple_ledger_v1 = @import("compact_tuple_ledger_v1.zig");
pub const engine = @import("engine.zig");
pub const verifier_tree = @import("verifier_tree.zig");
pub const ethereum_composition_relations_v2 =
    @import("ethereum_composition_relations_v2.zig");
pub const ethereum_composition_extension_geometry_v2 =
    @import("ethereum_composition_extension_geometry_v2.zig");
pub const ethereum_leaf_link_program_v1 =
    @import("ethereum_leaf_link_program_v1.zig");
pub const ethereum_leaf_child_field_program_v1 =
    @import("ethereum_leaf_child_field_program_v1.zig");
pub const ethereum_leaf_child_field_witness_v1 =
    @import("ethereum_leaf_child_field_witness_v1.zig");
pub const ethereum_vm_composition_program_v2 =
    @import("ethereum_vm_composition_program_v2.zig");
pub const incremental_ethereum_vm_composition_program_v4 =
    @import("incremental_ethereum_vm_composition_program_v4.zig");
pub const ethereum_vm_program_field_authority_v1 =
    @import("ethereum_vm_program_field_authority_v1.zig");
pub const ethereum_vm_verified_program_descriptor_v1 =
    @import("ethereum_vm_verified_program_descriptor_v1.zig");
pub const provider_shard_composition_program_v1 =
    @import("provider_shard_composition_program_v1.zig");
pub const provider_shard_child_field_emitter_v1 =
    @import("provider_shard_child_field_emitter_v1.zig");
pub const provider_shard_recursive_verifier_inputs_v1 =
    @import("provider_shard_recursive_verifier_inputs_v1.zig");
pub const provider_shard_wrapper_program_v1 =
    @import("provider_shard_wrapper_program_v1.zig");
pub const fixed_profile = @import("fixed_profile.zig");
pub const fixed_wire = @import("fixed_wire.zig");
pub const fixed_wire_adapter = @import("fixed_wire_adapter.zig");
pub const fri_profile_frontier = @import("fri_profile_frontier.zig");
pub const leaf_profile = @import("leaf_profile.zig");
pub const pair_node = @import("pair_node.zig");
pub const poseidon2_channel = @import("poseidon2_channel.zig");
pub const proof_ingress = @import("proof_ingress.zig");
pub const protocol = @import("protocol.zig");
pub const recording_poseidon_channel_v4 =
    @import("recording_poseidon_channel_v4.zig");
pub const relation_summary = @import("relation_summary.zig");
pub const recursion_air_composition_circuit = @import("recursion_air_composition_circuit.zig");
pub const recursion_air_composition_circuit_v3 = @import("recursion_air_composition_circuit_v3.zig");
/// Shared fixtures consumed by integration tests through the frontend owner.
pub const recursion_air_composition_circuit_v3_test_support =
    @import("recursion_air_composition_circuit_v3_test_support.zig");
pub const segment_leaf_authority = @import("segment_leaf_authority.zig");
pub const segment_leaf_authority_v2 = @import("segment_leaf_authority_v2.zig");
pub const segment_leaf_local_authority_v3 =
    @import("segment_leaf_local_authority_v3.zig");
pub const segment_leaf_local_projection_v3 =
    @import("segment_leaf_local_projection_v3.zig");
pub const segment_leaf_local_verified_link_v3 =
    @import("segment_leaf_local_verified_link_v3.zig");
pub const segment_leaf_outer_bundle = @import("segment_leaf_outer_bundle.zig");
pub const segment_leaf_outer_air_v2 = @import("segment_leaf_outer_air_v2.zig");
pub const segment_leaf_outer_authority_v2 = @import("segment_leaf_outer_authority_v2.zig");
pub const segment_outer_cohort_v2 = @import("segment_outer_cohort_v2.zig");
pub const segment_outer_noncore_audits_v2 = @import("segment_outer_noncore_audits_v2.zig");
pub const segment_publication_input_provider_authority_v2 =
    @import("segment_publication_input_provider_authority_v2.zig");
pub const segment_profile = @import("segment_profile.zig");
pub const segment_range_authority = @import("segment_range_authority.zig");
pub const segment_range_authority_v2 = @import("segment_range_authority_v2.zig");
pub const segment_shared_poseidon_schedule_v2 = @import("segment_shared_poseidon_schedule_v2.zig");
pub const temporal_shared_poseidon_schedule_v3 = @import("temporal_shared_poseidon_schedule_v3.zig");
pub const segment_transcript_outer_source = @import("segment_transcript_outer_source.zig");
pub const segment_transcript_outer_source_v2 = @import("segment_transcript_outer_source_v2.zig");
pub const segment_transcript_outer_components_v2 = @import("segment_transcript_outer_components_v2.zig");
pub const segment_public_outer_source = @import("segment_public_outer_source.zig");
pub const segment_public_outer_source_v2 = @import("segment_public_outer_source_v2.zig");
pub const segment_public_outer_components_v2 = @import("segment_public_outer_components_v2.zig");
pub const segment_public_native_sum_authority_v2 = @import("segment_public_native_sum_authority_v2.zig");
pub const segment_statement_outer_source = @import("segment_statement_outer_source.zig");
pub const segment_statement_outer_source_v2 = @import("segment_statement_outer_source_v2.zig");
pub const segment_statement_outer_components_v2 = @import("segment_statement_outer_components_v2.zig");
pub const segment_statement_v2 = @import("segment_statement_v2.zig");
pub const segment_statement_v2_transcript_layout = @import("segment_statement_v2_transcript_layout.zig");
pub const segment_transcript_witness = @import("segment_transcript_witness.zig");
pub const scheduled_channel = @import("scheduled_channel.zig");
pub const scheduled_channel_v2 = @import("scheduled_channel_v2.zig");
pub const native_scheduled_channel = @import("native_scheduled_channel.zig");
pub const outer_parent_child_admission = @import("outer_parent_child_admission.zig");
pub const outer_parent_range_authority = @import("outer_parent_range_authority.zig");
pub const outer_parent_statement_air_source = @import("outer_parent_statement_air_source.zig");
pub const outer_parent_statement_source = @import("outer_parent_statement_source.zig");
pub const outer_parent_transcript_source = @import("outer_parent_transcript_source.zig");
pub const span_statement = @import("span_statement.zig");
pub const span_continuation_v1 = @import("span_continuation_v1.zig");
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
pub const vm_air_composition_circuit_parallel_v4 =
    @import("vm_air_composition_circuit_parallel_v4.zig");
pub const vm_composition_base_geometry_v2 =
    @import("vm_composition_base_geometry_v2.zig");
pub const vm_air_composition_prepared_v2 =
    @import("vm_air_composition_prepared_v2.zig");
pub const vm_selected_lookup_compiler_v2 =
    @import("vm_selected_lookup_compiler_v2.zig");
pub const vm_leaf_context = @import("vm_leaf_context.zig");
pub const vm_leaf_context_v2 = @import("vm_leaf_context_v2.zig");
pub const ethereum_leaf_context_v1 = @import("ethereum_leaf_context_v1.zig");

pub const vm_composition_preparation = @import("vm_composition_preparation.zig");
pub const incremental_ethereum_composition_profile_v4 = @import("incremental_ethereum_composition_profile_v4.zig");
pub const ethereum_statement_arithmetic_v4 = @import("ethereum_statement_arithmetic_v4.zig");
pub const statement_root_routing_audit = @import("statement_root_routing_audit.zig");
pub const ethereum_clock_routing_v1 = @import("ethereum_clock_routing_v1.zig");

pub const ethereum_publication_routing_v1 = @import("ethereum_publication_routing_v1.zig");

pub const detached_parent_verifier_components_v1 = @import("detached_parent_verifier_components_v1.zig");
pub const detached_parent_components_v1 = @import("detached_parent_components_v1.zig");
pub const detached_pcs_preparation_v1 = @import("detached_pcs_preparation_v1.zig");
pub const detached_parent_prepared_v1 = @import("detached_parent_prepared_v1.zig");
pub const detached_parent_protocol_v1 = @import("detached_parent_protocol_v1.zig");
pub const detached_claims_v1 = @import("detached_claims_v1.zig");
pub const detached_payload_v1 = @import("detached_payload_v1.zig");

pub const artifact_limits = @import("artifact_limits.zig");
pub const detached_proof_preflight = @import("detached_proof_preflight.zig");
pub const detached_parent_verifier_v1 = @import("detached_parent_verifier_v1.zig");

pub const detached_segment_expected_v1 = @import("detached_segment_expected_v1.zig");
pub const detached_parent_command_v1 = @import("detached_parent_command_v1.zig");

pub const detached_segment_admission_v1 = @import("detached_segment_admission_v1.zig");
pub const segment_leaf_parameters_v2 = @import("segment_leaf_parameters_v2.zig");
pub const detached_segment_definitions_v1 = @import("detached_segment_definitions_v1.zig");
pub const detached_segment_verifier_components_v1 = @import("detached_segment_verifier_components_v1.zig");

pub const segment_leaf_statement_contract_v2 = @import("segment_leaf_statement_contract_v2.zig");
pub const detached_segment_public_inputs_v1 = @import("detached_segment_public_inputs_v1.zig");

pub const detached_segment_authority_boundary_v1 = @import("detached_segment_authority_boundary_v1.zig");
pub const detached_segment_protocol_v1 = @import("detached_segment_protocol_v1.zig");
pub const detached_segment_verifier_v1 = @import("detached_segment_verifier_v1.zig");
pub const detached_segment_command_v1 = @import("detached_segment_command_v1.zig");

pub const pcs_transcript_program_v1 = @import("pcs_transcript_program_v1.zig");
pub const transcript_frame_rows_v1 = @import("transcript_frame_rows_v1.zig");

pub const detached_child_views_v1 = @import("detached_child_views_v1.zig");
pub const transcript_payload_kind_v1 = @import("transcript_payload_kind_v1.zig");
pub const detached_prefix_preparation_v1 = @import("detached_prefix_preparation_v1.zig");
pub const detached_pcs_rows_v1 = @import("detached_pcs_rows_v1.zig");

pub const detached_segment_recording_components_v1 = @import("detached_segment_recording_components_v1.zig");
pub const detached_section_profile_v1 = @import("detached_section_profile_v1.zig");
pub const detached_memory_profile_v1 = @import("detached_memory_profile_v1.zig");
pub const detached_segment_protocol_fixture_v1 = @import("detached_segment_protocol_fixture_v1.zig");
pub const detached_recording_draws_v1 = @import("detached_recording_draws_v1.zig");
pub const detached_child_capture_v1 = @import("detached_child_capture_v1.zig");
pub const detached_native_leaf_preparation_v2 = @import("detached_native_leaf_preparation_v2.zig");
pub const detached_leaf_noncore_owner_v2 = @import("detached_leaf_noncore_owner_v2.zig");
pub const detached_composition_preparation_v1 = @import("detached_composition_preparation_v1.zig");
pub const detached_boundary_preparation_v1 = @import("detached_boundary_preparation_v1.zig");
pub const detached_parent_statement_preparation_v1 = @import("detached_parent_statement_preparation_v1.zig");
pub const detached_parent_arithmetic_v1 = @import("detached_parent_arithmetic_v1.zig");
pub const detached_parent_base_rows_v1 = @import("detached_parent_base_rows_v1.zig");
pub const transcript_logical_rows_v1 = @import("transcript_logical_rows_v1.zig");
pub const common_fold_catalog_v3 = @import("common_fold_catalog_v3.zig");
pub const capture_query_geometry_v1 = @import("capture_query_geometry_v1.zig");
pub const transcript_row_checks_v1 = @import("transcript_row_checks_v1.zig");
pub const detached_parent_preparation_v1 = @import("detached_parent_preparation_v1.zig");
pub const detached_recording_verifier_v1 = @import("detached_recording_verifier_v1.zig");

pub const detached_fri_core_v2 = @import("detached_fri_core_v2.zig");

pub const detached_leaf_cohort_v2 = @import("detached_leaf_cohort_v2.zig");
pub const detached_leaf_tuple_diagnostic_v2 = @import("detached_leaf_tuple_diagnostic_v2.zig");

pub const transaction_storage_v2 = @import("transaction_storage_v2.zig");

pub const leaf_interaction_generator_v2 = @import("leaf_interaction_generator_v2.zig");

pub const binary_verified_publication = @import("binary_verified_publication.zig");
pub const segment_verified_publication_v2 = @import("segment_verified_publication_v2.zig");
pub const segment_verified_artifact_v2 = @import("segment_verified_artifact_v2.zig");
pub const segment_outer_transaction_support_v2 = @import("segment_outer_transaction_support_v2.zig");
pub const segment_outer_transaction_v2 = @import("segment_outer_transaction_v2.zig");
pub const segment_public_wire_boundary_v2 = @import("segment_public_wire_boundary_v2.zig");
pub const engine_protocol = @import("engine_protocol.zig");
pub const canonical_proof_identity_v1 = @import("canonical_proof_identity_v1.zig");
pub const segment_outer_wire_geometry_v2 = @import("segment_outer_wire_geometry_v2.zig");
