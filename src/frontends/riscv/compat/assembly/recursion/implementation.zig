//! Recursion protocol namespace.

pub const vm_composition_sample_geometry = @import("stwo_riscv_rv32").recursion.vm_composition_sample_geometry;

pub const air = @import("../recursion_air/implementation.zig");
pub const detached_boundary_preparation_v1 = @import("detached_boundary_preparation.zig");
pub const detached_child_capture_v1 = @import("detached_child_capture.zig");
pub const detached_parent_statement_preparation_v1 = @import("detached_parent_statement_preparation.zig");
pub const detached_segment_recording_components_v1 = @import("detached_segment_recording_components.zig");
pub const detached_fri_core_v2 = @import("detached_fri_core.zig");
pub const detached_composition_preparation_v1 = @import("detached_composition_preparation.zig");
pub const detached_leaf_cohort_v2 = @import("detached_leaf_cohort.zig");
pub const detached_parent_preparation_v1 = @import("detached_parent_preparation.zig");

pub const segment_public_claim_hash_authority_v2 = @import("stwo_riscv_recursion").segment_public_claim_hash_authority;
pub const binary_fri_outer_source = @import("stwo_riscv_recursion").binary_fri_outer_source;
pub const binary_global_closure_outer_source = @import("stwo_riscv_recursion").binary_global_closure_outer_source;
pub const captured_fri = @import("stwo_riscv_recursion").captured_fri;
pub const compact_tuple_ledger_v1 = @import("stwo_riscv_recursion").compact_tuple_ledger;
pub const engine = @import("stwo_riscv_recursion").engine;
pub const verifier_tree = @import("stwo_riscv_recursion").verifier_tree;
pub const fixed_profile = @import("stwo_riscv_recursion_air").protocol.recursion.fixed_profile;
pub const fixed_wire = @import("stwo_riscv_recursion_air").protocol.recursion.fixed_wire;
pub const fixed_wire_adapter = @import("stwo_riscv_recursion").fixed_wire_adapter;
pub const fri_profile_frontier = @import("stwo_riscv_recursion").fri_profile_frontier;
pub const leaf_profile = @import("stwo_riscv_recursion").leaf_profile;
pub const pair_node = @import("stwo_riscv_recursion").pair_node;
pub const poseidon2_channel = @import("stwo_riscv_memory").recursion.poseidon2_channel;
pub const proof_ingress = @import("stwo_riscv_recursion").proof_ingress;
pub const protocol = @import("stwo_riscv_recursion_air").protocol.recursion.protocol;
pub const recording_poseidon_channel_v4 =
    @import("stwo_riscv_recursion").recording_poseidon_channel;
pub const recursion_air_composition_circuit_v3 = @import("recursion_air_composition_circuit_v3.zig");
/// Shared fixtures consumed by integration tests through the frontend owner.
pub const segment_leaf_authority = @import("stwo_riscv_recursion").segment_leaf_authority;
pub const segment_leaf_authority_v2 = @import("stwo_riscv_recursion").segment_leaf_authority_v2;
pub const segment_leaf_local_authority_v3 =
    @import("stwo_riscv_recursion").segment_leaf_local_authority;
pub const segment_leaf_local_projection_v3 =
    @import("stwo_riscv_recursion").segment_leaf_local_projection;
pub const segment_leaf_local_verified_link_v3 =
    @import("stwo_riscv_recursion").segment_leaf_local_verified_link;
pub const segment_leaf_outer_air_v2 = @import("stwo_riscv_recursion").segment_leaf_outer_air;
pub const segment_leaf_outer_authority_v2 = @import("stwo_riscv_recursion").segment_leaf_outer_authority;
pub const segment_outer_cohort_v2 = @import("stwo_riscv_recursion").segment_outer_cohort;
pub const segment_publication_input_provider_authority_v2 =
    @import("stwo_riscv_recursion").segment_publication_input_provider_authority;
pub const segment_profile = @import("stwo_riscv_rv32").recursion.segment_profile;
pub const segment_range_authority = @import("stwo_riscv_recursion").segment_range_authority;
pub const segment_shared_poseidon_schedule_v2 = @import("stwo_riscv_recursion").segment_shared_poseidon_schedule;
pub const segment_transcript_outer_source_v2 = @import("stwo_riscv_recursion").segment_transcript_outer_source_v2;
pub const segment_public_native_sum_authority_v2 = @import("stwo_riscv_recursion").segment_public_native_sum_authority;
pub const segment_statement_outer_source = @import("stwo_riscv_recursion").segment_statement_outer_source;
pub const segment_statement_v2 = @import("stwo_riscv_rv32").recursion.segment_statement;
pub const segment_transcript_witness = @import("stwo_riscv_recursion").segment_transcript_witness;
pub const native_scheduled_channel = @import("stwo_riscv_recursion").native_scheduled_channel;
pub const outer_parent_child_admission = @import("stwo_riscv_recursion").outer_parent_child_admission;
pub const span_statement = @import("stwo_riscv_rv32").recursion.span_statement;
pub const span_continuation_v1 = @import("stwo_riscv_recursion").span_continuation;
pub const statement_semantics_circuit = @import("stwo_riscv_recursion").statement_semantics_circuit;
pub const temporal_pair_node = @import("stwo_riscv_recursion").temporal_pair_node;
pub const transcript_program = @import("stwo_riscv_recursion").transcript_program;
pub const transcript_program_v2 = @import("stwo_riscv_recursion").transcript_program_v2;
pub const transcript_shape = @import("stwo_riscv_rv32").recursion.transcript_shape;
pub const vm_public_claim = @import("stwo_riscv_rv32").recursion.vm_public_claim;
pub const vm_public_semantics_circuit = @import("stwo_riscv_recursion").vm_public_semantics_circuit;
pub const vm_air_profile = @import("stwo_riscv_rv32").recursion.vm_air_profile;
pub const vm_air_profile_v2 = @import("stwo_riscv_rv32").recursion.vm_air_profile_v2;
pub const vm_air_composition_circuit = @import("stwo_riscv_recursion").vm_air_composition_circuit;
pub const vm_air_composition_prepared_v2 =
    @import("stwo_riscv_recursion").vm_air_composition_prepared;
pub const vm_leaf_context = @import("stwo_riscv_rv32").recursion.vm_leaf_context;
pub const vm_leaf_context_v2 = @import("stwo_riscv_rv32").recursion.vm_leaf_context_v2;

pub const vm_composition_preparation = @import("vm_composition_preparation.zig");

pub const detached_parent_verifier_components_v1 = @import("stwo_riscv_recursion").detached_parent_verifier_components;
pub const detached_parent_components_v1 = @import("stwo_riscv_recursion").detached_parent_components;
pub const detached_pcs_preparation_v1 = @import("stwo_riscv_recursion").detached_pcs_preparation;
pub const detached_parent_prepared_v1 = @import("stwo_riscv_recursion").detached_parent_prepared;
pub const detached_parent_protocol_v1 = @import("stwo_riscv_recursion").detached_parent_protocol;

pub const artifact_limits = @import("stwo_riscv_rv32").recursion.artifact_limits;
pub const detached_parent_verifier_v1 = @import("stwo_riscv_recursion").detached_parent_verifier;

pub const detached_parent_command_v1 = @import("stwo_riscv_recursion").detached_parent_command;

pub const detached_segment_admission_v1 = @import("stwo_riscv_recursion").detached_segment_admission;
pub const segment_leaf_parameters_v2 = @import("stwo_riscv_recursion").segment_leaf_parameters;
pub const detached_segment_definitions_v1 = @import("stwo_riscv_recursion").detached_segment_definitions;
pub const detached_segment_verifier_components_v1 = @import("stwo_riscv_recursion").detached_segment_verifier_components;

pub const segment_leaf_statement_contract_v2 = @import("stwo_riscv_recursion").segment_leaf_statement_contract;
pub const detached_segment_public_inputs_v1 = @import("stwo_riscv_recursion").detached_segment_public_inputs;

pub const detached_segment_authority_boundary_v1 = @import("stwo_riscv_recursion").detached_segment_authority_boundary;
pub const detached_segment_protocol_v1 = @import("stwo_riscv_recursion").detached_segment_protocol;
pub const detached_segment_verifier_v1 = @import("stwo_riscv_recursion").detached_segment_verifier;
pub const detached_segment_command_v1 = @import("stwo_riscv_recursion").detached_segment_command;

pub const pcs_transcript_program_v1 = @import("stwo_riscv_recursion").pcs_transcript_program;
pub const transcript_frame_rows_v1 = @import("stwo_riscv_recursion").transcript_frame_rows;

pub const detached_child_views_v1 = @import("stwo_riscv_recursion").detached_child_views;
pub const detached_prefix_preparation_v1 = @import("detached_prefix_preparation.zig");
pub const detached_pcs_rows_v1 = @import("detached_pcs_rows.zig");

pub const detached_section_profile_v1 = @import("stwo_riscv_recursion").detached_section_profile;
pub const detached_memory_profile_v1 = @import("stwo_riscv_recursion").detached_memory_profile;
pub const detached_segment_protocol_fixture_v1 = @import("stwo_riscv_recursion").detached_segment_protocol_fixture;
pub const detached_native_leaf_preparation_v2 = @import("stwo_riscv_recursion").detached_native_leaf_preparation;
pub const detached_leaf_noncore_owner_v2 = @import("stwo_riscv_recursion").detached_leaf_noncore_owner;
pub const detached_recording_verifier_v1 = @import("stwo_riscv_recursion").detached_recording_verifier;

pub const transaction_storage_v2 = @import("stwo_riscv_recursion").transaction_storage;

pub const leaf_interaction_generator_v2 = @import("stwo_riscv_recursion").leaf_interaction_generator;

pub const binary_verified_publication = @import("stwo_riscv_recursion").binary_verified_publication;
pub const segment_verified_publication_v2 = @import("stwo_riscv_recursion").segment_verified_publication;
pub const segment_verified_artifact_v2 = @import("stwo_riscv_recursion").segment_verified_artifact;
pub const segment_outer_transaction_v2 = @import("stwo_riscv_recursion").segment_outer_transaction;
pub const engine_protocol = @import("stwo_riscv_recursion_air").protocol.recursion.engine_protocol;
pub const canonical_proof_identity_v1 = @import("stwo_riscv_recursion").canonical_proof_identity;
pub const segment_outer_wire_geometry_v2 = @import("stwo_riscv_recursion").segment_outer_wire_geometry;

pub const vm_composition_base_geometry_v2 = @import("stwo_riscv_rv32").recursion.vm_composition_base_geometry;
pub const vm_selected_lookup_compiler_v2 = @import("stwo_riscv_recursion").vm_selected_lookup_compiler;
pub const vm_composition_graph_support_v2 = @import("stwo_riscv_recursion").vm_composition_graph_support;
pub const vm_composition_graph_base_v2 = @import("stwo_riscv_recursion").vm_composition_graph_base;
pub const vm_composition_transcript_aggregates_v2 = @import("stwo_riscv_recursion").vm_composition_transcript_aggregates;

pub const statement_arithmetic_preparation = @import("statement_arithmetic_preparation.zig");
