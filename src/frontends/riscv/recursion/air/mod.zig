//! Recursion-local components authored through the typed AIR compiler.

pub const blake3_native_transcript = @import("blake3_native_transcript.zig");
pub const inventory = @import("inventory.zig");
pub const composition_circuit = @import("composition_circuit.zig");
pub const composition_graph_recorder = @import("composition_graph_recorder.zig");
pub const control = @import("control.zig");
pub const control_component = @import("control_component.zig");
pub const control_relation = @import("control_relation.zig");
pub const control_slice_witness = @import("control_slice_witness.zig");
pub const control_witness = @import("control_witness.zig");
pub const direct_constraint_program = @import("direct_constraint_program.zig");
pub const field_public_word_v3 = @import("field_public_word_v3.zig");
pub const fixed_wire_v3 = @import("fixed_wire_v3.zig");
pub const field_statement_word_v3 = @import("field_statement_word_v3.zig");
pub const fri_merkle_anchor = @import("fri_merkle_anchor.zig");
pub const fri_merkle_anchor_witness = @import("fri_merkle_anchor_witness.zig");
pub const fri_merkle_leaf = @import("fri_merkle_leaf.zig");
pub const fri_merkle_leaf_relation = @import("fri_merkle_leaf_relation.zig");
pub const fri_merkle_leaf_witness = @import("fri_merkle_leaf_witness.zig");
pub const fri_merkle_node = @import("fri_merkle_node.zig");
pub const fri_merkle_node_relation = @import("fri_merkle_node_relation.zig");
pub const fri_merkle_node_witness = @import("fri_merkle_node_witness.zig");
pub const fri_verifier_control = @import("fri_verifier_control.zig");
pub const fri_verifier_control_witness = @import("fri_verifier_control_witness.zig");
pub const fri_verifier_circuit = @import("fri_verifier_circuit.zig");
pub const fri_verifier_input = @import("fri_verifier_input.zig");
pub const fri_verifier_input_relation = @import("fri_verifier_input_relation.zig");
pub const fri_verifier_input_witness = @import("fri_verifier_input_witness.zig");
pub const framework_device_interaction = @import("framework_device_interaction.zig");
pub const prepared_interaction_generation = @import("prepared_interaction_generation.zig");
pub const framework_interaction = @import("framework_interaction.zig");
pub const linear_ops = @import("linear_ops.zig");
pub const linear_ops_witness = @import("linear_ops_witness.zig");
pub const merkle_path = @import("merkle_path.zig");
pub const merkle_path_relation = @import("merkle_path_relation.zig");
pub const merkle_path_witness = @import("merkle_path_witness.zig");
pub const merkle_path_poseidon_bridge = @import("merkle_path_poseidon_bridge.zig");
pub const merkle_root = @import("merkle_root.zig");
pub const merkle_root_relation = @import("merkle_root_relation.zig");
pub const merkle_root_witness = @import("merkle_root_witness.zig");
pub const pcs_deep_input = @import("pcs_deep_input.zig");
pub const pcs_deep_circuit = @import("pcs_deep_circuit.zig");
pub const pcs_deep_input_witness = @import("pcs_deep_input_witness.zig");
pub const pow_check = @import("pow_check.zig");
pub const pow_check_witness = @import("pow_check_witness.zig");
pub const pow_frame = @import("pow_frame.zig");
pub const pow_frame_relation = @import("pow_frame_relation.zig");
pub const pow_frame_witness = @import("pow_frame_witness.zig");
pub const qm31_inv = @import("qm31_inv.zig");
pub const qm31_inv_witness = @import("qm31_inv_witness.zig");
pub const qm31_mul = @import("qm31_mul.zig");
pub const qm31_mul_add_v1 = @import("qm31_mul_add_v1.zig");
pub const detached_arithmetic_fusion_plan = @import("detached_arithmetic_fusion_plan.zig");
pub const detached_opening_accumulate4_v1 = @import("detached_opening_accumulate4_v1.zig");
pub const detached_opening_accumulation_plan = @import("detached_opening_accumulation_plan.zig");
pub const qm31_mul_full = @import("qm31_mul_full.zig");
pub const qm31_mul_full_witness = @import("qm31_mul_full_witness.zig");
pub const query_bits = @import("query_bits.zig");
pub const query_bits_relation = @import("query_bits_relation.zig");
pub const query_bits_witness = @import("query_bits_witness.zig");
pub const query_mapping = @import("query_mapping.zig");
pub const query_mapping_relation = @import("query_mapping_relation.zig");
pub const query_mapping_witness = @import("query_mapping_witness.zig");
pub const range_check_8_8_bridge = @import("range_check_8_8_bridge.zig");
pub const relation_effect = @import("relation_effect.zig");
pub const relation_interaction = @import("relation_interaction.zig");
pub const relation_challenge = @import("relation_challenge.zig");
pub const relation_challenge_witness = @import("relation_challenge_witness.zig");
pub const statement_input = @import("statement_input.zig");
pub const statement_input_relation = @import("statement_input_relation.zig");
pub const statement_input_witness = @import("statement_input_witness.zig");
pub const statement_semantics_input = @import("statement_semantics_input.zig");
pub const statement_semantics_input_relation = @import("statement_semantics_input_relation.zig");
pub const statement_semantics_input_witness = @import("statement_semantics_input_witness.zig");
pub const segment_boundary_components_v2 = @import("segment_boundary_components_v2.zig");
pub const segment_outer_adapter_manifest_v2 = @import("segment_outer_adapter_manifest_v2.zig");
pub const segment_outer_typed_catalog_v2 = @import("segment_outer_typed_catalog_v2.zig");
pub const segment_publication_input_provider_component_v2 =
    @import("segment_publication_input_provider_component_v2.zig");
pub const segment_publication_input_provider_v2 =
    @import("segment_publication_input_provider_v2.zig");
pub const trace_merkle = @import("trace_merkle.zig");
pub const trace_merkle_relation = @import("trace_merkle_relation.zig");
pub const trace_merkle_witness = @import("trace_merkle_witness.zig");
pub const transcript_air = @import("transcript_air.zig");
pub const transcript_air_witness = @import("transcript_air_witness.zig");
pub const transcript_binding = @import("transcript_binding.zig");
pub const transcript_binding_witness = @import("transcript_binding_witness.zig");
pub const transcript_payload = @import("transcript_payload.zig");
pub const transcript_payload_relation = @import("transcript_payload_relation.zig");
pub const transcript_payload_witness = @import("transcript_payload_witness.zig");
pub const transcript_state = @import("transcript_state.zig");
pub const transcript_state_witness = @import("transcript_state_witness.zig");
pub const transcript_word = @import("transcript_word.zig");
pub const transcript_word_witness = @import("transcript_word_witness.zig");
pub const universal_challenges = @import("universal_challenges.zig");
pub const vm_public_logup_control_witness_v2 =
    @import("vm_public_logup_control_witness_v2.zig");
pub const universal_catalog = @import("universal_catalog.zig");
pub const universal_adapter_manifest = @import("universal_adapter_manifest.zig");
pub const universal_manifest = @import("universal_manifest.zig");
pub const universal_relation_binding = @import("universal_relation_binding.zig");
pub const universal_roster = @import("universal_roster.zig");
pub const universal_shared_provider = @import("universal_shared_provider.zig");
pub const universal_typed_component = @import("universal_typed_component.zig");
/// Typed admission and core point-verification interface without prover construction.
pub const universal_typed_verifier_component = @import("universal_typed_verifier_component.zig");
pub const verifier_schedule = @import("verifier_schedule.zig");
pub const verifier_arithmetic_lowering = @import("verifier_arithmetic_lowering.zig");
pub const verifier_randomness = @import("verifier_randomness.zig");
pub const verifier_randomness_relation = @import("verifier_randomness_relation.zig");
pub const verifier_randomness_witness = @import("verifier_randomness_witness.zig");
pub const vm_air_composition_control = @import("vm_air_composition_control.zig");
pub const vm_air_composition_input = @import("vm_air_composition_input.zig");
pub const vm_air_composition_input_witness = @import("vm_air_composition_input_witness.zig");
pub const vm_public_claim_hash = @import("vm_public_claim_hash.zig");
pub const vm_public_claim_hash_witness = @import("vm_public_claim_hash_witness.zig");
pub const vm_public_claim_input = @import("vm_public_claim_input.zig");
pub const vm_public_claim_input_witness = @import("vm_public_claim_input_witness.zig");
pub const vm_public_io_hash = @import("vm_public_io_hash.zig");
pub const vm_public_io_hash_witness = @import("vm_public_io_hash_witness.zig");
pub const vm_public_claim_semantics_input = @import("vm_public_claim_semantics_input.zig");
pub const vm_public_claim_semantics_input_witness = @import("vm_public_claim_semantics_input_witness.zig");
pub const vm_public_logup_control = @import("vm_public_logup_control.zig");
pub const vm_public_logup_input = @import("vm_public_logup_input.zig");
pub const vm_public_logup_input_witness = @import("vm_public_logup_input_witness.zig");
pub const wire_interaction = @import("wire_interaction.zig");

// Opt-in linear initial-input lane; not selected by any active manifest.

// Opt-in companion bridge; no selected manifest/default changes.

pub const detached_graph_input_v1 = @import("detached_graph_input_v1.zig");
pub const detached_poseidon_graph_v1 = @import("detached_poseidon_graph_v1.zig");

pub const detached_parent_catalog_v1 = @import("detached_parent_catalog_v1.zig");
pub const segment_leaf_catalog_v2 = @import("segment_leaf_catalog_v2.zig");
pub const framework_polynomial_export_v1 = @import("framework_polynomial_export_v1.zig");

pub const query_bits_profile = @import("query_bits_profile.zig");

pub const verifier_component_parameters = @import("verifier_component_parameters.zig");

pub const proof_kind = @import("proof_kind.zig");

pub const segment_outer_manifest_contract_v2 = @import("segment_outer_manifest_contract_v2.zig");

pub const verifier_wire_claims = @import("verifier_wire_claims.zig");

pub const blake3_native_challenge_links = @import("blake3_native_challenge_links.zig");

pub const blake3_native_payload_links = @import("blake3_native_payload_links.zig");

pub const blake3_native_sample_links = @import("blake3_native_sample_links.zig");

pub const blake3_native_pcs_challenges = @import("blake3_native_pcs_challenges.zig");

pub const blake3_native_terminal_encoding = @import("blake3_native_terminal_encoding.zig");

pub const blake3_native_queries = @import("blake3_native_queries.zig");

pub const blake3_stark_paths = @import("blake3_stark_paths.zig");

pub const blake3_native_openings = @import("blake3_native_openings.zig");

pub const blake3_native_root_nonce = @import("blake3_native_root_nonce.zig");

pub const blake3_native_public_links = @import("blake3_native_public_links.zig");

pub const blake3_native_public_sources = @import("blake3_native_public_sources.zig");

pub const blake3_native_parent_rows = @import("blake3_native_parent_rows.zig");

pub const blake3_native_parent_test_support = @import("blake3_native_parent_test_support.zig");

pub const blake3_memory_boundary = @import("blake3_memory_boundary.zig");
