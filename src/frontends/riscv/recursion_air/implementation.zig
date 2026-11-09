//! Recursion-local components authored through the typed AIR compiler.

pub const blake3_native_transcript = @import("stwo_riscv_rv32").recursion_air_blake3_native_transcript;
pub const inventory = @import("stwo_riscv_rv32").recursion_air_inventory;
pub const composition_circuit = @import("stwo_riscv_rv32").recursion_air_composition_circuit;
pub const composition_graph_recorder = @import("stwo_riscv_rv32").recursion_air_composition_graph_recorder;
pub const control = @import("stwo_riscv_air_lang").framework_control;
pub const control_component = @import("control_component.zig");
pub const control_relation = @import("stwo_riscv_air_lang").framework_control_relation;
pub const control_slice_witness = @import("control_slice_witness.zig");
pub const control_witness = @import("control_witness.zig");
pub const direct_constraint_program = @import("stwo_riscv_air_lang").framework_direct_constraint_program;
pub const field_public_word_v3 = @import("field_public_word.zig");
pub const fixed_wire_v3 = @import("fixed_wire.zig");
pub const field_statement_word_v3 = @import("field_statement_word.zig");
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
pub const fri_verifier_circuit = @import("stwo_riscv_rv32").recursion_air_fri_verifier_circuit;
pub const fri_verifier_input = @import("fri_verifier_input.zig");
pub const fri_verifier_input_relation = @import("fri_verifier_input_relation.zig");
pub const fri_verifier_input_witness = @import("stwo_riscv_rv32").recursion_air_fri_verifier_input_witness;
pub const framework_device_interaction = @import("stwo_riscv_air_lang").framework_framework_device_interaction;
pub const prepared_interaction_generation = @import("prepared_interaction_generation.zig");
pub const framework_interaction = @import("stwo_riscv_air_lang").framework_framework_interaction;
pub const linear_ops = @import("stwo_riscv_air_lang").framework_linear_ops;
pub const linear_ops_witness = @import("linear_ops_witness.zig");
pub const merkle_path = @import("merkle_path.zig");
pub const merkle_path_relation = @import("merkle_path_relation.zig");
pub const merkle_path_witness = @import("merkle_path_witness.zig");
pub const merkle_path_poseidon_bridge = @import("merkle_path_poseidon_bridge.zig");
pub const merkle_root = @import("merkle_root.zig");
pub const merkle_root_relation = @import("merkle_root_relation.zig");
pub const merkle_root_witness = @import("merkle_root_witness.zig");
pub const pcs_deep_input = @import("pcs_deep_input.zig");
pub const pcs_deep_circuit = @import("stwo_riscv_recursion").air_pcs_deep_circuit;
pub const pcs_deep_input_witness = @import("stwo_riscv_rv32").recursion_air_pcs_deep_input_witness;
pub const pow_check = @import("pow_check.zig");
pub const pow_check_witness = @import("pow_check_witness.zig");
pub const pow_frame = @import("pow_frame.zig");
pub const pow_frame_relation = @import("pow_frame_relation.zig");
pub const pow_frame_witness = @import("pow_frame_witness.zig");
pub const qm31_inv = @import("stwo_riscv_air_lang").framework_qm31_inv;
pub const qm31_inv_witness = @import("qm31_inv_witness.zig");
pub const qm31_mul = @import("stwo_riscv_air_lang").framework_qm31_mul;
pub const qm31_mul_add_v1 = @import("stwo_riscv_air_lang").framework_qm31_mul_add;
pub const detached_arithmetic_fusion_plan = @import("stwo_riscv_rv32").recursion_air_detached_arithmetic_fusion_plan;
pub const detached_opening_accumulate4_v1 = @import("stwo_riscv_air_lang").framework_detached_opening_accumulate4;
pub const detached_opening_accumulation_plan = @import("stwo_riscv_rv32").recursion_air_detached_opening_accumulation_plan;
pub const qm31_mul_full = @import("qm31_mul_full.zig");
pub const qm31_mul_full_witness = @import("qm31_mul_full_witness.zig");
pub const query_bits = @import("query_bits.zig");
pub const query_bits_relation = @import("query_bits_relation.zig");
pub const query_bits_witness = @import("query_bits_witness.zig");
pub const query_mapping = @import("query_mapping.zig");
pub const query_mapping_relation = @import("query_mapping_relation.zig");
pub const query_mapping_witness = @import("query_mapping_witness.zig");
pub const range_check_8_8_bridge = @import("stwo_riscv_rv32").recursion_air_range_check_8_8_bridge;
pub const relation_effect = @import("stwo_riscv_air_lang").framework_relation_effect;
pub const relation_interaction = @import("stwo_riscv_air_lang").framework_relation_interaction;
pub const relation_challenge = @import("relation_challenge.zig");
pub const relation_challenge_witness = @import("relation_challenge_witness.zig");
pub const statement_input = @import("statement_input.zig");
pub const statement_input_relation = @import("statement_input_relation.zig");
pub const statement_input_witness = @import("stwo_riscv_rv32").recursion_air_statement_input_witness;
pub const statement_semantics_input = @import("statement_semantics_input.zig");
pub const statement_semantics_input_relation = @import("statement_semantics_input_relation.zig");
pub const statement_semantics_input_witness = @import("stwo_riscv_rv32").recursion_air_statement_semantics_input_witness;
pub const segment_boundary_components_v2 = @import("stwo_riscv_recursion").air_segment_boundary_components;
pub const segment_outer_adapter_manifest_v2 = @import("stwo_riscv_recursion").air_segment_outer_adapter_manifest;
pub const segment_outer_typed_catalog_v2 = @import("stwo_riscv_recursion").air_segment_outer_typed_catalog;
pub const segment_publication_input_provider_component_v2 =
    @import("stwo_riscv_recursion").air_segment_publication_input_provider_component;
pub const segment_publication_input_provider_v2 =
    @import("stwo_riscv_recursion").air_segment_publication_input_provider;
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
pub const universal_challenges = @import("stwo_riscv_air_lang").framework_universal_challenges;
pub const vm_public_logup_control_witness_v2 =
    @import("vm_public_logup_control_witness.zig");
pub const universal_catalog = @import("universal_catalog.zig");
pub const universal_adapter_manifest = @import("stwo_riscv_air_lang").framework_universal_adapter_manifest;
pub const universal_manifest = @import("stwo_riscv_rv32").recursion_air_universal_manifest;
pub const universal_relation_binding = @import("stwo_riscv_air_lang").framework_universal_relation_binding;
pub const universal_roster = @import("stwo_riscv_air_lang").framework_universal_roster;
pub const universal_shared_provider = @import("stwo_riscv_rv32").recursion_air_universal_shared_provider;
pub const universal_typed_component = @import("stwo_riscv_air_lang").framework_universal_typed_component;
/// Typed admission and core point-verification interface without prover construction.
pub const universal_typed_verifier_component = @import("stwo_riscv_air_lang").framework_universal_typed_verifier_component;
pub const verifier_schedule = @import("verifier_schedule.zig");
pub const verifier_arithmetic_lowering = @import("stwo_riscv_rv32").recursion_air_verifier_arithmetic_lowering;
pub const verifier_randomness = @import("verifier_randomness.zig");
pub const verifier_randomness_relation = @import("verifier_randomness_relation.zig");
pub const verifier_randomness_witness = @import("verifier_randomness_witness.zig");
pub const vm_air_composition_control = @import("vm_air_composition_control.zig");
pub const vm_air_composition_input = @import("vm_air_composition_input.zig");
pub const vm_air_composition_input_witness = @import("stwo_riscv_rv32").recursion_air_vm_air_composition_input_witness;
pub const vm_public_claim_hash = @import("vm_public_claim_hash.zig");
pub const vm_public_claim_hash_witness = @import("stwo_riscv_rv32").recursion_air_vm_public_claim_hash_witness;
pub const vm_public_claim_input = @import("vm_public_claim_input.zig");
pub const vm_public_claim_input_witness = @import("stwo_riscv_rv32").recursion_air_vm_public_claim_input_witness;
pub const vm_public_io_hash = @import("vm_public_io_hash.zig");
pub const vm_public_io_hash_witness = @import("stwo_riscv_rv32").recursion_air_vm_public_io_hash_witness;
pub const vm_public_claim_semantics_input = @import("vm_public_claim_semantics_input.zig");
pub const vm_public_claim_semantics_input_witness = @import("vm_public_claim_semantics_input_witness.zig");
pub const vm_public_logup_control = @import("vm_public_logup_control.zig");
pub const vm_public_logup_input = @import("vm_public_logup_input.zig");
pub const vm_public_logup_input_witness = @import("vm_public_logup_input_witness.zig");
pub const wire_interaction = @import("wire_interaction.zig");

// Opt-in linear initial-input lane; not selected by any active manifest.

// Opt-in companion bridge; no selected manifest/default changes.

pub const detached_graph_input_v1 = @import("detached_graph_input.zig");
pub const detached_poseidon_graph_v1 = @import("detached_poseidon_graph.zig");

pub const detached_parent_catalog_v1 = @import("detached_parent_catalog.zig");
pub const segment_leaf_catalog_v2 = @import("stwo_riscv_recursion").air_segment_leaf_catalog;
pub const framework_polynomial_export_v1 = @import("stwo_riscv_air_lang").framework_framework_polynomial_export;

pub const query_bits_profile = @import("query_bits_profile.zig");

pub const verifier_component_parameters = @import("verifier_component_parameters.zig");

pub const proof_kind = @import("stwo_riscv_air_lang").framework_proof_kind;

pub const segment_outer_manifest_contract_v2 = @import("stwo_riscv_recursion").air_segment_outer_manifest_contract;

pub const verifier_wire_claims = @import("verifier_wire_claims.zig");

pub const blake3_native_challenge_links = @import("stwo_riscv_recursion").air_blake3_native_challenge_links;

pub const blake3_native_payload_links = @import("stwo_riscv_recursion").air_blake3_native_payload_links;

pub const blake3_native_sample_links = @import("stwo_riscv_recursion").air_blake3_native_sample_links;

pub const blake3_native_pcs_challenges = @import("stwo_riscv_recursion").air_blake3_native_pcs_challenges;

pub const blake3_native_terminal_encoding = @import("stwo_riscv_recursion").air_blake3_native_terminal_encoding;

pub const blake3_native_queries = @import("stwo_riscv_recursion").air_blake3_native_queries;

pub const blake3_stark_paths = @import("stwo_riscv_recursion").air_blake3_stark_paths;

pub const blake3_native_openings = @import("stwo_riscv_recursion").air_blake3_native_openings;

pub const blake3_native_root_nonce = @import("stwo_riscv_rv32").recursion_air_blake3_native_root_nonce;

pub const blake3_native_public_links = @import("stwo_riscv_recursion").air_blake3_native_public_links;

pub const blake3_native_public_sources = @import("stwo_riscv_recursion").air_blake3_native_public_sources;

pub const blake3_native_parent_rows = @import("stwo_riscv_recursion").air_blake3_native_parent_rows;

pub const blake3_native_parent_test_support = @import("blake3_native_parent_test_support.zig");

pub const blake3_memory_boundary = @import("stwo_riscv_air_lang").framework_blake3_memory_boundary;
