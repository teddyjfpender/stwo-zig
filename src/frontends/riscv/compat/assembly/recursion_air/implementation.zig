//! Recursion-local components authored through the typed AIR compiler.

pub const blake3_native_transcript = @import("stwo_riscv_rv32").recursion.air.blake3_native_transcript;
pub const inventory = @import("stwo_riscv_rv32").recursion.air.inventory;
pub const composition_circuit = @import("stwo_riscv_rv32").recursion.air.composition_circuit;
pub const composition_graph_recorder = @import("stwo_riscv_rv32").recursion.air.composition_graph_recorder;
pub const control = @import("stwo_riscv_air_lang").framework.control;
pub const control_component = @import("stwo_riscv_recursion_air").control.component;
pub const control_relation = @import("stwo_riscv_air_lang").framework.control_relation;
pub const control_slice_witness = @import("stwo_riscv_recursion_air").control.slice_witness;
pub const control_witness = @import("stwo_riscv_recursion_air").control.witness;
pub const direct_constraint_program = @import("stwo_riscv_air_lang").framework.direct_constraint_program;
pub const field_public_word_v3 = @import("stwo_riscv_recursion_air").field_public_word;
pub const fixed_wire_v3 = @import("stwo_riscv_recursion_air").fixed_wire;
pub const field_statement_word_v3 = @import("stwo_riscv_recursion_air").field_statement_word;
pub const fri_merkle_anchor = @import("stwo_riscv_recursion_air").fri.merkle_anchor;
pub const fri_merkle_anchor_witness = @import("stwo_riscv_recursion_air").fri.merkle_anchor_witness;
pub const fri_merkle_leaf = @import("stwo_riscv_recursion_air").fri.merkle_leaf;
pub const fri_merkle_leaf_relation = @import("stwo_riscv_recursion_air").fri.merkle_leaf_relation;
pub const fri_merkle_leaf_witness = @import("stwo_riscv_recursion_air").fri.merkle_leaf_witness;
pub const fri_merkle_node = @import("stwo_riscv_recursion_air").fri.merkle_node;
pub const fri_merkle_node_relation = @import("stwo_riscv_recursion_air").fri.merkle_node_relation;
pub const fri_merkle_node_witness = @import("stwo_riscv_recursion_air").fri.merkle_node_witness;
pub const fri_verifier_control = @import("stwo_riscv_recursion_air").fri.verifier_control;
pub const fri_verifier_control_witness = @import("stwo_riscv_recursion_air").fri.verifier_control_witness;
pub const fri_verifier_circuit = @import("stwo_riscv_rv32").recursion.air.fri_verifier_circuit;
pub const fri_verifier_input = @import("stwo_riscv_recursion_air").fri.verifier_input;
pub const fri_verifier_input_relation = @import("stwo_riscv_recursion_air").fri.verifier_input_relation;
pub const fri_verifier_input_witness = @import("stwo_riscv_rv32").recursion.air.fri_verifier_input_witness;
pub const framework_device_interaction = @import("stwo_riscv_air_lang").framework.framework_device_interaction;
pub const prepared_interaction_generation = @import("stwo_riscv_recursion_air").prepared_interaction_generation;
pub const framework_interaction = @import("stwo_riscv_air_lang").framework.framework_interaction;
pub const linear_ops = @import("stwo_riscv_air_lang").framework.linear_ops;
pub const linear_ops_witness = @import("stwo_riscv_recursion_air").linear_ops_witness;
pub const merkle_path = @import("stwo_riscv_recursion_air").merkle.path;
pub const merkle_path_relation = @import("stwo_riscv_recursion_air").merkle.path_relation;
pub const merkle_path_witness = @import("stwo_riscv_recursion_air").merkle.path_witness;
pub const merkle_path_poseidon_bridge = @import("stwo_riscv_recursion_air").merkle.path_poseidon_bridge;
pub const merkle_root = @import("stwo_riscv_recursion_air").merkle.root;
pub const merkle_root_relation = @import("stwo_riscv_recursion_air").merkle.root_relation;
pub const merkle_root_witness = @import("stwo_riscv_recursion_air").merkle.root_witness;
pub const pcs_deep_input = @import("stwo_riscv_recursion_air").pcs_deep_input;
pub const pcs_deep_circuit = @import("stwo_riscv_recursion").air.pcs_deep_circuit;
pub const pcs_deep_input_witness = @import("stwo_riscv_rv32").recursion.air.pcs_deep_input_witness;
pub const pow_check = @import("stwo_riscv_recursion_air").pow.check;
pub const pow_check_witness = @import("stwo_riscv_recursion_air").pow.check_witness;
pub const pow_frame = @import("stwo_riscv_recursion_air").pow.frame;
pub const pow_frame_relation = @import("stwo_riscv_recursion_air").pow.frame_relation;
pub const pow_frame_witness = @import("stwo_riscv_recursion_air").pow.frame_witness;
pub const qm31_inv = @import("stwo_riscv_air_lang").framework.qm31_inv;
pub const qm31_inv_witness = @import("stwo_riscv_recursion_air").qm31.inv_witness;
pub const qm31_mul = @import("stwo_riscv_air_lang").framework.qm31_mul;
pub const qm31_mul_add_v1 = @import("stwo_riscv_air_lang").framework.qm31_mul_add;
pub const detached_arithmetic_fusion_plan = @import("stwo_riscv_rv32").recursion.air.detached_arithmetic_fusion_plan;
pub const detached_opening_accumulate4_v1 = @import("stwo_riscv_air_lang").framework.detached_opening_accumulate4;
pub const detached_opening_accumulation_plan = @import("stwo_riscv_rv32").recursion.air.detached_opening_accumulation_plan;
pub const qm31_mul_full = @import("stwo_riscv_recursion_air").qm31.mul_full;
pub const qm31_mul_full_witness = @import("stwo_riscv_recursion_air").qm31.mul_full_witness;
pub const query_bits = @import("stwo_riscv_recursion_air").query.bits;
pub const query_bits_relation = @import("stwo_riscv_recursion_air").query.bits_relation;
pub const query_bits_witness = @import("stwo_riscv_recursion_air").query.bits_witness;
pub const query_mapping = @import("stwo_riscv_recursion_air").query.mapping;
pub const query_mapping_relation = @import("stwo_riscv_recursion_air").query.mapping_relation;
pub const query_mapping_witness = @import("stwo_riscv_recursion_air").query.mapping_witness;
pub const range_check_8_8_bridge = @import("stwo_riscv_rv32").recursion.air.range_check_8_8_bridge;
pub const relation_effect = @import("stwo_riscv_air_lang").framework.relation_effect;
pub const relation_interaction = @import("stwo_riscv_air_lang").framework.relation_interaction;
pub const relation_challenge = @import("stwo_riscv_recursion_air").relation.challenge;
pub const relation_challenge_witness = @import("stwo_riscv_recursion_air").relation.challenge_witness;
pub const statement_input = @import("stwo_riscv_recursion_air").statement.input;
pub const statement_input_relation = @import("stwo_riscv_recursion_air").statement.input_relation;
pub const statement_input_witness = @import("stwo_riscv_rv32").recursion.air.statement_input_witness;
pub const statement_semantics_input = @import("stwo_riscv_recursion_air").statement.semantics_input;
pub const statement_semantics_input_relation = @import("stwo_riscv_recursion_air").statement.semantics_input_relation;
pub const statement_semantics_input_witness = @import("stwo_riscv_rv32").recursion.air.statement_semantics_input_witness;
pub const segment_boundary_components_v2 = @import("stwo_riscv_recursion").air.segment_boundary_components;
pub const segment_outer_adapter_manifest_v2 = @import("stwo_riscv_recursion").air.segment_outer_adapter_manifest;
pub const segment_outer_typed_catalog_v2 = @import("stwo_riscv_recursion").air.segment_outer_typed_catalog;
pub const segment_publication_input_provider_component_v2 =
    @import("stwo_riscv_recursion").air.segment_publication_input_provider_component;
pub const segment_publication_input_provider_v2 =
    @import("stwo_riscv_recursion").air.segment_publication_input_provider;
pub const trace_merkle = @import("stwo_riscv_recursion_air").trace_merkle;
pub const trace_merkle_relation = @import("stwo_riscv_recursion_air").trace_merkle_relation;
pub const trace_merkle_witness = @import("stwo_riscv_recursion_air").trace_merkle_witness;
pub const transcript_air = @import("stwo_riscv_recursion_air").transcript.air;
pub const transcript_air_witness = @import("stwo_riscv_recursion_air").transcript.air_witness;
pub const transcript_binding = @import("stwo_riscv_recursion_air").transcript.binding;
pub const transcript_binding_witness = @import("stwo_riscv_recursion_air").transcript.binding_witness;
pub const transcript_payload = @import("stwo_riscv_recursion_air").transcript.payload;
pub const transcript_payload_relation = @import("stwo_riscv_recursion_air").transcript.payload_relation;
pub const transcript_payload_witness = @import("stwo_riscv_recursion_air").transcript.payload_witness;
pub const transcript_state = @import("stwo_riscv_recursion_air").transcript.state;
pub const transcript_state_witness = @import("stwo_riscv_recursion_air").transcript.state_witness;
pub const transcript_word = @import("stwo_riscv_recursion_air").transcript.word;
pub const transcript_word_witness = @import("stwo_riscv_recursion_air").transcript.word_witness;
pub const universal_challenges = @import("stwo_riscv_air_lang").framework.universal_challenges;
pub const vm_public_logup_control_witness_v2 =
    @import("stwo_riscv_recursion_air").vm_public_logup_control_witness;
pub const universal_catalog = @import("stwo_riscv_recursion_air").universal_catalog;
pub const universal_adapter_manifest = @import("stwo_riscv_air_lang").framework.universal_adapter_manifest;
pub const universal_manifest = @import("stwo_riscv_rv32").recursion.air.universal_manifest;
pub const universal_relation_binding = @import("stwo_riscv_air_lang").framework.universal_relation_binding;
pub const universal_roster = @import("stwo_riscv_air_lang").framework.universal_roster;
pub const universal_shared_provider = @import("stwo_riscv_rv32").recursion.air.universal_shared_provider;
pub const universal_typed_component = @import("stwo_riscv_air_lang").framework.universal_typed_component;
/// Typed admission and core point-verification interface without prover construction.
pub const universal_typed_verifier_component = @import("stwo_riscv_air_lang").framework.universal_typed_verifier_component;
pub const verifier_schedule = @import("stwo_riscv_recursion_air").verifier_schedule;
pub const verifier_arithmetic_lowering = @import("stwo_riscv_rv32").recursion.air.verifier_arithmetic_lowering;
pub const verifier_randomness = @import("stwo_riscv_recursion_air").verifier_randomness;
pub const verifier_randomness_relation = @import("stwo_riscv_recursion_air").verifier_randomness_relation;
pub const verifier_randomness_witness = @import("stwo_riscv_recursion_air").verifier_randomness_witness;
pub const vm_air_composition_control = @import("stwo_riscv_recursion_air").vm_air_composition_control;
pub const vm_air_composition_input = @import("stwo_riscv_recursion_air").vm_air_composition_input;
pub const vm_air_composition_input_witness = @import("stwo_riscv_rv32").recursion.air.vm_air_composition_input_witness;
pub const vm_public_claim_hash = @import("stwo_riscv_recursion_air").vm_public_claim_hash;
pub const vm_public_claim_hash_witness = @import("stwo_riscv_rv32").recursion.air.vm_public_claim_hash_witness;
pub const vm_public_claim_input = @import("stwo_riscv_recursion_air").vm_public_claim_input;
pub const vm_public_claim_input_witness = @import("stwo_riscv_rv32").recursion.air.vm_public_claim_input_witness;
pub const vm_public_io_hash = @import("stwo_riscv_recursion_air").vm_public_io_hash;
pub const vm_public_io_hash_witness = @import("stwo_riscv_rv32").recursion.air.vm_public_io_hash_witness;
pub const vm_public_claim_semantics_input = @import("stwo_riscv_recursion_air").vm_public_claim_semantics_input;
pub const vm_public_claim_semantics_input_witness = @import("stwo_riscv_recursion_air").vm_public_claim_semantics_input_witness;
pub const vm_public_logup_control = @import("stwo_riscv_recursion_air").vm_public_logup_control;
pub const vm_public_logup_input = @import("stwo_riscv_recursion_air").vm_public_logup_input;
pub const vm_public_logup_input_witness = @import("stwo_riscv_recursion_air").vm_public_logup_input_witness;
pub const wire_interaction = @import("stwo_riscv_recursion_air").wire_interaction;

// Opt-in linear initial-input lane; not selected by any active manifest.

// Opt-in companion bridge; no selected manifest/default changes.

pub const detached_graph_input_v1 = @import("stwo_riscv_recursion_air").detached.graph_input;
pub const detached_poseidon_graph_v1 = @import("stwo_riscv_recursion_air").detached.poseidon_graph;

pub const detached_parent_catalog_v1 = @import("stwo_riscv_recursion_air").detached.parent_catalog;
pub const segment_leaf_catalog_v2 = @import("stwo_riscv_recursion").air.segment_leaf_catalog;
pub const framework_polynomial_export_v1 = @import("stwo_riscv_air_lang").framework.framework_polynomial_export;

pub const query_bits_profile = @import("stwo_riscv_recursion_air").query.bits_profile;

pub const verifier_component_parameters = @import("stwo_riscv_recursion_air").verifier_component_parameters;

pub const proof_kind = @import("stwo_riscv_air_lang").framework.proof_kind;

pub const segment_outer_manifest_contract_v2 = @import("stwo_riscv_recursion").air.segment_outer_manifest_contract;

pub const verifier_wire_claims = @import("stwo_riscv_recursion_air").verifier_wire_claims;

pub const blake3_native_challenge_links = @import("stwo_riscv_recursion").air.blake3_native_challenge_links;

pub const blake3_native_payload_links = @import("stwo_riscv_recursion").air.blake3_native_payload_links;

pub const blake3_native_sample_links = @import("stwo_riscv_recursion").air.blake3_native_sample_links;

pub const blake3_native_pcs_challenges = @import("stwo_riscv_recursion").air.blake3_native_pcs_challenges;

pub const blake3_native_terminal_encoding = @import("stwo_riscv_recursion").air.blake3_native_terminal_encoding;

pub const blake3_native_queries = @import("stwo_riscv_recursion").air.blake3_native_queries;

pub const blake3_stark_paths = @import("stwo_riscv_recursion").air.blake3_stark_paths;

pub const blake3_native_openings = @import("stwo_riscv_recursion").air.blake3_native_openings;

pub const blake3_native_root_nonce = @import("stwo_riscv_rv32").recursion.air.blake3_native_root_nonce;

pub const blake3_native_public_links = @import("stwo_riscv_recursion").air.blake3_native_public_links;

pub const blake3_native_public_sources = @import("stwo_riscv_recursion").air.blake3_native_public_sources;

pub const blake3_native_parent_rows = @import("stwo_riscv_recursion").air.blake3_native_parent_rows;

pub const blake3_native_parent_test_support = @import("stwo_riscv_recursion").testing.test_support.blake3_native_parent_test_support;

pub const blake3_memory_boundary = @import("stwo_riscv_air_lang").framework.blake3_memory_boundary;
