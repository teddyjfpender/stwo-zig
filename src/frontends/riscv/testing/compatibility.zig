//! Unstable package-owned hooks for adversarial and structural tests.
//!
//! Keeping these behind one named namespace lets repository tests exercise
//! committed-witness rejection without turning their implementation files into
//! cross-package relative-import entry points.

pub const interaction_legacy_test_oracle = @import("stwo_riscv_rv32").modules.air_interaction_legacy_test_oracle;

pub const clock_update_component_test =
    @import("stwo_riscv_rv32").modules.air_tests_clock_update_component_test;
pub const relation_export_components_test =
    @import("stwo_riscv_rv32").modules.air_tests_relation_export_components_test;
pub const relation_export_test = @import("stwo_riscv_rv32").modules.air_tests_relation_export_test;
pub const semantic_component_test = @import("stwo_riscv_rv32").modules.air_tests_semantic_component_test;
pub const typed_poseidon2_proof_test =
    @import("cases/air/lang/tests/typed_poseidon2_proof_test.zig");
pub const typed_lui = @import("stwo_riscv_air_lang").modules.typed_lui;
pub const typed_lui_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_lui_witness;
pub const lui_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_lui_legacy_test_oracle;
pub const typed_base_alu_imm_witness =
    @import("stwo_riscv_rv32").modules.air_lang_typed_base_alu_imm_witness;
pub const typed_base_alu_reg = @import("stwo_riscv_air_lang").modules.typed_base_alu_reg;
pub const typed_base_alu_reg_witness =
    @import("stwo_riscv_rv32").modules.air_lang_typed_base_alu_reg_witness;
pub const typed_auipc_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_auipc_witness;
pub const typed_branch_eq = @import("stwo_riscv_air_lang").modules.typed_branch_eq;
pub const typed_branch_eq_witness =
    @import("stwo_riscv_rv32").modules.air_lang_typed_branch_eq_witness;
pub const branch_eq_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_branch_eq_legacy_test_oracle;
pub const typed_branch_lt = @import("stwo_riscv_air_lang").modules.typed_branch_lt;
pub const typed_branch_lt_witness =
    @import("stwo_riscv_rv32").modules.air_lang_typed_branch_lt_witness;
pub const branch_lt_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_branch_lt_legacy_test_oracle;
pub const typed_jalr_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_jalr_witness;
pub const typed_jalr = @import("stwo_riscv_air_lang").modules.typed_jalr;
pub const jalr_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_jalr_legacy_test_oracle;
pub const typed_jal = @import("stwo_riscv_air_lang").modules.typed_jal;
pub const typed_jal_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_jal_witness;
pub const jal_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_jal_legacy_test_oracle;
pub const typed_load_store_witness =
    @import("stwo_riscv_rv32").modules.air_lang_typed_load_store_witness;
pub const typed_load_store_authority =
    @import("stwo_riscv_rv32").modules.air_lang_typed_load_store_authority;
pub const typed_fence = @import("stwo_riscv_air_lang").modules.typed_fence;
pub const typed_fence_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_fence_witness;
pub const typed_div_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_div_witness;
pub const typed_lt_imm = @import("stwo_riscv_air_lang").modules.typed_lt_imm;
pub const typed_lt_imm_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_lt_imm_witness;
pub const lt_imm_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_lt_imm_legacy_test_oracle;
pub const typed_lt_reg = @import("stwo_riscv_air_lang").modules.typed_lt_reg;
pub const typed_lt_reg_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_lt_reg_witness;
pub const lt_reg_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_lt_reg_legacy_test_oracle;
pub const typed_shifts_imm = @import("stwo_riscv_air_lang").modules.typed_shifts_imm;
pub const typed_shifts_imm_witness =
    @import("stwo_riscv_rv32").modules.air_lang_typed_shifts_imm_witness;
pub const shifts_imm_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_shifts_imm_legacy_test_oracle;
pub const shifts_imm_semantics =
    @import("stwo_riscv_rv32").modules.air_semantics_shifts_imm_legacy_test_oracle;
pub const typed_shifts_reg = @import("stwo_riscv_air_lang").modules.typed_shifts_reg;
pub const typed_shifts_reg_witness =
    @import("stwo_riscv_rv32").modules.air_lang_typed_shifts_reg_witness;
pub const shifts_reg_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_shifts_reg_legacy_test_oracle;
pub const shifts_reg_semantics =
    @import("stwo_riscv_rv32").modules.air_semantics_shifts_reg_legacy_test_oracle;
pub const typed_mul = @import("stwo_riscv_air_lang").modules.typed_mul;
pub const typed_mul_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_mul_witness;
pub const typed_mulh = @import("stwo_riscv_air_lang").modules.typed_mulh;
pub const typed_mulh_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_mulh_witness;
pub const mulh_legacy_test_oracle =
    @import("stwo_riscv_rv32").modules.runner_witness_mulh_legacy_test_oracle;
pub const public_data_v2_test_support = @import("stwo_riscv_rv32").modules.air_public_data_test_support;
pub const guest_precompile_test_elf =
    @import("stwo_riscv_rv32").modules.runner_guest_precompile_test_elf;
pub const guest_precompile_corpus_elf =
    @import("stwo_riscv_precompiles").modules.runner_c011_elf_test_support;
pub const guest_precompile_main_trace_support =
    @import("stwo_riscv_precompiles").modules.air_main_trace_test_support;
pub const bulk_memcpy_word_candidate_v1 =
    @import("stwo_riscv_precompiles").modules.air_bulk_memcpy_word_candidate;
pub const EthereumStackSwapCandidateExecutionSessionV1 =
    @import("stwo_riscv_rv32").modules.runner_segment_session.EthereumStackSwapCandidateExecutionSessionV1;
pub const EthereumBulkMemcpyCandidateExecutionSessionV1 =
    @import("stwo_riscv_rv32").modules.runner_segment_session.EthereumBulkMemcpyCandidateExecutionSessionV1;
pub const EthereumCombinedCandidateExecutionSessionV1 =
    @import("stwo_riscv_rv32").modules.runner_segment_session.EthereumCombinedCandidateExecutionSessionV1;
pub const ethereum_candidate_execution_capability_v1 = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_execution_capability;
pub const ethereum_candidate_execution_journal_v1 = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_execution_journal;
pub const ethereum_candidate_observed_journal_v1 = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_observed_journal;
pub const split_leaf_prepare =
    @import("stwo_riscv_rv32").modules.prover_guest_precompile_split_leaf_prepare;
pub const split_leaf_statement =
    @import("stwo_riscv_rv32").modules.prover_guest_precompile_split_leaf_statement;
pub const aggregation_test_fixture = @import("stwo_riscv_rv32").modules.aggregation_test_fixture;
pub const aggregation_types = @import("stwo_riscv_recursion_air").modules.protocol_aggregation_types;
/// Retained handwritten JALR evaluator for adversarial differential tests only.
pub const jalr_semantics =
    @import("stwo_riscv_rv32").modules.air_semantics_jalr_legacy_test_oracle;
pub const prover_orchestration = @import("stwo_riscv_rv32").modules.prover_orchestration;
pub const commitment_witness = @import("stwo_riscv_rv32").modules.prover_commitment_witness;
pub const statement_geometry = @import("stwo_riscv_rv32").modules.prover_statement_geometry;
pub const proof_workspace = @import("stwo_riscv_rv32").modules.prover_proof_workspace;
pub const main_trace_plan = @import("stwo_riscv_rv32").modules.prover_main_trace_plan;
pub const witness_hook = @import("stwo_riscv_rv32").modules.prover_test_witness_hook;

test {
    @import("std").testing.refAllDecls(@This());
}

/// Backend-neutral authorities consumed by cross-backend component proof tests.
/// Concrete engines and serialized proof transactions belong to src/products/riscv/cpu/tests.
pub const component_proof = struct {
    pub const narrow_air = @import("stwo_riscv_rv32").modules.air_memory_commitment_poseidon2_narrow_degree3;
    pub const universal_air = @import("stwo_riscv_rv32").modules.air_memory_commitment_poseidon2_universal_degree3;
    pub const poseidon_air = @import("stwo_riscv_memory").modules.air_poseidon2_air;
    pub const narrow_component = @import("stwo_riscv_rv32").modules.air_memory_commitment_poseidon2_narrow_component;
    pub const universal_component = @import("stwo_riscv_rv32").modules.air_memory_commitment_poseidon2_universal_component;
    pub const narrow_backend = @import("stwo_riscv_rv32").modules.air_memory_commitment_poseidon2_narrow_backend;
    pub const program_commitment = @import("stwo_riscv_rv32").modules.air_program_commitment;
    pub const program_interaction = @import("stwo_riscv_rv32").modules.air_program_interaction;
    pub const fixed_program_table = @import("stwo_riscv_rv32").modules.air_program_fixed_table;
    pub const trace_component = @import("stwo_riscv_rv32").modules.air_component;
    pub const relations = @import("stwo_riscv_air_lang").modules.shared_air_relation_challenges;
    pub const support = @import("stwo_riscv_rv32").modules.prover_memory_provider_shards_proof_harness;
};

pub const keccak_tuple_regression = @import("cases/air/guest_precompile/tests/keccakf_lookup_tuple_test.zig");

/// Backend-neutral AIR/fixture hooks used by the CPU integration proof corpus.
pub const blake3_proof = struct {
    pub const air_lang = @import("stwo_riscv_frontend").modules.compat_air_lang_mod;
    pub const blake3_state_tree = @import("stwo_riscv_memory").modules.air_blake3_state_tree;
    pub const blake3_byte_route = @import("stwo_riscv_air_lang").modules.framework_blake3_byte_route;
    pub const blake3_draw_witness = @import("stwo_riscv_recursion_air").modules.blake3_draw_witness;
    pub const blake3_field_bytes = @import("stwo_riscv_air_lang").modules.framework_blake3_field_bytes;
    pub const blake3_fixture_roster = @import("stwo_riscv_recursion_air").modules.blake3_fixture_roster;
    pub const blake3_frame_witness = @import("stwo_riscv_air_lang").modules.framework_blake3_frame_witness;
    pub const blake3_hash_plan = @import("stwo_riscv_air_lang").modules.framework_blake3_hash_plan;
    pub const blake3_hash_witness = @import("stwo_riscv_air_lang").modules.framework_blake3_hash_witness;
    pub const blake3_input_bridge = @import("stwo_riscv_air_lang").modules.framework_blake3_input_bridge;
    pub const blake3_lifted_leaf_plan = @import("stwo_riscv_recursion_air").modules.blake3_lifted_leaf_plan;
    pub const blake3_memory_path = @import("stwo_riscv_rv32").modules.recursion_air_blake3_memory_path;
    pub const blake3_memory_update = @import("stwo_riscv_rv32").modules.recursion_air_blake3_memory_update;
    pub const blake3_memory_update_chain = @import("stwo_riscv_rv32").modules.recursion_air_blake3_memory_update_chain;
    pub const blake3_merkle_path_witness = @import("stwo_riscv_recursion_air").modules.blake3_merkle_path_witness;
    pub const blake3_node_route = @import("stwo_riscv_recursion_air").modules.blake3_node_route;
    pub const blake3_private_word = @import("stwo_riscv_air_lang").modules.framework_blake3_private_word;
    pub const blake3_proof_fixture = @import("stwo_riscv_rv32").modules.recursion_air_blake3_proof_fixture;
    pub const blake3_proof_gate_test_support = @import("stwo_riscv_recursion_air").modules.blake3_proof_gate_test_support;
    pub const blake3_public_subtree_path = @import("stwo_riscv_rv32").modules.recursion_air_blake3_public_subtree_path;
    pub const blake3_query_witness = @import("stwo_riscv_recursion_air").modules.blake3_query_witness;
    pub const blake3_transcript_witness = @import("stwo_riscv_recursion_air").modules.blake3_transcript_witness;
    pub const readonly_consistency = @import("stwo_riscv_air_lang").modules.framework_readonly_consistency;
    pub const readonly_input = @import("stwo_riscv_air_lang").modules.framework_readonly_input;
    pub const test_support = @import("stwo_riscv_recursion_air").modules.test_support;
};
