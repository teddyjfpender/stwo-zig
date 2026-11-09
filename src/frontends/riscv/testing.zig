//! Unstable package-owned hooks for adversarial and structural tests.
//!
//! Keeping these behind one named namespace lets repository tests exercise
//! committed-witness rejection without turning their implementation files into
//! cross-package relative-import entry points.

pub const interaction_legacy_test_oracle = @import("air/interaction_legacy_test_oracle.zig");

pub const clock_update_component_test =
    @import("air/tests/clock_update_component_test.zig");
pub const relation_export_components_test =
    @import("air/tests/relation_export_components_test.zig");
pub const relation_export_test = @import("air/tests/relation_export_test.zig");
pub const semantic_component_test = @import("air/tests/semantic_component_test.zig");
pub const typed_poseidon2_proof_test =
    @import("air/lang/tests/typed_poseidon2_proof_test.zig");
pub const typed_lui = @import("air/lang/typed_lui.zig");
pub const typed_lui_witness = @import("air/lang/typed_lui_witness.zig");
pub const lui_legacy_test_oracle =
    @import("runner/witness/lui_legacy_test_oracle.zig");
pub const typed_base_alu_imm_witness =
    @import("air/lang/typed_base_alu_imm_witness.zig");
pub const typed_base_alu_reg = @import("air/lang/typed_base_alu_reg.zig");
pub const typed_base_alu_reg_witness =
    @import("air/lang/typed_base_alu_reg_witness.zig");
pub const typed_auipc_witness = @import("air/lang/typed_auipc_witness.zig");
pub const typed_branch_eq = @import("air/lang/typed_branch_eq.zig");
pub const typed_branch_eq_witness =
    @import("air/lang/typed_branch_eq_witness.zig");
pub const branch_eq_legacy_test_oracle =
    @import("runner/witness/branch_eq_legacy_test_oracle.zig");
pub const typed_branch_lt = @import("air/lang/typed_branch_lt.zig");
pub const typed_branch_lt_witness =
    @import("air/lang/typed_branch_lt_witness.zig");
pub const branch_lt_legacy_test_oracle =
    @import("runner/witness/branch_lt_legacy_test_oracle.zig");
pub const typed_jalr_witness = @import("air/lang/typed_jalr_witness.zig");
pub const typed_jalr = @import("air/lang/typed_jalr.zig");
pub const jalr_legacy_test_oracle =
    @import("runner/witness/jalr_legacy_test_oracle.zig");
pub const typed_jal = @import("air/lang/typed_jal.zig");
pub const typed_jal_witness = @import("air/lang/typed_jal_witness.zig");
pub const jal_legacy_test_oracle =
    @import("runner/witness/jal_legacy_test_oracle.zig");
pub const typed_load_store_witness =
    @import("air/lang/typed_load_store_witness.zig");
pub const typed_load_store_authority =
    @import("air/lang/typed_load_store_authority.zig");
pub const typed_fence = @import("air/lang/typed_fence.zig");
pub const typed_fence_witness = @import("air/lang/typed_fence_witness.zig");
pub const typed_div_witness = @import("air/lang/typed_div_witness.zig");
pub const typed_lt_imm = @import("air/lang/typed_lt_imm.zig");
pub const typed_lt_imm_witness = @import("air/lang/typed_lt_imm_witness.zig");
pub const lt_imm_legacy_test_oracle =
    @import("runner/witness/lt_imm_legacy_test_oracle.zig");
pub const typed_lt_reg = @import("air/lang/typed_lt_reg.zig");
pub const typed_lt_reg_witness = @import("air/lang/typed_lt_reg_witness.zig");
pub const lt_reg_legacy_test_oracle =
    @import("runner/witness/lt_reg_legacy_test_oracle.zig");
pub const typed_shifts_imm = @import("air/lang/typed_shifts_imm.zig");
pub const typed_shifts_imm_witness =
    @import("air/lang/typed_shifts_imm_witness.zig");
pub const shifts_imm_legacy_test_oracle =
    @import("runner/witness/shifts_imm_legacy_test_oracle.zig");
pub const shifts_imm_semantics =
    @import("air/semantics/shifts_imm_legacy_test_oracle.zig");
pub const typed_shifts_reg = @import("air/lang/typed_shifts_reg.zig");
pub const typed_shifts_reg_witness =
    @import("air/lang/typed_shifts_reg_witness.zig");
pub const shifts_reg_legacy_test_oracle =
    @import("runner/witness/shifts_reg_legacy_test_oracle.zig");
pub const shifts_reg_semantics =
    @import("air/semantics/shifts_reg_legacy_test_oracle.zig");
pub const typed_mul = @import("air/lang/typed_mul.zig");
pub const typed_mul_witness = @import("air/lang/typed_mul_witness.zig");
pub const typed_mulh = @import("air/lang/typed_mulh.zig");
pub const typed_mulh_witness = @import("air/lang/typed_mulh_witness.zig");
pub const mulh_legacy_test_oracle =
    @import("runner/witness/mulh_legacy_test_oracle.zig");
pub const public_data_v2_test_support = @import("air/public_data_v2_test_support.zig");
pub const guest_precompile_test_elf =
    @import("runner/guest_precompile/test_elf.zig");
pub const guest_precompile_corpus_elf =
    @import("runner/guest_precompile/c011_elf_test_support.zig");
pub const guest_precompile_main_trace_support =
    @import("air/guest_precompile/main_trace_test_support.zig");
pub const bulk_memcpy_word_candidate_v1 =
    @import("air/guest_precompile/bulk_memcpy_word_candidate_v1.zig");
pub const EthereumStackSwapCandidateExecutionSessionV1 =
    @import("runner/segment_session.zig").EthereumStackSwapCandidateExecutionSessionV1;
pub const EthereumBulkMemcpyCandidateExecutionSessionV1 =
    @import("runner/segment_session.zig").EthereumBulkMemcpyCandidateExecutionSessionV1;
pub const EthereumCombinedCandidateExecutionSessionV1 =
    @import("runner/segment_session.zig").EthereumCombinedCandidateExecutionSessionV1;
pub const ethereum_candidate_execution_capability_v1 = @import(
    "runner/guest_precompile/ethereum_candidate_execution_capability_v1.zig",
);
pub const ethereum_candidate_execution_journal_v1 = @import(
    "runner/guest_precompile/ethereum_candidate_execution_journal_v1.zig",
);
pub const ethereum_candidate_observed_journal_v1 = @import(
    "runner/guest_precompile/ethereum_candidate_observed_journal_v1.zig",
);
pub const split_leaf_prepare =
    @import("prover/guest_precompile/split_leaf_prepare.zig");
pub const split_leaf_statement =
    @import("prover/guest_precompile/split_leaf_statement.zig");
pub const aggregation_test_fixture = @import("aggregation/test_fixture.zig");
pub const aggregation_types = @import("aggregation/types.zig");
/// Retained handwritten JALR evaluator for adversarial differential tests only.
pub const jalr_semantics =
    @import("air/semantics/jalr_legacy_test_oracle.zig");
pub const prover_orchestration = @import("prover/orchestration.zig");
pub const commitment_witness = @import("prover/commitment_witness.zig");
pub const statement_geometry = @import("prover/statement_geometry.zig");
pub const proof_workspace = @import("prover/proof_workspace.zig");
pub const main_trace_plan = @import("prover/main_trace_plan.zig");
pub const witness_hook = @import("prover/test_witness_hook.zig");

test {
    @import("std").testing.refAllDecls(@This());
}

/// Backend-neutral authorities consumed by cross-backend component proof tests.
/// Concrete engines and serialized proof transactions belong to src/products/riscv/cpu/tests.
pub const component_proof = struct {
    pub const narrow_air = @import("air/memory_commitment/poseidon2_narrow_degree3_v1.zig");
    pub const universal_air = @import("air/memory_commitment/poseidon2_universal_degree3_v1.zig");
    pub const poseidon_air = @import("air/memory_commitment/poseidon2_air.zig");
    pub const narrow_component = @import("air/memory_commitment/poseidon2_narrow_component_v1.zig");
    pub const universal_component = @import("air/memory_commitment/poseidon2_universal_component_v1.zig");
    pub const narrow_backend = @import("air/memory_commitment/poseidon2_narrow_backend_v1.zig");
    pub const program_commitment = @import("air/program/commitment.zig");
    pub const program_interaction = @import("air/program/interaction.zig");
    pub const fixed_program_table = @import("air/program/fixed_table_v1.zig");
    pub const trace_component = @import("air/component.zig");
    pub const relations = @import("air/relation_challenges.zig");
    pub const support = @import("prover/memory_provider_shards/proof_harness.zig");
};

pub const keccak_tuple_regression = @import("air/guest_precompile/tests/keccakf_lookup_tuple_test.zig");

/// Backend-neutral AIR/fixture hooks used by the CPU integration proof corpus.
pub const blake3_proof = struct {
    pub const air_lang = @import("air/lang/mod.zig");
    pub const blake3_state_tree = @import("air/memory_commitment/blake3_state_tree.zig");
    pub const blake3_byte_route = @import("recursion/air/blake3_byte_route.zig");
    pub const blake3_draw_witness = @import("recursion/air/blake3_draw_witness.zig");
    pub const blake3_field_bytes = @import("recursion/air/blake3_field_bytes.zig");
    pub const blake3_fixture_roster = @import("recursion/air/blake3_fixture_roster.zig");
    pub const blake3_frame_witness = @import("recursion/air/blake3_frame_witness.zig");
    pub const blake3_hash_plan = @import("recursion/air/blake3_hash_plan.zig");
    pub const blake3_hash_witness = @import("recursion/air/blake3_hash_witness.zig");
    pub const blake3_input_bridge = @import("recursion/air/blake3_input_bridge.zig");
    pub const blake3_lifted_leaf_plan = @import("recursion/air/blake3_lifted_leaf_plan.zig");
    pub const blake3_memory_path = @import("recursion/air/blake3_memory_path.zig");
    pub const blake3_memory_update = @import("recursion/air/blake3_memory_update.zig");
    pub const blake3_memory_update_chain = @import("recursion/air/blake3_memory_update_chain.zig");
    pub const blake3_merkle_path_witness = @import("recursion/air/blake3_merkle_path_witness.zig");
    pub const blake3_node_route = @import("recursion/air/blake3_node_route.zig");
    pub const blake3_private_word = @import("recursion/air/blake3_private_word.zig");
    pub const blake3_proof_fixture = @import("recursion/air/blake3_proof_fixture.zig");
    pub const blake3_proof_gate_test_support = @import("recursion/air/blake3_proof_gate_test_support.zig");
    pub const blake3_public_subtree_path = @import("recursion/air/blake3_public_subtree_path.zig");
    pub const blake3_query_witness = @import("recursion/air/blake3_query_witness.zig");
    pub const blake3_transcript_witness = @import("recursion/air/blake3_transcript_witness.zig");
    pub const readonly_consistency = @import("recursion/air/readonly_consistency.zig");
    pub const readonly_input = @import("recursion/air/readonly_input.zig");
    pub const test_support = @import("recursion/air/test_support.zig");
};
