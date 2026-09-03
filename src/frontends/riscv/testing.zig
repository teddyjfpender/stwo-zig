//! Unstable package-owned hooks for adversarial and structural tests.
//!
//! Keeping these behind one named namespace lets repository tests exercise
//! committed-witness rejection without turning their implementation files into
//! cross-package relative-import entry points.

pub const clock_update_component_test =
    @import("air/clock_update_component_test.zig");
pub const relation_export_components_test =
    @import("air/relation_export_components_test.zig");
pub const relation_export_test = @import("air/relation_export_test.zig");
pub const semantic_component_test = @import("air/semantic_component_test.zig");
pub const typed_poseidon2_proof_test =
    @import("air/lang/typed_poseidon2_proof_test.zig");
pub const typed_lui = @import("air/lang/typed_lui.zig");
pub const typed_lui_witness = @import("air/lang/typed_lui_witness.zig");
pub const lui_legacy_test_oracle =
    @import("runner/witness/lui_legacy_test_oracle.zig");
pub const typed_base_alu_imm_witness =
    @import("air/lang/typed_base_alu_imm_witness.zig");
pub const base_alu_imm_legacy_test_oracle =
    @import("runner/witness/base_alu_imm_legacy_test_oracle.zig");
pub const typed_base_alu_reg = @import("air/lang/typed_base_alu_reg.zig");
pub const typed_base_alu_reg_witness =
    @import("air/lang/typed_base_alu_reg_witness.zig");
pub const base_alu_reg_legacy_test_oracle =
    @import("runner/witness/base_alu_reg_legacy_test_oracle.zig");
pub const typed_auipc_witness = @import("air/lang/typed_auipc_witness.zig");
pub const auipc_legacy_test_oracle =
    @import("runner/witness/auipc_legacy_test_oracle.zig");
pub const typed_branch_eq = @import("air/lang/typed_branch_eq.zig");
pub const typed_branch_eq_witness =
    @import("air/lang/typed_branch_eq_witness.zig");
pub const branch_eq_legacy_test_oracle =
    @import("runner/witness/branch_eq_legacy_test_oracle.zig");
pub const branch_eq_semantics =
    @import("air/semantics/branch_eq_legacy_test_oracle.zig");
pub const typed_branch_lt = @import("air/lang/typed_branch_lt.zig");
pub const typed_branch_lt_witness =
    @import("air/lang/typed_branch_lt_witness.zig");
pub const branch_lt_legacy_test_oracle =
    @import("runner/witness/branch_lt_legacy_test_oracle.zig");
pub const branch_lt_semantics =
    @import("air/semantics/branch_lt_legacy_test_oracle.zig");
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
pub const load_store_legacy_test_oracle =
    @import("runner/witness/load_store_legacy_test_oracle.zig");
pub const typed_fence = @import("air/lang/typed_fence.zig");
pub const typed_fence_witness = @import("air/lang/typed_fence_witness.zig");
pub const fence_legacy_test_oracle =
    @import("runner/witness/fence_legacy_test_oracle.zig");
pub const typed_div_witness = @import("air/lang/typed_div_witness.zig");
pub const div_legacy_test_oracle =
    @import("runner/witness/div_legacy_test_oracle.zig");
pub const typed_lt_imm = @import("air/lang/typed_lt_imm.zig");
pub const typed_lt_imm_witness = @import("air/lang/typed_lt_imm_witness.zig");
pub const lt_imm_legacy_test_oracle =
    @import("runner/witness/lt_imm_legacy_test_oracle.zig");
pub const lt_imm_semantics =
    @import("air/semantics/lt_imm_legacy_test_oracle.zig");
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
pub const mul_legacy_test_oracle =
    @import("runner/witness/mul_legacy_test_oracle.zig");
pub const typed_mulh = @import("air/lang/typed_mulh.zig");
pub const typed_mulh_witness = @import("air/lang/typed_mulh_witness.zig");
pub const mulh_legacy_test_oracle =
    @import("runner/witness/mulh_legacy_test_oracle.zig");
pub const guest_precompile_test_elf =
    @import("runner/guest_precompile/test_elf.zig");
pub const guest_precompile_corpus_elf =
    @import("runner/guest_precompile/c011_elf_test_support.zig");
pub const guest_precompile_main_trace_support =
    @import("air/guest_precompile/main_trace_test_support.zig");
pub const bulk_memcpy_proof_harness_v1 =
    @import("air/guest_precompile/bulk_memcpy_proof_harness_v1.zig");
pub const bulk_memcpy_proof_trace_v1 =
    @import("air/guest_precompile/bulk_memcpy_trace_v1.zig");
pub const bulk_memcpy_proof_component_v1 =
    @import("air/guest_precompile/bulk_memcpy_component_v1.zig");
pub const bulk_memcpy_word_candidate_v1 =
    @import("air/guest_precompile/bulk_memcpy_word_candidate_v1.zig");
pub const bulk_memcpy_relations_v1 =
    @import("air/guest_precompile/bulk_memcpy_relations_v1.zig");
pub const stack_swap_proof_harness_v1 =
    @import("air/guest_precompile/stack_swap_proof_harness_v1.zig");
pub const stack_swap_proof_component_v1 =
    @import("air/guest_precompile/stack_swap_component_v1.zig");
pub const stack_swap_proof_stark_component_v1 =
    @import("air/guest_precompile/stack_swap_stark_component_v1.zig");
pub const stack_swap_proof_trace_v1 =
    @import("air/guest_precompile/stack_swap_trace_v1.zig");
pub const stack_swap_candidate_abi_v1 =
    @import("isa/stack_swap_candidate_v1.zig");
pub const stack_swap_caller_candidate_v1 =
    @import("air/guest_precompile/stack_swap_caller_candidate_v1.zig");
pub const stack_swap_word_candidate_v1 =
    @import("air/guest_precompile/stack_swap_word_candidate_v1.zig");
pub const stack_swap_relations_v1 =
    @import("air/guest_precompile/stack_swap_relations_v1.zig");
pub const stack_swap_private_registry_v1 =
    @import("isa/stack_swap_private_registry_v1.zig");
pub const stack_swap_vm_profile_v1 =
    @import("air/guest_precompile/stack_swap_vm_profile_v1.zig");
pub const stack_swap_vm_integration_v1 =
    @import("prover/guest_precompile/stack_swap_vm_integration_v1.zig");
pub const stack_swap_candidate_dispatch_v1 =
    @import("runner/guest_precompile/stack_swap_candidate_dispatch_v1.zig");
pub const ethereum_stack_swap_candidate_authority_v1 =
    @import("isa/ethereum_stack_swap_candidate_v1.zig");
pub const ethereum_stack_swap_candidate_decode_v1 =
    @import("prover/guest_precompile/ethereum_stack_swap_candidate_decode_v1.zig");
pub const ethereum_stack_swap_candidate_state_v1 =
    @import("runner/guest_precompile/ethereum_stack_swap_candidate_v1.zig");
pub const ethereum_stack_swap_candidate_result_v1 =
    @import("runner/ethereum_stack_swap_candidate_result_v1.zig");
pub const EthereumStackSwapCandidateExecutionSessionV1 =
    @import("runner/segment_session.zig").EthereumStackSwapCandidateExecutionSessionV1;
pub const bulk_memcpy_private_registry_v1 =
    @import("isa/bulk_memcpy_private_registry_v1.zig");
pub const bulk_memcpy_vm_profile_v1 =
    @import("air/guest_precompile/bulk_memcpy_vm_profile_v1.zig");
pub const bulk_memcpy_candidate_dispatch_v1 =
    @import("runner/guest_precompile/bulk_memcpy_candidate_dispatch_v1.zig");
pub const ethereum_bulk_memcpy_candidate_authority_v1 =
    @import("isa/ethereum_bulk_memcpy_candidate_v1.zig");
pub const ethereum_bulk_memcpy_candidate_decode_v1 =
    @import("prover/guest_precompile/ethereum_bulk_memcpy_candidate_decode_v1.zig");
pub const ethereum_bulk_memcpy_candidate_state_v1 =
    @import("runner/guest_precompile/ethereum_bulk_memcpy_candidate_v1.zig");
pub const ethereum_bulk_memcpy_candidate_result_v1 =
    @import("runner/ethereum_bulk_memcpy_candidate_result_v1.zig");
pub const EthereumBulkMemcpyCandidateExecutionSessionV1 =
    @import("runner/segment_session.zig").EthereumBulkMemcpyCandidateExecutionSessionV1;
pub const ethereum_candidate_combined_authority_v1 =
    @import("isa/ethereum_candidate_combined_authority_v1.zig");
pub const ethereum_candidate_private_registry_v1 =
    @import("isa/ethereum_candidate_private_registry_v1.zig");
pub const ethereum_candidate_combined_decode_v1 =
    @import("prover/guest_precompile/ethereum_candidate_combined_decode_v1.zig");
pub const ethereum_candidate_combined_dispatch_v1 =
    @import("runner/guest_precompile/ethereum_candidate_combined_dispatch_v1.zig");
pub const ethereum_candidate_combined_elf_receipt_v1 =
    @import("runner/guest_precompile/ethereum_candidate_combined_elf_receipt_v1.zig");
pub const ethereum_candidate_combined_state_v1 =
    @import("runner/guest_precompile/ethereum_candidate_combined_v1.zig");
pub const ethereum_candidate_combined_result_v1 =
    @import("runner/ethereum_candidate_combined_result_v1.zig");
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
pub const bulk_memcpy_lifted_composition_diagnostic_v1 =
    @import("air/guest_precompile/bulk_memcpy_lifted_composition_diagnostic_v1.zig");
pub const split_leaf_prepare =
    @import("prover/guest_precompile/split_leaf_prepare.zig");
pub const split_leaf_statement =
    @import("prover/guest_precompile/split_leaf_statement.zig");
pub const narrow_memory_provider_proof_harness =
    @import("prover/memory_provider_shards/proof_harness.zig");
pub const narrow_memory_provider_joint_protocol =
    @import("prover/memory_provider_shards/joint_protocol.zig");
pub const narrow_memory_provider_joint_proof =
    @import("prover/memory_provider_shards/joint_proof.zig");
pub const narrow_memory_provider_joint_proof_v2 =
    @import("prover/memory_provider_shards/joint_provider_proof_v2.zig");
pub const narrow_memory_provider_full_core_joint_protocol =
    @import("prover/memory_provider_shards/full_core_joint_protocol.zig");
pub const narrow_memory_provider_full_core_joint_verifier =
    @import("prover/memory_provider_shards/full_core_joint_verifier.zig");
pub const narrow_memory_provider_full_core_provider_proof_v2 =
    @import("prover/memory_provider_shards/full_core_provider_proof_v2.zig");
pub const narrow_memory_provider_ethereum_omit_proof_v1 =
    @import("prover/memory_provider_shards/ethereum_omit_provider_proof_v1.zig");
pub const narrow_memory_provider_shard_authority =
    @import("prover/memory_provider_shards/authority.zig");
pub const narrow_memory_provider_degree5_proof_v1 =
    @import("prover/memory_provider_shards/degree5_provider_proof_v1.zig");
pub const narrow_memory_provider_degree5_order_proof_v2 =
    @import("prover/memory_provider_shards/degree5_provider_order_proof_v2.zig");
pub const narrow_memory_provider_degree5_ethereum_omit_proof_v1 =
    @import("prover/memory_provider_shards/degree5_ethereum_omit_provider_proof_v1.zig");
pub const narrow_memory_provider_ethereum_candidate_protocol_v1 =
    @import("prover/memory_provider_shards/ethereum_candidate_omit_protocol_v1.zig");
pub const narrow_memory_provider_degree5_ethereum_candidate_v1 =
    @import("prover/memory_provider_shards/degree5_ethereum_candidate_provider_v1.zig");
pub const narrow_memory_provider_order_component =
    @import("prover/memory_provider_shards/provider_order_component.zig");
pub const ethereum_leaf_child_field_test =
    @import("recursion/ethereum_leaf_child_field_test.zig");
pub const provider_shard_child_field_test =
    @import("recursion/provider_shard_child_field_test.zig");
pub const aggregation_test_fixture = @import("aggregation/test_fixture.zig");
pub const aggregation_types = @import("aggregation/types.zig");
pub const binary_pair_outer_fixture =
    @import("testing/binary_pair_outer_fixture.zig");
/// Retained handwritten JALR evaluator for adversarial differential tests only.
pub const jalr_semantics =
    @import("air/semantics/jalr_legacy_test_oracle.zig");
pub const prover_orchestration = @import("prover/orchestration.zig");
pub const commitment_witness = @import("prover/commitment_witness.zig");
pub const statement_geometry = @import("prover/statement_geometry.zig");
pub const proof_workspace = @import("prover/proof_workspace.zig");
pub const main_trace_plan = @import("prover/main_trace_plan.zig");
pub const witness_hook = @import("prover/test_witness_hook.zig");
/// Unstable joined-leaf proof surfaces. These remain outside the production
/// prover facade until the genuine Ethereum + V4 cold-capture gate succeeds.
pub const incremental_ethereum_orchestration_v4_internal =
    @import("prover/incremental_ethereum_orchestration_v3.zig");
pub const incremental_ethereum_verifier_v4_internal =
    @import("prover/incremental_ethereum_verifier_v3.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
