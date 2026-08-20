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
pub const split_leaf_prepare =
    @import("prover/guest_precompile/split_leaf_prepare.zig");
pub const split_leaf_statement =
    @import("prover/guest_precompile/split_leaf_statement.zig");
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

test {
    @import("std").testing.refAllDecls(@This());
}
