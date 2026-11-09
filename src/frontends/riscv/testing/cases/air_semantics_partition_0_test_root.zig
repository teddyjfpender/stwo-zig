//! One required compilation partition of the complete focused target.

test {
    _ = @import("stwo_riscv_rv32").modules.air_interaction_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_auipc_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_base_alu_imm_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_base_alu_reg_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_branch_eq_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_branch_lt_legacy_test_oracle;
    _ = @import("stwo_riscv_air_lang").modules.shared_air_semantics_common;
    _ = @import("stwo_riscv_air_lang").modules.shared_air_semantics_control_common;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_div_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_fence_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_jal_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_jalr_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_load_store_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_lt_imm_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_lt_reg_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_lui_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_mod;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_mul_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_mulh_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_shift_common;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_shifts_imm_legacy_test_oracle;
    _ = @import("stwo_riscv_rv32").modules.air_semantics_shifts_reg_legacy_test_oracle;
    _ = @import("stwo_riscv_air_lang").modules.tests_direct_witness_executor_test;
    _ = @import("stwo_riscv_air_lang").modules.tests_hint_recipe_test;
    _ = @import("air/lang/tests/lookup_batch_execution_test.zig");
    _ = @import("air/lang/tests/lookup_batch_performance_test.zig");
    _ = @import("air/lang/tests/lookup_batch_planner_test.zig");
    _ = @import("stwo_riscv_air_lang").modules.tests_range_refinement_test;
    _ = @import("air/lang/tests/row_window_test.zig");
    _ = @import("air/lang/tests/access_transaction_test.zig");
    _ = @import("stwo_riscv_rv32").modules.runner_tests_fence_retirement_test;
}
