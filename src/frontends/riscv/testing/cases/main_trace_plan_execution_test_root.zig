//! Focused compile/run root for the prepared Tree-1 generation slice.

comptime {
    _ = @import("stwo_riscv_rv32").modules.prover_tests_main_trace_plan_execution_test;
    _ = @import("stwo_riscv_rv32").modules.prover_main_trace_plan_execution_production;
    _ = @import("stwo_riscv_rv32").modules.prover_tests_main_trace_plan_execution_production_test;
    _ = @import("stwo_riscv_rv32").modules.prover_main_witness_work;
    _ = @import("stwo_riscv_rv32").modules.prover_tree2_main_source;
}
