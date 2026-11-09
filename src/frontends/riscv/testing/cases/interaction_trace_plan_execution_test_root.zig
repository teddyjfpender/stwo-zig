//! Focused compile/run root for the prepared Tree-2 interaction epoch.

comptime {
    _ = @import("stwo_riscv_rv32").modules.prover_tests_interaction_trace_plan_test;
    _ = @import("stwo_riscv_rv32").modules.prover_interaction_trace_plan_execution_production;
    _ = @import("stwo_riscv_rv32").modules.prover_interaction_trace_prepared_logup;
}
