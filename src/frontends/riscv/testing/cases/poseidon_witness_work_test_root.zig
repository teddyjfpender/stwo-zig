//! Focused P-003 sparse-memory and guest-Poseidon exact-work gate.

comptime {
    _ = @import("stwo_riscv_rv32").modules.prover_tests_poseidon_witness_work_test;
    _ = @import("stwo_riscv_rv32").modules.prover_commitment_witness;
    _ = @import("stwo_riscv_rv32").modules.air_guest_precompile_main_trace;
    _ = @import("stwo_riscv_rv32").modules.prover_main_trace_plan_execution_production_generators;
}
