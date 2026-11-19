//! Registration for unchanged timing bodies owned by their test fixtures.

test "typed AUIPC hot rows retain paired legacy throughput in every build mode" {
    try @import("stwo_riscv_testing").benchmarks.auipc_witness.benchmarkLegacyThroughput();
}

test "E-020 BASE_ALU_IMM fixed direct evaluator retains legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.base_alu_imm_evaluator.benchmarkLegacyThroughput();
}

test "E-020 BASE_ALU_REG fixed direct evaluator retains at least 0.97x legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.base_alu_reg_evaluator.benchmarkLegacyThroughput();
}

test "BRANCH_EQ production direct and lookup evaluators retain legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.branch_eq_evaluator.benchmarkLegacyThroughput();
}

test "BRANCH_LT production direct and lookup evaluators retain legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.branch_lt_evaluator.benchmarkLegacyThroughput();
}

test "DIV fixed direct evaluator strictly preserves legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.div_evaluator.benchmarkLegacyThroughput();
}

test "E-019 typed FENCE fixed direct and lookup hot paths retain production throughput" {
    try @import("stwo_riscv_testing").benchmarks.fence_evaluator.benchmarkLegacyThroughput();
}

test "JAL production direct and lookup evaluators retain legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.jal_evaluator.benchmarkLegacyThroughput();
}

test "typed JAL hot rows retain paired legacy throughput in every build mode" {
    try @import("stwo_riscv_testing").benchmarks.jal_witness.benchmarkLegacyThroughput();
}

test "JALR production direct and lookup evaluators retain legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.jalr_evaluator.benchmarkLegacyThroughput();
}

test "typed JALR authority hot rows retain paired legacy throughput and scaling" {
    try @import("stwo_riscv_testing").benchmarks.jalr_witness.benchmarkLegacyThroughput();
}

test "LOAD_STORE fixed direct and lookup evaluators strictly preserve legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.load_store_evaluator.benchmarkLegacyThroughput();
}

test "LT_IMM production direct and lookup paths strictly preserve legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.lt_imm_evaluator.benchmarkLegacyThroughput();
}

test "LT_REG fixed direct and lookup evaluators retain legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.lt_reg_evaluator.benchmarkLegacyThroughput();
}

test "E-018 typed LUI fixed direct and lookup hot paths retain production throughput" {
    try @import("stwo_riscv_testing").benchmarks.lui_evaluator.benchmarkLegacyThroughput();
}

test "typed LUI authority hot rows retain paired legacy throughput and scaling" {
    try @import("stwo_riscv_testing").benchmarks.lui_witness.benchmarkLegacyThroughput();
}

test "MUL fixed direct evaluator strictly preserves legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.mul_evaluator.benchmarkLegacyThroughput();
}

test "typed MUL hot rows retain paired legacy throughput and linear scaling" {
    try @import("stwo_riscv_testing").benchmarks.mul_witness.benchmarkLegacyThroughput();
}

test "MULH fixed direct evaluator strictly preserves legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.mulh_evaluator.benchmarkLegacyThroughput();
}

test "SHIFTS_IMM fixed direct and lookup evaluators preserve legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.shifts_imm_evaluator.benchmarkLegacyThroughput();
}

test "SHIFTS_REG fixed direct and lookup evaluators retain legacy throughput" {
    try @import("stwo_riscv_testing").benchmarks.shifts_reg_evaluator.benchmarkLegacyThroughput();
}

test "typed AUIPC retirement retains at least 97 percent legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.auipc_retirement_test.benchmarkLegacyThroughput();
}

test "E-020 BASE_ALU_IMM retirement retains paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.base_alu_imm_retirement_test.benchmarkLegacyThroughput();
}

test "E-020 BASE_ALU_REG retirement retains at least 0.97x legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.base_alu_reg_retirement_test.benchmarkLegacyThroughput();
}

test "typed BRANCH_EQ retirement retains at least 0.97x legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.branch_eq_retirement_test.benchmarkLegacyThroughput();
}

test "typed BRANCH_LT retirement retains at least 97 percent legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.branch_lt_retirement_test.benchmarkLegacyThroughput();
}

test "DIV retirement strictly preserves paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.div_retirement_test.benchmarkLegacyThroughput();
}

test "E-019 staged FENCE retirement retains paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.fence_retirement_test.benchmarkLegacyThroughput();
}

test "JAL retirement retains paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.jal_retirement_test.benchmarkLegacyThroughput();
}

test "typed JALR retirement retains at least 97 percent legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.jalr_retirement_test.benchmarkLegacyThroughput();
}

test "LOAD_STORE retirement strictly preserves paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.load_store_retirement_test.benchmarkLegacyThroughput();
}

test "LT_IMM retirement strictly preserves paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.lt_imm_retirement_test.benchmarkLegacyThroughput();
}

test "LT_REG retirement retains at least 0.97x legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.lt_reg_retirement_test.benchmarkLegacyThroughput();
}

test "E-018 staged LUI retirement retains paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.lui_retirement_test.benchmarkLegacyThroughput();
}

test "MUL retirement strictly preserves paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.mul_retirement_test.benchmarkLegacyThroughput();
}

test "MULH retirement strictly preserves paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.mulh_retirement_test.benchmarkLegacyThroughput();
}

test "SHIFTS_IMM retirement strictly preserves paired legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.shifts_imm_retirement_test.benchmarkLegacyThroughput();
}

test "SHIFTS_REG retirement retains at least 0.97x legacy throughput" {
    try @import("stwo_riscv_rv32").testing.execution.tests.shifts_reg_retirement_test.benchmarkLegacyThroughput();
}

test "split sequential shadow path retains paired combined throughput" {
    try @import("stwo_riscv_testing").benchmarks.split_main_trace.benchmarkLegacyThroughput();
}

test "interaction trace epoch: paired scheduler performance sample" {
    try @import("stwo_riscv_rv32").testing.prover.tests.interaction_trace_plan_performance_test.benchmarkLegacyThroughput();
}
