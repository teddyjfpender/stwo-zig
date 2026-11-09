//! Registration for unchanged timing bodies owned by their test fixtures.

test "typed AUIPC hot rows retain paired legacy throughput in every build mode" {
    try @import("typed_auipc_witness_test.zig").benchmarkLegacyThroughput();
}

test "E-020 BASE_ALU_IMM fixed direct evaluator retains legacy throughput" {
    try @import("typed_base_alu_imm_authority_test.zig").benchmarkLegacyThroughput();
}

test "E-020 BASE_ALU_REG fixed direct evaluator retains at least 0.97x legacy throughput" {
    try @import("typed_base_alu_reg_authority_test.zig").benchmarkLegacyThroughput();
}

test "BRANCH_EQ production direct and lookup evaluators retain legacy throughput" {
    try @import("typed_branch_eq_authority_test.zig").benchmarkLegacyThroughput();
}

test "BRANCH_LT production direct and lookup evaluators retain legacy throughput" {
    try @import("typed_branch_lt_authority_test.zig").benchmarkLegacyThroughput();
}

test "DIV fixed direct evaluator strictly preserves legacy throughput" {
    try @import("typed_div_authority_test.zig").benchmarkLegacyThroughput();
}

test "E-019 typed FENCE fixed direct and lookup hot paths retain production throughput" {
    try @import("typed_fence_authority_test.zig").benchmarkLegacyThroughput();
}

test "JAL production direct and lookup evaluators retain legacy throughput" {
    try @import("typed_jal_authority_test.zig").benchmarkLegacyThroughput();
}

test "typed JAL hot rows retain paired legacy throughput in every build mode" {
    try @import("typed_jal_witness_test.zig").benchmarkLegacyThroughput();
}

test "JALR production direct and lookup evaluators retain legacy throughput" {
    try @import("typed_jalr_authority_test.zig").benchmarkLegacyThroughput();
}

test "typed JALR authority hot rows retain paired legacy throughput and scaling" {
    try @import("typed_jalr_witness_test.zig").benchmarkLegacyThroughput();
}

test "LOAD_STORE fixed direct and lookup evaluators strictly preserve legacy throughput" {
    try @import("typed_load_store_authority_test.zig").benchmarkLegacyThroughput();
}

test "LT_IMM production direct and lookup paths strictly preserve legacy throughput" {
    try @import("typed_lt_imm_authority_test.zig").benchmarkLegacyThroughput();
}

test "LT_REG fixed direct and lookup evaluators retain legacy throughput" {
    try @import("typed_lt_reg_authority_test.zig").benchmarkLegacyThroughput();
}

test "E-018 typed LUI fixed direct and lookup hot paths retain production throughput" {
    try @import("typed_lui_authority_test.zig").benchmarkLegacyThroughput();
}

test "typed LUI authority hot rows retain paired legacy throughput and scaling" {
    try @import("typed_lui_witness_test.zig").benchmarkLegacyThroughput();
}

test "MUL fixed direct evaluator strictly preserves legacy throughput" {
    try @import("typed_mul_authority_test.zig").benchmarkLegacyThroughput();
}

test "typed MUL hot rows retain paired legacy throughput and linear scaling" {
    try @import("typed_mul_witness_test.zig").benchmarkLegacyThroughput();
}

test "MULH fixed direct evaluator strictly preserves legacy throughput" {
    try @import("typed_mulh_authority_test.zig").benchmarkLegacyThroughput();
}

test "SHIFTS_IMM fixed direct and lookup evaluators preserve legacy throughput" {
    try @import("typed_shifts_imm_authority_test.zig").benchmarkLegacyThroughput();
}

test "SHIFTS_REG fixed direct and lookup evaluators retain legacy throughput" {
    try @import("typed_shifts_reg_authority_test.zig").benchmarkLegacyThroughput();
}
